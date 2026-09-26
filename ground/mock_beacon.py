#!/usr/bin/env python3
"""SHIPTRACE mock beacon: a software stand-in for the ESP32 firmware.

Implements the same validation order, state machine and JSON log format as the
firmware spec, so ground control and the attack scripts can be built and tested
before the hardware is ready. It is also the reference the firmware is checked against.

    python mock_beacon.py                 # listen on UDP 4210
    python mock_beacon.py --log logs/beacon_events.jsonl

Press Enter in this window to simulate holding the physical reset button.
"""
import argparse
import hashlib
import hmac
import json
import socket
import sys
import threading
import time
from collections import deque
from pathlib import Path

import protocol as P

RATE_LIMIT = 5          # more than this many packets in 1 s -> RATE
HEX = set("0123456789abcdef")


class Beacon:
    def __init__(self, key, log_path=None):
        self.key = key
        self.state = "READY"
        self.last_seq = 0
        self.angle = 90
        self.window = deque()
        self.lock = threading.Lock()
        self.t0 = time.monotonic()
        self.log_file = None
        if log_path:
            Path(log_path).parent.mkdir(parents=True, exist_ok=True)
            self.log_file = open(log_path, "a", encoding="utf-8")

    # ---------- logging ----------
    def log(self, **evt):
        record = {"ms": int((time.monotonic() - self.t0) * 1000), **evt}
        line = json.dumps(record)
        print(line, flush=True)
        if self.log_file:
            self.log_file.write(line + "\n")
            self.log_file.flush()

    def set_state(self, new, reason):
        if new == self.state:
            return
        self.log(evt="STATE", **{"from": self.state}, to=new, reason=reason)
        self.state = new
        if new == "SAFE_MODE":
            print(f"\n*** SAFE MODE ({reason}) - relay OPEN, servo UNPOWERED, red LED ON ***"
                  f"\n*** press Enter to simulate holding the reset button ***\n",
                  file=sys.stderr, flush=True)
        elif new == "READY":
            print("\n=== READY - relay CLOSED, servo powered, green LED ON ===\n",
                  file=sys.stderr, flush=True)

    # ---------- physical reset button ----------
    def press_reset(self):
        with self.lock:
            if self.state == "SAFE_MODE":
                # lastSeq is deliberately NOT reset, so old packets stay unreplayable.
                self.set_state("READY", "BUTTON")
            else:
                print("[beacon] reset button ignored (not in SAFE_MODE)", file=sys.stderr)

    # ---------- packet handling ----------
    def handle(self, data, src):
        now = time.monotonic()
        with self.lock:
            # 1. Rate window counts every packet, before any parsing or crypto.
            self.window.append(now)
            while self.window and now - self.window[0] > 1.0:
                self.window.popleft()

            text = data.decode("ascii", errors="replace").rstrip("\r\n")
            parts = text.split("|")
            seq_hint = (int(parts[1]) if len(parts) > 1 and parts[0] == P.VERSION
                        and parts[1].isdigit() and len(parts[1]) < 20 else 0)

            if self.state == "SAFE_MODE":
                self.log(evt="REJECT", src=src, reason="SAFE_MODE", seq=seq_hint)
                return f"REJECT|{seq_hint}|SAFE_MODE"

            reason, seq, cmd, arg = self.validate(data, text, parts)
            if reason:
                self.log(evt="REJECT", src=src, reason=reason, seq=seq if seq is not None else seq_hint,
                         raw=text[:80])
                self.set_state("SAFE_MODE", reason)
                return f"REJECT|{seq if seq is not None else seq_hint}|{reason}"

            # 7. Accept: lastSeq is updated only after every check passes.
            self.last_seq = seq
            self.log(evt="ACCEPT", src=src, seq=seq, cmd=cmd, arg=arg)
            if cmd == "AIM":
                self.angle = arg
                self.set_state("TRACKING", "AIM")
                print(f"[beacon] servo -> {arg:3d} deg", file=sys.stderr, flush=True)
            return f"ACK|{seq}"

    def validate(self, data, text, parts):
        """Return (reason, seq, cmd, arg). reason is None when the packet is valid."""
        if len(self.window) > RATE_LIMIT:
            return "RATE", None, None, None

        # 2. Format
        if (len(data) > P.MAX_PACKET or len(parts) != 5 or parts[0] != P.VERSION
                or not parts[1].isdigit() or len(parts[1]) > 20
                or not parts[3].isdigit() or len(parts[3]) > 3
                or len(parts[4]) != 64 or set(parts[4]) - HEX):
            return "BAD_FORMAT", None, None, None
        seq, cmd, arg = int(parts[1]), parts[2], int(parts[3])
        if seq >= 2 ** 64:
            return "BAD_FORMAT", None, None, None

        # 3. HMAC over the exact received text, constant-time compare
        expected = hmac.new(self.key, "|".join(parts[:4]).encode("ascii"),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, parts[4]):
            return "BAD_HMAC", seq, cmd, arg

        # 4. Replay (only meaningful once the signature is known good)
        if seq <= self.last_seq:
            return "REPLAY", seq, cmd, arg

        # 5. Command whitelist
        if cmd not in P.COMMANDS:
            return "UNKNOWN_CMD", seq, cmd, arg

        # 6. Argument bounds
        lo, hi = P.COMMANDS[cmd]
        if not lo <= arg <= hi:
            return "BAD_ARG", seq, cmd, arg

        return None, seq, cmd, arg


def button_thread(beacon):
    for _ in sys.stdin:
        beacon.press_reset()


def main():
    ap = argparse.ArgumentParser(description="SHIPTRACE mock ESP32 beacon")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=P.PORT)
    ap.add_argument("--log", default=None, help="append JSON events to this file")
    args = ap.parse_args()

    beacon = Beacon(P.load_key(), args.log)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    print(f"[beacon] MOCK listening on UDP {args.bind}:{args.port} - state READY",
          file=sys.stderr, flush=True)
    threading.Thread(target=button_thread, args=(beacon,), daemon=True).start()

    try:
        while True:
            try:
                data, addr = sock.recvfrom(2048)
            except ConnectionResetError:
                continue  # Windows reports ICMP port-unreachable here; ignore it
            reply = beacon.handle(data, addr[0])
            sock.sendto(reply.encode("ascii"), addr)
    except KeyboardInterrupt:
        print("\n[beacon] stopped", file=sys.stderr)


if __name__ == "__main__":
    main()
