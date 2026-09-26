#!/usr/bin/env python3
"""SHIPTRACE ground control: turns vision bearings into signed AIM commands.

Reads one input per line from stdin, either the vision tracker's JSON
    {"state": "TARGET_ACQUIRED", "angle": 97, ...}   /   {"state": "SEARCHING", "angle": null}
or a bare angle typed by hand (e.g. 120) for manual/fallback control.

    python -u vision/tracker.py --source 0 | python ground/ground_control.py --target <ESP32_IP>
    python -u fake_vision.py | python ground_control.py --target 127.0.0.1
    python ground_control.py --target <ESP32_IP>          (then type angles)

Guarantees (so our own traffic never trips the beacon's flood detector):
  * at most one packet every MIN_INTERVAL seconds (<= 3.3 packets/s; beacon trips at > 5/s)
  * newest bearing wins; stale ones are dropped, never queued
  * PING heartbeat only when nothing else was sent in the last HEARTBEAT seconds
  * angles outside 0..180 are never sent
"""
import argparse
import json
import queue
import socket
import sys
import threading
import time
from pathlib import Path

import protocol as P

MIN_INTERVAL = 0.30   # s between any two packets
HEARTBEAT = 1.0       # s of silence before sending PING
DEADBAND = 2          # deg change needed before re-sending AIM
LINK_TIMEOUT = 3.0    # s without any reply -> warn that the link is down


def reader(q):
    """Parse stdin lines into ('angle', int) or ('lost', None) events."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                print(f"[ground] ignoring bad JSON: {line[:60]}", file=sys.stderr)
                continue
            angle = obj.get("angle")
            if angle is None or obj.get("state") == "SEARCHING":
                q.put(("lost", None))
                continue
        else:
            angle = line
        try:
            angle = int(round(float(angle)))
        except (TypeError, ValueError):
            print(f"[ground] ignoring non-numeric input: {line[:60]}", file=sys.stderr)
            continue
        if not 0 <= angle <= 180:
            print(f"[ground] refusing out-of-range angle {angle}", file=sys.stderr)
            continue
        q.put(("angle", angle))
    q.put(("eof", None))


class GroundControl:
    def __init__(self, target, port, log_path):
        self.addr = (target, port)
        self.key = P.load_key()
        self.seq = P.SeqCounter()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setblocking(False)
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        self.log_file = open(log_path, "a", encoding="utf-8")
        self.last_tx = 0.0
        self.last_rx = time.monotonic()
        self.link_warned = False
        self.last_sent_angle = None
        self.beacon_safe = False

    def log(self, **evt):
        self.log_file.write(json.dumps({"t": round(time.time(), 3), **evt}) + "\n")
        self.log_file.flush()

    def send(self, cmd, arg):
        seq = self.seq.next()
        pkt = P.build(self.key, seq, cmd, arg)
        try:
            self.sock.sendto(pkt, self.addr)
        except OSError as e:
            print(f"[ground] send failed: {e}", file=sys.stderr)
            return
        self.last_tx = time.monotonic()
        self.log(evt="TX", seq=seq, cmd=cmd, arg=arg, dst=self.addr[0])
        if cmd == "AIM":
            print(f"[ground] TX AIM {arg:3d}  seq={seq}")

    def poll_replies(self):
        while True:
            try:
                data, _ = self.sock.recvfrom(256)
            except BlockingIOError:
                break
            except ConnectionResetError:
                # Windows: nothing is listening on the target port
                self.warn_link("no beacon listening at %s:%d" % self.addr)
                break
            self.last_rx = time.monotonic()
            self.link_warned = False
            reply = P.parse_reply(data)
            self.log(evt="RX", **reply)
            if reply["kind"] == "REJECT":
                if not self.beacon_safe:
                    print(f"\n!!! BEACON REJECTED OUR COMMAND ({reply['reason']}) - "
                          f"beacon is in SAFE MODE, AIM paused until physical reset !!!\n")
                self.beacon_safe = True
            elif reply["kind"] == "ACK":
                if self.beacon_safe:
                    print("\n=== beacon back to READY - resuming tracking ===\n")
                    self.last_sent_angle = None   # force re-send of the next bearing
                self.beacon_safe = False
            else:
                print(f"[ground] unexpected reply: {reply['raw']}", file=sys.stderr)

    def warn_link(self, msg):
        if not self.link_warned:
            print(f"[ground] WARNING: {msg}", file=sys.stderr)
            self.link_warned = True

    def run(self, q):
        pending = None
        eof = False
        print(f"[ground] sending to {self.addr[0]}:{self.addr[1]} "
              f"(min interval {MIN_INTERVAL}s, heartbeat {HEARTBEAT}s)")
        while True:
            # Drain input: newest bearing wins.
            try:
                while True:
                    kind, val = q.get_nowait()
                    if kind == "angle":
                        pending = val
                    elif kind == "lost":
                        if pending is not None or self.last_sent_angle is not None:
                            print("[ground] target lost - SEARCHING (holding last aim)")
                        pending = None
                        self.last_sent_angle = None
                    elif kind == "eof" and not eof:
                        eof = True
                        print("[ground] input ended - heartbeat only (Ctrl+C to quit)")
            except queue.Empty:
                pass

            now = time.monotonic()
            if pending is not None and (self.beacon_safe or (
                    self.last_sent_angle is not None and abs(pending - self.last_sent_angle) < DEADBAND)):
                pending = None   # drop: beacon locked out, or change too small to matter
            if now - self.last_tx >= MIN_INTERVAL:
                if pending is not None:
                    self.send("AIM", pending)
                    self.last_sent_angle = pending
                    pending = None
                elif now - self.last_tx >= HEARTBEAT:
                    self.send("PING", 0)

            self.poll_replies()
            if time.monotonic() - self.last_rx > LINK_TIMEOUT:
                self.warn_link(f"no reply for {LINK_TIMEOUT:.0f}s - is the beacon up and on this network?")
            time.sleep(0.02)


def main():
    ap = argparse.ArgumentParser(description="SHIPTRACE ground control")
    ap.add_argument("--target", default="127.0.0.1", help="ESP32 (or mock beacon) IP")
    ap.add_argument("--port", type=int, default=P.PORT)
    ap.add_argument("--log", default="logs/ground_events.jsonl")
    args = ap.parse_args()

    gc = GroundControl(args.target, args.port, args.log)
    q = queue.Queue()
    threading.Thread(target=reader, args=(q,), daemon=True).start()
    try:
        gc.run(q)
    except KeyboardInterrupt:
        print("\n[ground] stopped")


if __name__ == "__main__":
    main()
