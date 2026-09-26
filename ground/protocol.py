#!/usr/bin/env python3
"""SHIPTRACE command protocol v1.

Shared by ground_control.py, attacker.py and mock_beacon.py.
Wire format (UDP, port 4210, one command per packet, ASCII):

    v1|<seq>|<cmd>|<arg>|<hmac>

hmac = lowercase hex HMAC-SHA256 over the exact text "v1|<seq>|<cmd>|<arg>".
seq  = unsigned 64-bit, milliseconds since the Unix epoch, strictly increasing.

Run this file directly to self-test against the firmware test vectors:
    python protocol.py
"""
import hashlib
import hmac
import os
import sys
import time
from pathlib import Path

PORT = 4210
VERSION = "v1"
MAX_PACKET = 127
COMMANDS = {"AIM": (0, 180), "PING": (0, 0)}

# Demo key shared with the firmware test vectors. Replace it for the real demo by
# creating ground/key.hex (64 hex chars) and putting the same key in secrets.h.
DEMO_KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
KEY_FILE = Path(__file__).with_name("key.hex")

TEST_VECTORS = [
    (1727400000123, "AIM", 97,
     "481a7630e8caf04d9d5cdc3c67a2512f30e51f043a1d483e92f0cdf60b03fe71"),
    (1727400000124, "PING", 0,
     "af34712c68b77d0965611d10419bcf5bae3d92a64a1814c6cf0cf137303be26f"),
]


def load_key(quiet=False):
    """Key priority: SHIPTRACE_KEY env var, then key.hex, then the demo key."""
    env = os.environ.get("SHIPTRACE_KEY", "").strip()
    if env:
        hexkey, origin = env, "SHIPTRACE_KEY env var"
    elif KEY_FILE.exists():
        hexkey, origin = KEY_FILE.read_text().strip(), str(KEY_FILE.name)
    else:
        hexkey, origin = DEMO_KEY_HEX, "DEMO key (create key.hex before the real demo)"
    key = bytes.fromhex(hexkey)
    if len(key) != 32:
        raise ValueError(f"key from {origin} must be 32 bytes (64 hex chars), got {len(key)}")
    if not quiet:
        print(f"[protocol] using {origin}", file=sys.stderr)
    return key


def signed_text(seq, cmd, arg):
    return f"{VERSION}|{seq}|{cmd}|{arg}"


def sign(key, seq, cmd, arg):
    msg = signed_text(seq, cmd, arg).encode("ascii")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def build(key, seq, cmd, arg):
    """Return the full signed packet as bytes."""
    return f"{signed_text(seq, cmd, arg)}|{sign(key, seq, cmd, arg)}".encode("ascii")


class SeqCounter:
    """Millisecond-epoch sequence numbers that never repeat or go backwards."""

    def __init__(self):
        self.last = 0

    def next(self):
        seq = max(int(time.time() * 1000), self.last + 1)
        self.last = seq
        return seq


def parse_reply(data):
    """Parse 'ACK|<seq>' or 'REJECT|<seq>|<REASON>' into a dict."""
    text = data.decode("ascii", errors="replace").strip()
    parts = text.split("|")
    if parts[0] == "ACK" and len(parts) == 2:
        return {"kind": "ACK", "seq": parts[1], "raw": text}
    if parts[0] == "REJECT" and len(parts) == 3:
        return {"kind": "REJECT", "seq": parts[1], "reason": parts[2], "raw": text}
    return {"kind": "UNKNOWN", "raw": text}


def _self_test():
    key = bytes.fromhex(DEMO_KEY_HEX)
    ok = True
    for seq, cmd, arg, expected in TEST_VECTORS:
        got = sign(key, seq, cmd, arg)
        match = hmac.compare_digest(got, expected)
        ok &= match
        print(f"{signed_text(seq, cmd, arg):28s} {'OK' if match else 'MISMATCH'}  {got}")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(_self_test())
