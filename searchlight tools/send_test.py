#!/usr/bin/env python3
"""
SHIPTRACE beacon test client — standard library only (socket, hmac, hashlib).

Usage:
    python send_test.py <ESP32_IP> <case>

Cases:
    valid    - one correctly signed AIM command (should ACK)
    ping     - one correctly signed PING (should ACK)
    replay   - a valid AIM, then the exact same packet again (2nd should REJECT|REPLAY)
    badhmac  - correct format, wrong signature (should REJECT|BAD_HMAC)
    unsigned - old-style unsigned command, doesn't match the protocol at all
               (should REJECT|BAD_FORMAT)
    badarg   - valid signature but AIM arg out of range (should REJECT|BAD_ARG)
    unknowncmd - valid signature, cmd "FIRE" (should REJECT|UNKNOWN_CMD)
    flood    - 8 distinct, validly-signed packets as fast as possible
               (the 6th+ should REJECT|RATE)

This uses the DEMO key from secrets.h.example. If you've swapped in a random
key on the device, update DEMO_KEY_HEX below to match, or these will all
come back BAD_HMAC.
"""

import socket
import sys
import time
import hmac
import hashlib

DEMO_KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
KEY = bytes.fromhex(DEMO_KEY_HEX)
PORT = 4210
TIMEOUT = 2.0


def sign(msg: str) -> str:
    return hmac.new(KEY, msg.encode("ascii"), hashlib.sha256).hexdigest()


def build_packet(seq, cmd, arg, bad_hmac=False):
    msg = f"v1|{seq}|{cmd}|{arg}"
    mac = sign(msg)
    if bad_hmac:
        # flip the first hex char so it's syntactically valid but wrong
        flipped = "0" if mac[0] != "0" else "1"
        mac = flipped + mac[1:]
    return f"{msg}|{mac}".encode("ascii")


def send(sock, ip, packet, label):
    sock.sendto(packet, (ip, PORT))
    print(f"--> [{label}] {packet.decode('ascii', errors='replace')}")
    try:
        data, _addr = sock.recvfrom(256)
        print(f"<-- [{label}] {data.decode('ascii', errors='replace')}")
    except socket.timeout:
        print(f"<-- [{label}] (no reply, timed out)")


def now_seq():
    return int(time.time() * 1000)


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)

    ip = sys.argv[1]
    case = sys.argv[2]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    if case == "valid":
        send(sock, ip, build_packet(now_seq(), "AIM", 97), "valid")

    elif case == "ping":
        send(sock, ip, build_packet(now_seq(), "PING", 0), "ping")

    elif case == "replay":
        pkt = build_packet(now_seq(), "AIM", 45)
        send(sock, ip, pkt, "replay-1st")
        time.sleep(0.2)
        send(sock, ip, pkt, "replay-2nd")

    elif case == "badhmac":
        send(sock, ip, build_packet(now_seq(), "AIM", 60, bad_hmac=True), "badhmac")

    elif case == "unsigned":
        pkt = b"AIM 90"
        send(sock, ip, pkt, "unsigned")

    elif case == "badarg":
        send(sock, ip, build_packet(now_seq(), "AIM", 200), "badarg")

    elif case == "unknowncmd":
        send(sock, ip, build_packet(now_seq(), "FIRE", 0), "unknowncmd")

    elif case == "flood":
        base = now_seq()
        for i in range(8):
            pkt = build_packet(base + i, "AIM", 10 + i)
            send(sock, ip, pkt, f"flood-{i}")

    else:
        print(f"Unknown case: {case}")
        print(__doc__)
        sys.exit(1)

    sock.close()


if __name__ == "__main__":
    main()
