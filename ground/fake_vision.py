#!/usr/bin/env python3
"""SHIPTRACE fake vision: emits tracker-format JSON so ground control can be tested
without the camera. Also a demo fallback if the camera dies.

    python -u fake_vision.py | python ground_control.py --target 127.0.0.1
    python -u fake_vision.py --lost-every 15     # drop the target for 2 s every 15 s
"""
import argparse
import json
import math
import sys
import time


def main():
    ap = argparse.ArgumentParser(description="SHIPTRACE fake vision source")
    ap.add_argument("--hz", type=float, default=3.0, help="lines per second (contract: <= 4)")
    ap.add_argument("--period", type=float, default=8.0, help="seconds per full sweep")
    ap.add_argument("--center", type=float, default=90.0)
    ap.add_argument("--span", type=float, default=60.0, help="+/- degrees around center")
    ap.add_argument("--lost-every", type=float, default=0.0, help="0 = never lose the target")
    args = ap.parse_args()

    hz = min(args.hz, 4.0)
    t0 = time.time()
    was_lost = False
    try:
        while True:
            t = time.time() - t0
            lost = args.lost_every > 0 and (t % args.lost_every) > args.lost_every - 2.0
            if lost:
                if not was_lost:
                    print(json.dumps({"t": round(time.time(), 3), "state": "SEARCHING", "angle": None}),
                          flush=True)
                was_lost = True
            else:
                was_lost = False
                angle = args.center + args.span * math.sin(2 * math.pi * t / args.period)
                angle = max(0, min(180, round(angle)))
                print(json.dumps({"t": round(time.time(), 3), "state": "TARGET_ACQUIRED",
                                  "angle": angle, "cx": 0, "cy": 0, "radius": 0}), flush=True)
            time.sleep(1.0 / hz)
    except (KeyboardInterrupt, BrokenPipeError):
        sys.exit(0)


if __name__ == "__main__":
    main()
