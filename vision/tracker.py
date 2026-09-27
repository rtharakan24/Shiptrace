#!/usr/bin/env python3
"""
SHIPTRACE vision tracker -- finds the floating high-visibility target in the tote
(any colour listed in config "targets"; default ORANGE and NEON GREEN) and emits the
searchlight servo bearing (0-180 deg) as JSON lines on stdout. If several coloured
blobs are visible, the largest one wins.

Dependencies: Python 3, opencv-python (or python3-opencv from apt), numpy.

STDOUT CONTRACT (one JSON object per line, only when a command should be sent):
  {"t": 1727400000.123, "state": "TARGET_ACQUIRED", "angle": 97, "cx": 412, "cy": 188, "radius": 23, "target": "orange"}
  {"t": 1727400001.456, "state": "SEARCHING", "angle": null}
Everything else goes to stderr.

RATE RULE: never more than 4 lines/s (hard cap, regardless of config), and a
TARGET_ACQUIRED line is only sent when the angle moved >= deadband since the
last emitted line (or on (re)acquisition).

Usage (see README.md):
  python vision/tracker.py --source 0                 # live camera
  python vision/tracker.py --source 0 --tune          # HSV trackbars for "orange", 's' saves
  python vision/tracker.py --source 0 --tune --tune-target green   # tune the green range
  python vision/tracker.py --source 0 --calibrate     # click the servo
  python vision/tracker.py --source demo.mp4          # video file, loops
  python vision/tracker.py --source 0 --headless      # Pi over SSH
  python vision/tracker.py --source 0 --record out.mp4
"""

import argparse
import copy
import json
import math
import os
import sys
import time

import cv2
import numpy as np

HARD_MAX_EMIT_HZ = 4.0          # absolute ceiling; ESP32 flood detector trips at >5/s
WIN_MAIN = "SHIPTRACE"
WIN_MASK = "Mask"
WIN_CTRL = "HSV Controls"

DEFAULT_TARGETS = [
    {"name": "orange", "lower": [5, 120, 120], "upper": [25, 255, 255]},
    {"name": "green", "lower": [35, 100, 100], "upper": [80, 255, 255]},   # neon / lime green
]

DEFAULT_CONFIG = {
    "targets": DEFAULT_TARGETS,
    "min_area": 150,
    "morph_kernel": 5,
    "servo_x": 320,
    "servo_y": 470,
    "invert": False,
    "ema_alpha": 0.4,
    "deadband_deg": 2,
    "max_emit_hz": 4.0,
    "lost_timeout_s": 1.0,
    "acquire_frames": 3,
    "rotate": 0,
    "frame_width": 640,
    "frame_height": 480,
    "process_width": 640,
    "record_fps": 20,
}


# --------------------------------------------------------------------------- #
# Logging / config
# --------------------------------------------------------------------------- #
def log(msg):
    sys.stderr.write("[tracker %s] %s\n" % (time.strftime("%H:%M:%S"), msg))
    sys.stderr.flush()


def die(msg, code=1):
    log("ERROR: " + msg)
    sys.exit(code)


def load_config(path):
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if os.path.isfile(path):
        try:
            with open(path, "r") as f:
                user = json.load(f)
        except (ValueError, OSError) as e:
            die("could not read config %s: %s" % (path, e), 2)
        if not isinstance(user, dict):
            die("config %s must be a JSON object" % path, 2)
        # Legacy single-colour config (hsv_lower/hsv_upper): keep the tuned orange
        # values as the first target and add the default green target.
        if "targets" not in user and ("hsv_lower" in user or "hsv_upper" in user):
            legacy = {"name": "orange",
                      "lower": user.pop("hsv_lower", DEFAULT_TARGETS[0]["lower"]),
                      "upper": user.pop("hsv_upper", DEFAULT_TARGETS[0]["upper"])}
            user["targets"] = [legacy] + copy.deepcopy(DEFAULT_TARGETS[1:])
            log("migrated old hsv_lower/hsv_upper config to 'targets' (orange + green)")
            migrated = True
        else:
            migrated = False
        for k, v in user.items():
            if k not in DEFAULT_CONFIG:
                log("warning: unknown config key '%s' ignored" % k)
                continue
            cfg[k] = v
    else:
        log("config %s not found -- using defaults and creating it" % path)
        migrated = False
        save_config(path, cfg)

    # Sanitise types so a hand-edited config can't crash the loop.
    try:
        targets = []
        for t in cfg["targets"]:
            lo = [int(x) for x in t["lower"]][:3]
            hi = [int(x) for x in t["upper"]][:3]
            if len(lo) != 3 or len(hi) != 3:
                die("target '%s': lower/upper must each have 3 numbers" % t.get("name", "?"), 2)
            targets.append({"name": str(t.get("name", "target%d" % len(targets))),
                            "lower": lo, "upper": hi})
        if not targets:
            die("config 'targets' is empty -- need at least one colour", 2)
        cfg["targets"] = targets
        for k in ("min_area", "morph_kernel", "servo_x", "servo_y", "acquire_frames",
                  "rotate", "frame_width", "frame_height", "process_width", "record_fps"):
            cfg[k] = int(cfg[k])
        for k in ("ema_alpha", "deadband_deg", "max_emit_hz", "lost_timeout_s"):
            cfg[k] = float(cfg[k])
        cfg["invert"] = bool(cfg["invert"])
    except (TypeError, ValueError, KeyError) as e:
        die("bad value in config %s: %s" % (path, e), 2)
    if cfg["rotate"] not in (0, 90, 180, 270):
        die("rotate must be 0, 90, 180 or 270", 2)
    cfg["ema_alpha"] = min(1.0, max(0.01, cfg["ema_alpha"]))
    cfg["morph_kernel"] = max(1, cfg["morph_kernel"])
    cfg["acquire_frames"] = max(1, cfg["acquire_frames"])
    cfg["record_fps"] = max(1, cfg["record_fps"])
    if migrated:
        save_config(path, cfg)
    log("tracking colours: %s" % ", ".join(t["name"] for t in cfg["targets"]))
    return cfg


def save_config(path, cfg):
    d = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(d):
        os.makedirs(d)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)


# --------------------------------------------------------------------------- #
# Video source (camera or looping file)
# --------------------------------------------------------------------------- #
class Source(object):
    MAX_CAM_FAILS = 30

    def __init__(self, spec, cfg):
        self.spec = spec
        self.cfg = cfg
        self.is_cam = spec.strip().lstrip("-").isdigit()
        self.fails = 0
        self.cap = self._open()
        self.file_dt = 0.0
        self.next_t = time.monotonic()
        if not self.is_cam:
            fps = self.cap.get(cv2.CAP_PROP_FPS)
            if not fps or fps != fps or fps < 1 or fps > 240:
                fps = 30.0
            self.file_dt = 1.0 / fps
            log("video file %s @ %.1f fps (will loop)" % (spec, fps))

    def _open(self):
        if self.is_cam:
            idx = int(self.spec)
            if sys.platform.startswith("win"):
                cap = cv2.VideoCapture(idx, cv2.CAP_DSHOW)   # MSMF is slow/flaky with C270
            else:
                cap = cv2.VideoCapture(idx)
            if cap is None or not cap.isOpened():
                die("could not open camera index %d. Is the C270 plugged in? "
                    "Try --source 1 (laptops often have a built-in cam at 0), and "
                    "close any other app using the camera." % idx, 2)
            cap.set(cv2.CAP_PROP_FRAME_WIDTH, self.cfg["frame_width"])
            cap.set(cv2.CAP_PROP_FRAME_HEIGHT, self.cfg["frame_height"])
            try:
                cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)          # lower latency on V4L2
            except Exception:
                pass
        else:
            if not os.path.isfile(self.spec):
                die("video file not found: %s" % self.spec, 2)
            cap = cv2.VideoCapture(self.spec)
            if cap is None or not cap.isOpened():
                die("could not open video file %s" % self.spec, 2)
        ok, frame = cap.read()
        if not ok or frame is None:
            die("source %s opened but returned no frames" % self.spec, 2)
        self.first = frame
        return cap

    def _prep(self, frame):
        w, h = self.cfg["frame_width"], self.cfg["frame_height"]
        if frame.shape[1] != w or frame.shape[0] != h:
            frame = cv2.resize(frame, (w, h), interpolation=cv2.INTER_AREA)
        r = self.cfg["rotate"]
        if r == 90:
            frame = cv2.rotate(frame, cv2.ROTATE_90_CLOCKWISE)
        elif r == 180:
            frame = cv2.rotate(frame, cv2.ROTATE_180)
        elif r == 270:
            frame = cv2.rotate(frame, cv2.ROTATE_90_COUNTERCLOCKWISE)
        return frame

    def read(self):
        """Returns a prepared BGR frame, or None for a transient failure."""
        if self.first is not None:
            frame, self.first = self.first, None
            return self._prep(frame)

        if not self.is_cam:
            # pace file playback to its native fps so the demo looks real-time
            now = time.monotonic()
            if self.next_t > now:
                time.sleep(self.next_t - now)
            self.next_t = max(self.next_t + self.file_dt, time.monotonic() - 0.5)

        ok, frame = self.cap.read()
        if ok and frame is not None:
            self.fails = 0
            return self._prep(frame)

        if not self.is_cam:
            # end of file -> loop
            self.cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
            ok, frame = self.cap.read()
            if not ok or frame is None:
                self.cap.release()
                self.cap = cv2.VideoCapture(self.spec)
                ok, frame = self.cap.read()
                if not ok or frame is None:
                    die("video file %s cannot be re-read for looping" % self.spec, 1)
            log("video looped")
            return self._prep(frame)

        self.fails += 1
        if self.fails >= self.MAX_CAM_FAILS:
            raise IOError("camera stopped delivering frames (%d failed reads)" % self.fails)
        time.sleep(0.02)
        return None

    def release(self):
        try:
            self.cap.release()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
def hsv_mask(hsv, lo, hi):
    """inRange with hue wrap-around support (if H low > H high)."""
    if lo[0] <= hi[0]:
        return cv2.inRange(hsv, np.array(lo, np.uint8), np.array(hi, np.uint8))
    m1 = cv2.inRange(hsv, np.array([0, lo[1], lo[2]], np.uint8),
                     np.array([hi[0], hi[1], hi[2]], np.uint8))
    m2 = cv2.inRange(hsv, np.array([lo[0], lo[1], lo[2]], np.uint8),
                     np.array([179, hi[1], hi[2]], np.uint8))
    return cv2.bitwise_or(m1, m2)


class Detector(object):
    def __init__(self, cfg):
        self.cfg = cfg
        self._k = None
        self._kernel = None
        self.preview_name = None   # in --tune mode, show only this colour's mask

    def kernel(self):
        k = max(1, int(self.cfg["morph_kernel"]))
        if k != self._k:
            self._k = k
            self._kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (k, k))
        return self._kernel

    def detect(self, frame):
        """Returns ((cx, cy, radius, area, colour_name) or None, mask).
        Coordinates in full-frame pixels. The mask is the union of all colour masks."""
        h, w = frame.shape[:2]
        pw = self.cfg["process_width"]
        scale = 1.0
        img = frame
        if 0 < pw < w:
            scale = float(pw) / w
            img = cv2.resize(frame, (pw, int(round(h * scale))), interpolation=cv2.INTER_AREA)

        blur = cv2.GaussianBlur(img, (5, 5), 0)
        hsv = cv2.cvtColor(blur, cv2.COLOR_BGR2HSV)
        kern = self.kernel()
        min_area = self.cfg["min_area"] * scale * scale

        combined = None
        preview = None
        best, best_area, best_name = None, 0.0, None
        for t in self.cfg["targets"]:
            mask = hsv_mask(hsv, t["lower"], t["upper"])
            mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, kern)
            mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, kern)
            combined = mask if combined is None else cv2.bitwise_or(combined, mask)
            if t["name"] == self.preview_name:
                preview = mask

            # [-2] works on both OpenCV 3.x (3 return values) and 4.x (2 return values)
            contours = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)[-2]
            for c in contours:
                a = cv2.contourArea(c)
                if a >= min_area and a > best_area:
                    best, best_area, best_name = c, a, t["name"]
        out_mask = preview if preview is not None else combined
        if best is None:
            return None, out_mask
        (x, y), r = cv2.minEnclosingCircle(best)
        return (x / scale, y / scale, r / scale, best_area / (scale * scale), best_name), out_mask


def bearing_deg(tx, ty, sx, sy, invert):
    a = math.degrees(math.atan2(sy - ty, tx - sx))
    if a < 0:                       # target "behind" the servo edge -> clamp to nearest end
        a = 0.0 if a >= -90.0 else 180.0
    a = min(180.0, max(0.0, a))
    if invert:
        a = 180.0 - a
    return a


# --------------------------------------------------------------------------- #
# Rate-limited stdout emitter
# --------------------------------------------------------------------------- #
class Emitter(object):
    def __init__(self, cfg, enabled):
        hz = min(max(0.1, cfg["max_emit_hz"]), HARD_MAX_EMIT_HZ)
        self.min_interval = 1.0 / hz
        self.deadband = max(0.0, cfg["deadband_deg"])
        self.enabled = enabled
        self.last_t = -1e9
        self.last_angle = None
        self.last_state = None
        self.last_wall = None
        self.count = 0

    def _write(self, obj):
        now = time.monotonic()
        self.last_t = now
        self.last_wall = time.time()
        self.last_state = obj["state"]
        self.last_angle = obj["angle"]
        self.count += 1
        if not self.enabled:
            return
        try:
            sys.stdout.write(json.dumps(obj) + "\n")
            sys.stdout.flush()
        except (BrokenPipeError, OSError):
            log("stdout closed (ground control exited) -- stopping")
            raise SystemExit(0)

    def rate_ok(self):
        return time.monotonic() - self.last_t >= self.min_interval

    def target(self, angle, cx, cy, radius, colour):
        if not self.rate_ok():
            return False
        if (self.last_state == "TARGET_ACQUIRED" and self.last_angle is not None
                and abs(angle - self.last_angle) < self.deadband):
            return False
        self._write({"t": round(time.time(), 3), "state": "TARGET_ACQUIRED",
                     "angle": int(angle), "cx": int(round(cx)), "cy": int(round(cy)),
                     "radius": int(round(radius)), "target": colour})
        return True

    def searching(self, wait=False):
        """Emit SEARCHING once, only after a target was previously announced."""
        if self.last_state != "TARGET_ACQUIRED":
            return False
        if not self.rate_ok():
            if not wait:
                return False
            time.sleep(max(0.0, self.min_interval - (time.monotonic() - self.last_t)))
        self._write({"t": round(time.time(), 3), "state": "SEARCHING", "angle": None})
        return True


# --------------------------------------------------------------------------- #
# Recording (real-time speed regardless of processing FPS)
# --------------------------------------------------------------------------- #
class Recorder(object):
    def __init__(self, path, fps, size):
        self.fps = fps
        self.path = path
        self.writer = cv2.VideoWriter(path, cv2.VideoWriter_fourcc(*"mp4v"), fps, size)
        if not self.writer.isOpened():
            alt = os.path.splitext(path)[0] + ".avi"
            log("mp4v writer unavailable, falling back to MJPG %s" % alt)
            self.path = alt
            self.writer = cv2.VideoWriter(alt, cv2.VideoWriter_fourcc(*"MJPG"), fps, size)
        if not self.writer.isOpened():
            die("could not open video writer for %s" % path, 3)
        self.t0 = None
        self.n = 0
        log("recording to %s at %d fps" % (self.path, fps))

    def write(self, frame):
        now = time.monotonic()
        if self.t0 is None:
            self.t0 = now
        due = int((now - self.t0) * self.fps) + 1
        if due - self.n > self.fps * 2:          # after a long stall, don't dump a freeze-frame
            self.n = due - 1
        while self.n < due:                      # duplicate frames so playback is real-time
            self.writer.write(frame)
            self.n += 1

    def close(self):
        self.writer.release()
        log("recording saved: %s (%.1f s)" % (self.path, self.n / float(self.fps)))


# --------------------------------------------------------------------------- #
# Overlay
# --------------------------------------------------------------------------- #
GREEN = (0, 255, 0)
YELLOW = (0, 255, 255)
ORANGE = (0, 140, 255)
CYAN = (255, 255, 0)
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)
FONT = cv2.FONT_HERSHEY_DUPLEX


def put_text_bg(img, text, org, scale, color, thick, pad=6, degree=False):
    """Text on a dark box. degree=True draws a real degree symbol after the text
    (Hershey fonts can't render the unicode degree sign)."""
    (tw, th), base = cv2.getTextSize(text, FONT, scale, thick)
    deg_r = max(3, int(th * 0.18))
    extra = (deg_r * 2 + 6) if degree else 0
    x, y = org
    cv2.rectangle(img, (x - pad, y - th - pad), (x + tw + extra + pad, y + base + pad), BLACK, -1)
    cv2.putText(img, text, (x, y), FONT, scale, color, thick, cv2.LINE_AA)
    if degree:
        cv2.circle(img, (x + tw + deg_r + 4, y - th + deg_r), deg_r, color, max(1, thick - 1), cv2.LINE_AA)
    return tw + extra


def fit_scale(text, max_w, scale, thick):
    while scale > 0.4:
        (tw, _), _ = cv2.getTextSize(text, FONT, scale, thick)
        if tw <= max_w:
            break
        scale -= 0.05
    return scale


def draw_overlay(frame, cfg, state, det, angle, holding, fps, emitter, mode_hint):
    h, w = frame.shape[:2]
    sx, sy = cfg["servo_x"], cfg["servo_y"]

    # servo marker + bearing guide arc
    cv2.ellipse(frame, (sx, sy), (60, 60), 0, 180, 360, (200, 200, 200), 1, cv2.LINE_AA)
    right_lbl, left_lbl = ("180", "0") if cfg["invert"] else ("0", "180")
    cv2.putText(frame, right_lbl, (sx + 64, sy - 4), FONT, 0.45, (200, 200, 200), 1, cv2.LINE_AA)
    cv2.putText(frame, left_lbl, (sx - 64 - 28, sy - 4), FONT, 0.45, (200, 200, 200), 1, cv2.LINE_AA)
    cv2.putText(frame, "90", (sx - 9, sy - 66), FONT, 0.45, (200, 200, 200), 1, cv2.LINE_AA)
    cv2.rectangle(frame, (sx - 7, sy - 7), (sx + 7, sy + 7), CYAN, 2)
    cv2.putText(frame, "SERVO", (sx + 12, sy + 5 if sy < h - 12 else sy - 12), FONT, 0.45, CYAN, 1, cv2.LINE_AA)

    if det is not None:
        cx, cy, r = int(round(det[0])), int(round(det[1])), int(round(det[2]))
        col = GREEN if state == "TARGET_ACQUIRED" else ORANGE
        cv2.line(frame, (sx, sy), (cx, cy), col, 2, cv2.LINE_AA)
        cv2.circle(frame, (cx, cy), max(r, 4), col, 3, cv2.LINE_AA)
        arm = r + 12
        cv2.line(frame, (cx - arm, cy), (cx + arm, cy), col, 1, cv2.LINE_AA)
        cv2.line(frame, (cx, cy - arm), (cx, cy + arm), col, 1, cv2.LINE_AA)
        cv2.circle(frame, (cx, cy), 3, col, -1)

    # big status banner
    if state == "TARGET_ACQUIRED" and angle is not None:
        colour = det[4].upper() if det is not None else "TARGET"
        text = "%s ACQUIRED - BEARING %d" % (colour, angle)
        sc = fit_scale(text, w - 150, 1.0, 2)
        put_text_bg(frame, text, (14, 40), sc, GREEN, 2, degree=True)
        if holding:
            put_text_bg(frame, "(target momentarily lost - holding)", (14, 74), 0.5, ORANGE, 1)
    else:
        put_text_bg(frame, "SEARCHING", (14, 40), 1.0, YELLOW, 2)

    # FPS top-right
    ftxt = "%4.1f FPS" % fps
    (fw, _), _ = cv2.getTextSize(ftxt, FONT, 0.6, 1)
    put_text_bg(frame, ftxt, (w - fw - 12, 28), 0.6, WHITE, 1)

    # command telemetry bottom-left
    if not emitter.enabled:
        tx = "TX OFF (%s mode)" % mode_hint
    elif emitter.last_wall is None:
        tx = "TX: no command sent yet"
    else:
        la = "null" if emitter.last_angle is None else str(emitter.last_angle)
        tx = "TX #%d: %s %s  (%.1fs ago)" % (emitter.count, emitter.last_state, la,
                                             time.time() - emitter.last_wall)
    put_text_bg(frame, tx, (14, 104), 0.5, WHITE, 1, pad=4)


# --------------------------------------------------------------------------- #
# Tune / calibrate helpers
# --------------------------------------------------------------------------- #
TRACKBARS = [  # (name, key in the tuned target dict, index, max)
    ("H low", "lower", 0, 179), ("H high", "upper", 0, 179),
    ("S low", "lower", 1, 255), ("S high", "upper", 1, 255),
    ("V low", "lower", 2, 255), ("V high", "upper", 2, 255),
]


def _noop(_):
    pass


def setup_tune_windows(cfg, tgt):
    cv2.namedWindow(WIN_CTRL, cv2.WINDOW_NORMAL)
    cv2.resizeWindow(WIN_CTRL, 420, 330)
    for name, key, i, mx in TRACKBARS:
        cv2.createTrackbar(name, WIN_CTRL, int(tgt[key][i]), mx, _noop)
    cv2.createTrackbar("Min area", WIN_CTRL, int(cfg["min_area"]), 5000, _noop)
    cv2.createTrackbar("Kernel", WIN_CTRL, int(cfg["morph_kernel"]), 21, _noop)
    cv2.namedWindow(WIN_MASK, cv2.WINDOW_AUTOSIZE)


def read_trackbars(cfg, tgt):
    for name, key, i, _ in TRACKBARS:
        tgt[key][i] = cv2.getTrackbarPos(name, WIN_CTRL)
    cfg["min_area"] = cv2.getTrackbarPos("Min area", WIN_CTRL)
    cfg["morph_kernel"] = max(1, cv2.getTrackbarPos("Kernel", WIN_CTRL))


def sample_hsv_to_trackbars(frame, x, y):
    """Click-to-sample: set the HSV range around the median colour of a 9x9 patch."""
    h, w = frame.shape[:2]
    x0, x1 = max(0, x - 4), min(w, x + 5)
    y0, y1 = max(0, y - 4), min(h, y + 5)
    patch = cv2.cvtColor(cv2.GaussianBlur(frame, (5, 5), 0)[y0:y1, x0:x1], cv2.COLOR_BGR2HSV)
    hm, sm, vm = [int(np.median(patch[:, :, c])) for c in range(3)]
    h_lo, h_hi = (hm - 10) % 180, (hm + 10) % 180
    s_lo, v_lo = max(60, sm - 70), max(60, vm - 80)
    for name, val in (("H low", h_lo), ("H high", h_hi), ("S low", s_lo), ("S high", 255),
                      ("V low", v_lo), ("V high", 255)):
        cv2.setTrackbarPos(name, WIN_CTRL, val)
    log("sampled HSV (%d,%d,%d) at (%d,%d) -> lower [%d,%d,%d] upper [%d,255,255]"
        % (hm, sm, vm, x, y, h_lo, s_lo, v_lo, h_hi))
    if sm < 80:
        log("warning: low saturation -- that click looks like glare/white, not a bright target")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def parse_args():
    here = os.path.dirname(os.path.abspath(__file__))
    p = argparse.ArgumentParser(description="SHIPTRACE high-visibility target bearing tracker")
    p.add_argument("--source", default="0", help="camera index (e.g. 0) or path to a video file")
    p.add_argument("--config", default=os.path.join(here, "config.json"), help="config JSON path")
    p.add_argument("--tune", action="store_true", help="HSV trackbars + mask preview; 's' saves")
    p.add_argument("--tune-target", default=None,
                   help="which colour to tune, by name from config 'targets' (default: the first)")
    p.add_argument("--calibrate", action="store_true", help="click the servo to save its position")
    p.add_argument("--headless", action="store_true", help="no windows (Pi over SSH)")
    p.add_argument("--record", metavar="OUT.mp4", help="save the annotated video")
    return p.parse_args()


def main():
    args = parse_args()
    if args.headless and (args.tune or args.calibrate):
        die("--tune and --calibrate need a display; drop --headless", 2)
    if args.tune and args.calibrate:
        die("use --tune and --calibrate one at a time", 2)

    cfg = load_config(args.config)
    cv2.setUseOptimized(True)

    tune_tgt = None
    if args.tune:
        names = [t["name"] for t in cfg["targets"]]
        want = args.tune_target or names[0]
        if want not in names:
            die("--tune-target '%s' not in config targets %s" % (want, names), 2)
        tune_tgt = cfg["targets"][names.index(want)]

    mode_hint = "tune" if args.tune else ("calibrate" if args.calibrate else "")
    emit_enabled = not (args.tune or args.calibrate)
    if not emit_enabled:
        log("%s mode: stdout commands are DISABLED (no servo moves)" % mode_hint)

    src = Source(args.source, cfg)
    detector = Detector(cfg)
    if tune_tgt is not None:
        detector.preview_name = tune_tgt["name"]
    emitter = Emitter(cfg, emit_enabled)
    recorder = None
    show = not args.headless

    # mutable holder so mouse callbacks can see the latest frame
    ui = {"frame": None}

    if show:
        cv2.namedWindow(WIN_MAIN, cv2.WINDOW_AUTOSIZE)
        if args.tune:
            setup_tune_windows(cfg, tune_tgt)

            def on_mouse_tune(event, x, y, flags, param):
                if event == cv2.EVENT_LBUTTONDOWN and ui["frame"] is not None:
                    sample_hsv_to_trackbars(ui["frame"], x, y)
            cv2.setMouseCallback(WIN_MAIN, on_mouse_tune)
            log("TUNE [%s]: click the %s object to auto-sample, adjust sliders until the Mask "
                "shows ONLY the target as a solid white blob, then press 's' to save, 'q' to quit"
                % (tune_tgt["name"], tune_tgt["name"]))
        elif args.calibrate:
            def on_mouse_cal(event, x, y, flags, param):
                if event == cv2.EVENT_LBUTTONDOWN:
                    cfg["servo_x"], cfg["servo_y"] = int(x), int(y)
                    save_config(args.config, cfg)
                    log("servo position saved: (%d, %d) -> %s" % (x, y, args.config))
                    fh = ui["frame"].shape[0] if ui["frame"] is not None else cfg["frame_height"]
                    if y < fh / 2:
                        log("warning: servo is in the TOP half of the image; bearings will clamp. "
                            "Set \"rotate\": 180 in config (or turn the camera) so the servo "
                            "edge is at the bottom, then re-calibrate.")
            cv2.setMouseCallback(WIN_MAIN, on_mouse_cal)
            log("CALIBRATE: click the servo pivot. Then move the target straight out from the "
                "servo -- the bearing should read ~90. Press 'q' when done.")

    state = "SEARCHING"
    seen_streak = 0
    last_seen = None
    ema = None
    shown_angle = None
    fps = 0.0
    prev_t = time.monotonic()
    last_hb = prev_t
    frames_hb = 0
    exit_code = 0

    log("running: source=%s config=%s headless=%s" % (args.source, args.config, args.headless))
    try:
        while True:
            try:
                frame = src.read()
            except IOError as e:
                log("ERROR: %s" % e)
                emitter.searching(wait=True)
                exit_code = 1
                break
            if frame is None:
                continue

            if args.tune and show:
                read_trackbars(cfg, tune_tgt)

            det, mask = detector.detect(frame)
            now = time.monotonic()

            holding = False
            if det is not None:
                seen_streak += 1
                last_seen = now
                raw = bearing_deg(det[0], det[1], cfg["servo_x"], cfg["servo_y"], cfg["invert"])
                a = cfg["ema_alpha"]
                ema = raw if ema is None else a * raw + (1.0 - a) * ema
                angle_i = int(math.floor(ema + 0.5))
                if state == "SEARCHING" and seen_streak >= cfg["acquire_frames"]:
                    state = "TARGET_ACQUIRED"
                    log("TARGET ACQUIRED (%s) at bearing %d (area %.0f px)"
                        % (det[4], angle_i, det[3]))
                if state == "TARGET_ACQUIRED":
                    shown_angle = angle_i
                    emitter.target(angle_i, det[0], det[1], det[2], det[4])
            else:
                seen_streak = 0
                if state == "TARGET_ACQUIRED":
                    if now - last_seen > cfg["lost_timeout_s"]:
                        state = "SEARCHING"
                        ema = None
                        shown_angle = None
                        log("target lost > %.1fs -> SEARCHING" % cfg["lost_timeout_s"])
                    else:
                        holding = True
                if state == "SEARCHING":
                    emitter.searching()      # sends once; retries next frame if rate-limited

            # FPS (smoothed)
            dt = now - prev_t
            prev_t = now
            if dt > 0:
                fps = (1.0 / dt) if fps == 0 else 0.9 * fps + 0.1 * (1.0 / dt)

            frames_hb += 1
            if now - last_hb >= 5.0:
                log("%.1f FPS | %s | bearing %s | cmds sent %d"
                    % (frames_hb / (now - last_hb), state,
                       "-" if shown_angle is None else shown_angle, emitter.count))
                last_hb, frames_hb = now, 0

            need_overlay = show or args.record
            if need_overlay:
                vis = frame.copy()
                draw_overlay(vis, cfg, state, det, shown_angle, holding, fps, emitter, mode_hint)
                if args.tune:
                    put_text_bg(vis, "TUNE [%s]: click target | sliders | s=save q=quit"
                                % tune_tgt["name"], (14, 134), 0.5, YELLOW, 1, pad=4)
                elif args.calibrate:
                    put_text_bg(vis, "CALIBRATE: click the servo pivot | q=quit",
                                (14, 134), 0.5, YELLOW, 1, pad=4)

                if args.record:
                    if recorder is None:
                        recorder = Recorder(args.record, cfg["record_fps"],
                                            (vis.shape[1], vis.shape[0]))
                    recorder.write(vis)

                if show:
                    ui["frame"] = frame
                    cv2.imshow(WIN_MAIN, vis)
                    if args.tune:
                        small = cv2.resize(mask, (320, int(320 * mask.shape[0] / mask.shape[1])),
                                           interpolation=cv2.INTER_NEAREST)
                        cv2.imshow(WIN_MASK, small)
                    key = cv2.waitKey(1) & 0xFF
                    if key in (ord("q"), 27):
                        break
                    if key == ord("s") and args.tune:
                        save_config(args.config, cfg)
                        log("saved %s HSV lower %s upper %s min_area %d kernel %d -> %s"
                            % (tune_tgt["name"], tune_tgt["lower"], tune_tgt["upper"],
                               cfg["min_area"], cfg["morph_kernel"], args.config))
    except KeyboardInterrupt:
        log("interrupted")
    finally:
        src.release()
        if recorder is not None:
            recorder.close()
        if show:
            cv2.destroyAllWindows()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())