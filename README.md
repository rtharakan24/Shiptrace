# SHIPTRACE

**Secure Hardware-Integrated Person Localization and Tracking for Rescue at Sea**
HackGT 13 · Hardware Track

SHIPTRACE is a ship-mounted man-overboard spotter. A camera finds a person in the water, and a searchlight automatically turns to point rescuers at them. The command link is authenticated, so an attacker who tries to hijack the spotter with forged, replayed or flooded commands triggers a **physical lockdown**: a relay cuts actuator power and the device stays in SAFE MODE until a human presses a reset button.

> SHIPTRACE finds a person overboard and points rescuers to them, and when an attacker tries to hijack it, the hardware physically locks itself down instead of obeying.

---

## How it works

```text
 C270 webcam over water tank
        │  frames
        ▼
 vision/tracker.py ── HSV color detection → bearing angle (0–180°)
        │  JSON lines on stdout
        ▼
 ground/ground_control.py ── signs AIM commands (HMAC-SHA256, sequence numbers, rate-limited)
        │  UDP :4210 over Wi-Fi
        ▼
 ESP32 "rescue beacon" (firmware/) ── verifies every packet
        │                         │
        │ valid                   │ forged / replayed / flooded / malformed
        ▼                         ▼
 servo aims searchlight     relay opens → servo unpowered → red LED → SAFE MODE (latched)
                                          │
                              physical button held 2 s → READY
```

## Security model

| Threat | Defense | Result |
|---|---|---|
| Forged command from an unknown device | HMAC-SHA256 over every command with a shared 256-bit key, constant-time compare | `BAD_HMAC` → SAFE MODE |
| Unsigned / malformed command | Strict parser: 5 fields, `v1`, numeric fields, 64-char hex MAC, ≤127 bytes | `BAD_FORMAT` → SAFE MODE |
| Replay of a captured legitimate command | Strictly increasing 64-bit sequence number, checked only after the MAC is valid | `REPLAY` → SAFE MODE |
| Command flood | More than 5 packets in a sliding 1 s window, counted before any crypto | `RATE` → SAFE MODE |
| Out-of-range or unknown command | Command whitelist (`AIM`, `PING`) and argument bounds (0–180) | `UNKNOWN_CMD` / `BAD_ARG` → SAFE MODE |
| Attacker unlocks the device remotely | No network reset command exists; recovery needs a physical button | Human-in-the-loop recovery |
| Firmware crash, reboot or power glitch | Relay is driven so that GPIO LOW = de-energized = actuator unpowered | Fails safe |

**Design principles**
- **Deterministic safety.** Simple, auditable rules decide when to trip. AI is used only after the fact to explain incidents, never in the control loop.
- **Physical enforcement.** The response to an attack is a relay cutting power, not just a software flag.
- **Defense in depth.** Ground control refuses to send out-of-range angles, and the beacon rejects them again.

## Command protocol (v1)

UDP, port 4210, one command per packet, ASCII:

```text
v1|<seq>|<cmd>|<arg>|<hmac>
v1|1727400000123|AIM|97|481a7630e8caf04d9d5cdc3c67a2512f30e51f043a1d483e92f0cdf60b03fe71
```

| Field | Meaning |
|---|---|
| `seq` | Unsigned 64-bit, milliseconds since the Unix epoch, strictly increasing (restarts never look like replays) |
| `cmd` / `arg` | `AIM` 0–180, or `PING` 0 |
| `hmac` | Lowercase hex HMAC-SHA256 of `v1|<seq>|<cmd>|<arg>` |

Replies: `ACK|<seq>` or `REJECT|<seq>|<REASON>`.
Validation order: rate → format → HMAC → replay → command → argument → accept.

## Repository layout

```text
vision/     C270 target detection → bearing angle (OpenCV)
ground/     Ground control, mock beacon, fake vision, attack tooling
firmware/   ESP32 beacon: HMAC verification, state machine, servo, relay
docs/       Wiring, demo script, incident reports
```

## Quick start (no hardware needed)

Requires Python 3 (standard library only). Run from the `ground/` folder.

```bash
python protocol.py                                     # self-test: prints PASS
python mock_beacon.py --log logs/beacon_events.jsonl   # terminal 1: software ESP32
python -u fake_vision.py | python ground_control.py --target 127.0.0.1   # terminal 2
```

On Windows PowerShell, wrap the pipe: `cmd /c "python -u fake_vision.py | python ground_control.py --target 127.0.0.1"`

Simulate an attack (terminal 3):

```bash
python -c "import socket;socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b'AIM|90',('127.0.0.1',4210))"
```

The mock beacon enters SAFE MODE and ground control pauses. Press **Enter** in terminal 1 to simulate the physical reset button, and tracking resumes.

Against the real ESP32: `python ground_control.py --target <ESP32_IP>`

## Keys

All components default to a **public demo key** so the test vectors work. Before a real demo:

```bash
python -c "import secrets; print(secrets.token_hex(32))" > ground/key.hex
```

Put the same value in `firmware/shiptrace_beacon/secrets.h`. Both files are gitignored.

## Hardware

| Part | Role |
|---|---|
| Logitech C270 webcam | Overhead view of the water tank |
| Raspberry Pi 3 or laptop | Vision + ground control |
| Inland ESP32 DevKit (ESP-WROOM-32) | Rescue beacon: verification and actuation |
| DC gearmotor | Searchlight actuator, pulses for 1 s per valid AIM command |
| 3× 2SA1015 PNP transistors (Darlington) | Motor switching, driven by releasing the GPIO pin |
| FR207 flyback diode | Absorbs voltage spike when the motor switches off |
| 2×AA battery pack (3V) | Motor power, isolated from logic — kept below 3.3V so the PNP transistors fully switch off |
| Red/green LEDs, pushbutton | Status and physical reset |

## Honest limitations

- Localization is a camera-relative bearing, not GPS.
- The water tank stands in for the ocean and the servo for a searchlight turret.
- The shared key is symmetric; a production system would use per-device keys and secure key storage (for example ESP32 flash encryption and secure boot).
- The beacon keeps its last sequence number in RAM, so a reboot resets replay protection until the next valid command. Persisting it to flash is a planned improvement.

## Team
Reuben Tharakan | Ishaan Khambaswadkar | Vihaan Chindarkar

HackGT 13 · Georgia Tech
