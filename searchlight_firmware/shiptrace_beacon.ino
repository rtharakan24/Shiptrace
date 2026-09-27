// SHIPTRACE rescue beacon firmware — ESP32
//
// Actuator: a DC gearmotor on 2xAA, switched high-side by 3x 2SA1015 PNP
// transistors in a Darlington (T1 drives the bases of T2+T3). GPIO26 is the
// only motor control: driven LOW = motor powered; released (INPUT) = 10k
// pull-ups to the 2xAA + rail hold every base at its emitter = motor unpowered. The pin is also released
// during boot and reset (a panic reboots), so the motor is fail-safe OFF.
// Never power the motor pack while the ESP32 is unpowered: an unpowered pin
// clamps the base node low and the motor would run.
// A valid AIM produces one short pulse; the angle is validated and logged
// but not physically positioned (no feedback on this motor).
//
// Validation order (do not reorder — this is the security contract):
//   1. RATE      (count every packet in a 1s window, before any parsing)
//   2. FORMAT    (5 fields, "v1", numeric seq/arg, 64 lowercase hex chars)
//   3. BAD_HMAC
//   4. REPLAY    (seq <= lastSeq; checked only after HMAC is valid)
//   5. UNKNOWN_CMD
//   6. BAD_ARG
//   7. Accept: update lastSeq, ACK, act.

#include <WiFi.h>
#include <WiFiUdp.h>
#include "mbedtls/md.h"
#include "secrets.h"

// Network: the ESP32 runs its own access point (no eduroam/venue Wi-Fi
// dependency, no phone hotspot needed). Ground control's laptop connects
// to AP_SSID directly; the beacon is always reachable at 192.168.4.1.

// ---------- Pins ----------
#define MOTOR_PIN     26
#define RED_LED_PIN   25
#define GREEN_LED_PIN 27
#define BUTTON_PIN    33
#define ONBOARD_LED   2

#define MOTOR_PULSE_MS 1000  // keep short: 2SA1015 is only rated 150mA continuous

// ---------- Protocol ----------
#define UDP_PORT        4210
#define MAX_PACKET_LEN  127
#define RATE_LIMIT      5     // more than this many packets/second -> REJECT RATE
#define RATE_WINDOW_MS  1000
#define BUTTON_HOLD_MS  2000

WiFiUDP udp;

enum State { ST_BOOT, ST_READY, ST_TRACKING, ST_SAFE_MODE };
State currentState = ST_BOOT;

uint64_t lastSeq = 0;
bool haveLastSeq = false; // lastSeq only meaningful once we've accepted a packet

// ---------- Rate limiting ----------
#define RATE_BUF_SIZE 40
uint32_t rateBuf[RATE_BUF_SIZE];
int rateBufIdx = 0;
int rateBufFilled = 0;

bool rateCheck(uint32_t now) {
  rateBuf[rateBufIdx] = now;
  rateBufIdx = (rateBufIdx + 1) % RATE_BUF_SIZE;
  if (rateBufFilled < RATE_BUF_SIZE) rateBufFilled++;

  int countInWindow = 0;
  for (int i = 0; i < rateBufFilled; i++) {
    if (now - rateBuf[i] <= RATE_WINDOW_MS) countInWindow++;
  }
  return countInWindow <= RATE_LIMIT;
}

// ---------- Motor (PNP high-side, active LOW) ----------
// OFF releases the pin rather than driving it HIGH, so "off" is exactly the
// same electrical state as boot/reset/crash: only the pull-up is in charge.
uint32_t motorOffAt = 0;
bool motorRunning = false;

void motorOff() {
  pinMode(MOTOR_PIN, INPUT);
  motorRunning = false;
}

void motorPulse() {
  pinMode(MOTOR_PIN, OUTPUT);
  digitalWrite(MOTOR_PIN, LOW);
  motorRunning = true;
  motorOffAt = millis() + MOTOR_PULSE_MS;
}

void serviceMotor() {
  if (motorRunning && (int32_t)(millis() - motorOffAt) >= 0) motorOff();
}

// ---------- Onboard LED (blink on accept) ----------
uint32_t onboardLedOffAt = 0;
bool onboardLedOn = false;

void flashOnboardLed() {
  digitalWrite(ONBOARD_LED, HIGH);
  onboardLedOn = true;
  onboardLedOffAt = millis() + 80;
}

void serviceOnboardLed() {
  if (onboardLedOn && (int32_t)(millis() - onboardLedOffAt) >= 0) {
    digitalWrite(ONBOARD_LED, LOW);
    onboardLedOn = false;
  }
}

// ---------- Logging (one JSON object per line) ----------
void logAccept(const char* src, uint64_t seq, const char* cmd, int arg) {
  char line[192];
  snprintf(line, sizeof(line),
    "{\"ms\":%lu,\"evt\":\"ACCEPT\",\"src\":\"%s\",\"seq\":%llu,\"cmd\":\"%s\",\"arg\":%d}",
    (unsigned long)millis(), src, (unsigned long long)seq, cmd, arg);
  Serial.println(line);
}

void logReject(const char* src, const char* reason, uint64_t seq) {
  char line[192];
  snprintf(line, sizeof(line),
    "{\"ms\":%lu,\"evt\":\"REJECT\",\"src\":\"%s\",\"reason\":\"%s\",\"seq\":%llu}",
    (unsigned long)millis(), src, reason, (unsigned long long)seq);
  Serial.println(line);
}

void logState(const char* from, const char* to, const char* reason) {
  char line[160];
  snprintf(line, sizeof(line),
    "{\"ms\":%lu,\"evt\":\"STATE\",\"from\":\"%s\",\"to\":\"%s\",\"reason\":\"%s\"}",
    (unsigned long)millis(), from, to, reason);
  Serial.println(line);
}

const char* stateName(State s) {
  switch (s) {
    case ST_BOOT: return "BOOT";
    case ST_READY: return "READY";
    case ST_TRACKING: return "TRACKING";
    case ST_SAFE_MODE: return "SAFE_MODE";
  }
  return "UNKNOWN";
}

// ---------- HMAC ----------
void hmacHex(const uint8_t* msg, size_t msgLen, char outHex[65]) {
  uint8_t digest[32];
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                   HMAC_KEY, sizeof(HMAC_KEY), msg, msgLen, digest);
  for (int i = 0; i < 32; i++) sprintf(outHex + i * 2, "%02x", digest[i]);
  outHex[64] = 0;
}

bool constTimeEqual(const char* a, const char* b, size_t len) {
  uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) diff |= (uint8_t)a[i] ^ (uint8_t)b[i];
  return diff == 0;
}

bool isDigits(const char* s, size_t len) {
  if (len == 0) return false;
  for (size_t i = 0; i < len; i++) if (s[i] < '0' || s[i] > '9') return false;
  return true;
}

bool isLowerHex(const char* s, size_t len) {
  for (size_t i = 0; i < len; i++) {
    char c = s[i];
    bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    if (!ok) return false;
  }
  return true;
}

// ---------- State transitions ----------
void enterSafeMode(const char* reason) {
  if (currentState == ST_SAFE_MODE) return; // already latched
  const char* from = stateName(currentState);
  motorOff();
  digitalWrite(GREEN_LED_PIN, LOW);
  digitalWrite(RED_LED_PIN, HIGH);
  // Onboard LED is the SAFE_MODE indicator (no external LEDs on this build).
  // Cancel any pending accept-flash so it can't switch the solid light off.
  onboardLedOn = false;
  digitalWrite(ONBOARD_LED, HIGH);
  currentState = ST_SAFE_MODE;
  logState(from, "SAFE_MODE", reason);
}

void enterReady(const char* reason) {
  const char* from = stateName(currentState);
  currentState = ST_READY;
  motorOff();
  digitalWrite(RED_LED_PIN, LOW);
  digitalWrite(GREEN_LED_PIN, HIGH);
  onboardLedOn = false;
  digitalWrite(ONBOARD_LED, LOW);
  logState(from, "READY", reason);
}

// Self-test failure is a hard stop: never let a broken crypto path reach
// the network. Red LED blinks forever, WiFi never connects, nothing accepts.
void haltSafe(const char* why) {
  motorOff();
  Serial.print("FATAL: ");
  Serial.println(why);
  while (true) {
    digitalWrite(RED_LED_PIN, HIGH);
    digitalWrite(ONBOARD_LED, HIGH);
    delay(150);
    digitalWrite(RED_LED_PIN, LOW);
    digitalWrite(ONBOARD_LED, LOW);
    delay(150);
  }
}

// ---------- Packet handling ----------
void sendReply(IPAddress ip, uint16_t port, uint64_t seq, const char* reason /* NULL for ACK */) {
  char reply[64];
  if (reason == nullptr) {
    snprintf(reply, sizeof(reply), "ACK|%llu", (unsigned long long)seq);
  } else {
    snprintf(reply, sizeof(reply), "REJECT|%llu|%s", (unsigned long long)seq, reason);
  }
  udp.beginPacket(ip, port);
  udp.write((const uint8_t*)reply, strlen(reply));
  udp.endPacket();
}

// Best-effort seq extraction for packets we reject without full parsing
// (used only for the SAFE_MODE fast-reject path so replies carry a seq).
uint64_t bestEffortSeq(const char* buf, size_t len) {
  const char* p1 = (const char*)memchr(buf, '|', len);
  if (!p1) return 0;
  size_t off1 = p1 - buf;
  const char* p2 = (const char*)memchr(p1 + 1, '|', len - off1 - 1);
  if (!p2) return 0;
  size_t seqLen = p2 - (p1 + 1);
  if (seqLen == 0 || seqLen > 20) return 0;
  char seqBuf[21];
  memcpy(seqBuf, p1 + 1, seqLen);
  seqBuf[seqLen] = 0;
  if (!isDigits(seqBuf, seqLen)) return 0;
  return strtoull(seqBuf, nullptr, 10);
}

void handlePacket(uint8_t* data, int len, IPAddress srcIP, uint16_t srcPort) {
  uint32_t now = millis();
  char srcStr[24];
  snprintf(srcStr, sizeof(srcStr), "%s", srcIP.toString().c_str());

  // Already latched: reject everything immediately, no state change.
  if (currentState == ST_SAFE_MODE) {
    uint64_t seq = bestEffortSeq((const char*)data, len);
    logReject(srcStr, "SAFE_MODE", seq);
    sendReply(srcIP, srcPort, seq, "SAFE_MODE");
    return;
  }

  // 1. RATE — count before any parsing/crypto.
  if (!rateCheck(now)) {
    logReject(srcStr, "RATE", 0);
    sendReply(srcIP, srcPort, 0, "RATE");
    enterSafeMode("RATE");
    return;
  }

  if (len <= 0 || len > MAX_PACKET_LEN) {
    logReject(srcStr, "BAD_FORMAT", 0);
    sendReply(srcIP, srcPort, 0, "BAD_FORMAT");
    enterSafeMode("BAD_FORMAT");
    return;
  }

  char buf[MAX_PACKET_LEN + 1];
  memcpy(buf, data, len);
  buf[len] = 0;

  // 2. FORMAT — exactly 5 fields, "v1", numeric seq/arg, 64 lowercase hex.
  char* pipes[4];
  int pipeCount = 0;
  for (int i = 0; i < len && pipeCount < 5; i++) {
    if (buf[i] == '|') {
      if (pipeCount < 4) pipes[pipeCount] = &buf[i];
      pipeCount++;
    }
  }

  bool formatOk = (pipeCount == 4);
  uint64_t seq = 0;
  char cmdBuf[16] = {0};
  long argVal = -1;
  char hmacBuf[65] = {0};
  size_t msgLen = 0;

  if (formatOk) {
    char* verField = buf;              size_t verLen = pipes[0] - buf;
    char* seqField = pipes[0] + 1;     size_t seqLen = pipes[1] - seqField;
    char* cmdField = pipes[1] + 1;     size_t cmdLen = pipes[2] - cmdField;
    char* argField = pipes[2] + 1;     size_t argLen = pipes[3] - argField;
    char* hmacField = pipes[3] + 1;    size_t hmacLen = (buf + len) - hmacField;
    msgLen = pipes[3] - buf;

    if (verLen != 2 || memcmp(verField, "v1", 2) != 0) formatOk = false;
    if (formatOk && (seqLen == 0 || seqLen > 20 || !isDigits(seqField, seqLen))) formatOk = false;
    if (formatOk && (cmdLen == 0 || cmdLen > 10)) formatOk = false;
    if (formatOk && (argLen == 0 || argLen > 20 || !isDigits(argField, argLen))) formatOk = false;
    if (formatOk && (hmacLen != 64 || !isLowerHex(hmacField, hmacLen))) formatOk = false;

    if (formatOk) {
      char seqBuf[21];
      memcpy(seqBuf, seqField, seqLen); seqBuf[seqLen] = 0;
      seq = strtoull(seqBuf, nullptr, 10);

      size_t copyLen = cmdLen < sizeof(cmdBuf) - 1 ? cmdLen : sizeof(cmdBuf) - 1;
      memcpy(cmdBuf, cmdField, copyLen); cmdBuf[copyLen] = 0;

      char argStr[21];
      memcpy(argStr, argField, argLen); argStr[argLen] = 0;
      argVal = strtol(argStr, nullptr, 10);

      memcpy(hmacBuf, hmacField, 64); hmacBuf[64] = 0;
    }
  }

  if (!formatOk) {
    // seq may still be extractable even though the packet is malformed
    // elsewhere; best-effort only, per spec ("seq 0 if unparseable").
    uint64_t s = bestEffortSeq((const char*)data, len);
    logReject(srcStr, "BAD_FORMAT", s);
    sendReply(srcIP, srcPort, s, "BAD_FORMAT");
    enterSafeMode("BAD_FORMAT");
    return;
  }

  // 3. BAD_HMAC
  char computedHex[65];
  hmacHex((const uint8_t*)buf, msgLen, computedHex);
  if (!constTimeEqual(computedHex, hmacBuf, 64)) {
    logReject(srcStr, "BAD_HMAC", seq);
    sendReply(srcIP, srcPort, seq, "BAD_HMAC");
    enterSafeMode("BAD_HMAC");
    return;
  }

  // 4. REPLAY — only checked now that HMAC is valid.
  if (haveLastSeq && seq <= lastSeq) {
    logReject(srcStr, "REPLAY", seq);
    sendReply(srcIP, srcPort, seq, "REPLAY");
    enterSafeMode("REPLAY");
    return;
  }

  // 5. UNKNOWN_CMD
  bool isAim = (strcmp(cmdBuf, "AIM") == 0);
  bool isPing = (strcmp(cmdBuf, "PING") == 0);
  if (!isAim && !isPing) {
    logReject(srcStr, "UNKNOWN_CMD", seq);
    sendReply(srcIP, srcPort, seq, "UNKNOWN_CMD");
    enterSafeMode("UNKNOWN_CMD");
    return;
  }

  // 6. BAD_ARG
  if (isAim && (argVal < 0 || argVal > 180)) {
    logReject(srcStr, "BAD_ARG", seq);
    sendReply(srcIP, srcPort, seq, "BAD_ARG");
    enterSafeMode("BAD_ARG");
    return;
  }
  if (isPing && argVal != 0) {
    logReject(srcStr, "BAD_ARG", seq);
    sendReply(srcIP, srcPort, seq, "BAD_ARG");
    enterSafeMode("BAD_ARG");
    return;
  }

  // 7. Accept.
  lastSeq = seq;
  haveLastSeq = true;
  flashOnboardLed();
  logAccept(srcStr, seq, cmdBuf, (int)argVal);
  sendReply(srcIP, srcPort, seq, nullptr);

  if (isAim) {
    if (currentState == ST_READY) {
      currentState = ST_TRACKING;
      logState("READY", "TRACKING", "AIM");
    }
    motorPulse();
  }
  // PING: no state/motor change, just keeps the link alive.
}

// ---------- Button (hold >= 2s to exit SAFE_MODE) ----------
bool buttonHeld = false;
uint32_t buttonPressedAt = 0;

void serviceButton() {
  bool pressed = (digitalRead(BUTTON_PIN) == LOW);
  if (pressed && !buttonHeld) {
    buttonHeld = true;
    buttonPressedAt = millis();
  } else if (!pressed) {
    buttonHeld = false;
  }

  if (buttonHeld && currentState == ST_SAFE_MODE &&
      (millis() - buttonPressedAt) >= BUTTON_HOLD_MS) {
    enterReady("BUTTON_RESET"); // lastSeq is intentionally NOT reset
    buttonHeld = false;
  }
}

// ---------- HMAC self-test against the spec's test vectors ----------
bool runHmacSelfTest() {
  struct Vector { const char* msg; const char* expected; };
  Vector vectors[2] = {
    {"v1|1727400000123|AIM|97",
     "481a7630e8caf04d9d5cdc3c67a2512f30e51f043a1d483e92f0cdf60b03fe71"},
    {"v1|1727400000124|PING|0",
     "af34712c68b77d0965611d10419bcf5bae3d92a64a1814c6cf0cf137303be26f"}
  };
  bool allPass = true;
  for (int i = 0; i < 2; i++) {
    char computed[65];
    hmacHex((const uint8_t*)vectors[i].msg, strlen(vectors[i].msg), computed);
    bool pass = (strcmp(computed, vectors[i].expected) == 0);
    Serial.print("HMAC self-test vector ");
    Serial.print(i);
    Serial.print(": computed=");
    Serial.print(computed);
    Serial.print(" expected=");
    Serial.print(vectors[i].expected);
    Serial.println(pass ? " PASS" : " FAIL");
    allPass = allPass && pass;
  }
  return allPass;
}

void setup() {
  Serial.begin(115200);
  delay(300);

  // Fail-safe defaults FIRST, before anything else can run.
  motorOff();
  pinMode(RED_LED_PIN, OUTPUT);
  digitalWrite(RED_LED_PIN, LOW);
  pinMode(GREEN_LED_PIN, OUTPUT);
  digitalWrite(GREEN_LED_PIN, LOW);
  pinMode(ONBOARD_LED, OUTPUT);
  digitalWrite(ONBOARD_LED, LOW);
  pinMode(BUTTON_PIN, INPUT_PULLUP);

  Serial.println("=== SHIPTRACE beacon boot ===");
  if (!runHmacSelfTest()) {
    haltSafe("HMAC self-test failed — refusing to arm");
  }
  Serial.println("HMAC self-test PASSED");

  // The ESP32 hosts its own network (no venue Wi-Fi dependency). Ground
  // control's laptop joins AP_SSID directly; the beacon is always reachable
  // at the fixed softAP address 192.168.4.1.
  WiFi.mode(WIFI_AP);
  bool apOk = WiFi.softAP(AP_SSID, AP_PASS);
  if (!apOk) {
    haltSafe("softAP() failed to start — check AP_SSID/AP_PASS in secrets.h");
  }
  for (int i = 0; i < 6; i++) {
    digitalWrite(ONBOARD_LED, i % 2);
    delay(100);
  }
  digitalWrite(ONBOARD_LED, LOW);
  Serial.print("AP started, SSID=");
  Serial.print(AP_SSID);
  Serial.print(", IP=");
  Serial.println(WiFi.softAPIP());

  udp.begin(UDP_PORT);
  Serial.print("UDP listening on port ");
  Serial.println(UDP_PORT);

  enterReady("AP_STARTED");
  Serial.println("=== boot complete, JSON logging begins below ===");
}

void loop() {
  serviceButton();
  serviceOnboardLed();
  serviceMotor();

  int packetSize = udp.parsePacket();
  if (packetSize > 0) {
    uint8_t buf[MAX_PACKET_LEN + 8];
    int len = udp.read(buf, sizeof(buf));
    IPAddress srcIP = udp.remoteIP();
    uint16_t srcPort = udp.remotePort();
    handlePacket(buf, len, srcIP, srcPort);
  }
}
