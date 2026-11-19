// Smart Locker - ECE 2804
// Shreya P Bodanki,  Vishnu Ramesh
// runs on a bare atmega328p off a 9 v battery
//
// pins (arduino -> chip)
// A0 keypad 23   A1 servo current 24   A2 batt 25   A3 batt switch 26
// D2 lock button 4   D4 servo power 6   D6 green 12   D7 red 13
// D8 buzzer 14   D9 servo 15

// pins
const uint8_t KEYPAD_PIN = A0;
const uint8_t LOCK_BTN = 2;
const uint8_t SERVO_PWR = 4;     // irfz44n gate, high = servo on
const uint8_t SERVO_SENSE = A1;  // 1 ohm shunt
const uint8_t BUZZER = 8;
const uint8_t LED_RED = 7;
const uint8_t LED_GREEN = 6;

// buzzer tones in hz
const uint16_t TONE_OK = 1200;
const uint16_t TONE_BAD = 2000;
const uint16_t TONE_PROG = 1600;

// servo on timer1
// 16 mhz / 8 = 0.5 us per tick, top 40000 = 20 ms
const uint16_t SERVO_TOP = 40000;
const uint16_t PULSE_MIN = 450;
const uint16_t PULSE_MAX = 2500;
const uint16_t LOCK_US = 900;
const uint16_t UNLOCK_US = 1900;
const uint16_t TRAVEL_DIVISOR = 4;
const uint16_t SETTLE_MARGIN = 500;  // keep power on long enough for the stall test

bool servo_running = false;
uint16_t current_pulse = LOCK_US;
uint16_t target_pulse = LOCK_US;
unsigned long move_start = 0, move_len = 0;
int servoPeak = 0;            // highest current this move
unsigned long overStart = 0;  // when current went over the threshold
unsigned long overRunMax = 0; // longest run over the threshold

void servoInit() {
  DDRB |= (1 << PB1);
  PORTB &= ~(1 << PB1);
  TCCR1A = (1 << WGM11);  // fast pwm, top = icr1
  TCCR1B = (1 << WGM13) | (1 << WGM12) | (1 << CS11);
  ICR1 = SERVO_TOP;
  OCR1A = (uint16_t)LOCK_US * 2;
}

void servoMoveTo(uint16_t us) {
  digitalWrite(SERVO_PWR, HIGH);  // power the servo
  DDRB |= (1 << PB1);             // signal pin back to output
  if (us < PULSE_MIN) us = PULSE_MIN;
  if (us > PULSE_MAX) us = PULSE_MAX;
  OCR1A = us * 2;
  TCCR1A |= (1 << COM1A1);
  uint16_t delta = (us > current_pulse) ? (us - current_pulse) : (current_pulse - us);
  target_pulse = us;
  move_len = (unsigned long)(delta / TRAVEL_DIVISOR) + SETTLE_MARGIN;
  move_start = millis();
  servo_running = true;
  servoPeak = 0; overStart = 0; overRunMax = 0;
}

void servoStop() {
  TCCR1A &= ~(1 << COM1A1);       // stop pulses
  PORTB &= ~(1 << PB1);
  DDRB &= ~(1 << PB1);            // high z so nothing leaks into the servo
  digitalWrite(SERVO_PWR, LOW);   // cut servo ground
  if (servoPeak > 0) {
    Serial.print("[SERVO] peak="); Serial.print(servoPeak);
    Serial.print(" longest_run_ms="); Serial.println(overRunMax);
  }
  servo_running = false;
}

void servoUpdate() {
  if (servo_running && (millis() - move_start >= move_len)) {
    current_pulse = target_pulse;
    servoStop();
  }
}

// eeprom with raw registers
uint8_t eeRead(uint16_t addr) {
  while (EECR & (1 << EEPE));
  EEAR = addr;
  EECR |= (1 << EERE);
  return EEDR;
}

void eeWrite(uint16_t addr, uint8_t data) {
  while (EECR & (1 << EEPE));
  EEAR = addr;
  EEDR = data;
  uint8_t s = SREG; cli();
  EECR |= (1 << EEMPE);
  EECR |= (1 << EEPE);
  SREG = s;
}

// 4c secure password storage
// sha256 from the fips 180-4 spec, constants kept in flash
const uint32_t SHA_K[64] PROGMEM = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint32_t rotr(uint32_t x, uint8_t n) { return (x >> n) | (x << (32 - n)); }

// one block sha256, input up to 55 bytes
void sha256(const uint8_t* msg, uint8_t len, uint8_t out[32]) {
  uint32_t H[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

  // pad with 0x80, zeros, then length in bits
  uint8_t block[64];
  for (uint8_t i = 0; i < 64; i++) block[i] = 0;
  for (uint8_t i = 0; i < len; i++) block[i] = msg[i];
  block[len] = 0x80;
  uint16_t bits = (uint16_t)len * 8;
  block[62] = (uint8_t)(bits >> 8);
  block[63] = (uint8_t)bits;

  // message schedule
  uint32_t w[64];
  for (uint8_t t = 0; t < 16; t++)
    w[t] = ((uint32_t)block[4 * t] << 24) | ((uint32_t)block[4 * t + 1] << 16) |
           ((uint32_t)block[4 * t + 2] << 8) | (uint32_t)block[4 * t + 3];
  for (uint8_t t = 16; t < 64; t++) {
    uint32_t s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3);
    uint32_t s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10);
    w[t] = w[t - 16] + s0 + w[t - 7] + s1;
  }

  // 64 rounds
  uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
  uint32_t e = H[4], f = H[5], g = H[6], h = H[7];
  for (uint8_t t = 0; t < 64; t++) {
    uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t t1 = h + S1 + ch + pgm_read_dword(&SHA_K[t]) + w[t];
    uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = S0 + mj;
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  H[0] += a; H[1] += b; H[2] += c; H[3] += d;
  H[4] += e; H[5] += f; H[6] += g; H[7] += h;

  // output big endian
  for (uint8_t i = 0; i < 8; i++) {
    out[4 * i] = (uint8_t)(H[i] >> 24);
    out[4 * i + 1] = (uint8_t)(H[i] >> 16);
    out[4 * i + 2] = (uint8_t)(H[i] >> 8);
    out[4 * i + 3] = (uint8_t)H[i];
  }
}

// check our sha256 against the fips test vector for abc
void shaSelfTest() {
  uint8_t d[32];
  sha256((const uint8_t*)"abc", 3, d);
  Serial.print("[SHA] abc = ");
  for (uint8_t i = 0; i < 32; i++) {
    if (d[i] < 16) Serial.print('0');
    Serial.print(d[i], HEX);
  }
  Serial.println();
  Serial.println("[SHA] want BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
}

const uint8_t PW_LEN = 4;
const uint8_t HASH_LEN = 32;
const uint16_t MAGIC_ADDR = 0;
const uint16_t HASH_ADDR = 1;     // hash at 1 to 32
const uint8_t MAGIC_VAL = 0xA7;   // a7 sha256, a6 old fnv, a5 old plaintext
const uint8_t SALT[4] = {0x5A, 0xC3, 0x19, 0xE7};
const uint16_t STRETCH = 100;     // rehash rounds
uint8_t storedHash[HASH_LEN];

// salt + pin hashed, then rehashed STRETCH times
// uses out[32] not HASH_LEN because of arduino auto prototypes
void hashPin(const char* pin, uint8_t out[32]) {
  uint8_t buf[HASH_LEN + 4 + PW_LEN + 2];  // digest + salt + pin + round
  for (uint8_t i = 0; i < 4; i++) buf[i] = SALT[i];
  for (uint8_t i = 0; i < PW_LEN; i++) buf[4 + i] = (uint8_t)pin[i];
  sha256(buf, 4 + PW_LEN, out);
  for (uint16_t r = 1; r < STRETCH; r++) {
    for (uint8_t i = 0; i < HASH_LEN; i++) buf[i] = out[i];
    for (uint8_t i = 0; i < 4; i++) buf[HASH_LEN + i] = SALT[i];
    for (uint8_t i = 0; i < PW_LEN; i++) buf[HASH_LEN + 4 + i] = (uint8_t)pin[i];
    buf[HASH_LEN + 4 + PW_LEN] = (uint8_t)(r >> 8);
    buf[HASH_LEN + 4 + PW_LEN + 1] = (uint8_t)r;
    sha256(buf, HASH_LEN + 4 + PW_LEN + 2, out);
  }
}

// print what is stored in eeprom
void printEeprom() {
  uint8_t m = eeRead(MAGIC_ADDR);
  Serial.print("[EEPROM] addr 0 magic = 0x");
  if (m < 16) Serial.print('0');
  Serial.println(m, HEX);
  Serial.print("[EEPROM] addr 1-32 = ");
  for (uint8_t i = 0; i < HASH_LEN; i++) {
    uint8_t b = eeRead(HASH_ADDR + i);
    if (b < 16) Serial.print('0');
    Serial.print(b, HEX);
  }
  Serial.println();
}

void readHash() {
  for (uint8_t i = 0; i < HASH_LEN; i++) storedHash[i] = eeRead(HASH_ADDR + i);
}

void writeHash(const uint8_t* h) {
  for (uint8_t i = 0; i < HASH_LEN; i++) eeWrite(HASH_ADDR + i, h[i]);
}

void loadPassword() {
  if (eeRead(MAGIC_ADDR) != MAGIC_VAL) {  // first boot, store hash of 1234
    uint8_t h[HASH_LEN];
    hashPin("1234", h);
    writeHash(h);
    eeWrite(MAGIC_ADDR, MAGIC_VAL);
  }
  readHash();
}

void savePassword(const char* newpw) {
  uint8_t h[HASH_LEN];
  hashPin(newpw, h);
  writeHash(h);
  eeWrite(MAGIC_ADDR, MAGIC_VAL);
  readHash();
}

bool checkPassword(const char* entry) {
  uint8_t n = 0;
  while (n <= PW_LEN && entry[n] != '\0') n++;
  if (n != PW_LEN) return false;  // exactly 4 digits
  uint8_t h[HASH_LEN];
  hashPin(entry, h);              // compare hashes not pins
  for (uint8_t i = 0; i < HASH_LEN; i++)
    if (h[i] != storedHash[i]) return false;
  return true;
}

// keypad on one analog pin
const uint8_t NUM_KEYS = 12;
const int PRESS_THRESH = 300;
const int KEY_ADC[NUM_KEYS] = {1004, 919, 828, 758, 707, 652,
                               608, 574, 538, 504, 482, 455};
const char KEY_CHAR[NUM_KEYS] = {'1', '2', '3', '4', '5', '6',
                                 '7', '8', '9', '*', '0', '#'};
const unsigned long DEBOUNCE_MS = 50;
char lastStable = 0, candidate = 0;
unsigned long candidateTime = 0;

char readKeypad() {
  int raw = 0;
  for (uint8_t i = 0; i < 8; i++) raw += analogRead(KEYPAD_PIN);
  raw /= 8;  // average 8 reads
  char thisKey = 0;
  if (raw > PRESS_THRESH) {
    int best = 9999, bestIdx = -1;
    for (uint8_t i = 0; i < NUM_KEYS; i++) {
      int d = abs(raw - KEY_ADC[i]);
      if (d < best) { best = d; bestIdx = i; }
    }
    if (best <= raw / 40) thisKey = KEY_CHAR[bestIdx];  // tolerance scales with reading
  }
  if (thisKey != candidate) { candidate = thisKey; candidateTime = millis(); return 0; }
  if (millis() - candidateTime < DEBOUNCE_MS) return 0;
  if (candidate != 0 && lastStable == 0) { lastStable = candidate; return candidate; }
  if (candidate == 0) lastStable = 0;
  return 0;
}

// 4a low battery detection
// 1M / 470k divider switched at the top by a tp0606
// A3 drives a 2n7000 that turns the tp0606 on
const uint8_t BATT_SENSE = A2;
const uint8_t BATT_EN = A3;
const uint16_t BATT_SETTLE_MS = 250;  // 320k source charges slowly
// 63.4 counts per volt from 8.00 v and 7.01 v, 7.2 v -> 456
const int BATT_LOW_COUNT = 456;

int readBatteryCounts() {
  digitalWrite(BATT_EN, HIGH);  // divider on
  delay(BATT_SETTLE_MS);
  int v = 0;
  for (uint8_t i = 0; i < 4; i++) {  // keep the last of 4
    v = analogRead(BATT_SENSE);
    Serial.print(" s"); Serial.print(i); Serial.print("="); Serial.print(v);
  }
  Serial.println();
  digitalWrite(BATT_EN, LOW);   // divider off
  return v;
}

void lowBatteryWarning() {
  Serial.println("[BATT] low - replace the battery");
  for (uint8_t i = 0; i < 2; i++) {
    digitalWrite(LED_RED, HIGH);
    tone(BUZZER, TONE_BAD, 100);
    delay(150);
    digitalWrite(LED_RED, LOW);
    delay(150);
  }
}

void checkBattery() {
  int c = readBatteryCounts();
  Serial.print("[BATT] counts="); Serial.println(c);
  if (c < BATT_LOW_COUNT) lowBatteryWarning();
}

bool lockButtonPressed() { return digitalRead(LOCK_BTN) == LOW; }

// 3a blocked motor detection
// 1 ohm shunt on A1 through 1k + 4.7uF, 1 count = 4.79 ma
// free move settles to 0, stall holds at 46
// both spike to ~155 at the start so this is a duration test
const uint16_t BLOCK_IGNORE_MS = 250;  // skip the startup spike
const uint16_t BLOCK_HOLD_MS = 300;    // must stay high this long
const int BLOCK_COUNT = 25;            // between 0 and 46

bool motorBlocked() {
  if (!servo_running) return false;  // shunt floats when servo is off
  if (millis() - move_start < BLOCK_IGNORE_MS) return false;
  int c = analogRead(SERVO_SENSE);
  if (c > servoPeak) servoPeak = c;
  if (c > BLOCK_COUNT) {
    if (overStart == 0) overStart = millis();
    unsigned long run = millis() - overStart;
    if (run > overRunMax) overRunMax = run;
    if (run >= BLOCK_HOLD_MS) return true;
  } else {
    overStart = 0;  // any dip resets it
  }
  return false;
}

// state machine
enum { LOCKED, UNLOCKED, LOCKING, ERROR } state = LOCKED;
char entered[16];
uint8_t entLen = 0;
bool programming = false;
unsigned long lastStar = 0, errorStart = 0, lockStart = 0;
unsigned long lastActivity = 0;
unsigned long unlockedAt = 0;
const unsigned long ERROR_TIME = 1500;
const unsigned long SERVO_SETTLE = 900;     // longer than the stall test
const unsigned long IDLE_TIMEOUT = 10000;   // locked and idle -> sleep
const unsigned long AUTO_LOCK_MS = 10000;   // unlocked -> lock itself

// 3c and 4d sleep
ISR(INT0_vect) {
  EIMSK &= ~(1 << INT0);
  state = LOCKED;
  lastActivity = millis();
}

void enterSleep() {
  servoMoveTo(LOCK_US);
  delay(600);
  servoStop();  // also cuts servo power
  digitalWrite(LED_RED, LOW);
  digitalWrite(LED_GREEN, LOW);
  noTone(BUZZER);
  Serial.println("[SLEEP] power down");
  Serial.flush();
  ADCSRA &= ~(1 << ADEN);  // adc off
  ACSR |= (1 << ACD);      // comparator off
  EIMSK |= (1 << INT0);
  SMCR = (1 << SM1);       // power down mode
  SMCR |= (1 << SE);
  cli();
  MCUCR = (1 << BODS) | (1 << BODSE);  // bod off, timed sequence
  MCUCR = (1 << BODS);
  __asm__ __volatile__("sei\n\tsleep");
  SMCR &= ~(1 << SE);
  ADCSRA |= (1 << ADEN);
  Serial.println("[WAKE] int0");
  checkBattery();
}

void setup() {
  Serial.begin(9600);
  pinMode(LOCK_BTN, INPUT_PULLUP);
  pinMode(BUZZER, OUTPUT);
  pinMode(LED_RED, OUTPUT);
  pinMode(LED_GREEN, OUTPUT);
  pinMode(BATT_EN, OUTPUT);
  digitalWrite(BATT_EN, LOW);     // divider off
  pinMode(SERVO_PWR, OUTPUT);
  digitalWrite(SERVO_PWR, LOW);   // servo off
  EICRA &= ~((1 << ISC01) | (1 << ISC00));  // int0 low level wake
  shaSelfTest();
  servoInit();
  unsigned long t = micros();
  loadPassword();
  Serial.print("[HASH] boot load us="); Serial.println(micros() - t);
  printEeprom();
  checkBattery();  // before the servo moves
  servoMoveTo(LOCK_US);
  lastActivity = millis();
  Serial.println("[BOOT] locked");
}

void loop() {
  unsigned long now = millis();
  servoUpdate();

  switch (state) {
    case LOCKED: {
      char key = readKeypad();
      if (key) {
        lastActivity = now;
        if (key == '*') {
          if (now - lastStar < 800) {  // double star -> program mode
            programming = true; entLen = 0;
            digitalWrite(LED_RED, HIGH);
            digitalWrite(LED_GREEN, HIGH);
            tone(BUZZER, TONE_PROG, 120);
            Serial.println("[PROG] enter new 4-digit code, then #");
          } else {
            entLen = 0;
            Serial.println("[CLEAR]");
          }
          lastStar = now;
        }
        else if (key == '#') {
          entered[entLen] = '\0';
          if (programming) {
            if (entLen == PW_LEN) {
              savePassword(entered);
              tone(BUZZER, TONE_OK, 120);
              Serial.println("[PROG] saved");
            } else {
              Serial.println("[PROG] need exactly 4 digits - cancelled");
            }
            programming = false;
            digitalWrite(LED_RED, LOW);
            digitalWrite(LED_GREEN, LOW);
          } else {
            Serial.print("[SUBMIT] len="); Serial.println(entLen);
            unsigned long t = micros();
            bool ok = checkPassword(entered);
            Serial.print("[HASH] us="); Serial.println(micros() - t);
            if (ok) {
              Serial.println("[CHECK] correct -> UNLOCKED");
              digitalWrite(LED_GREEN, HIGH);
              tone(BUZZER, TONE_OK, 120);
              servoMoveTo(UNLOCK_US);
              unlockedAt = now;
              state = UNLOCKED;
            } else {
              Serial.println("[CHECK] wrong -> ERROR");
              digitalWrite(LED_RED, HIGH);
              tone(BUZZER, TONE_BAD);
              errorStart = now;
              state = ERROR;
            }
          }
          entLen = 0;
        }
        else if (entLen < 15) {
          entered[entLen++] = key;
          Serial.print(programming ? "[NEW] " : "[KEY] ");
          Serial.println(key);
        }
      }
      if (now - lastActivity > IDLE_TIMEOUT) enterSleep();
    } break;

    case UNLOCKED:
      if (lockButtonPressed() || now - unlockedAt > AUTO_LOCK_MS) {
        Serial.println(lockButtonPressed() ? "[LOCK BTN] -> LOCKING" : "[AUTO LOCK] -> LOCKING");
        digitalWrite(LED_GREEN, LOW);
        servoMoveTo(LOCK_US);
        lockStart = now;
        state = LOCKING;
      }
      break;

    case LOCKING:
      if (motorBlocked()) {
        Serial.print("[BLOCKED] peak="); Serial.print(servoPeak);
        Serial.print(" held_ms="); Serial.print(overRunMax);
        Serial.print(" after_ms="); Serial.println(now - lockStart);
        servoMoveTo(UNLOCK_US);  // go back to unlocked
        digitalWrite(LED_GREEN, HIGH);
        tone(BUZZER, TONE_BAD, 300);
        unlockedAt = now;        // restart auto lock
        state = UNLOCKED;
        Serial.println("[BLOCKED] -> UNLOCKED");
      } else if (now - lockStart > SERVO_SETTLE) {
        Serial.println("[SERVO SET] -> LOCKED");
        state = LOCKED;
        lastActivity = now;
      }
      break;

    case ERROR:
      if (now - errorStart > ERROR_TIME) {
        digitalWrite(LED_RED, LOW);
        noTone(BUZZER);
        Serial.println("[ERROR CLEARED] -> LOCKED");
        state = LOCKED;
        lastActivity = now;
      }
      break;
  }
}
