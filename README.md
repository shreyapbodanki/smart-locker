# Personal Smart Locker

ECE 2804 Integrated Design Project at Virginia Tech, Milestones 3 and 4.
Shreya Bodanki and Vishnu Ramesh.

A keypad-controlled locker built on a bare ATmega328P (16 MHz) that runs from a 9 V battery through an MCP1702 5 V regulator. It uses no libraries. The servo PWM, EEPROM access and SHA-256 are all written against the registers.

## Features
- **Keypad on one analog pin.** All 12 keys are read through a resistor ladder on A0, averaged and debounced.
- **Servo lock.** Timer1 generates the 50 Hz PWM. An IRFZ44N cuts the servo's power between moves.
- **Blocked motor detection (3a).** A 1 Ω shunt on A1 measures servo current. If the current stays high for 300 ms, the lock returns to unlocked.
- **Power-down sleep (3c, 4d).** The chip sleeps after 10 s idle and wakes on INT0. The brown-out detector and analog comparator are off during sleep. Measured sleep current is 0.1 µA.
- **Low battery alert (4a).** A divider is switched in by a TP0606 MOSFET only while measuring. The chip warns below 7.2 V.
- **Status LEDs and buzzer (4b).** Green means unlocked, red means wrong code, and both mean reprogramming.
- **Secure password storage (4c).** A salted SHA-256 hash, stretched 100 rounds, is stored in EEPROM, never the PIN itself. The hash is implemented from FIPS 180-4 and checked against the "abc" test vector at every boot.
- **Auto lock.** The locker locks itself 10 s after unlocking.

## Usage
- Default PIN is `1234`. Enter the 4 digits, then `#`.
- `*` clears the entry. Press `*` twice to set a new PIN, then enter 4 digits and `#`.
- Flashing over ISP erases the EEPROM, so the PIN resets to 1234.

## Files
- `smart_locker.ino` is the full sketch.
- `SL_schematic.png` is the circuit schematic.
