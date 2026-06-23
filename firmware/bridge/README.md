<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Serial-to-LoRa Bridge

Minimal firmware that exposes raw LoRa TX/RX over USB serial. Flash this onto a RAK4631 (or similar) to use it as a radio peripheral for host-side LICHEN development.

## Why?

Developing mesh protocols is faster on a real computer than on a microcontroller. This bridge lets you:

- Run LICHEN Python/Rust code on your Mac/Linux box
- Use real LoRa radios for TX/RX
- Debug with full tooling (debuggers, profilers, printf)
- Test two nodes without flashing full firmware

## Protocol

Text-based, human-readable, easy to debug with a terminal:

```
# Transmit (host → radio)
TX 48454c4c4f\n

# Response
OK\n

# Received packet (radio → host)
RX -85 7.5 48454c4c4f\n

# Configure radio
CFG SF=10 BW=125 CR=5 FREQ=915000000 PWR=22\n

# Query status
STATUS\n
```

All packets are hex-encoded. RSSI in dBm, SNR in dB.

## Building (Arduino)

1. Install Arduino IDE or CLI
2. Install board support:
   - Add `https://raw.githubusercontent.com/RAKWireless/RAKwireless-Arduino-BSP-Index/main/package_rakwireless.com_rui_index.json` to board URLs
   - Install "RAKwireless nRF Boards"
3. Install RadioLib library
4. Select board: "WisBlock RAK4631"
5. Compile and upload `rak4631_bridge.ino`

## Building (PlatformIO)

```ini
[env:rak4631]
platform = nordicnrf52
board = wiscore_rak4631
framework = arduino
lib_deps = jgromes/RadioLib
```

## Usage

```bash
# Find the port
ls /dev/cu.usbmodem*

# Test with screen
screen /dev/cu.usbmodem22424101 115200
# Type: STATUS<enter>
# Should see: OK SF=10 BW=125.00 ...

# Or use the Python interface
python serial_radio.py
```

## Python Integration

`serial_radio.py` provides `SerialRadio` class — drop-in for simulator's radio interface:

```python
from serial_radio import SerialRadio

radio = SerialRadio("/dev/cu.usbmodem22424101")
await radio.connect()
await radio.configure(sf=10, bw=125, freq_hz=915_000_000)
await radio.transmit(b"hello")

pkt = await radio.receive(timeout=5.0)
if pkt:
    print(f"Got: {pkt.data} rssi={pkt.rssi}")
```

## Supported Hardware

Tested:
- RAK4631 (nRF52840 + SX1262)

Should work (adjust pins):
- Heltec LoRa 32 V3 (ESP32-S3 + SX1262)
- LilyGo T-Beam Supreme (ESP32-S3 + SX1262)
- Any board with SX1262/SX1276 + USB serial

## Pin Configuration

For RAK4631 (in the .ino file):
```cpp
#define LORA_NSS   42
#define LORA_DIO1  47
#define LORA_BUSY  46
#define LORA_RST   38
```

For other boards, check RadioLib examples or your board's pinout.
