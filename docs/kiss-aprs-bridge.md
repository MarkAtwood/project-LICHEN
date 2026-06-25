# KISS/APRS Bridge Specification

LICHEN provides a KISS interface for compatibility with legacy TNC applications
(APRSDroid, aprs.fi, etc.). This document describes the bridge architecture.

## Overview

```
┌─────────────────┐     KISS/BLE      ┌─────────────────┐
│   APRSDroid     │◄──────────────────►│  LICHEN Node    │
│   (phone app)   │    or Serial      │                 │
└─────────────────┘                   └────────┬────────┘
                                               │
                                               ▼ LoRa
                                        ┌──────────────┐
                                        │ LICHEN Mesh  │
                                        └──────────────┘
```

## Port Assignments

| Port | Content | Direction |
|------|---------|-----------|
| 0 | AX.25/APRS frames | TX: App→Radio, RX: Radio→App |
| 1 | Raw LICHEN frames | TX: App→Radio, RX: Radio→App |

## Callsign Mapping

LICHEN uses 8-byte Interface Identifiers (IID). AX.25 requires 6-character
callsigns. We synthesize callsigns from IIDs:

```
IID: fe80:0000:00XX:YYZZ
         └─────┬─────┘
               ▼
Callsign: L + base36(XXYYZZ)

Example:
IID: fe80::00:11:22:33 → XXYYZZ = 0x112233 = 1122867
1122867 in base36 = "NU7F"
Callsign: "LNU7F"
```

Prefix `L` for LICHEN. Max 5 chars (fits AX.25 limit of 6).

Broadcast addresses: `CQ`, `BEACON`, `ALL` → empty IID (broadcast)

## APRS Message Format

Incoming LICHEN payloads are wrapped as APRS messages for display in the
Messages tab:

```
:ADDRESSEE:message text{msgid
```

- ADDRESSEE: 9 chars, padded with spaces (recipient callsign)
- message text: payload content
- msgid: numeric ID for ack tracking

### Delivery Confirmation

1. App sends message with `{42`
2. Bridge extracts text, sends via LICHEN with tracking
3. Remote node receives, sends ACK (0x06 + msgid bytes)
4. Bridge receives ACK, forwards to app as `:SENDER   :ack42`
5. App shows delivery checkmark

## APRS Packet Synthesis

When receiving structured LICHEN payloads (CBOR/JSON), the bridge synthesizes
proper APRS packet types instead of plain messages:

### Position

Payload with `lat`/`lon` keys → APRS position report

```json
{"lat": 37.7749, "lon": -122.4194, "alt": 100}
```
↓
```
!3746.49N/12225.16W>/A=000328
```

### Weather

Payload with `temp`/`humidity`/`pressure` → APRS weather report

```json
{"temp": 22.5, "humidity": 65, "pressure": 1013.2}
```
↓
```
_.../...t072h65b10132
```

### Telemetry

Payload with numeric array or `ch0`-`ch4` keys → APRS telemetry

```json
[100, 150, 200, 50, 75]
```
↓
```
T#000,100,150,200,050,075,00000000
```

## Payload Formatting

Unknown payloads are formatted for readability:

| Input | Output |
|-------|--------|
| UTF-8 text | As-is |
| CBOR `{"temp":22}` | `{temp:22}` |
| JSON `[1,2,3]` | `[1,2,3]` |
| Binary (CoAP header) | `[CoAP] 12B: 4001 0001 abcd...` |
| Binary (SCHC header) | `[SCHC] 8B: 0012 3456...` |
| Other binary | `16B: dead beef 0123...` |

## BLE GATT Service

**Service UUID:** `00000001-ba2a-46c9-ae49-01b0961f68bb`

| Characteristic | UUID | Properties |
|----------------|------|------------|
| TX (to device) | `00000002-ba2a-46c9-ae49-01b0961f68bb` | Write |
| RX (from device) | `00000003-ba2a-46c9-ae49-01b0961f68bb` | Notify, Read |

## Implementation Files

```
src/lichen/interface/kiss/
├── __init__.py      # Public exports
├── framing.py       # KISS encode/decode, escaping
├── handler.py       # Frame dispatch, config commands
├── serial.py        # Serial/USB transport
├── gatt.py          # BLE GATT service (stub)
├── ax25.py          # AX.25 UI frame codec
├── callsign.py      # IID ↔ callsign mapping
├── aprs.py          # APRS message format, ack tracking
├── aprs_synth.py    # Position/weather/telemetry synthesis
├── payload_fmt.py   # Unknown payload formatting
└── bridge.py        # KISS ↔ LinkLayer bridge
```

## Cargo Features (Rust)

For embedded targets, KISS/APRS is optional:

```toml
[features]
kiss = []            # Core KISS framing
kiss-aprs = ["kiss"] # + APRS synthesis, AX.25
kiss-ble = ["kiss"]  # + BLE GATT service
```

## Test Coverage

313 tests across all KISS modules. Run with:

```bash
cd python && uv run pytest tests/interface/test_kiss*.py -v
```
