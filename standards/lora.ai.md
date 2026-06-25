<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# LoRa PHY Reference (AI Distilled)

## LICHEN Defaults

| Param | Value | Register (SX126x) |
|-------|-------|-------------------|
| SF | 10 | `0x0702` (SF10=0x0A) |
| BW | 125 kHz | `0x0704` (0x04) |
| CR | 4/5 | `0x0705` (0x01) |
| Preamble | 8 symbols | `SetPacketParams` |
| Sync Word | 0x34 | `0x0740-0x0741` |
| CRC | On | `SetPacketParams` |

Sync words: LICHEN=0x34, Meshtastic=0x2B, LoRaWAN=0x34/0x12

## Regional Frequencies

| Region | Band (MHz) | Channels | Duty Cycle |
|--------|------------|----------|------------|
| US/CA FCC | 902-928 | 64 @ 200kHz | None (FHSS) |
| EU ETSI | 863-870 | 3 @ 125kHz | 1% / 0.1% |
| AU/NZ | 915-928 | 64 @ 200kHz | None |
| AS923 | 923 | Variable | LBT |

EU sub-bands: 868.1, 868.3, 868.5 MHz (default), 869.525 (10% DC)

## Airtime Calculation

```
T_sym = 2^SF / BW_Hz          # symbol time in seconds
T_pre = (N_pre + 4.25) * T_sym
N_pay = 8 + max(ceil((8*PL - 4*SF + 44) / (4*SF)) * (CR+4), 0)
T_pay = N_pay * T_sym
T_air = T_pre + T_pay
```

Where: SF=spreading factor, BW_Hz=bandwidth, N_pre=preamble symbols, PL=payload bytes, CR=1..4 (maps to 4/5..4/8)

## Quick Airtime Table (SF10, 125kHz, CR4/5)

| Payload | Airtime | Symbols |
|---------|---------|---------|
| 20 B | ~250 ms | ~31 |
| 50 B | ~370 ms | ~46 |
| 100 B | ~550 ms | ~67 |
| 200 B | ~900 ms | ~110 |

T_sym at SF10/125kHz = 8.192 ms

## Link Budget

| Param | Value |
|-------|-------|
| TX Power | +14 to +22 dBm |
| RX Sensitivity | -137 dBm @ SF10 |
| Path Loss (1km, 915MHz) | ~110 dB |
| Typical Range (LOS) | 5-15 km |

Sensitivity by SF: SF7=-123dBm, SF8=-126dBm, SF9=-129dBm, SF10=-132dBm, SF11=-134.5dBm, SF12=-137dBm

## SX126x Key Registers

| Address | Name | Notes |
|---------|------|-------|
| 0x0702 | SF | Spreading factor |
| 0x0704 | BW | Bandwidth |
| 0x0705 | CR | Coding rate |
| 0x0740 | SyncWord[0] | MSB |
| 0x0741 | SyncWord[1] | LSB |
| 0x08AC | RxGain | 0x96=boosted |

Commands: `SetPacketParams`, `SetModulationParams`, `SetRfFrequency`

## Constraints

- Max payload: 255 bytes (register limit)
- LICHEN MTU: 200 bytes (after headers)
- EU 1% DC @ SF10: ~3.7 msgs/hour (50B payload)
- Preamble detect: min 5 symbols

## Not Used

LICHEN does NOT use LoRaWAN (star topology, gateway-centric). Only references LoRa Alliance for regional freq plans.
