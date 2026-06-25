<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Other Standards - AI Reference

Dense reference for IEEE, OASIS, regulatory limits. Skip to section needed.

## MQTT-SN (OASIS)

Lightweight pub/sub over UDP for sensor networks.

| Parameter | Value |
|-----------|-------|
| Port | **10883** |
| QoS levels | 0, 1, 2 |
| Topic IDs | 2-byte short IDs |
| Security | DTLS (optional) |

## BLE Service UUIDs

| Service | UUID | Notes |
|---------|------|-------|
| KISS TNC | `00000001-ba2a-46c9-ae49-01b0961f68bb` | Serial framing |
| LICHEN Native | TBD | Full protocol |
| Nordic UART (NUS) | `6E400001-B5A3-F393-E0A9-E50E24DCCA9E` | Serial over BLE |

## Regulatory Limits by Region

| Region | Band (MHz) | Max Power | Duty Cycle | Authority |
|--------|------------|-----------|------------|-----------|
| **US** | 902-928 | 1W EIRP | None (FHSS/DSS) | FCC Part 15 |
| **EU** | 863-870 | 25 mW | 1% | ETSI EN 300 220 |
| **AU** | 915-928 | 1W EIRP | None | ACMA |
| **JP** | 920-928 | 20 mW | None | MIC |

### EU Sub-bands (ETSI)

| Sub-band (MHz) | Power | Duty |
|----------------|-------|------|
| 863.0-868.0 | 25 mW | 1% |
| 868.0-868.6 | 25 mW | 1% |
| 868.7-869.2 | 25 mW | 0.1% |
| 869.4-869.65 | 500 mW | 10% |
| 869.7-870.0 | 25 mW | 1% |

## Other Standards Used

| Standard | Use |
|----------|-----|
| IEEE 754 | Float representation |
| ISO 8601 | Timestamps |
| ISO 3309 | CRC-32 algorithm |
| JSON Schema Draft-07 | Test vector validation |

## PCAP Integration

- DLT: `DLT_USER0` (147) or registered
- Dissector: `tools/wireshark/`
