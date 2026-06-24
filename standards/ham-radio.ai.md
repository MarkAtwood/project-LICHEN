<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Ham Radio Protocols - AI Summary

KISS protocol reference for LICHEN implementation.

## KISS Frame Format

```
FEND | CMD | DATA... | FEND
0xC0 | 1B  | 0-n     | 0xC0
```

## Byte Escaping

In DATA, escape special bytes:

| Raw  | Escaped     |
|------|-------------|
| 0xC0 | 0xDB 0xDC   |
| 0xDB | 0xDB 0xDD   |

Constants:
- `FEND  = 0xC0` — frame delimiter
- `FESC  = 0xDB` — escape prefix
- `TFEND = 0xDC` — escaped FEND
- `TFESC = 0xDD` — escaped FESC

## Commands (CMD byte)

| Value | Name        | Direction    | Purpose            |
|-------|-------------|--------------|--------------------|
| 0x00  | DataFrame   | Bidirectional| Raw packet payload |
| 0x01  | TXDELAY     | Host->TNC    | TX key-up delay    |
| 0x02  | Persistence | Host->TNC    | CSMA p-value       |
| 0x03  | SlotTime    | Host->TNC    | CSMA slot interval |
| 0x04  | TxTail      | Host->TNC    | TX tail time       |
| 0x05  | FullDuplex  | Host->TNC    | Half/full duplex   |
| 0x0F  | Return      | Host->TNC    | Exit KISS mode     |

## BLE KISS UUIDs (aprs.fi spec)

```
Service:    00000001-ba2a-46c9-ae49-01b0961f68bb
TX Char:    00000002-ba2a-46c9-ae49-01b0961f68bb  (write, phone->TNC)
RX Char:    00000003-ba2a-46c9-ae49-01b0961f68bb  (notify, TNC->phone)
```

MTU: negotiate 244+ bytes for full KISS frames.

## Encoding Example

To send `[0xC0, 0x41, 0xDB]` as data:

```
TX: C0 00 DB DC 41 DB DD C0
    ^  ^  ^^^^^  ^  ^^^^^  ^
    |  |  esc'd  |  esc'd  FEND
    |  CMD       data
    FEND
```

## LICHEN Usage

KISS used for app compatibility (aprs.fi, APRSDroid, direwolf).
LICHEN frames are NOT AX.25 — KISS carries raw LICHEN payloads.

## References

- [KISS Spec](http://www.ax25.net/kiss.aspx)
- [BLE-KISS-API](https://github.com/hessu/aprs-specs/blob/master/BLE-KISS-API.md)
