<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# SCHC Profile for LoRa Mesh Networks

```
Internet-Draft                                              LICHEN Project
draft-lichen-schc-lora-00                                       July 2026
Intended status: Experimental
Expires: January 2027
```

## Status of This Document

**PRELIMINARY DRAFT — WORK IN PROGRESS**

This document is an early draft developed alongside a reference implementation.
It will be updated as implementation experience is gained. Coding agents with
human oversight may modify this specification as needed.

This Internet-Draft is submitted in full conformance with the provisions of
BCP 78 and BCP 79.

## Abstract

This document defines a Static Context Header Compression (SCHC) profile for
LoRa mesh networks. It specifies compression rules for IPv6, UDP, and CoAP
headers optimized for the LICHEN protocol, along with fragmentation parameters
suitable for LoRa's characteristics. The profile enables efficient transmission
of IPv6 packets over LoRa links with typical payloads of 50-200 bytes.

## Table of Contents

1.  Introduction
2.  Terminology
3.  SCHC Architecture for LoRa Mesh
4.  Compression Rules
5.  Fragmentation Profile
6.  Rule Versioning
7.  Implementation Considerations
8.  Security Considerations
9.  IANA Considerations
10. References

Appendix A.  Complete Rule Set
Appendix B.  Compression Examples

## 1. Introduction

LoRa (Long Range) is a spread-spectrum modulation technique enabling
long-range, low-power wireless communication. LoRa networks typically
operate at low data rates (300 bps to 27 kbps) with small MTUs (50-250
bytes depending on spreading factor).

SCHC (Static Context Header Compression), specified in RFC 8724, provides
header compression and fragmentation for LPWAN technologies. This document
defines a SCHC profile tailored for LoRa mesh networks running IPv6 with
CoAP application traffic.

### 1.1. Design Goals

- **Aggressive compression:** Reduce IPv6+UDP+CoAP headers from 60+ bytes
  to 6-12 bytes for common cases
- **Efficient fragmentation:** Use ACK-on-Error mode to minimize overhead
- **Mesh-friendly:** Support multi-hop routing without per-hop decompression
- **Versioned rules:** Enable firmware updates without breaking interoperability

### 1.2. Relationship to Other Specifications

This profile is designed for use with:
- LICHEN link layer (draft-lichen-link)
- RPL routing (RFC 6550, with LoRa tuning per draft-lichen-rpl-lora)
- CoAP (RFC 7252) and OSCORE (RFC 8613)

This profile does NOT use IEEE 802.15.4 or 6LoWPAN IPHC (RFC 6282). SCHC
replaces 6LoWPAN for both compression and fragmentation.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

- **Rule:** A SCHC compression/decompression rule
- **Rule ID:** Identifier for a rule (variable length in SCHC, fixed 8-bit here)
- **TV:** Target Value in a rule entry
- **MO:** Matching Operator: `equal` (exact match), `ignore` (always match), `MSB(k)` (match most-significant k bits), `match-mapping` (value must be in the `mapping` list per FieldDescriptor; see `python/src/lichen/schc/rules.py:32`, equivalent in rules.rs:15). Example: `FieldDescriptor("M", 8, MO.MATCH_MAPPING, CDA.MAPPING_SENT, mapping=(0x10, 0x20))` (cross-ref: appendix-schc.md:A.1, test/vectors/schc_compression.json for PIO vectors).
- **CDA:** Compression/Decompression Action (not-sent, value-sent, etc.)
- **FCN:** Fragment Counter Number
- **DTAG:** Datagram Tag (identifies fragments of same packet)

## 3. SCHC Architecture for LoRa Mesh

### 3.1. Protocol Stack

```
+----------------------------------+
|  Application (CoAP + OSCORE)     |
+----------------------------------+
|  Transport (UDP)                 |
+----------------------------------+
|  Network (IPv6)                  |
+----------------------------------+
|  SCHC Compression/Fragmentation  |  <-- This profile
+----------------------------------+
|  LICHEN Link Layer               |
+----------------------------------+
|  LoRa PHY                        |
+----------------------------------+
```

### 3.2. Compression Point

SCHC compression/decompression occurs at:
- **Origin:** Compress before transmission
- **Destination:** Decompress after reception

Intermediate routers (relays) forward compressed packets without
decompression. This requires end-to-end rule synchronization.

### 3.3. Context Provisioning

SCHC contexts (rule sets) are provisioned statically:
- Built into firmware at compile time
- Identified by Rule Set Version (see 03-adaptation.md §5.7)
- Synchronized via DIO advertisement

Dynamic rule negotiation is NOT supported in this profile.

## 4. Compression Rules

See spec/03-adaptation.md §5.5, spec/appendix-schc.md, and test/vectors/ for canonical rule set (version 2).

Rule IDs are fixed 8-bit values synchronized with `lichen-core::constants.rs` and `constants.toml`. Current set (MUST match all implementations and test vectors):

| Range | Usage |
|-------|-------|
| 0-4 | Compression rules |
| 5-254 | Reserved for future use |
| 255 | No compression (uncompressed fallback) |

### 4.2. Rule 0: Link-local IPv6 + UDP + CoAP

### 4.2. Rule Field Descriptors

Field descriptors (TV, MO, CDA per RFC 8724 §7) are defined in `rust/lichen-schc/src/rules.rs` (with matching implementations in C and Python). See Appendix A for the current rule set summary. CoAP compression follows RFC 8824 and is applied after IPv6/UDP where used. OSCORE is compressed as opaque payload.

**Rule Definition:**

| Field | TV | MO | CDA | Sent |
|-------|----|----|-----|------|
| IPv6.Version | 6 | equal | not-sent | 0 |
| IPv6.TrafficClass | 0 | equal | not-sent | 0 |
| IPv6.FlowLabel | 0 | equal | not-sent | 0 |
| IPv6.PayloadLength | - | ignore | compute | 0 |
| IPv6.NextHeader | 17 | equal | not-sent | 0 |
| IPv6.HopLimit | 64 | ignore | not-sent | 0 |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent | 0 |
| IPv6.SrcIID | - | ignore | deviid | 0 |
| IPv6.DstPrefix | fe80::/64 | equal | not-sent | 0 |
| IPv6.DstIID | - | ignore | deviid | 0 |
| UDP.SrcPort | 5683 | MSB(12) | LSB | 4 bits |
| UDP.DstPort | 5683 | MSB(12) | LSB | 4 bits |
| UDP.Length | - | ignore | compute | 0 |
| UDP.Checksum | - | ignore | compute | 0 |

**Compressed size:** 4-6 bytes

**deviid:** Derive IID from link-layer address (EUI-64 or short address).

### 4.3. Rule 1: Global IPv6 + UDP + CoAP

For traffic to/from internet via border router.

**Applicability:**
- IPv6 source is mesh (ULA or GUA)
- IPv6 destination is global (2000::/3) or vice versa

**Rule Definition:**

| Field | TV | MO | CDA | Sent |
|-------|----|----|-----|------|
| IPv6.Version | 6 | equal | not-sent | 0 |
| IPv6.TrafficClass | 0 | ignore | value-sent | 8 bits |
| IPv6.FlowLabel | 0 | ignore | value-sent | 20 bits |
| IPv6.PayloadLength | - | ignore | compute | 0 |
| IPv6.NextHeader | 17 | equal | not-sent | 0 |
| IPv6.HopLimit | - | ignore | value-sent | 8 bits |
| IPv6.SrcAddr | - | ignore | value-sent | 128 bits |
| IPv6.DstAddr | - | ignore | value-sent | 128 bits |
| UDP.SrcPort | - | ignore | value-sent | 16 bits |
| UDP.DstPort | - | ignore | value-sent | 16 bits |
| UDP.Length | - | ignore | compute | 0 |
| UDP.Checksum | - | ignore | compute | 0 |

**Compressed size:** 41 bytes

### 4.4. Rule 2: ICMPv6 Echo

For ICMPv6 echo request and reply.

**Applicability:**
- Next header is ICMPv6 (58)
- ICMPv6 type is 128 or 129

**Rule Definition:**

| Field | TV | MO | CDA | Sent |
|-------|----|----|-----|------|
| IPv6.Version | 6 | equal | not-sent | 0 |
| IPv6.TrafficClass | 0 | equal | not-sent | 0 |
| IPv6.FlowLabel | 0 | equal | not-sent | 0 |
| IPv6.PayloadLength | - | ignore | compute | 0 |
| IPv6.NextHeader | 58 | equal | not-sent | 0 |
| IPv6.HopLimit | 64 | ignore | not-sent | 0 |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent | 0 |
| IPv6.SrcIID | - | ignore | deviid | 0 |
| IPv6.DstPrefix | fe80::/64 | equal | not-sent | 0 |
| IPv6.DstIID | - | ignore | deviid | 0 |
| ICMPv6.Type | - | ignore | value-sent | 8 bits |
| ICMPv6.Code | - | ignore | value-sent | 8 bits |
| ICMPv6.Checksum | - | ignore | compute | 0 |

**Compressed size:** 3 bytes

### 4.5. Rule 3: RPL DIO

For RPL DODAG Information Object (code 1).

**Applicability:**
- Next header is ICMPv6 (58)
- ICMPv6 type is RPL (155)
- ICMPv6 code is 1

**Rule Definition:**

| Field | TV | MO | CDA | Sent |
|-------|----|----|-----|------|
| IPv6.Version | 6 | equal | not-sent | 0 |
| IPv6.TrafficClass | 0 | equal | not-sent | 0 |
| IPv6.FlowLabel | 0 | equal | not-sent | 0 |
| IPv6.PayloadLength | - | ignore | compute | 0 |
| IPv6.NextHeader | 58 | equal | not-sent | 0 |
| IPv6.HopLimit | 255 | equal | not-sent | 0 |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent | 0 |
| IPv6.SrcIID | - | ignore | deviid | 0 |
| IPv6.DstAddr | ff02::1a | equal | not-sent | 0 |
| ICMPv6.Type | 155 | equal | not-sent | 0 |
| ICMPv6.Code | 1 | equal | not-sent | 0 |
| ICMPv6.Checksum | - | ignore | compute | 0 |

**Compressed size:** 8 bytes

### 4.6. Rule 4: RPL DAO

For RPL Destination Advertisement Object (code 2).

**Applicability:**
- Next header is ICMPv6 (58)
- ICMPv6 type is RPL (155)
- ICMPv6 code is 2

**Rule Definition:**

| Field | TV | MO | CDA | Sent |
|-------|----|----|-----|------|
| IPv6.Version | 6 | equal | not-sent | 0 |
| IPv6.TrafficClass | 0 | equal | not-sent | 0 |
| IPv6.FlowLabel | 0 | equal | not-sent | 0 |
| IPv6.PayloadLength | - | ignore | compute | 0 |
| IPv6.NextHeader | 58 | equal | not-sent | 0 |
| IPv6.HopLimit | 255 | equal | not-sent | 0 |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent | 0 |
| IPv6.SrcIID | - | ignore | deviid | 0 |
| IPv6.DstPrefix | fe80::/64 | equal | not-sent | 0 |
| IPv6.DstIID | - | ignore | deviid | 0 |
| ICMPv6.Type | 155 | equal | not-sent | 0 |
| ICMPv6.Code | 2 | equal | not-sent | 0 |
| ICMPv6.Checksum | - | ignore | compute | 0 |

**Compressed size:** 6 bytes

### 4.7. Rule 5: Link-local IPv6 + UDP + MQTT-SN

For MQTT-SN traffic (port 10883) per adaptation rules.

**Applicability:**
- IPv6 source and destination are link-local (fe80::/10)
- Next header is UDP
- UDP ports are 10883

**Rule Definition:**

| Field | TV | MO | CDA | Sent |
|-------|----|----|-----|------|
| IPv6.Version | 6 | equal | not-sent | 0 |
| IPv6.TrafficClass | 0 | equal | not-sent | 0 |
| IPv6.FlowLabel | 0 | equal | not-sent | 0 |
| IPv6.PayloadLength | - | ignore | compute | 0 |
| IPv6.NextHeader | 17 | equal | not-sent | 0 |
| IPv6.HopLimit | 64 | ignore | not-sent | 0 |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent | 0 |
| IPv6.SrcIID | - | ignore | deviid | 0 |
| IPv6.DstPrefix | fe80::/64 | equal | not-sent | 0 |
| IPv6.DstIID | - | ignore | deviid | 0 |
| UDP.SrcPort | 10883 | equal | not-sent | 0 |
| UDP.DstPort | 10883 | equal | not-sent | 0 |
| UDP.Length | - | ignore | compute | 0 |
| UDP.Checksum | - | ignore | compute | 0 |

**Compressed size:** 1 byte (Rule ID only)

### 4.8. CoAP Compression

### 4.4. RPL Options Compression

| CoAP Field | TV | MO | CDA |
|------------|----|----|-----|
| Version | 1 | equal | not-sent |
| Type | - | ignore | value-sent |
| TKL | - | ignore | value-sent |
| Code | - | ignore | value-sent |
| MID | - | ignore | value-sent |
| Token | - | ignore | value-sent |
| Options | - | ignore | value-sent |

**Mapping Table:**

| Index (2b) | Option Type | Use Case                     | RFC Reference                  |
|------------|-------------|------------------------------|--------------------------------|
| 0          | 0           | Pad1                         | RFC 6550 §6.7.1                |
| 1          | 1           | PadN                         | RFC 6550 §6.7.2                |
| 2          | 3           | Prefix Information (PIO)     | RFC 6550 §6.7.6 / RFC 4861 §4.6.2 |
| 3          | 2           | DAG Metric Container         | RFC 6550 §6.7.3                |

Example PIO FieldDescriptor (index 2, for RPL.Option.Type):

```python
# python/src/lichen/schc/rules.py style
FieldDescriptor(
    "RPL.Option.Type", 8, MO.MATCH_MAPPING, CDA.MAPPING_SENT,
    mapping=(0, 1, 3, 2),  # type -> compressed 2b index
)
```

Equivalent struct in `rust/lichen-schc/src/rules.rs` near RPL_DIO_FIELDS (lines 108-117). For PIO fields: Length=NotSent (value=4), PrefixLen=NotSent (64), Flags=MSB(common L/A/R), Lifetimes=MSB(0)/context, Prefix=LSB(64) or elided for DODAG-derived addresses. Full TLV parsing by upper layer post-decompression. See appendix-schc.md §A.1, rules.rs:108, rules.py:262 (_DIO_BASE_FIELDS), and test/vectors/schc_compression.json.

### 5.1. Parameters (current constants)

| Parameter                  | Value          | Reference                          |
|----------------------------|----------------|------------------------------------|
| m (window bits)            | 1              | constants.toml [schc.fragment]     |
| n (FCN bits)               | 6              | constants.toml [schc.fragment]     |
| t (DTAG bits)              | 0              | constants.toml [schc.fragment]     |
| Rule ID                    | 8 bits (0-7,255) | §4.1, lichen-core::constants.rs  |
| RCS                        | CRC-32, 4 bytes| constants.toml, fragment.rs:21     |
| retransmission_timeout_s   | 10s            | constants.toml, fragment.rs:24     |
| max_ack_requests           | 3              | constants.toml, fragment.rs:25     |
| inactivity_timeout_s       | 60s            | constants.toml, fragment.rs:26     |
| bitmap_msb_first           | true           | constants.toml                     |

### 5.2. Formats

Regular fragment: RuleID(8) + W(1) + FCN(6) + Tile

All-1: RuleID(8) + W(1) + 0b111111 + RCS(32) + Tile

ACK: RuleID(8) + control(8) + n(8) + bitmap-bytes (MSB-first, 1=missing)

### 5.3. Operation

Sender tiles with window_size from constants, uses FCN countdown per window, sends All-1 with RCS. Receiver uses bitmap for NACKs, verifies RCS on reassembly. Max ~12KB/datagram; larger use app chunking.

## 6. Implementation Considerations

### 6.1. Rule Set Version

Each firmware release defines a Rule Set Version (8-bit integer):

| Version | Meaning |
|---------|---------|
| 0 | Reserved |
| 1 | Initial LICHEN release |
| 2+ | Future versions |

### 6.2. DIO Advertisement

DODAG roots advertise Rule Set Version in DIO messages:

```
DIO Rule Version Option (Type TBD):
+--------+--------+--------+
| Type   | Length | Version|
+--------+--------+--------+
   1B       1B       1B
```

### 6.3. Version Compatibility

- Nodes SHOULD only join DODAG if Rule Set Version matches
- Mismatched nodes MAY communicate via Rule 255 (no compression)
- Version changes require coordinated firmware update

### 6.4. Adding Rules

When adding new rules:
1. Assign new Rule ID (do not reuse)
2. Increment Rule Set Version
3. Maintain old rules for one version cycle
4. Document changes in release notes

## 7. Implementation Considerations

### 7.1. Memory Requirements

| Component | RAM | Flash |
|-----------|-----|-------|
| Rule storage | ~500 bytes | ~2 KB |
| Fragmentation state | ~200 bytes per packet | - |
| Reassembly buffer | L2 MTU × 63 | - |

Total: ~1-2 KB RAM, ~2-3 KB Flash

### 6.2. Processing Requirements

- Compression: O(n) where n = number of rules (typically <10)
- Decompression: O(1) after rule lookup
- Fragmentation: O(1) per fragment
- Reassembly: O(fragments) for bitmap management

### 6.3. Existing Implementations

- **libschc:** C library, MIT license (recommended)
- **openschc:** Python reference, BSD license
- **Custom:** May be needed for constrained targets

## 7. Security Considerations

### 7.1. Compression Oracle Attacks

SCHC compression does not introduce compression oracle vulnerabilities
because rule selection is based on header fields, not encrypted content.

### 7.2. Fragmentation Attacks

**Resource exhaustion:** Attackers may send partial fragment sequences
to exhaust reassembly buffers. Mitigations:
- Inactivity timer (60s) to garbage collect stale state
- Limit concurrent reassembly sessions (e.g., 4 per neighbor)
- Authenticate fragments at link layer

**Fragment injection:** Attackers may inject fragments into ongoing
reassembly. Mitigations:
- RCS (CRC-32) validates complete packet
- Link-layer signatures authenticate sender

### 7.3. Rule Mismatch

Rule mismatch between sender and receiver causes packet loss or
corruption. Version advertisement in DIO prevents this for nodes
in the same DODAG.

## 8. IANA Considerations

This document requests no IANA allocations.

Note: SCHC Context ID registry entries (if any future versions request them) MUST be coordinated with the IETF LPWAN WG to ensure no conflicts with other LPWAN SCHC profiles (RFC 9011 and successors).

Future versions may request:
- DIO Option Type for Rule Version advertisement
- Rule ID registry for standardized rules

## 9. References

### 9.1. Normative References

[RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
           Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119,
           March 1997, <https://www.rfc-editor.org/info/rfc2119>.

[RFC8724]  Minaburo, A., Toutain, L., Gomez, C., Barthel, D., and JC.
           Zuniga, "SCHC: Static Context Header Compression and
           Fragmentation for LPWAN", RFC 8724, DOI 10.17487/RFC8724,
           April 2020, <https://www.rfc-editor.org/info/rfc8724>.

[RFC8824]  Minaburo, A., Toutain, L., and R. Andreasen, "Static Context
           Header Compression (SCHC) for the Constrained Application
           Protocol (CoAP)", RFC 8824, DOI 10.17487/RFC8824, June 2021,
           <https://www.rfc-editor.org/info/rfc8824>.

### 9.2. Informative References

[RFC6550]  Winter, T., Ed., Thubert, P., Ed., Brandt, A., Hui, J.,
           Kelsey, R., Levis, P., Pister, K., Struik, R., Vasseur, JP.,
           and R. Alexander, "RPL: IPv6 Routing Protocol for Low-Power
           and Lossy Networks", RFC 6550, DOI 10.17487/RFC6550, March 2012,
           <https://www.rfc-editor.org/info/rfc6550>.

Rule 0: Link-local IPv6 + UDP + CoAP (4-6 bytes compressed)
Rule 1: Global IPv6 + UDP + CoAP (41 bytes compressed)
Rule 2: ICMPv6 Echo (3 bytes compressed)
Rule 3: RPL DIO (8 bytes compressed)
Rule 4: RPL DAO (6 bytes compressed)
Rule 5: Link-local IPv6 + UDP + MQTT-SN (1 byte compressed)
Rule 255: No compression (fallback)
```

## Appendix B. Compression Examples

Worked examples of packet compression/decompression appear in `test/vectors/schc_compression.json` (and related schc*.json vectors).

## Authors' Address

LICHEN Project
<https://github.com/MarkAtwood/project-LICHEN>
