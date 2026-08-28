<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# LICHEN: Standards-Based LoRa IPv6 Mesh Networking

*Technical project description for grant applications — 500-node real-world deployment*

## What LICHEN is

LICHEN (**L**oRa **I**Pv6 **C**oAP **H**ybrid **E**xtended **N**etwork) is an
open-source, standards-based mesh networking protocol that brings real Internet
Protocol networking to low-power radio hardware. It answers a simple question:
*what would Meshtastic be if it were built on the Internet's own architecture?*

Where proprietary meshes use vendor-specific addressing and opaque protocols,
LICHEN runs the IETF stack end to end on $45 LoRa radios:

| Layer | Standard |
|---|---|
| Application | CoAP (RFC 7252), SenML (RFC 8428), MQTT-SN |
| Security | OSCORE (RFC 8613), EDHOC (RFC 9528), 48-byte Schnorr link signatures |
| Network | Native IPv6 — key-derived addresses, no central authority |
| Adaptation | 6LoWPAN (RFC 4944) + SCHC header compression (RFC 8724) |
| Routing | RPL (RFC 6550) non-storing DODAG |
| Physical | LoRa CSS on unlicensed ISM bands, Meshtastic-compatible hardware |

Every device runs one of three independent implementations — embedded firmware
(Zephyr RTOS, C), a Linux gateway stack (Rust), and a Python reference/oracle —
all validated against a shared corpus of bit-exact test vectors. Cross-language
conformance is enforced in continuous integration, not asserted in a document.

## Why it matters

Community mesh networking today is locked into proprietary designs: fixed
protocols, closed governance, no path to standardization, and no interoperability
beyond the vendor's own apps. LICHEN demonstrates the alternative: the same cheap
hardware, but with globally meaningful IPv6 addresses derived from device keys,
IETF-standardized compression and security, and a protocol documented well enough
to submit as Internet-Drafts.

Open standards matter here for the same reason they matter everywhere else:
they let incompatible communities interoperate, they outlive any single
maintainer, and they invite scrutiny. All of LICHEN's specifications are
published under CC-BY-4.0 and all code under GPL-3.0.

## Current state

- Three independent implementations (C/Zephyr, Rust, Python) sharing one
  conformance suite; protocol spec complete across 18 chapters plus
  Internet-Draft-style annexes.
- Working link layer (TDMA, CSMA, relay, replay protection), RPL routing,
  SCHC compression, OSCORE/EDHOC security, CoAP services (messaging,
  position, SOS, presence, check-in, waypoints).
- Hardware bring-up in progress on Seeed T-Echo (nRF52840 + LR1110) with
  Renode-based CI validation; RAK2287 concentrator gateway integration scoped.
- Simulator infrastructure (discrete-event, mobility models, Renode) used for
  protocol validation at density.

## The proposed deployment

A 500-node mesh deployed across three major hacker conferences (CCC, DEFCON,
and one European spring event) — the first real-world scale stress test of a
standards-based LoRa IPv6 mesh at conference densities (50+ nodes/km²).

Attendees receive pre-flashed nodes that auto-join the mesh: position sharing,
encrypted messaging, SOS, and internet routing through multi-channel border
routers. The network is deliberately operated at the edge of congestion to
generate genuinely useful engineering data.

Every artifact is public: firmware, gateway code, simulator, test vectors,
deployment logs, and a post-conference performance report. Hardware is resold
after each event, recovering the majority of the cost and seeding future runs.

## Outcomes

1. A proven, documented, reproducible open mesh stack others can deploy.
2. Public performance datasets for a protocol class that has none.
3. IETF Internet-Draft submissions for the protocol's novel elements.
4. A template (bills of materials, flash jigs, logistics runbook) any community
   can reuse for its own deployment.
