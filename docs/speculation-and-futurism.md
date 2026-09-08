<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Speculation and Futurism

Ideas, roadmap thinking, and forward-looking technical speculation that
don't belong in the normative spec. Nothing here is committed to — it's
a scratchpad for "what if" that survives across sessions.

---

## LICHEN 2: Full-Band Narrow-Chirp FHSS PHY

LICHEN 1 already has channel hopping — CCP-16 assigns per-peer channels via
`FNV1A32(EUI64 + epoch) mod N` across up to 64 channels (US915) at 125 kHz
bandwidth with 200 kHz spacing. CCP-12 synchronized hopping is spec'd but
optional. This gives channel *diversity* but not true FHSS: channels change
on epoch boundaries (hours/days), transmissions are one-at-a-time per node,
and only ~13 MHz of the 26 MHz band is used.

**LICHEN 2 vision:** Replace 125 kHz CSS channels with 500 Hz or 250 Hz
chirps spanning the full 902-928 MHz band.

**What changes from LICHEN 1 hopping:**
- Channel width: 125 kHz → 500/250 Hz (250-500× narrower)
- Channel count: 64 → ~52,000 (800× more)
- Hopping rate: per-epoch (hours) → per-packet or per-slot
- Parallelism: one TX at a time → ~50-100 simultaneous orthogonal TXs
- Band utilization: ~13 MHz partial → 26 MHz full
- Node capacity: ~20-50 → ~500-2000 before congestion

**Hardware path:**
- SX1262 already supports LR-FHSS (488/244 Hz channels) — but only LoRaWAN uplink
- LICHEN 2 contribution: bidirectional mesh over LR-FHSS
- Prototyping: SDR (USRP/PlutoSDR), or next-gen Semtech silicon
- Production: pre-certified module with LICHEN 2 firmware baked in

**What survives from LICHEN 1:** Everything above the link layer — IPv6, SCHC,
RPL, OSCORE, CoAP, DTN, node classes, Schnorr48 link signatures. CCP-16's
peer-keyed channel selection concept carries forward (now selecting from
52K channels instead of 64).

**What changes:** PHY (wide CSS → narrow FHSS chirps), MAC (CSMA/TDMA →
time-frequency grid with parallel TX), CCP becomes distributed spectrum
coordination (essentially a distributed SAS).

---

## Regulatory Roadmap (FCC, 902-928 MHz)

### Phase 1: Development (no cost, immediate)
Part 97 amateur radio. 1500W PEP, any modulation, no encryption (authentication
ok per recent FCC ruling). Licensed hams only, no commercial use. Good for
protocol development and range testing.

### Phase 2: Demos (free, 2-4 weeks lead time)
FCC Experimental License (Part 5, Form 442). Flexible power, specific geographic
areas and time periods. Conference demos and field R&D.

### Phase 3: Production ($10-15K per device, 3-6 months)
Part 15.247 FHSS device certification. 1W conducted + 6 dBi antenna. LICHEN 2
FHSS parameters (≥50 hop channels, ≤400ms dwell) fit within existing rules by
design. Pre-certified module firmware path: work with Semtech/RAK/Heltec to
certify LICHEN 2 firmware as part of module grant — other products inherit.

### Phase 4: Higher power (12-24 months, if needed)
FCC waiver petition. Argument: LICHEN 2 FHSS is demonstrably better-behaved
than what Part 15.247 assumes (narrow chirps = less per-channel interference,
strict per-freq duty cycle = self-policing, provable aggregate power budget).
Could justify higher EIRP than standard Part 15.247.

### Phase 5: Light licensing (years, requires lobbying)
CBRS-style approach. CCP as a distributed Spectrum Access System (SAS). Requires
FCC rulemaking. LICHEN 3 territory.

### Current state (LICHEN 1)
No new certification needed. T-Echo, RAK4631 SX1262 modules are already FCC
Part 15.247 certified. LICHEN 1 firmware operates within existing module grants.

---

## Full BPv7 (Bundle Protocol) Gateway Interop

RFC 9171 (BPv7) is the IETF DTN standard. LICHEN 1 borrows custody transfer
concepts but implements them as CoAP-layer behavior (see spec §10.2 and the
cwqh epic). Full BPv7 interop — a gateway translating between LICHEN CoAP DTN
messages and BPv7 bundles — is LICHEN 2 scope. Use case: connecting a LICHEN
mesh to space DTN networks, military DTN infrastructure, or academic DTN testbeds.

---

## CCP as Distributed Spectrum Coordination

LICHEN 1's CCP (Coordinated Capacity Planning) handles TDMA slot allocation
and channel hopping within a single 125 kHz channel. LICHEN 2's full-band FHSS
turns CCP into a distributed spectrum coordinator:

- Time-frequency grid: each slot is (time, frequency) not just (time)
- Neighbor-aware channel assignment: nodes avoid frequencies used by neighbors
- Aggregate interference budgeting: CCP tracks total band utilization and
  throttles when approaching regulatory limits
- This is functionally a mesh-native, decentralized SAS (Spectrum Access System)

The existing CCP wire format and negotiation protocol may need major revision
or replacement. The CCP *concept* (nodes negotiate capacity cooperatively)
carries forward.

---

## Multi-Band Operation

LICHEN nodes could operate on multiple bands simultaneously:

- **900 MHz:** Long range, primary mesh backbone
- **2.4 GHz:** Short range, high bandwidth (LoRa 2.4 GHz or BLE mesh)
- **Sub-GHz regional:** 868 MHz (EU), 433 MHz (Asia), etc.

A multi-band node uses 900 MHz for mesh control plane (routing, CCP,
announcements) and 2.4 GHz for bulk data transfer when neighbors are close.
This is analogous to how Wi-Fi uses 2.4 GHz for coverage and 5 GHz for speed.

Hardware: already possible with dual-radio boards (SX1262 + SX1280, or
SX1262 + nRF52840 BLE).

---

## Mesh-Aware Compression Beyond SCHC

LICHEN 1 uses static SCHC rules (shared context = shared rule set). Future
work could explore:

- **Learned compression:** Nodes that exchange many messages learn per-peer
  header patterns and negotiate custom SCHC rules dynamically
- **Semantic compression:** CoAP payloads (SenML, CBOR) could be delta-encoded
  against previous values (e.g., position = delta from last position, not
  absolute coordinates)
- **Network coding:** Instead of forwarding individual packets, relay nodes
  combine packets with XOR coding — receivers reconstruct from any sufficient
  subset. This is especially powerful for broadcast/multicast.

---

## Planetary-Scale DTN

If LICHEN meshes exist in multiple cities, the DTN store-and-forward system
could bridge them via:

- **Internet backhaul:** Gateway nodes in each mesh forward custody messages
  via Yggdrasil overlay. Already possible with LICHEN 1 gateway + DTN store.
- **Sneakernet:** A node physically carried between meshes delivers stored
  messages on arrival. The DTN store + custody transfer handles this natively.
- **Satellite:** A LEO satellite link (Iridium, Starlink) as a high-latency
  backhaul for custody messages. The satellite is just another hop in the
  custody chain.

The addressing (Yggdrasil /128) already works globally. The routing doesn't —
inter-mesh routing requires a discovery mechanism (DNS-like, or a global
custody directory).

---

## Post-Quantum Link Security

LICHEN 1 uses Ed25519 (Schnorr48 truncated signatures) for link security.
Ed25519 is not quantum-resistant. Options for LICHEN 2+:

- **ML-DSA (Dilithium):** NIST PQC standard. Signatures are 2-3 KB — far too
  large for 255-byte LoRa frames. Not viable for link-layer per-packet signing.
- **SPHINCS+:** Hash-based, ~7-40 KB signatures. Even worse.
- **SQIsign:** Isogeny-based, ~200 byte signatures. Promising but immature
  and computationally expensive.
- **Hybrid approach:** Use Ed25519 for link layer (packet-level, must be small),
  use ML-KEM/ML-DSA for session establishment (EDHOC key exchange, happens
  once per session, can tolerate larger messages).
- **Pragmatic assessment:** A quantum computer that can break Ed25519 on
  captured LoRa packets is not a near-term threat for the LICHEN use case
  (hiking, SAR, events). Monitor SQIsign maturity. Revisit when signature
  sizes reach ~100 bytes.

---

## Energy Harvesting Mesh Nodes

Solar-powered relay nodes are already in the node class model. Beyond solar:

- **Piezoelectric:** Trail vibration, foot traffic
- **Thermoelectric:** Temperature differential (underground cable conduit,
  industrial pipe surface)
- **RF harvesting:** Ambient RF from cell towers / broadcast — unlikely to
  provide enough for LoRa TX, but could trickle-charge a supercap for
  infrequent beacons

A mesh-aware power management protocol: nodes announce their energy budget
in CCP. Neighbors route around energy-constrained nodes when alternatives
exist. Relay nodes reduce TX power or duty cycle when battery/harvester is
low, and announce the change so the mesh adapts.

---

## Conference / Event Mode

The 500-node conference demo scenario has unique properties:

- **Dense deployment:** All nodes within a few hundred meters
- **Short duration:** Hours, not days
- **Known attendee count:** Pre-registered, pre-provisioned
- **Disposable keys:** TOFU is fine — no long-term trust needed
- **Content is ephemeral:** Chat, positions, and status have no long-term value

Optimizations for this mode:
- Lower SF (SF7) for short range + higher throughput
- Aggressive TDMA with tight slot assignment (CCP knows the exact node count)
- Multicast-optimized routing (broadcast position updates, not unicast)
- Pre-loaded channel plans (no negotiation phase)
- "Swag mode" firmware: boot → join mesh → show status on e-ink → done

---

## Identity Verification via Stripe / ID.me / CLEAR

LICHEN CA attestation doesn't require a physical passport reader booth.
Third-party identity verification services handle the PII; the LICHEN
cert carries only the signed attestation result — zero PII on the node.

**Services:**
- **Stripe Identity:** Government ID via photo + selfie. $1.50/verification.
  Self-service API. Returns pass/fail + metadata. Best for basic "is a real
  human with a government ID" verification.
- **ID.me:** Government ID + group affiliation verification. Military (active,
  veteran, dependent), first responder, nurse, teacher, student — verified
  against state/federal databases. OAuth flow. Best for professional trust
  ("this person is a verified first responder") without LICHEN ever seeing
  their name or credentials.
- **CLEAR Verified:** Biometric identity (iris + fingerprint + face) plus a
  digital ID flow similar to ID.me. Enterprise partnership model. Best for
  high-security deployments.

**The cert contains NO PII:**
```
Subject: Ed25519 key a3b2c1d4...
Issuer: LICHEN Community Root CA
Attributes:
  verification_service: id.me
  verification_date: 2027-03-15
  verified_groups: [first_responder]
  verified_level: government_id
```

**Remote verification changes the game.** No booth needed. Buy a radio →
go to `verify.lichen.network` → complete Stripe/ID.me/CLEAR flow → signed
cert downloaded to node via USB/BLE. Works from anywhere.

**Growth hack:** Subsidize first-responder and military group verification
(free via ID.me). SAR teams adopt at zero cost. Their use generates the
credibility stories that sell enterprise accounts.

**The DEF CON booth offers all three paths:**
1. Physical passport/eID/CAC reader (theatrical, fun, free)
2. Stripe Identity QR code (scan, verify on phone, $15)
3. ID.me/CLEAR OAuth (richest attributes — group verification)

---

## P25-Style IETF Network

What if we built something like P25 (public safety land mobile radio) but
used IETF specs everywhere instead of proprietary codecs and protocols?
If the link is fast enough, LICHEN wouldn't need to be so aggressive about
header compression. Encryption and federation always on, autoconfiguring.
Essentially: LICHEN's protocol stack on a higher-bandwidth radio.

---

## Burning Man 2028+ (5000+ Nodes)

At Burning Man scale (5000+ nodes, multi-square-mile playa), the mesh
architecture shifts:

- LOADng + gateways become the primary routing strategy (spec already
  defines mesh algorithm selector)
- Pre-sell to camp organizers: "$99/pair, preprogrammed with your camp
  name and your people's burner names, shipping or pickup on playa"
- Rangers SOS deduplication: multiple SOSs within 25 meters and 5 minutes
  are the same incident
- Post-event: nodes go home with attendees, seeding local meshes everywhere

---

## DEF CON / Conference Merchandise Model

Conference radios as collectible tech merch:

- Add $99 to conference enrollment, pick up at booth with badge
- Special conference-branded firmware and certificate stamped into the radio
- Story: "DC28 radios working on a flight home, 6 people chatting the
  whole way back"
- DC29 vision: passport/ID reader integration for certificate stamping
- Sell radios in pairs at $99/pair, spec printed as 300-page PoD
  paperback for $49

---

## Smart Home / IoT Cottage Industry

If LICHEN gets IPSO device ontology support (which it already defines via
SenML profiles):

- "A fast growing cottage industry of sensor manufacturers for the Home
  Assistant / smart home crowd. No hub. No special integration."
- LICHEN carries every lab instrument reading that fits in its bandwidth
- Grad students at any university discover the protocol already defines
  their sensor data formats
- Eventually: Tuya offers smart home devices in LICHEN SKUs
- Explicit non-goal: sleepy mode. "Use Matter or Zigbee if you want
  sleepy." LICHEN nodes are always-on mesh participants.

---

## "I Like You" — Mesh Social / Dating App

A mutual-match social app running on the mesh:

- Nodes exchange anonymized interest signals
- Mutual match triggers: node IDs revealed, DM channel opens
- No server, no internet, no data collection — runs entirely on mesh
- Privacy: only mutual matches learn each other's identity
- Conference scenario: meet people at the event, not through a phone app
- Inevitable media cycle: "worst thing ever" article → usage skyrockets

---

## 911 / SOS Gateway Integration

Gateway operators with a DID (phone number) enrollment can bridge SOS
alerts to 911/SIP:

- Mesh SOS alert reaches gateway → gateway places VoIP/SIP call to PSAP
- Voice bridge for two-way communication between mesh and dispatcher
- Requires careful design: false positives, liability, PSAP professional
  acceptance
- Target: article in PSAP professional magazine about the integration

---

## The REI Box (2032)

Someone sells a ruggedized unit at REI that combines:
- LICHEN radio (mesh comms)
- USB battery pack
- SPOT satellite transmitter (backup SOS)
- Avalanche rescue beacon

One box, four safety systems. The LICHEN radio handles group
coordination; SPOT handles "nobody can hear me"; the beacon handles
burial location.

---

## Semtech Goes to the FCC (2029)

If LICHEN saturates LoRa spectrum in populated areas, Semtech has
commercial incentive to petition FCC/Ofcom for wider LoRa allocations.
"We want to widen LoRa. A lot." LICHEN's success becomes Semtech's
lobbying ammunition. If expanded to 10 MHz, the frequency hopping
algorithm adapts automatically (CCP already handles channel plans).

---

## Market Disruption Timeline

Speculative press/analyst narrative:

- **2028:** Economist notes LICHEN development cost was <0.5% of coding
  cost for competitive systems (Meshtastic, MeshCore, LoRaWAN)
- **2029:** Economic analysis of consumer surplus from explosive growth
- **2030:** Zigbee and Matter device displacement by LICHEN alternatives
  (LICHEN uses IPSO ontology that Matter rejected due to Zigbee firmware
  conflicts)
- **2036:** Recognition as "the most impactful comms tech since the
  smartphone"

---

## "Never Talk to the Press"

Policy: the documentation is the documentation. The spec is public. The
code is public. Media can read it. No interviews, no exclusive access,
no quotes. If someone writes an unfair article, the project responds
by shipping features, not press releases.

---

*This document is a living scratchpad. Add freely. Remove when ideas are
promoted to spec or killed by analysis.*
