<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Speculation and Futurism

Ideas, roadmap thinking, and forward-looking technical speculation that
don't belong in the normative spec. Nothing here is committed to — it's
a scratchpad for "what if" that survives across sessions.

**RF/CCP status: EXPERIMENTAL.** These proposals inform future work; they do
not activate a PHY or regional channel plan. [CCP Revision 2](../spec/02b-ccp-receiver-aware.md)
owns the adopted receiver-aware policy, but its wire activation remains gated.
It preserves baseline SCHC compression, fragmentation, and security. The
[CCP conformance guide](ccp-conformance.md) specifies required evidence, not
completed qualification of the experiments here.

---

## LICHEN 2: Full-Band Narrow-Chirp FHSS PHY

Historical CCP-16 describes receiver-keyed home channels; CCP-12 describes
synchronized hopping. Home-channel assignment is not itself a compliant FHSS
sequence, and a single radio's one-at-a-time operation does not distinguish
FHSS from other modes. CCP-2 now makes the receiver's authenticated channel,
generation, profile, and availability authoritative; legacy formulas and
examples are not proof of deployed receiver-aware scheduling.

The current [Python US915 list](../python/src/lichen/channel_plan.py) uses
centers `902.3 + 0.2*i` MHz for `i=0..63`. Extending the same grid to
`i=0..127` is an **EXPERIMENTAL candidate**, not a configuration-only change:

| Grid | Centers (MHz) | Center span | Nominal 125 kHz outer envelope | Sum of nominal widths |
|------|---------------|-------------|-------------------------------|-----------------------|
| Current 64-entry Python list | 902.3-914.9 | 12.6 MHz | 902.2375-914.9625 MHz (12.725 MHz) | 8 MHz |
| Candidate 128-entry list | 902.3-927.7 | 25.4 MHz | 902.2375-927.7625 MHz (25.525 MHz) | 16 MHz |

Neither envelope is a measured occupied bandwidth or a contiguous receive
passband. The 128-entry grid is not a maximum channel count or instantaneous
26 MHz reception. Legacy three-bit `rx_channel` and u32 beacon masks cannot
represent it; C/Zephyr's `LICHEN_N_CHANNELS` defaults to 8 with Kconfig range
1..16. CCP-2 specifies wider representation, but exact wire encoding,
implementation, board RF coverage, and authorization still need qualification.
No existing plan ID/version is extended or newly enabled here.

**LICHEN 2 vision (EXPERIMENTAL):** Explore 500 Hz or 250 Hz CSS chirps and
fast hopping across the 902-928 MHz allocation, rather than 125 kHz CSS.

**What could change from LICHEN 1 hopping:**
- Channel width: 125 kHz to hypothetical 500/250 Hz (250-500 times narrower)
- Channel count: about 52,000 abstract 500 Hz bins in 26 MHz, not demonstrated
  orthogonal channels or a legal hopset; spacing and guard requirements matter
- Hopping rate: per-fragment or per-slot sequences, distinct from home channels
- Parallelism: a research target of 50-100 simultaneous links, requiring actual
  independent receiver resources and interference measurements, not a multiplier
- Band utilization: investigate the upper half too, without claiming full-band RX
- Node capacity: 500-2000 nodes is a scenario to test, not an established increase
  from a universal 20-50-node baseline

**Hardware path:**
- SX1262 supports ordinary LoRa RX/TX at discrete bandwidths from about 7.8 to
  500 kHz and silicon tuning from 150 to 960 MHz; board RF paths, driver support,
  and operating authorization are separate ([SX1261/2 datasheet](https://www.elecrow.com/download/product/CRT01268N/SX1261-2_V2_1_Datasheet.pdf)).
- LR-FHSS uses GMSK, not 500 Hz CSS chirps. SX1262 LR-FHSS support is TX-only;
  that limitation does not make its ordinary LoRa modem TX-only.
- Generic SX1302/SX1303 concentrator capability does not establish LR-FHSS RX.
  [Semtech's clarification](https://github.com/Lora-net/sx1302_hal/issues/110#issuecomment-1630754437)
  identifies a specific SX1301-plus-FPGA/DSP gateway, not an SX1302 MCU upgrade.
- Bidirectional LR-FHSS mesh and a new narrow-CSS PHY are separate experiments.
  Prototyping could use a suitable SDR (USRP/PlutoSDR) or future receiver silicon;
  RF coverage, demodulation, and simultaneous-channel capacity need validation.
- Production goal: a module whose grant covers the actual firmware/profile and
  host integration, not automatic permission inherited from a pre-certified part.

**What should survive from LICHEN 1:** The goal is to retain IPv6, SCHC, RPL,
OSCORE, CoAP, DTN, node classes, and Schnorr48 link signatures. Receiver-keyed
rendezvous remains useful, but neither legacy nor CCP-2 encodings imply support
for 52K channels. Any changed framing/authentication needs separate review.

**What might change:** PHY and MAC could use narrower signals and a
time-frequency grid with independent links. CCP could support distributed
spectrum coordination; the SAS analogy is conceptual, not regulatory authority.

### Narrower Ordinary LoRa (EXPERIMENTAL)

Trying 31.25, 15.625, or 7.8125 kHz ordinary LoRa is distinct from both LR-FHSS
and the hypothetical 500 Hz PHY. Narrowing bandwidth lengthens symbols and
preambles; LDRO and coding overhead prevent simple application-rate scaling.
The following independent Semtech-formula calculations use SF10, CR 4/5,
eight preamble symbols, explicit header, and CRC. Lengths are **modem payload
bytes**, including link framing, not application bytes; times are seconds.

| BW (Hz) | LDRO (`DE`) | Preamble alone | 10 bytes | 62 bytes | 255 bytes |
|---------|-------------|----------------|----------|----------|-----------|
| 125000 | 0 | 0.100352 | 0.288768 | 0.698368 | 2.295808 |
| 31250 | 1 | 0.401408 | 1.155072 | 3.284992 | 11.149312 |
| 15625 | 1 | 0.802816 | 2.310144 | 6.569984 | 22.298624 |
| 7812.5 | 1 | 1.605632 | 4.620288 | 13.139968 | 44.597248 |

Source: [Semtech SX1261/2 airtime and LDRO definitions](https://cdn.sparkfun.com/assets/6/b/5/1/4/SX1262_datasheet.pdf),
Sections 6.1.1.4 and 6.1.4; the [conformance guide](ccp-conformance.md#independent-oracles)
records the formula. These are arithmetic, not RF measurements, and exclude
retuning, guards, and any outer FEC. At 31.25 kHz even this preamble exceeds
400 ms, so short application data does not make it ordinary narrow-FHSS eligible.

The current Zephyr LoRa API exposes only 125/250/500 kHz enums. An exact
SKU/board/driver experiment would need verified narrowband support, frequency
error and packet-time drift, acquisition, settling, IRQ timing, and CPU budgets.
Having a TCXO does not guarantee its accuracy over temperature or the combined
transmitter/receiver error budget. This does not alter baseline profile `0x01`.

---

## Regulatory Roadmap (FCC, 902-928 MHz)

**EXPERIMENTAL planning only:** Costs and timelines below are rough estimates,
not quotes, promises, or permission to transmit. Operating-basis review and RF
measurements are distinct from software conformance.

### Phase 1: Development (amateur experiment, qualification first)
Part 97 could support eligible noncommercial protocol development and range
testing, not arbitrary modulation/traffic at 1500 W. SS emissions have a
**10 W PEP maximum** under [97.313(j)](https://www.ecfr.gov/current/title-47/part-97/section-97.313),
and paragraph (a) requires minimum necessary power. Station/operator licensing
and location eligibility apply; see [Part 97](https://www.ecfr.gov/current/title-47/part-97).
The hopset needs the interference and geographic restrictions of
[97.303](https://www.ecfr.gov/current/title-47/part-97/section-97.303), including
the 33 cm restrictions, not just an amateur license and in-band centers.

An experiment needs an assigned-callsign identification method satisfying
[97.119](https://www.ecfr.gov/current/title-47/part-97/section-97.119); an EUI-64
or key-derived IPv6 address is not a callsign substitute. Station control under
[97.109](https://www.ecfr.gov/current/title-47/part-97/section-97.109) and any
automatic-data operation under [97.221](https://www.ecfr.gov/current/title-47/part-97/section-97.221)
need review against the actual SS/data emission classification and
[97.311](https://www.ecfr.gov/current/title-47/part-97/section-97.311).

Authentication of readable traffic is distinct from confidentiality. Ordinary
OSCORE confidentiality is not automatically permitted by
[97.113(a)(4)](https://www.ecfr.gov/current/title-47/part-97/section-97.113) or
97.311. A human-approved, explicitly separate experimental profile and traffic
policy would be needed; this is not permission to automatically disable
production security. Neither no-cost nor immediate operation is assured.

### Phase 2: Demos (experimental authorization)
An FCC Experimental License ([Part 5](https://www.ecfr.gov/current/title-47/part-5),
Form 442 as applicable) is a possible path for conference demos and field R&D.
Power, emissions, location, and duration depend on the actual authorization.
The earlier 2-4 week lead time is an unverified planning estimate; approval
and fee-free operation are not assured.

### Phase 3: Production (estimated $10-15K per design, 3-6 months)
These are preliminary certification-budget guesses, not lab quotes. Under
[15.247(a)(1)](https://www.ecfr.gov/current/title-47/part-15/section-15.247),
ordinary 902-928 MHz FHSS with **measured 20 dB bandwidth below 250 kHz** needs
at least 50 hopping frequencies, carrier spacing of at least the greater of
25 kHz and that measured bandwidth, pseudorandom ordering, equal average use
by each transmitter, and receivers with matching bandwidths hopping in
synchronization. A 500 Hz signal does not permit 500 Hz carrier spacing under
this rule.

Each transmitter's occupancy limit is an aggregate **0.4 seconds per physical
frequency in 20 seconds**, not a per-packet allowance. Headers, control traffic,
parity, forwarding, and retries all count. Two 300 ms transmissions by that
transmitter on one frequency within that window exceed it; hashing fragments
across 128 indices does not prove compliant use. Fixed rendezvous/control traffic
needs particular care.
Section 15.247(h) restricts coordination between hopping systems for the express
purpose of avoiding simultaneous frequency occupancy; CCP coordination needs
operating-basis review, not an assumption that all distributed scheduling is legal.

Standalone DTS under 15.247(a)(2) instead needs at least **500 kHz measured
6 dB bandwidth**, plus its other limits. Nominal 125 kHz CSS is not automatically
eligible. Hybrid operation under 15.247(f) has distinct qualification/test
conditions; neither hopping CSS nor the word "Hybrid" in LICHEN proves them.
The 1 W conducted ceiling applies to qualifying 50-or-more-channel US FHSS,
not every configuration. Antenna gain above 6 dBi triggers the applicable
conducted-power reduction under (b)(4); approved antennas and grant limits also
apply. There is no blanket "1 W plus 6 dBi maximum" permission.

Possible module path: work with the actual grantee and test/certification body
to cover LICHEN firmware and host integration. Reuse is conditional on the
grant and integration requirements, not automatic inheritance by other products.

### Phase 4: Higher power (speculative 12-24 month estimate, if needed)
An FCC waiver petition could investigate whether narrower signals and enforced
per-frequency budgets justify higher EIRP. Better coexistence and aggregate
interference behavior would need evidence; they are not established properties
of LICHEN 2. Neither the waiver nor its timeline is promised.

### Phase 5: Light licensing (speculative years, requires lobbying)
A CBRS-style approach with CCP as a distributed SAS is a research/policy idea,
not an authorized SAS. It would require FCC action and potentially rulemaking.
LICHEN 3 territory, with no committed outcome or schedule.

### Current state (LICHEN 1)
Grant coverage has not been established here for current LICHEN firmware.
For each T-Echo, RAK4631, or other board, review the actual FCC ID and grants,
module/board BOM, approved antennas, RF settings, and firmware behavior.
Assess changes under [2.1043](https://www.ecfr.gov/current/title-47/part-2/section-2.1043)
with the grantee/TCB as applicable. Software-only does not mean RF-neutral;
neither a new certification requirement nor a no-new-certification exemption
can be assumed from the chip name or an FCC logo.

---

## The 900 MHz Physics Ceiling

**EXPERIMENTAL thought experiment, not a calculated physics ceiling.** The
earlier suggestion of 0.1% utilization has no supporting measurements or
capacity model here. Could narrower signals and better coordination make more
use of the band? The 100-lane-highway/traffic-lights analogy motivates that
question; it does not establish a capacity multiplier or explain vendor choices.

**Full 26 MHz band, narrow chirps, cooperative coordination:**

Dividing 26 MHz into 250 Hz bins gives 104,000 abstract bins, not demonstrated
orthogonal channels or a legal hopset. LR-FHSS's GMSK waveform does not validate
250 Hz CSS, and ordinary Part 15 FHSS still has the carrier-spacing rules above.
The suggested 500-1000 simultaneous links is an unvalidated stress-test target,
requiring independent receive resources, a link/interference model, and an
authorized coordination scheme. A 10-20 km open-terrain hop is likewise a
range target needing a link budget and measurements. A hypothetical 1 W/6 dBi
operating point is subject to the actual grant and power/antenna rules, not
permission or evidence that this range is achievable.

**What future receiver silicon could explore:**

- Endpoint multichannel reception inspired by concentrators, targeting 50+
  simultaneous narrow channels; actual passbands and demodulators need design
- Per-packet FHSS tracking multiple peers with independent per-link timing and
  sufficient RX resources, not one single-channel receiver following all sources
- Adaptive channel width for a range/throughput trade, negotiated per-link in
  a separate qualified profile, not an automatic change to CCP-2 profile `0x01`
- Full-duplex or near-duplex within one band, requiring RF isolation/filtering
  and self-interference engineering; frequency separation alone does not supply it

**Aggregate capacity with cooperative spectrum sharing:**

A narrow-FHSS/cooperative-sharing experiment could investigate these speculative
scenario targets; none is a derived or measured capacity, separately or together:

- ~5,000-10,000 active nodes per square kilometer, with an explicit traffic load
- ~100-500 simultaneous transmissions, with actual receiver resources specified
- ~500 kbps - 1 Mbps aggregate mesh goodput (shared, not per-node), after framing,
  coding/LDRO, control, retransmission, and multihop forwarding costs
- 10+ km individual links where measured link margins and legal power permit

Evaluation needs topology, antenna heights, propagation, correlated interference,
receiver contention, latency/loss, and per-transmitter regulatory accounting.
Neither bin count nor aggregate network averages establish these outcomes.

**What regulators would need to see:**

A coexistence study would need to measure interference under comparable load,
goodput, power, and receiver conditions. Narrower signals alone do not prove
less interference when airtime or traffic changes. Per-frequency accounting can
constrain conforming nodes; it neither forces other nodes to cooperate nor turns
CCP into an authorized SAS. Section 15.247(h) coordination restrictions remain a
review gate. Evidence might support a higher-EIRP or altered-occupancy petition,
but neither favorable findings nor the FCC's response is established here.

Competitive pressure could encourage Semtech or other vendors to explore such
receivers. There is no sourced vendor roadmap or evidence of deliberate
withholding here; this remains a market hypothesis, not an explanation of motives.

**Demo path: GNU Radio + Net44 + Sovereign Tech Fund**

Prototype a candidate LICHEN 2 PHY in GNU Radio on a suitable USRP/PlutoSDR
configuration, then test bidirectional hopping and the capacity hypotheses;
the exact SDR passband and processing capacity need validation too. A possible
Net44/AMPRNet allocation could support an IPv4 backhaul carrying the same
upstream Yggdrasil IPv6 identities, subject to allocation/traffic eligibility.
It is not an assumption that the historical 44.0.0.0/8 is wholly available.

Sovereign Tech Fund (STF) is a possible funding avenue for the open-source
infrastructure work, not an endorsement or committed budget. EU/ETSI operation
needs its own applicable sub-band/access rules and equipment-conformity review;
duty-cycle accounting alone is not a finding that LICHEN is compliant.
Seek the applicable experimental authorization **before** on-air demos. Their
measured results, including failures, could inform a Phase 4 waiver petition;
they do not automatically obtain a Phase 2 license or activate a new RF plan.

---

## Full BPv7 (Bundle Protocol) Gateway Interop

RFC 9171 (BPv7) is the IETF DTN standard. LICHEN 1 borrows custody transfer
concepts but implements them as CoAP-layer behavior (see spec §10.2 and the
cwqh epic). Full BPv7 interop — a gateway translating between LICHEN CoAP DTN
messages and BPv7 bundles — is LICHEN 2 scope. Use case: connecting a LICHEN
mesh to space DTN networks, military DTN infrastructure, or academic DTN testbeds.

---

## CCP as Distributed Spectrum Coordination

CCP coordinates radio opportunities across a channel plan, not hopping
"within" one 125 kHz channel. [CCP-2](../spec/02b-ccp-receiver-aware.md)
separates receiver rendezvous, directional link robustness, congestion admission,
and control-traffic scaling. It accounts for actual receiver resources and
complete operations; it does not enable the full-band FHSS experiments here.
An **EXPERIMENTAL** extension could investigate distributed spectrum coordination:

- Time-frequency grid: each slot is (time, frequency) not just (time)
- Neighbor-aware channel assignment: respect receiver commitments and investigate
  interference avoidance, subject to the 15.247(h) coordination restriction
- Interference budgeting: measure shared band use while enforcing each applicable
  transmitter/frequency limit; network averages cannot substitute for those limits
- A mesh-native, decentralized SAS is an analogy, not equivalent authority

CCP-2's accepted policy already gates activation on an exact versioned wire
contract and independent vectors. Experimental hopping would need its own
explicit profile, receiver/hop-time contract, and qualification; spare legacy
bits or a larger frequency list are not activation. The CCP *concept* (nodes
negotiate capacity cooperatively) carries forward. See the
[conformance and microfragment gates](ccp-conformance.md#microfragment-experiment-gate).

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

## LICHEN 1.5: Software FHSS via Microfragmentation

**Status: EXPERIMENTAL, not a CCP-2 activation or baseline change.**
Software hopping between ordinary LoRa packets is a possible intermediate
step toward LICHEN 2, using existing SX1262-class hardware rather than assuming
a new narrow-chirp or wideband receiver. Board, driver, timing, and equipment
authorization feasibility remain to be demonstrated.

**The insight:** SX1262 can receive ordinary LoRa and retune between packets,
even though its LR-FHSS support is transmit-only. Per-fragment software hopping
could spread a larger encoded block over frequencies and recover partial loss
with an outer erasure code. It does not require LR-FHSS reception, nor does a
generic SX1302/SX1303 establish that capability. A 300 ms hop is an experiment
target, not proof that tuning/acquisition or authenticated framing fits.

**Candidate design:**
1. Sender and receiver share a **per-link sequence and time context**, bound to
   identities, block ID, plan/version, profile, and schedule generation. A
   deterministic sequence, possibly FNV-based like historical CCP-16, needs a
   specified preimage and usage analysis; a hash alone proves neither legal
   pseudorandom/equal-average use nor receiver availability.
2. First fragment ("header") uses the receiver's authenticated rendezvous during
   a committed receive opportunity. It describes block length, fragment count,
   coding, and hop timing. Header loss, repetition, and reacquisition need an
   explicit recovery design; all such emissions consume airtime and occupancy.
3. Data and parity fragments follow the sequence. **Outer FEC spans fragment
   erasures**: ordinary LoRa coding-rate FEC works within each PHY packet and
   cannot reconstruct missing packets. Neither an outer code nor rate is selected.
4. Receiver advances by the shared time/sequence phase even when a fragment is
   missing, collects a sufficient coded subset, and authenticates the recovered
   whole block before delivery. Fragment indices, lengths, identity/replay
   binding, duplicate handling, bounded reassembly/CPU, expiry, and abort behavior
   need design, including resistance to injected fragments consuming resources.

**What this could get:**
- Per-fragment frequency diversity on qualified T-Echo / RAK4631 configurations
- Burst/collision resilience: a damaged subset need not destroy the block if
  the selected erasure code can recover it; correlated loss can still defeat it
- A candidate FHSS operating profile, not compliance from "128 channels and
  300 ms" alone; the measured-bandwidth, spacing, synchronization, equal-use,
  aggregate occupancy, coordination, and grant checks above still apply

**300 ms frame-fit check:** For BW 125 kHz, CR 4/5, preamble 8, explicit header,
CRC, and applicable LDRO, the Semtech formula gives these upper bounds. They
include each packet's PHY overhead in its airtime but **do not reserve time for
retuning, extra acquisition, responses, or guards** in the 300 ms opportunity.

| SF | LDRO | Maximum complete modem payload within 300 ms |
|----|------|---------------------------------------------|
| 7 | off | 187 bytes |
| 8 | off | 98 bytes |
| 9 | off | 44 bytes |
| 10 | off | 14 bytes |
| 11 | on | Even an empty packet cannot fit |
| 12 | on | Even an empty packet cannot fit |

Current signed broadcast framing plus dispatch already needs **62 bytes**;
extended framing needs **70 bytes**, before a microfragment header/body.
Thus 300 ms SF10 fragments are impossible with current authentication, even
with no application data. A 130-byte modem payload fits SF7's RF-only bound,
not 130 useful bytes at SF10; even SF7 leaves at most 125 bytes after the
62-byte overhead, before microfragment metadata. Authentication amortization
or replacement would require separate security review and independent vectors,
not weakening baseline signatures or changing audited OSCORE internals here.

**What this doesn't get:**
- Parallel reception at one SX1262: its single half-duplex RX chain can follow
  only one source at a time. Independent links might coexist, but many sources
  addressing the same receiver still need non-overlapping receive commitments.
- Network-wide lockstep hopping does not create 128 parallel channels: all
  nodes following the same phase occupy the same channel at that instant.
- A 50-100x capacity promise. Wideband/multichannel hardware still has finite
  passbands, demodulators, TX chains, and interference limits to measure.

**CPU cost:** Unmeasured. Benchmark the actual MCU/driver path for retuning and
settling, acquisition, SPI/IRQ handling, timeouts, outer FEC, signing and
verification, memory use, and missed deadlines. Neither a universal 100 us
retune nor a 10-cycle hash or 99%-idle MCU is established. The radio offloads
ordinary LoRa modulation, not all of these tasks.

**Ecosystem question:** Ordinary LoRa already permits peer-to-peer RX/TX;
LR-FHSS reception is a separate hardware/implementation constraint. Whether
this particular software-hopping mesh approach is novel needs a prior-art
survey. No evidence here establishes Semtech's margins/motives or that
Meshtastic, MeshCore, or TTN simply overlooked the idea.

**Large-packet model (the proposed "jumbogram" model, EXPERIMENTAL):** A candidate
goal is to replace **SCHC fragmentation**, not compression, with microfragment
reassembly inside an explicitly versioned experimental profile. Baseline RFC 8724
fragmentation remains unchanged. The 255-byte LoRa PHY limit could become an
internal detail rather than the packet size exposed above this adaptation.

An IPv6 MTU of 1280 is the minimum-MTU target, **not an IPv6 jumbogram**. Carrying
a 1280-byte IPv6 packet needs at least **1281 encoded bytes** for SCHC raw
fallback, plus the experiment's own metadata, authentication, and parity.
Reassembly remains bounded; a larger exposed MTU does not make CoAP headers
disappear, abolish all limits, or guarantee that IPv6 never fragments. Larger
CoAP/OTA blocks and a simpler single-fragmentation path remain useful goals,
subject to actual header, memory, path-MTU, and application block-size limits.

For illustration only, if a validated payload/overhead design fits that encoded
packet into 50 data fragments and adds 50 parity fragments, 100 complete
300 ms hop opportunities would take **30 seconds of scheduled block time**.
This is conditional on validated PHY payload capacity and tuning/guard overhead;
header acquisition/recovery and mandatory waits can add time. It is not an
SF10/current-authentication result. Rate-1/2 alone does not guarantee recovery
from any 50 missing fragments; that depends on the selected erasure code and
recoverable metadata. Actual emitted airtime is accounted separately.

**Design objective:** Prefer surviving a burst over minimizing single-message
latency, even if that costs 3x/4x airtime and latency. Idle periods may make that
trade attractive, but airtime still consumes regulated occupancy, shared spectrum,
receiver opportunities, and energy. It is not free, and parity cannot bypass
CCP admission or displace a committed receive/control window.

The experimental stack would be: IPv6 -> SCHC compression -> microfragmentation
with outer FEC -> ordinary LoRa channel hops. One fragmentation layer, not two,
is the goal, not proven lower overhead after repeated preambles and framing.
Whole-block ARQ above the microfragmenter is one candidate when FEC fails;
compare it with selective retransmission/SCHC ACK-on-Error on the same encoded
input and resource budget. FEC can avoid a feedback round trip, but is not
universally better than retransmitting a few missing tiles. A rendezvous header
costs one channel opportunity only if acquisition succeeds without recovery.

**Capacity impact (EXPERIMENTAL):** Graceful degradation under burst loss is
the hypothesis. Earlier ~9x concurrency, ~3.5x throughput, and 32% versus 1.3%
loss claims are unsupported toy estimates assuming independent collisions,
not measured network capacity. Channel count or code rate alone cannot establish
them. Compare baseline and microfrag with the same source load, receiver
resources, topology, legal airtime budgets, and complete framing; include
correlated interference, header loss, shared receivers, latency, goodput, and
failed/zero-delivery cases. The [microfragment experiment gate](ccp-conformance.md#microfragment-experiment-gate)
keeps this proposal testable without promoting it to the baseline.

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

## "Silent Observer" Passive Node Detection

**Promoted to real feature — see bead epic for implementation.**

Nodes that participate in routing but never originate application traffic,
have TOFU-only identity, and are unvouched by any peer are tagged "Silent
observer" in the UI. The implication is obvious; the firmware doesn't say
it. The community will coin their own term.

Detection: `app_packets_seen == 0 && vouch_count == 0 && age > 1 hour`.
Three per-neighbor counters, zero protocol changes, pure local heuristic.

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

## Cloud IAM Bridge: Generic Hooks for Enterprise Identity

LICHEN nodes have Ed25519 identities. Cloud platforms have IAM (Identity
and Access Management) — AWS IAM, Azure AD, GCP IAM. These are different
worlds: LICHEN identity is cryptographic and self-sovereign; cloud identity
is centralized and policy-managed. Bridging them is inevitable if any cloud
provider adopts LICHEN for edge IoT.

**The offer:** Add generic identity bridge hooks to the LICHEN spec and
reference implementations — not AWS-specific, not Azure-specific, but
abstract enough that any cloud IAM system can bind to a LICHEN node
identity without the spec knowing or caring which cloud it is.

**What the hooks look like:**

1. **Attestation binding.** A LICHEN node's Ed25519 public key can be
   signed by an external authority (cloud CA, enterprise PKI, identity
   provider) and the attestation carried in the node's Announce payload.
   The attestation says "cloud provider X vouches that this key belongs
   to device Y in account Z." Mesh peers don't need to understand the
   attestation — they just see a signed blob from a trusted root. The
   cloud gateway does understand it and maps the node to an IAM principal.

2. **Credential injection.** OSCORE contexts require symmetric key
   material derived from an EDHOC exchange. The EDHOC initiator
   credential can be an X.509 cert or a raw public key. If the cert is
   issued by a cloud HSM (AWS CloudHSM, Azure Key Vault, GCP Cloud KMS),
   the node's OSCORE security context is rooted in the cloud trust chain
   without the mesh protocol knowing anything about the cloud. The key
   material never leaves the HSM; the node gets a derived session key.

3. **Policy-as-data.** A cloud-managed node can carry an opaque policy
   blob in its LCI (LICHEN Configuration Interface) resource. The blob
   is meaningful only to the cloud gateway — it might encode IAM role
   ARNs, Azure RBAC assignments, or GCP IAM bindings. The LICHEN spec
   defines the CoAP resource and the max size. The spec does not define
   the contents. The cloud provider fills in their semantics.

4. **Telemetry export.** CCP already logs transmission metadata
   (timestamps, frequencies, power, durations). A cloud bridge can
   export this telemetry to CloudWatch / Azure Monitor / Cloud Logging
   as a standard CoAP Observe subscription on the gateway. The spec
   defines the observable resource format (SenML). The cloud decides
   what to do with it.

**What the spec does NOT do:**

- No AWS-specific types, fields, or behaviors in the wire protocol
- No cloud dependency for mesh operation — nodes work without backhaul
- No cloud-managed key escrow — the node owns its Ed25519 private key
- No vendor lock-in via protocol extensions — everything above is
  generic, and multiple cloud providers implementing the same hooks
  compete on service quality, not protocol capture

**Why this is strategically correct:**

If a cloud provider wants LICHEN integration and the spec doesn't have
generic hooks, they'll add proprietary extensions. Those extensions
will be technically competent (they have good engineers) but designed
to lock devices into their ecosystem (they have good business people).
Once proprietary extensions exist, the open spec is sidelined.

Generic hooks pre-empt this. The cloud provider gets what they need
(IAM binding, credential management, policy injection, telemetry) and
the spec stays vendor-neutral. The hooks are designed by someone who
spent seven years watching how cloud providers interact with open
protocols and knows exactly where the capture points are.

The right time to add these hooks is before any cloud provider commits
to LICHEN integration, not after. After, it's a negotiation. Before,
it's architecture.

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
lobbying ammunition. This is an EXPERIMENTAL market/regulatory scenario, not
a Semtech commitment. A hypothetical 10 MHz-wide PHY would need suitable
hardware, a new explicit profile/plan, and regulatory qualification; CCP channel
plans do not make that expansion automatic or authorize it.

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
