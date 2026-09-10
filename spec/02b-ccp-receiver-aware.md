<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# CCP Revision 2: Receiver-Aware Capacity

**Status:** Adopted policy requirements, 2026-09-09. Wire activation is gated
by Section 2; this document does not claim deployed implementation conformance.

The `ccp-receiver-aware` decision in [decisions.jsonl](decisions.jsonl)
supersedes the older density-driven channel/SF policy. This document owns the
current CCP requirements. Conflicting CCP examples in older chapters, drafts,
constants, issue descriptions, and fixtures describe legacy behavior, not an
alternative implementation of Revision 2. The historical
[CCP chapter](02a-coordinated-capacity.md) remains a reference for unchanged
primitives explicitly incorporated below.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY have their RFC 2119
and RFC 8174 meanings. Requirement identifiers `CCP2-001` through `CCP2-026`
are stable conformance references.

## 1. Scope and Separation

CCP coordinates finite radio opportunities. It does not guarantee delivery,
force peers to cooperate, or create capacity by increasing queue sizes.

| Decision | Evidence | Result |
|----------|----------|--------|
| Receiver rendezvous | Authenticated receiver contract and shared plan/generation | Channel, profile, and receive opportunity |
| Link robustness | Directional receiving-end link evidence | A mutually supported PHY profile |
| Congestion admission | Actual airtime/service, queue age, and contention | Pace, defer, or reject eligible traffic |
| Control-traffic scaling | Observed distinct peers | Startup delay, announce frequency and scope |

**CCP2-001:** Implementations MUST keep these decisions separate. Density,
gateway load, queue depth, and channel utilization MUST NOT directly select a
remote receiver's channel or cause an SF increase. The `density-high` decision's
`>10` boundary remains applicable to the existing adaptive airtime-budget tiers;
its CH0-fallback and SF-escalation consequences are superseded. Existing
control-traffic density tiers and their numeric values are unchanged.

This revision preserves upstream Yggdrasil identity, SCHC compression and
baseline fragmentation, existing signature domains, and best-effort custody.
It does not introduce a new reservation exchange per packet, mandatory
multi-radio hardware, mandatory hopping, or an experimental PHY.

## 2. Wire Activation and Migration

**CCP2-002:** Revision 2 MUST NOT be enabled on air until its exact versioned
schedule/rendezvous encoding and independent byte vectors have been specified
and reviewed. That follow-up must define the message discriminator, version,
authenticated transcript, bounds, required fields, duplicate/unknown-field
handling, replay/freshness rules, and mixed-version rejection. Policy tests and
offline implementation work MAY precede wire activation. Passing such tests
MUST NOT be described as complete wire conformance.

The following are semantic requirements for that encoding, not newly allocated
wire fields. Encoding work MUST preserve them rather than choose another policy:

| Context | Required information |
|---------|----------------------|
| Schedule identity | Policy revision, full authorized root identity, DODAG scope, schedule generation, PHY profile, regional plan ID and version |
| Timing | Authenticated activation/expiry, period, phase/reference instant, control-window duration, and units for all offsets/durations |
| Receiver commitment | Authenticated receiver identity, permitted plan-index set, home channel, profile, receive intervals, and validity bound |
| Transmit grant | Identified owner, applicable intervals, receiver/radio exclusions, and validity bound |
| Hardware capability | Supported profiles/channels and actual simultaneous RX/TX capabilities, not merely tunable settings |

**CCP2-003:** Policy revision, PHY profile ID, regional plan ID/version, schedule
generation, SFN, SCHC Rule Set Version, link signature-domain version, and JSON
fixture `format_version` MUST remain distinct namespaces. Existing RPL options,
SCHC Rule IDs, or spare legacy bits MUST NOT be repurposed without the explicit
wire revision. An optional field ignored by old nodes is not safe discrimination
for changed scheduling semantics.

**CCP2-004:** An unversioned or incompatible advertisement MUST NOT activate a
Revision 2 data schedule. Mixed deployments require an explicitly specified
compatible control path or isolated/coordinated migration. CH0 contact does not
bypass SCHC version admission, authentication, regulatory restrictions, or the
receiver's actual availability. Legacy interoperability is not assumed.

## 3. Regional Plans and Receiver Channels

**CCP2-005:** Plans MUST use an ordered list of 1 through 255 entries with stable
indices; index zero is CH0 and is included in the count. Channel indices use the
full unsigned-octet range permitted by the count. Plan IDs and operating-class
IDs MUST NOT be interchanged. Frequency lookup MUST use the identified plan,
not an unchecked operating-class base plus an index-dependent offset.

**CCP2-006:** Permitted sets MUST retain global plan indices. Their canonical
bitset representation is a byte string of `ceil(channel_count / 8)` bytes;
index `i` occupies bit `7 - (i mod 8)` of byte `floor(i / 8)`. Unused trailing
bits MUST be zero. A mask MUST NOT be truncated to u32/u64 or treated as a
population count followed by renumbering. Thus 128 entries require 16 bytes.
The wire gate specifies the enclosing field, not a different bit convention.

**CCP2-007:** The receiver's fresh authenticated rendezvous is authoritative
for channel selection. Where deterministic home-channel derivation is used:

```text
eligible = receiver's advertised permitted data indices, ascending, excluding 0
h = FNV1a32(receiver_wire_eui64 || schedule_generation_as_LE_u32)
home = eligible[h mod len(eligible)]
```

Use the existing FNV-1a32 basis `0x811c9dc5`, prime `0x01000193`, and exact
eight-byte wire EUI-64. The generation is shared receiver context, not the link
replay epoch. Sender-local density, SFN, channel-mask renumbering, or a different
local epoch MUST NOT alter this preimage or selection. The sender validates the
selected physical channel against its own permissions; if unusable, it MUST NOT
rehash over a different local subset and assume the receiver followed.

**CCP2-008:** A home channel MUST remain stable for its advertised generation
and validity period. CCA failure or congestion MUST NOT trigger unilateral
per-packet retuning. Missing/stale context, no usable data channel, or loss of
sync invokes the defined control/discovery path, not a density-triggered CH0
data mode. Unknown plan IDs do not establish a common CH0 frequency; without a
locally permitted, understood rendezvous, transmission MUST be suppressed.

The old Announce `rx_channel < 8` and 32-bit beacon mask cannot represent this
contract. Widening a frequency list alone is insufficient. The wire revision
must bind the wider index/mask to the plan and schedule it means.

## 4. Receiver-Aware Scheduling

**CCP2-009:** Schedules MUST provide periodic common CH0 control/discovery
windows and explicit data opportunities. All participating single-radio nodes
return for those control windows except during their eligible control TX.
They MUST NOT claim continuous CH0 reception while tuned elsewhere. Control
window geometry must fit complete control exchanges, tuning/settling, clock
uncertainty, and legal airtime budgets; no universal cadence is selected here.

**CCP2-010:** A transmission is eligible only when its sender has a valid TX
opportunity and its next-hop receiver has a compatible RX opportunity on the
same physical channel/profile. Standing assignments and receiver commitments
MUST prohibit overlapping RX/TX obligations on a half-duplex radio. A newly
queued transmission MUST NOT preempt a committed receive interval. A grant
identifies its owner; an anonymous broadcast `slot_map` is not an assignment
to every listener.

**CCP2-011:** The existing candidate calculation is retained:

```text
candidate = ((FNV1a32(wire_eui64) + u32(SFN)) mod 2^32) mod num_slots
```

`num_slots` MUST be positive. This yields a candidate, not an exclusive grant
or proof of receiver availability. At eight slots, equal hash residues collide
for every SFN; common rotation does not resolve them. Explicit assignments or
specified collision repair MUST resolve sender/receiver conflicts. Unassigned
fallback access remains contended and MUST NOT be represented as collision-free.

**CCP2-012:** Admission MUST establish that the complete applicable operation
fits before the protected boundary: setup/retuning/CCA, full PHY frame, required
turnaround/response if any, and the single trailing guard. Profile `0x01` keeps
the 50 ms guard and 2,346 ms minimum for a 255-byte SF10 frame plus guard only.
That minimum is not an allowance for unspecified setup or ACK airtime. No new
universal link ACK is introduced; SCHC/CoAP responses obtain their own valid
opportunities unless explicitly included in a reserved exchange.

**CCP2-013:** Hardware capability MUST describe actual simultaneous reception
and TX/RX behavior. Configurable channels/SFs and scanning do not imply parallel
reception. Multiple receive chains do not imply multiple transmit chains.
Gateway allocation MUST respect passband placement, demodulator limits, and
half-duplex constraints. Channel count alone MUST NOT establish a throughput
multiplier. Interfering DODAGs need compatible control rendezvous or an explicit
discovery fallback; routing partitions do not isolate radio interference.

**CCP2-014:** Only a validated TDMA synchronization object can maintain or
recover the schedule. Ordinary authenticated data MUST NOT count as a beacon.
Authentication, authorized time provenance, epoch-floor and current-generation
checks precede adoption. The quality ordering in
[Packets and Timing Section 14.6](09-packets-timing.md#146-time-synchronization)
governs, not the reversed legacy CCP stratum interpretation. Scheduled TX stops
on invalid synchronization; extended control listening and three consecutive
valid beacons provide recovery. This revision uses `>=3` missed beacons, as in
the canonical legacy CCP recovery FSM, not the conflicting `>3` summary.

## 5. PHY Selection and Measurement

**CCP2-015:** Scheduled profile `0x01` remains SF10, 125 kHz, CR 4/5, eight
preamble symbols, explicit header, CRC, and LDRO off. Its parameters MUST NOT
change inside a generation. A future adaptive profile requires receiver
agreement, directional link-margin evidence, hysteresis, a defined activation
boundary, and correct airtime geometry. The earlier hysteresis decision remains
applicable to such adaptation, not permission to retune this fixed profile.

**CCP2-016:** Queue load, density, CCA exhaustion, and unattributed loss MUST NOT
be treated as proof of insufficient link sensitivity. Denying admission MUST NOT
implicitly select SF12. RF evidence must retain receiver, direction, channel,
profile, observation time, coverage, and validity; stale/unknown evidence MUST
remain unknown. Incoming-link SNR does not automatically characterize the
opposite direction. An SF12 data link also needs a viable bootstrap/control
path; unreceivable control traffic cannot be repaired by data-only adaptation.

**CCP2-017:** Density MUST count observed distinct immediate radio peers over
the stated observation window, with uncertainty/coverage retained. Relayed
Announce origins are not additional directly heard peers. Weak RSSI and loss
MUST NOT add synthetic neighbors. Local TX airtime, observed busy time, CCA
deferrals, queue service, and directional delivery evidence are separate metrics.
TX completion is not delivery; a missing universal link ACK cannot supply a
packet-loss estimate. RX-driven estimators must not silently freeze as traffic
is suppressed or nodes are off-channel.

## 6. Admission, Congestion, and Compliance

**CCP2-018:** Every transmission MUST satisfy both locally provisioned legal
constraints and the retained adaptive airtime ceiling. Existing density tiers
and rolling one-hour accounting remain upper bounds, never new regulatory
permissions. Remote advertisements MAY narrow local permissions, never expand
frequencies, power, permitted modes, or budgets. Unsupported profiles fail
closed rather than falling back to an unauthorized transmission.

**CCP2-019:** Airtime accounting MUST include complete emitted frames, control,
forwarding, retries, and any experimental parity/header traffic. Limits apply
to their actual regulatory group or physical frequency, as specified by the
operating basis. Aliased plan indices, SF changes, retuning, and plan changes
MUST NOT reset or duplicate an allowance for the same physical resource.
Use monotonic elapsed time; clock corrections or restart MUST NOT erase an
active restriction. Restore valid accounting or wait out the applicable window.

**CCP2-020:** Priority orders eligible traffic; it MUST NOT bypass receiver
commitments, frame-fit checks, legal limits, or adaptive ceilings. Keep existing
bounded queues, deadlines, priorities and explicit back-pressure. Implementations
SHOULD coalesce explicitly replaceable position/status updates, not arbitrary
messages or historical samples. Custody remains best effort under its existing
storage/expiry rules; this revision does not change custody eviction policy.

**CCP2-021:** CCA-clear establishes an access check, not successful delivery.
Preserve bounded contention retries and recheck remaining operation time and
budgets after deferral. Congestion response SHOULD reduce admitted low-priority
traffic to actual service rather than enlarge queues or increase SF. Any new
feedback controller requires independently specified behavior and stability
evidence; this revision does not invent new tuning constants.

**CCP2-022:** A deployment profile MUST identify its operating authority and
document applicable measured bandwidth/spacing, hopping, occupancy, power,
antenna, emissions, and equipment-authorization conditions. Software enforcement
conformance is distinct from RF compliance and grant coverage. In particular,
under ordinary US 902-928 MHz FHSS with measured 20 dB bandwidth below 250 kHz,
50 available channels alone do not establish compliance: pseudorandom/equal-
average transmitter use, receiver synchronization, carrier spacing, and aggregate
0.4-second occupancy per physical frequency in 20 seconds also matter. Fixed
receiver-home operation or fixed CH0 may be incompatible with that operating
basis. Such a combination MUST NOT be enabled merely because the radio tunes
there or individual packets pass a duration check.

Standalone DTS has a separate minimum 500 kHz measured 6 dB bandwidth rule;
125 kHz CSS is not automatically eligible. Hybrid rules have distinct test
conditions and are not implied by the project's name. Exact grantee/TCB review
may be required for changed operating configurations; neither new certification
nor exemption from it is presumed. See [47 CFR 15.247](https://www.ecfr.gov/current/title-47/part-15/section-15.247)
and [47 CFR 2.1043](https://www.ecfr.gov/current/title-47/part-2/section-2.1043).

## 7. Full-Band and Experimental Profiles

**CCP2-023:** Channel-plan representation MUST NOT impose a lower-half-US915
restriction. A candidate 128-entry conventional-LoRa grid is
`902300000 + 200000*i` Hz for `i=0..127`: centers 902.3-927.7 MHz and nominal
125 kHz edges 902.2375-927.7625 MHz. This is an unqualified candidate, not a
newly enabled regional plan, certified profile, mathematical maximum channel
count, or promise of contiguous/simultaneous 26 MHz reception. It must receive
a distinct plan/version only after explicit qualification; legacy tables are
not silently extended. Measured bandwidth, board RF paths, driver enums,
oscillators, retuning, receiver passbands and authorization remain gates.

**CCP2-024:** Narrow-band ordinary LoRa, software microfragment hopping,
LR-FHSS, and a future narrow-channel LICHEN 2 PHY are separate experimental
profiles. None is enabled by Revision 2. Silicon tuning capability does not
establish driver support, reception capability, authentication feasibility, or
legal operation. Experiments MUST count preamble, LDRO, complete authenticated
framing, reacquisition, and parity costs, not application bytes alone. Amateur
operation needs its own station/control/identification and permitted-traffic
qualification; it MUST NOT silently disable production OSCORE/security policy.

## 8. Conformance and Evidence

**CCP2-025:** Legacy CCP fixtures MUST remain identified as legacy policy
tests. Their density/SF/CH0 outputs MUST NOT be rewritten from the revised
implementation to manufacture conformance. New revision-specific fixtures
need independent arithmetic, wire encoding, signature and state-transition
oracles. Production TX/RX paths in Python, Rust and C/Zephyr must consume them;
tests duplicating the algorithm instead of calling production are insufficient.

**CCP2-026:** Claims MUST distinguish policy-tested, wire-tested, integrated,
RF-measured, and authorization-reviewed configurations. Missing evidence remains
not assessed, not passed. Capacity results must report workload, topology,
receiver resources, latency, loss, airtime and accounting limits, including
failures; zero delivery cannot appear as a latency improvement.

The [CCP conformance guide](../docs/ccp-conformance.md) maps every requirement
to tests and qualification evidence. Implementation and qualification work is
tracked under Beads epic `project-LICHEN-kudc`; the normative policy publication
task is `project-LICHEN-worker6-q74u`. The policy is accepted; unfinished wire,
implementation, and equipment evidence remain explicit blockers to deployment.

[Index](README.md) | [Historical CCP](02a-coordinated-capacity.md)
