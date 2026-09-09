<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# CCP Revision 2 Conformance and Qualification

This is the test and evidence contract for
[CCP Revision 2](../spec/02b-ccp-receiver-aware.md). It specifies required checks;
it is not a report that those checks already pass. Work is tracked under
`project-LICHEN-worker6-x7hh`, a revision-specific branch of the existing CCP
epic `project-LICHEN-kudc`. The policy publication task is
`project-LICHEN-worker6-q74u`.

## Evidence Classes

| Claim | Required evidence |
|-------|-------------------|
| Policy tested | Independent semantic vectors exercised through production policy APIs |
| Wire tested | Finalized revision discriminator, exact bytes/signatures, parser rejection and mixed-version tests |
| Integrated | Real TX/RX scheduler paths in Python, Rust and C/Zephyr, not only helper calls |
| RF measured | Exact board/radio/antenna/firmware configuration and repeatable measurements |
| Authorization reviewed | Applicable operating basis and device/station-specific documentary evidence |

Each result records requirement IDs, source revision, vector corpus version and
provenance, command, environment, artifact, and pass/fail/not-assessed status.
Missing tests, unsupported hardware, or unresolved operating authority are not
passes. A product-wide compliance claim cannot be inferred from one board or
one software language passing. A source or waveform change invalidates affected
evidence until reviewed.

## Requirement Matrix

| Requirement | Required cases and independent oracle |
|-------------|---------------------------------------|
| CCP2-001 | Same receiver/context at densities 0, 9, 10, 11 and 50 keeps its channel/profile. Retained duty tiers still change at the specified boundaries. Explicit policy table, not production-derived expected values. |
| CCP2-002 | On-air activation denied before complete wire contract and reviewed vectors; offline policy tests remain usable without claiming wire conformance. |
| CCP2-003 | Distinguish policy/PHY/plan/generation/SFN/SCHC/signature/JSON versions; mutation of one cannot silently select another namespace. |
| CCP2-004 | Absent, unknown, duplicated or incompatible revision/mode cannot activate data scheduling; ignored legacy options never establish compatibility. |
| CCP2-005 | Counts 0, 1, 8, 32, 64, 128, 255 and 256; indices 7/8, 15/16, 31/32, 63/64, 127/128 and last valid/out-of-range. Compare exact integer-Hz plan entries, not base-plus-index assumptions. |
| CCP2-006 | Masks beyond 32/64 bits, nonzero padding, wrong length, all-zero/CH0-only sets, and sparse set `{0,64,127}`. Independently encode bit positions into hex byte strings. |
| CCP2-007 | Receiver versus sender identity; receiver versus local generation; sparse permitted indices; sender cannot use selected home channel; forwarded Announce origin is not the actual next-hop receiver. Independent FNV and ordered-set selection. |
| CCP2-008 | CCA failure and asymmetric density do not retune the receiver contract; expired/unknown plan and unsupported channel cause legal discovery or suppression, not local rehash. |
| CCP2-009 | Common control windows with off-channel data, clock uncertainty, retune time and overlapping DODAGs. A one-radio event model forbids simultaneous channels. |
| CCP2-010 | Sender grant without receiver commitment; receiver TX overlaps RX; queued high-priority TX arrives during committed RX; anonymous slot-map ownership. Explicit event traces decide eligibility. |
| CCP2-011 | Equal modulo-eight hash residues remain colliding through SFN wrap; assignments/collision repair, not hash equality, establish exclusive opportunities. Zero slots rejected. |
| CCP2-012 | Complete operation ends exactly at the allowed boundary, one time unit late, setup exceeds slack, and protocol response has no valid turn. Independently calculate full-frame airtime and guard. |
| CCP2-013 | One radio, multiple RX chains, one TX chain, restricted passbands, demodulator exhaustion, and overlapping roots. Hardware resources are finite inputs, never inferred from channel-list length. |
| CCP2-014 | Ordinary signed data, malformed beacon, bad signature, retired signer, stale generation and invalid time cannot maintain/recover sync. Exactly three missed beacons and three valid recovery beacons; root/generation change and SFN wrap. |
| CCP2-015 | Fixed profile 0x01 never becomes SF11/12 under congestion. Unconfirmed or unsupported profile transitions denied. No data-only SF12 reachability claim without viable control. |
| CCP2-016 | Reverse-direction SNR, CCA exhaustion and end-to-end timeout cannot masquerade as receiving-end sensitivity measurements; stale/unknown evidence remains unknown. |
| CCP2-017 | Duplicate direct senders, relayed origins, idle many versus busy few, weak RSSI/loss without extra peers, off-channel/sleep sampling, and observation gaps while admission is suppressed. |
| CCP2-018 | Legal ceiling stricter than adaptive ceiling and vice versa; unauthorized remote expansion of frequency/power/budget/profile rejected on every TX path. |
| CCP2-019 | Control, data, forwarding, retries and parity share applicable accounts; channel aliases, retune, SF/plan changes, restart and wall-clock correction cannot reset active limits. Rolling-window boundary cases use an independent interval ledger. |
| CCP2-020 | Existing queue bounds, expiry and priorities; replaceable status coalescing does not alter ordinary messages/custody; full queues signal existing back-pressure without inventing MAC ACKs. |
| CCP2-021 | CCA clear is not delivery; deferral consumes remaining operation time; exhaustion denies TX without returning an implied SF12 profile. |
| CCP2-022 | Operating-basis enforcement and grant evidence checked separately. Ordinary narrow FHSS includes 49/50 eligible-channel boundary, bandwidth/spacing, actual pseudorandom/equal-average use and per-frequency occupancy. A 128-entry list alone is not compliance. |
| CCP2-023 | Candidate 128-channel integer-Hz grid, nominal edges and upper indices; actual board/driver/plan lookup agrees. Candidate remains disabled without qualification. |
| CCP2-024 | Experimental profile cannot silently replace baseline PHY/security/SCHC. Narrowband LDRO, full authenticated fragment size, receiver acquisition, FEC and CPU costs included; amateur and unlicensed modes never substitute for each other automatically. |
| CCP2-025 | Every active case consumed by each production implementation; unknown vector shape fails, zero-case success forbidden, legacy vectors preserved and explicitly classified. |
| CCP2-026 | Failed/zero-delivery scenarios remain failures; reports separate loss/latency/airtime, policy tests, RF measurements and authorization review. |

## Independent Oracles

Freeze revision-specific fixtures only after the wire contract is defined.
Use independent byte encoders/state tables and a reference signature path;
never use the production decoder/encoder as its own oracle. Existing primitive
vectors may be reused where semantics are unchanged. Cross-language agreement
is additional evidence, not a substitute for independent expected results.

The following values are independent arithmetic anchors, not measurements:

| Case | Expected result |
|------|-----------------|
| Candidate centers `902300000 + 200000*i`, `i=0..127` | First 902300000 Hz; last 927700000 Hz |
| Candidate nominal BW 125000 Hz | Outer edges 902237500 and 927762500 Hz; 16 MHz sum of nominal widths, not contiguous 26 MHz reception |
| 128-entry mask `{0,64,127}` | `80000000000000008000000000000001` |
| SF10/BW125k/CR4/5, preamble 8, explicit header, CRC, LDRO off; PHY 100 B | 1.026048 seconds |
| Same profile, PHY 255 B | 2.295808 seconds; with 50 ms guard, ceil to 2346 ms before adding other operation costs |
| SF12/BW125k/CR4/5, preamble 8, explicit header, CRC, LDRO on; PHY 100 B | 3.940352 seconds; hypothetical comparison, not profile 0x01 |
| SF10/BW31.25k, CR4/5, preamble 8, explicit header, CRC, LDRO on; PHY 10 B | 1.155072 seconds; preamble alone 0.401408 seconds |
| Ordinary narrow FHSS, two 250 ms emissions on the same physical frequency within 20 seconds | Second emission denied if it would raise total occupancy above 400 ms, despite each packet being under 400 ms |

Airtime uses the Semtech LoRa formula with complete PHY payload length `L`:

```text
Tsym = 2^SF / BW
Npayload = 8 + max(ceil((8*L - 4*SF + 28 + 16*CRC - 20*IH)
                       / (4*(SF - 2*DE))) * (CR + 4), 0)
Tpacket = (Npreamble + 4.25 + Npayload) * Tsym
```

Here `CR=1` means 4/5, `IH=0` means explicit header, `CRC=1` enables payload
CRC, and `DE` is LDRO. Driver enums are not these formula inputs. Semtech
recommends LDRO at long symbol durations; narrowband tests must not simply scale
an LDRO-off airtime. Source: [SX1261/2 datasheet](https://cdn.sparkfun.com/assets/6/b/5/1/4/SX1262_datasheet.pdf),
Sections 6.1.1.4 and 6.1.4.

## Production and RF Gates

Run policy, codec, fuzz and integration gates in Python, Rust and host/native
C/Zephyr. Exercise the actual scheduler/driver boundary, radio completion/IRQ
events, receiver commitments, rejection paths, and persistent accounting. A
helper-only test is not proof that production respects its result. Use the
local Linux builder for native simulation before considering cloud tooling.

RF qualification records exact chip, module/FCC ID where applicable, board
revision, oscillator, antenna, firmware, power, and channel/PHY plan. Measure
low/mid/high-band performance, retune/CAD/settling, carrier error and packet-time
drift, RX/TX turnaround, passband placement, demodulator limits and relevant
emissions. Follow [bench port-safety procedures](bench-operations.md) before
hardware access. A supported tuning register is not board qualification.

US authorization review distinguishes ordinary FHSS, standalone DTS, hybrid,
and amateur/experimental operating bases. Record the actual grant conditions
or station authority and any grantee/TCB determination; do not infer permission
from an FCC logo or a channel count. Fixed CH0/receiver-home scheduling must be
assessed against the selected hopping/coordination rules, not presumed eligible.
Sources: [15.247](https://www.ecfr.gov/current/title-47/part-15/section-15.247),
[2.1043](https://www.ecfr.gov/current/title-47/part-2/section-2.1043), and
[Part 97](https://www.ecfr.gov/current/title-47/part-97).

## Microfragment Experiment Gate

The research goal is burst-survival/goodput rather than minimum single-message
latency. No capacity multiplier or CPU percentage is assumed.

Specify the actual per-link time/hop context, acquisition/header recovery,
fragment metadata, authenticated identity/replay binding, bounded reassembly,
expiry/abort, and an independently specified across-fragment erasure code.
Loss of a fragment must not lose hop phase. Network-wide lockstep hopping is
not independent simultaneous per-link hopping. CRC or LoRa coding-rate FEC does
not authenticate fragments or reconstruct arbitrarily missing PHY packets.

Compare baseline SCHC ACK-on-Error against the proposed single fragmentation
layer on the same encoded input, RF resources, source load and airtime limits.
If microfrag replaces SCHC fragmentation, that change belongs only to an
explicitly versioned experimental transport. Baseline SCHC remains required.
An IPv6 MTU of 1280 is not a jumbogram; uncompressed SCHC fallback alone needs
1281 encoded bytes. Preserve all framing and bounded-state obligations.

For separate ordinary LoRa packets of at most 300 ms, with BW125 kHz, CR4/5,
preamble 8, explicit header/CRC and applicable LDRO, maximum complete PHY
payloads are SF7:187 B, SF8:98 B, SF9:44 B, SF10:14 B. SF11/12 cannot fit even
an empty packet. Current signed broadcast framing plus dispatch is already
62 B, before a fragment body. Shortening application payloads therefore cannot
produce authenticated 300 ms fragments at the current SF10 baseline.

Any proposed amortized/per-session authentication change needs a separate
security review and independent oracle; this gate does not permit weakening
link authentication or editing audited OSCORE internals. Benchmark the actual
MCU path, including signing/verification, IRQ/SPI, retuning, timeouts and FEC,
with missed-deadline and memory evidence. Compare independent-link and shared-
receiver topologies, correlated interference, control loss and empty delivery.
An ideal independent-collision binomial model is not a network capacity result.
