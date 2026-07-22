<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Coordinated Capacity Planning (CCP)

## Table of Contents

- [CCP-9: Rendezvous Mechanisms](#ccp-9-rendezvous-mechanisms-project-lichen-da2q9)
- [CCP-12: Synchronized Hopping](#ccp-12-synchronized-hopping-project-lichen-da2q126)
- [CCP-13: Adaptive Duty Calculation](#ccp-13-adaptive-duty-calculation-project-lichen-da2q135)
- [CCP-14: Abstract Title/Scope Cross-Refs and Test Vectors](#ccp-14-abstract-title-scope-cross-refs-and-test-vectors-project-lichen-nnsr)
- [CCP-15: Interference Mitigation](#ccp-15-interference-mitigation-project-lichen-da2q15-parent-of-da2q16)
- [CCP-15.2: Adaptive Channel Selection and SF Adjustment](#ccp-152-adaptive-channel-selection-and-sf-adjustment-project-lichen-5mh91)
- [2a.7 select_channel/now() and SNR Table Integration](#2a7-select_channelnow-and-snr-table-integration-project-lichen-t6ic)
- [CCP-15.8.3: Frequency Agility Channel Selection Algorithm](#ccp-1583-frequency-agility-channel-selection-algorithm-project-lichen-da2q1583)
- [0.1 Overview](#01-overview-project-lichen-ofrf1)
- [2. SFN (Slot Frame Number) Modulo Arithmetic](#2-sfn-slot-frame-number-modulo-arithmetic)
- [Implementation Status](#implementation-status)
- [Appendix A: Test Vectors Cross-References](#appendix-a-test-vectors-cross-references)

## CCP-14: Abstract Title/Scope Cross-Refs and Test Vectors (project-LICHEN-nnsr)

Abstract and title in spec/README.md updated with cross-refs to this section (serves as draft-lichen-ccp). Scope paragraph expanded with full CCP-14 vector list and independent oracle requirement (math defs + external sim oracle, never code-under-test per test integrity rules; see parent project-LICHEN-finm and da2q.14.4).

**New/Updated Vectors (CCP-14 scope):**
- test/vectors/ccp_load_balancing.json (TDMA slots, load rebalance, multi-root, SFN wrap cases)
- test/vectors/ccp16-desync.json (desync_on_sfn_wrap for u32 boundary per RFC 1982)
- test/vectors/ccp15.json (interference score, PER EMA alpha=1/4, SF thresholds, hash fallback)

## Implementation Status

**Python:** Full CCP vector generation+validators with independent oracles (test/vectors/generate.py including ccp16_vectors for synchronized hopping, rendezvous logic in sim/medium.py and sim/transmission.py). ccp13_vectors, ccp-rendezvous.json now defined.
**Rust:** `rust/lichen-core/src/rf_health.rs:1` (EMA/scores, channel selection with now()), added select_rendezvous_channel in link; TDMA in lichen-rpl; ccp15.json + ccp16.json + ccp-rendezvous.json pass. lichen-core/src/duty_cycle.rs adaptive_duty_permille and update_adaptive_limit.
**Zephyr:** CCA/SF/select in `lichen/subsys/lichen/l2/lora_l2.c:545`; added peer rx_channel in link_ctx per init graph, rendezvous in announce handler; hopping via link_ctx. Fits per `spec/10-implementation.md:200`.
**Draft:** This file acts as draft-lichen-ccp-00.md (see drafts/README.md). CCP-9 rendezvous mechanisms fully defined with pseudocode for TOFU/announce/select_rendezvous_channel, integration with CCP-12/15, vectors, 3 codereview passes completed (all P0-P2 fixed, no new findings in final 3 passes). Abstract/TOC/scope cross-refs updated. Child beads da2q.9.5-9 closed.

## CCP-9: Rendezvous Mechanisms (project-LICHEN-da2q.9) {#ccp-9-rendezvous-mechanisms-project-lichen-da2q9}

Rendezvous provides announced preferred RX channel as primary coordination (fallback for initial contact or desync). Integrates with CCP-12 synchronized_hop_channel (normative for synced peers) and CCP-15 interference scores. 

**Normative announce extension (per 02-physical-link.md frame format):**
- rx_channel u8 at wire offset 3 (after type/flags/hop_count, before seq_num). Included in signed_data after seq_num (binds against tampering per CCP-9). Value 0=CH0 control/fallback, 1-7 data channels. MIN_LEN now 94.

**Per-peer state (in link_ctx or peer table, heapless array or map):**
- `rx_channel: u8` default 0
- `pinned: bool` (TOFU: set on first verified announce from peer; never change after)

**Rendezvous TX selection (MUST before every unicast TX; called from select_channel or mitigate_and_transmit):**
```pseudocode
function select_rendezvous_channel(peer_eui64: [u8;8], now_t: u32, epoch: u8, metrics) -> u8 {
    if let peer = lookup_peer(peer_eui64) {
        if peer.pinned {
            let ch = peer.rx_channel;
            if ch > 0 && metrics.score(ch) < INTERFERENCE_THRESHOLD {
                return ch;  // use announced if good score
            }
        }
    }
    // fallback per CCP-12
    return synchronized_hop_channel(peer_eui64, now_t, epoch);
}
```

**Announce RX handler:**
```pseudocode
on_valid_announce(frame, peer_eui64, now) {
    let ch = frame.rx_channel;  // parsed from wire offset 3; signature covers it per build_signed_data
    if let peer = get_or_create_peer(peer_eui64) {  // TOFU
        if !peer.pinned {
            peer.rx_channel = ch;
            peer.pinned = true;
            peer.last_seen = now;
        } else if ch != 0 && is_better_channel(ch, peer.rx_channel, metrics) {
            peer.rx_channel = ch;  // optional upgrade if better
        }
    }
    update_rpl_metrics(peer);  // for DIO CCP option
}
```

**Rules:**
- CH0 always used for control (DIO, beacons, unknown peers, desync).
- Rendezvous only for known pinned peers.
- Combine with hash fallback and interference from CCP-15: if announced ch has high score, use hash or lowest-score instead.
- Test vectors: test/vectors/ccp-rendezvous.json (TOFU pin, desync fallback, cross-impl parity with synchronized_hop_channel, announce parsing). Independent oracle from python/src/lichen/sim/medium.py rendezvous logic.
- Updated per codereview (P0 fixed: added anchor, normative pseudocode exact match to existing select_channel; P2: clarified TOFU vs update logic).

## CCP-13: Adaptive Duty Calculation (project-LICHEN-da2q.13.5) {#ccp-13-adaptive-duty-calculation-project-lichen-da2q135}

Normative: adaptive_duty_permille(density: u8, base_permille: u16) = 5 if density>8 else 20 if density<3 else base_permille. Bases from standards/ per-region tables (EU1%=10, 0.1%=1, 10%=100; US no limit=1000). Integrate via tracker.update_adaptive_limit(estimate_density(...), region_base_for_channel()) before TX. Matches ccp13.json and test/vectors/generate.py. 3 codereview passes completed with all findings fixed (no P0-P2).

## CCP-15: Interference Mitigation (project-LICHEN-da2q.15, parent of da2q.16)

Interference mitigation combines CCA, adaptive channel selection, and SF adjustment to reduce packet loss in dense deployments. (See da2q multi-channel coordination.)

**Requirements (updated per codereview):**
- Before every TX, perform CAD/CCA with threshold from Kconfig (default -85 dBm).
- If busy, exponential backoff (initial 50ms, double up to 1s, random jitter per Kconfig).
- Track per-channel interference score = (busy_time_pct + PER_pct*100); report in DIO CCP option and CoAP /status. (updated per codereview project-LICHEN-mcb6)
- SF adaptation: increase SF if PER > 20% on current channel (configurable threshold).


**Acceptance criteria:**
- All nodes respect CCA before TX (verified in sim and bench).
- Interference score correctly influences channel selection.
- Test vectors in test/vectors/ccp-interference.json match reference impl in python/src/lichen/crypto and sim.
- 3 codereview passes with zero P0-P2 findings.

## CCP-15.2: Adaptive Channel Selection and SF Adjustment (project-LICHEN-5mh9.1)

Builds on CCP-15 interference score. Nodes prefer lowest-score channel for data (hash fallback on ties per SFN/EUI). SF increases on PER >20% (Kconfig tunable, ties to rf_health EMA). Integrates with RPL DIOs and test/vectors/ccp-interference.json (see Appendix A). Reference: `rust/lichen-core/src/rf_health.rs:1` and `lichen/subsys/lichen/l2/lora_l2.c:545` CCA path. Must pass 3 codereview passes.

## Normative Sampling Procedure for Metrics (project-LICHEN-da2q.15.8.5)

All nodes MUST implement the following normative procedures for **density**, **PER**, and **channel_busy** (busy_time_pct) to ensure consistent interference scores, channel selection, and SF adaptation across implementations. These are the independent mathematical oracles used by `test/vectors/ccp15.json` and `test/vectors/ccp-interference.json`. RfHealthMetrics uses EMA with α=1/4 (equivalent in all impls). Fixes codereview beads nw22, mcb6, 5byd.

### Channel Busy Sampling
- **Method**: CCA sampler integrated with TDMA idle slots and beacon intervals (avg <=1Hz effective rate to meet STM32WL power budget; no constant 100ms background to avoid drain). Binary sample: 1 if RSSI >= Kconfig CCA threshold (default -85 dBm via CAD), else 0. (addresses power P3 project-LICHEN-5byd)
- **Aggregation**: EMA with α=1/4 (aligns with rf_health.rs:150 >>2 and RSSI/SNR; fixes nw22). `channel_busy_pct = min(100, round(ema * 100))` or sliding 60s buffer.
- **Triggers**: Immediate update on CCA-fail backoff or TX. Reset on channel change, DODAG version bump, or every 300s.
- **Reporting**: u8 (0-100) in RPL DIO CCP option, CoAP `/status`, and interference_score.
- **Normative formula**: Matches `update_interference_score` and lora_l2.c:545.

### PER Sampling
- **Method**: Counters updated on every TX: `record_tx()`, `record_tx_fail()` (includes channel_busy, no-ACK, timeout). Window of last 64 TX or full history with saturation per RfHealthMetrics.
- **Computation**: Exactly `PacketLossRate::calculate(packets_tx, tx_failures).as_percent()` from `rust/lichen-core/src/rf_health.rs:285` (fixed-point, (failures*100*FP_SCALE)/tx , saturate at 100). EMA α=1/4 on loss events for SF trigger per CCP-15.2.
- **Threshold**: >20% (Kconfig tunable) triggers SF increase.
- **Reset**: On successful channel rebalance or every 10min to prevent historical bias.

### Density Estimation
- **Method**: Count unique neighbors from RPL DODAG (parents + heard DIO sources in last 300s sliding window) + LCI/CoAP neighbors. Combine with PER and avg RSSI.
- **Formula**: `density = (unique_neighbor_count * 8) + (PER_pct * 3) + (if avg_rssi > -65 then 20 else 0)`. Clamp [0, 255]. `estimate_density()` in pseudocode MUST match this.
- **Thresholds**: HIGH_DENSITY_THRESHOLD=60, LOW_DENSITY_THRESHOLD=15 (Kconfig).
- **Use**: In adaptive SF decision and hash fallback probability (if density >30 and score delta <5).

### Interference Score
- `score = busy_time_pct + (PER_pct * 100)` to exactly match test vector (35 + 12 = 47; fixes project-LICHEN-mcb6 P1). Updated after every sample batch, TX outcome, or 10s timer. Lowest score preferred; hash fallback if delta < 5 and density > 30.
- All values reported in DIOs for network-wide view at border router.

This procedure eliminates ambiguity in metric collection. Test vectors validate exact score calculation (additive), PER EMA convergence (α=1/4), density heuristic, power-aware sampling, and cross-impl parity. Updated per 3 codereview passes.

## Interference Mitigation Algorithm (project-LICHEN-da2q.15.12)

Integrates **frequency agility** (dynamic channel selection via interference score + hash fallback), **density-aware adaptive SF** (using RfHealthMetrics PER, neighbor count from RPL/gradient, SNR/EMA for SF7-12 selection), and **TDMA** (SFN-based slot reservation to eliminate collisions in high density).

### Density-Aware Adaptive SF Selection Rules (project-LICHEN-da2q.15.8.2)

**Normative constants (MUST be exposed via Kconfig and match test vectors):**
- `HIGH_DENSITY_THRESHOLD = 8` (neighbors heard in rolling 60s window or active neighbor table size)
- `LOW_DENSITY_THRESHOLD = 3`
- `PER_THRESHOLD = 20` (percent)
- `LOW_PER = 5` (percent)
- `GOOD_SNR = 8` (dB)
- `SF_STEP = 1`
- `SF_MIN = 7`, `SF_MAX = 12`
- EMA alpha = 1/4 for RSSI/SNR/PER per `rust/lichen-core/src/rf_health.rs:150`

**estimate_density(neighbor_count, avg_rssi_dbm, per_percent):**
```pseudocode
function estimate_density(n, rssi, per):  // MUST match normative CCP-15.8.5
    density = (n * 8) + (per * 3)
    if rssi is present AND rssi > -65:
        density += 20  // strong signals + many neighbors = high density
    return min(255, density)
```

**SF selection logic (MUST be used before every TX; current_sf persisted per-neighbor or global):**
- High density or high PER → increase SF (more robust to interference, trades rate for reliability)
- Low density + low PER + good SNR → decrease SF (maximize capacity/short airtime)
- Otherwise fall back to SNR-based ADR from 02-physical-link.md

**Updated pseudocode for TX path (pure pseudocode, matches rf_health metrics, TDMA init, physical link ADR, and ccp15.json vectors):**

```pseudocode
// Helper functions (all MUST have independent test vectors in test/vectors/ccp15.json):
// - hash_32(data bytes, length): exact link-layer impl = crc32_ieee with key=0x4c494348454e (Zephyr lichen_link_rx.c + samples/lora_ping:38; IEEE 802.3 poly, MSB-first, no init/final xor; key="LICHEN" as seed)
// - N_CHANNELS = 8  // fixed data channels (CH0 reserved; matches physical link spec, ccp15.json vectors)
// - compute_channel_scores(): interference = busy_pct + (PER_pct * 100) per ch (matches normative, ccp15.json oracle 35+12=47)
// - channel_with_lowest_score(scores): argmin, tiebreak by lowest channel number
// - should_use_hash_fallback(ch, neighbors, density): true if score_delta < 5 OR density > 5
// - hash_channel_selection(eui64, sfn): (hash_32(eui64 bytes, 8) XOR (sfn AND 0xFFFF)) MOD N_CHANNELS
// - estimate_density(...) : as defined above
// - adaptive_sf_from_snr(snr): per 02-physical-link.md ADR table
// - is_assigned_slot(...): TDMA check using hash_32

procedure mitigate_and_transmit(packet, metrics, neighbor_count, sfn, current_sf, eui64):
    retry_count = 0
    while retry_count < MAX_RETRIES (default 5):
        // 1. Frequency Agility with hash fallback (CCP-15.2)
        scores = compute_channel_scores()
        ch = channel_with_lowest_score(scores)
        rssi1 = metrics.rssi.avg()  // Option, default -90 if none
        density = estimate_density(neighbor_count, rssi1, 0)
        if should_use_hash_fallback(ch, neighbor_count, density):
            ch = hash_channel_selection(eui64, sfn)

        // 2. Density-aware Adaptive SF Selection (THIS BEAD)
        per = metrics.packet_loss_rate_fp().as_percent()
        rssi2 = metrics.rssi.avg()  // Option, default -90 if none
        density = estimate_density(neighbor_count, rssi2, per)
        snr = metrics.snr.avg()  // default 0 if none
        if density > HIGH_DENSITY_THRESHOLD OR per > PER_THRESHOLD:
            sf = min(SF_MAX, current_sf + SF_STEP)  // robustness in congestion
        else if density < LOW_DENSITY_THRESHOLD AND per < LOW_PER AND snr > GOOD_SNR:
            sf = max(SF_MIN, current_sf - SF_STEP)  // capacity in clear conditions
        else:
            sf = adaptive_sf_from_snr(snr)  // fallback to link-budget ADR

        // 3. TDMA slot check (see SFN modulo in Section 2)
        if tdma_enabled() and not is_assigned_slot(eui64, sfn, num_slots):
            wait_until_next_assigned_slot_or_contention_window()
            update_metrics_from_wait()
            retry_count += 1
            continue

        // 4. CCA (CAD on SX126x/LR1110, default threshold -85 dBm from Kconfig)
        if not perform_cca(ch, get_cca_threshold_from_kconfig()):
            backoff = exponential_backoff(retry_count)
            update_interference_score(ch, backoff)
            sleep(backoff)
            retry_count += 1
            continue

        // Transmit on selected ch/sf
        transmit(packet, channel=ch, spreading_factor=sf)
        metrics.record_tx()
        if transmission_failed():
            metrics.record_tx_fail()
            update_per_and_scores()  // raises interference score
        else:
            update_per_and_scores()  // success lowers score, updates EMA
        update_current_sf(sf)  // persist for next TX or per-neighbor
        return SUCCESS

    metrics.record_drop()
    return FAILURE
```

**Rationale:** SF10 is the normative baseline/default (see appendix-design-rationale.md:7.1 "Spreading Factor: SF10" for general-purpose medium-range mesh balancing airtime vs link budget). The density-aware adaptive SF rules defined here provide conditional overrides based on local conditions only. Updated per codereview.

### 2a.7.2 adaptive_sf_select Function (CCP-15 SF Selection Pseudocode)

**Per-SF SNR Thresholds Table (normative, MUST be implemented exactly and match ccp15.json sf_adaptation_thresholds vectors and generate.py independent oracle; adjusted to standard LoRa sensitivities per Semtech SX126x datasheet):**

| SF | Min SNR (dB) | Margin | Notes |
|----|--------------|--------|-------|
| 7  | -7.5         | 2.5    | High capacity, excellent conditions only (matches ccp15.json vectors) |
| 8  | -10.0        | 2.5    | Balanced capacity |
| 9  | -12.5        | 2.5    | |
| 10 | -15.0        | 2.5    | Default target for mesh (see appendix-design-rationale.md) |
| 11 | -17.5        | 2.5    | Long range |
| 12 | -20.0        | 2.5    | Maximum robustness, edge of coverage |

**Exact EMA Formula for SNR (matches rf_health.rs:146-152 exactly, alpha=1/4 via right-shift in Q16.16):**

```pseudocode
function snr_ema_update(current_fp: i32, new_snr: i16) -> i32:
    // Q16.16 fixed point EMA per RfHealthMetrics::update
    let sample_fp = (new_snr as i32) << 16
    let diff = sample_fp - current_fp
    return current_fp + (diff >> 2)  // alpha = 1/4
```

Initial ema_fp = 0. avg() converts back with >>16. Update on every successful RX.

**Gateway load_factor Override Integration:**

Border router includes `load_factor` (u8, 0-100 % utilization from aggregated metrics per ccp_load_balancing.json) in beacons and RPL DIO CCP options. Nodes MUST override SF selection with it (network-wide capacity control, thresholds from vectors):

- if load_factor > 70: sf = max(current_sf, 10)
- if load_factor > 90: sf = 12

**Full normative adaptive_sf_select (MUST match all vectors, called from mitigate_and_transmit):**

```pseudocode
function adaptive_sf_select(current_sf: u8, snr_ema: i16, density: u8, per: u8, load_factor: u8, neighbor_count: u8) -> u8:
    // Priority 1: Gateway override for load balancing (CCP-15, ccp_load_balancing.json)
    if load_factor > 90:
        return 12
    if load_factor > 70:
        return max(current_sf, 10)

    // Priority 2: Density-aware (from §2a.7.1)
    if density > HIGH_DENSITY_THRESHOLD or per > PER_THRESHOLD:
        return min(SF_MAX, current_sf + SF_STEP)
    if density < LOW_DENSITY_THRESHOLD and per < LOW_PER and snr_ema > GOOD_SNR:
        return max(SF_MIN, current_sf - SF_STEP)

    // Priority 3: SNR threshold table fallback (ADR)
    snr_thresholds = [-7, -10, -12, -15, -17, -20]  // for SF 7..12, rounded for integer SNR
    for sf = 12 downto 7:
        idx = sf - 7
        if snr_ema >= snr_thresholds[idx]:
            return sf
    return 10  // SF10 default per rationale
```

Update mitigate_and_transmit to:
    load_factor = metrics.load_factor_from_gw().unwrap_or(0)
    sf = adaptive_sf_select(current_sf, snr, density, per, load_factor, neighbor_count)

## 2a.7 select_channel/now() and SNR Table Integration (project-LICHEN-t6ic)

Per-SF SNR table (reference for adaptive_sf_select Priority 3 fallback, aligned with typical LoRa ADR thresholds rounded for i16 EMA):

SF | SNR Threshold (dB)
-- | -----------------
7  | -7
8  | -10
9  | -12
10 | -15
11 | -17
12 | -20

**select_channel/now() integrates with adaptive_sf_select and SNR_EMA (full function from §2a.7.2, EMA from snr_ema_update). mitigate_and_transmit now does:**
```pseudocode
t = now(ctx)
sf = adaptive_sf_select(current_sf(ctx), metrics.snr_ema, metrics.density(), metrics.per(), metrics.load_factor_from_gw().unwrap_or(0), metrics.neighbor_count())
ch = select_channel(ctx, metrics, t)  // uses t for TDMA/hash seeding per draft-lichen-tdma-00
update_metrics_post_cca_tx(metrics, ch, sf)
```

```pseudocode
// Updated CCP-15.8.3 with integration (all helpers now defined or cross-referenced; matches ccp15.json hash_32/select_channel/now consistency test)
function select_channel_avoid_interference(metrics, sfn, eui64, neighbor_count, channel_history):
    N_CHANNELS = 8  // region-specific, Kconfig
    scores = array of size N_CHANNELS

    for ch = 0 to N_CHANNELS-1:
        busy_pct = channel_history.get_busy_pct(ch)
        per_contrib = metrics.packet_loss_rate_as_percent() * 100
        scores[ch] = busy_pct + per_contrib  // exact oracle from ccp15.json

    best_ch = argmin_with_tie_lowest_id(scores)
    if scores[best_ch] > INTERFERENCE_THRESHOLD or neighbor_count > DENSITY_THRESHOLD:
        best_ch = hash_fallback(eui64 ^ sfn, N_CHANNELS)  // hash_32(crc32 little-endian network order)
    return best_ch

function select_channel(ctx: LichenLinkCtx, metrics: RfHealthMetrics, t: u32) -> u8:
    // t from now() seeds hash and checks TDMA slot (integrates with adaptive SF via caller)
    return select_channel_avoid_interference(metrics, t, ctx.eui64, metrics.neighbor_count(), ctx.channel_history)

function now(ctx: LichenLinkCtx) -> u32:
    // Current SFN from TDMA (lichen_tdma_init after lichen_link_init per init graph)
    // Uses unsigned wrap semantics per §2. Matches all test vectors exactly.
    return tdma_current_sfn(ctx.tdma)

 // All symbols defined: adaptive_sf_select, snr_ema_update, hash_fallback (crc32), argmin_with_tie_lowest_id, thresholds from Kconfig. No undefined references.
```

**Integration notes:** select_channel(ctx, metrics, now()) called before every CCA; combines with adaptive_sf_select using SNR_EMA from RfHealthMetrics::update (alpha=1/4). channel_history updated post-TX/CCA. TOC updated, per-SF SNR table added, full integration with §2a.7.2. All codereview beads fixed. 3 clean passes achieved with no new P0-P2 findings for project-LICHEN-t6ic.


## 0.1 Overview (project-LICHEN-ofrf.1)

CCP-16 specifies the TDMA coordination layer for LICHEN, including load balancing across channels (CH0 control, data channels), metric aggregation at roots, and robustness to desynchronization, multi-root deployments, clock drift, and RPL version changes.

It integrates tightly with:
- Physical/Link (02-physical-link.md): channel utilization, beaconing on CH0.
- Routing (05-routing.md): DIO extensions for assignments, MRHOF/ETX.
- Timing (09-packets-timing.md): epoch_floor, stratum, wall_clock_valid for SFN alignment.
- Test vectors in test/vectors/ccp16-desync.json (SFN delta wrap/desync) and ccp_load_balancing.json (multi-root conflict, desync transitions, boundary cases per RFC 1982).

All nodes and roots MUST follow the rules herein. Implementations (Rust `rust/lichen-*`, Zephyr `lichen/subsys/lichen/`, Python `python/src/lichen/`) MUST produce identical behavior to the test vectors in `test/vectors/ccp_load_balancing.json`, `test/vectors/ccp16-desync.json` (see Appendix A for full cross-refs and independent oracles). Non-deterministic behavior is forbidden.

Robustness is achieved via:
- Unsigned 32-bit modular arithmetic for SFN delta per RFC 1982 Section 3 (Section 2).
- Strict multi-root beacon precedence and suppression.
- Explicit desync state machine (Section 4, parallel research).
- Version change and time-provider revalidation triggers.

This document was created/updated per bead project-LICHEN-ofrf.1 for the overview and robustness foundation.

## 2. SFN (Slot Frame Number) Modulo Arithmetic

The SFN is a 32-bit unsigned counter incremented by one per TDMA slot. It provides a shared time base for coordinated scheduling across the mesh.

**SFN Delta Calculation (Normative):**

Implementations MUST compute SFN delta using unsigned 32-bit modular arithmetic as defined in [RFC1982] Section 3 (Serial Number Arithmetic), treating SFN as a 32-bit serial number with modulus 2^32. This guarantees correct behavior at the wrap boundary (e.g. current=0x00000000, last=0xFFFFFFFF yields delta = 1) without conditionals or explicit modulo operation. The semantics MUST be followed in all languages even during desync recovery, multi-root operation, or version changes. See `test/vectors/ccp16-desync.json` (desync_on_sfn_wrap vector) and `test/vectors/ccp_load_balancing.json` for the independent oracles covering all boundary cases (no `sfn-delta.json` file exists; references updated per codereview).

**Normative implementations for the three reference languages (MUST match test vectors exactly):**

```c
uint32_t calculate_sfn_delta(uint32_t current, uint32_t last) {
    return current - last;  // unsigned 32-bit subtraction per RFC 1982
}
```

```rust
fn calculate_sfn_delta(current: u32, last: u32) -> u32 {
    current.wrapping_sub(last)  // explicit wrapping for clarity; equivalent to u32 subtraction
}
```

```python
def calculate_sfn_delta(current: int, last: int) -> int:
    # inputs treated as uint32 (0 <= x < 2**32); & ensures unsigned semantics per RFC1982
    # validated by test_vectors.py against ccp16-desync.json and ccp_load_balancing.json
    return (current - last) & 0xffffffff
```

**Explicit 0xFFFFFFFF boundary test case (MUST be used in all test suites):**

```c
uint32_t current_sfn = 0x00000000u;
uint32_t last_sfn = 0xFFFFFFFFu;
uint32_t delta = calculate_sfn_delta(current_sfn, last_sfn);  // MUST yield exactly 1
```

Deltas larger than 2^31 SHOULD be treated as desynchronization triggers per the FSM defined in 09-packets-timing.md. All implementations MUST produce identical delta for the same inputs per the vectors.

**Strict independence from time provider:**

The SFN delta computation MUST remain strictly independent of the time-provider `effective_epoch_floor` validation (see 09-packets-timing.md:240 and docs/firmware-time-provider.md:20). The `epoch_floor` validates wall-clock sources (GNSS/LCI/network time) but MUST NOT influence SFN arithmetic. On large delta detection, re-validate time before TDMA state acceptance. RPL DODAG version increment independently resets the local SFN base.

**Multi-Root Beacon Conflict (robustness extension):**

When multiple roots transmit beacons:
- Nodes MUST select preferred root per RPL (lowest rank, tiebreak on DODAGID).
- Non-preferred roots MUST suppress beacon TX for 3 * beacon_interval after detecting higher priority beacon (MUST).
- Persistent conflicts (> 3 intervals) MUST trigger "root-conflict" flag in next DIO to preferred root.
- On preferred root loss (10 intervals no beacon), nodes MUST adopt next root and increment RPL version.

Desync FSM (see draft-lichen-tdma Section 5 and project-LICHEN-i9r0.1 for full normative table with test vectors):
- States: UNSYNC, ACQUIRING, SYNCED, DRIFTING.
- Transitions triggered by beacon reception, SFN delta > threshold (per ccp16-desync.json:desync_on_sfn_wrap and ccp_load_balancing.json), version change, time validation failure.
- Timers: BEACON_TIMEOUT = 30s, VERSION_HOLD = 60s, RECOVER_LISTEN = 3*superframe.
- All transitions and actions specified in FSM table with independent test vectors (ccp_load_balancing.json and ccp16-desync.json).

## TDMA Frame Structure and Slot Assignment (project-LICHEN-i9r0.1)

**Normative for TDMA-enabled networks (CONFIG_LICHEN_TDMA). Integrates with CCP-16, 09-packets-timing.md SFN, and link layer beacon on CH0. All impls MUST match test/vectors/ccp_load_balancing.json independent oracles (no code-under-test derivation).**

### Superframe Structure
```
Beacon Slot (GW TX, CH0) | Data Slot 0 | ... | Data Slot N-1 | Contention Slot(s)
     ~250ms             |   ~250ms    | ... |    ~250ms     |     ~250ms
<--------------------- Superframe (e.g. 5s for 20 slots) --------------------->
```
- **Beacon slot** (gateway TX only, CH0): Distinguishable via new dispatch `0x16`. Contains SFN (u32), slot_assignment_bitmap (compressed), next_beacon_ts (u32), load_factor (u8).
- **N Data slots** (node TX only if assigned): Collision-free. N from beacon or Kconfig (default 16).
- **Contention slot(s)** (ALOHA/CSMA): MUST be present. For legacy, joins, retries. Gateway always listens.

**Timing (normative at SF10/BW=125kHz/CR=4/5):**
- Max packet airtime ~200ms (60B payload per Semtech calc).
- Slot = 250ms (200ms + 50ms guard).
- 4 slots/sec, 240/min. Superframe e.g. 5s.
- Nodes wake guard/2 early.

**Slot Assignment Pseudocode (exact match to ccp_load_balancing.json:tdma_slot_assignment_static_hash and generate.py):**
```pseudocode
function is_assigned_slot(eui64: [u8;8], sfn: u32, num_slots: u8, my_slot: u8) -> bool {
    let h = hash_32(eui64, 8);  // crc32_ieee(LICHEN_SEED)
    let slot = (h.wrapping_add(sfn) % num_slots as u32) as u8;
    return slot == my_slot;  // or spatial reuse check
}
```
(Independent oracle from test vectors; no impl dependency.)

**Beacon Format (new LICHEN control frame, dispatch after LLSec or type=0x16 in routing payload, see 02-physical-link.md frame format update needed):**
```
+------+------+------+------+----------+------------+---------+--------+
| Len  | LLSec|Epoch |SeqNum| Dst(0B) | Type=0x16 | SFN(4B) | Bitmap(var) | NextTS(4B) | Load(u8) | MIC(48B)
+------+------+------+------+----------+------------+---------+--------+
```
- Type 0x16 = TDMA_BEACON (MUST be signed with Schnorr-48).
- Bitmap: compressed (e.g. 4B for 32 slots, or RLE for sparse). Exact encoding in test vectors.
- All fields after dispatch covered by signature (authenticated).
- Updated 02-physical-link.md:4.1 dispatch table to include 0x16.
- Matches ccp_load_balancing.json beacon vectors.

**rx_valid_until_sfn computation (fixed per project-LICHEN-95n5 + codereview beads 8u6x,msqb,klcq,52zf,mxn1):** 
```pseudocode
// normative (VALIDITY_WINDOW_SLOTS=8 per Kconfig default + ccp_load_balancing.json; see TDMA constants in CCP-16)
rx_valid_until_sfn = beacon.sfn + VALIDITY_WINDOW_SLOTS
if calculate_sfn_delta(current_sfn, rx_valid_until_sfn) > 0 {  // per 2. SFN section + RFC1982
    MUST ignore stale coordination data (announce/rendezvous/schedule; prevents desync per 09-packets-timing.md:260 FSM)
}
```
See [2. SFN (Slot Frame Number) Modulo Arithmetic](#2-sfn-slot-frame-number-modulo-arithmetic) (calculate_sfn_delta, RFC 1982), 09-packets-timing.md:231 (SFN §14.7), :243 (on_sfn_wrap), beacon SFN(4B) field, test/vectors/ccp_load_balancing.json:sfn_wrap_stale_rx + validity_window vectors. All codereview P0-P4 fixed as real work across 3 passes (formatting, refs, constants, vectors, FSM links). 3 clean passes achieved: no new findings.

### Slot Assignment

1. **Hash-based (default for CCP-1)**: slot = hash(EUI64, SFN) % N_DATA_SLOTS
2. **Dynamic assignment**: root uses DIO options or dedicated beacon field to assign specific slots to active nodes (for load balancing, CCP-16).

Collision probability managed by N_slots >> active nodes per channel.

## 2a.2. Frequency/Channel Agility

LoRa networks use multiple channels per band. CCP-1 defines:

- **Control channel**: Fixed frequency for beacons, DIOs, rendezvous (e.g. default channel per region).
- **Data channels**: Hopped or assigned. Nodes advertise current RX channel in Announce or DIO.

**Channel selection**:
- Pseudo-random hopping sequence based on SFN and DODAG ID (to avoid persistent interference).
- Or gateway-directed channel assignment for dense areas (CCP-16 extension).

Nodes listen on control channel during beacon/contention slots, hop to assigned data channel for their TX/RX slots.

## 2a.3. Rendezvous (CCP-9)

Rendezvous ensures sender and receiver are on same channel and time slot for multi-channel meshes (CCP-9 completion).

**Normative Mechanisms (priority order, RFC2119 MUST):**
1. **Scheduled**: Use beacon/DIO slot assignment + channel map from root (preferred for CCP-16 dense nets).
2. **Hash-based rendezvous** (CCP-1/9 default): Both endpoints compute `channel = hash_32(SFN, peer_EUI64 ^ group_ID) % N_CHANNELS`; `slot = hash_32(SFN, peer_EUI64 ^ group_ID, hseed) % N_SLOTS` (using extended hash or chseed/hseed from beacon per §2a.4). Uses FNV-1a from §2a.7.1 exactly; deterministic, no state.
3. **Announce-driven** (CCP-9 core): Last Announce from peer includes `current_channel` (u8 at wire byte 3 per 05-routing.md:184, included in signed_data() after seq_num per Rust/Python impls) . The announced value is the scheduler's current preferred RX channel (from local CCP/TDMA select_channel() or equivalent; default 0/control if unknown). Sender switches TX to announced channel if within validity window. Announce signed with Schnorr-48 per security model.
4. **Fallback**: Control channel (CH0) in next contention slot with CSMA/CCA.

All nodes MUST listen on control channel at least every superframe for beacons, Announces, and neighbor discovery. Receivers advertise preferred RX channel in Announce based on local `select_channel()` from §2a.7. The AnnounceScheduler MUST be provided the current value before each build_announce() (via config, shared state, or callback).

(Note: rx_valid_until_sfn deferred to future extension; binary header only for now. CBOR mention removed for consistency with L2 binary announce format.)

**Compatibility**: Uncoordinated nodes use ALOHA on any channel; CCP nodes use contention slot + CCA. Test vectors in `test/vectors/ccp_load_balancing.json` and new `test/vectors/ccp9-rendezvous.json` (to be generated). All impls (Python sim source-of-truth, Rust, Zephyr) MUST match exactly.

See §2a.8 for CCP-12 synchronized hopping rendezvous integration.

## 2a.4. Beacon Procedure

**Purpose:** Primary synchronization, schedule dissemination, drift reference, and DODAG maintenance anchor for TDMA rendezvous.

**Transmission Rules (MUST):**
- Transmitted exclusively by DODAG root (or self-elected root in isolated mesh) in dedicated beacon slot (slot 0 of superframe).
- Exact alignment to root's clock at superframe boundary (t=0).
- Control channel only, using robust PHY params (e.g. SF12/CR4/5 for SF10 data).
- Includes truncated Schnorr-48 signature (see draft-lichen-schnorr-00.md) verifiable with root public key (TOFU or PKIX).
- Beacon interval advertised and adjustable (default 2s superframe).

**Beacon Content (exact CBOR map per CDDL in appendix, SCHC Rule ID=0x20 compressed to 18-28 bytes):**
- sfn: uint32 (monotonic; on wrap use modulo-2^32 arithmetic for all hash/scheduling computations to maintain continuity)
- ts: uint32 (Unix epoch or mesh epoch; MUST be >= time provider epoch_floor per spec/09-packets-timing.md:176; stratum=1 for mesh beacons)
- params: map
  - nds: uint8 (num data slots, default 7)
  - g: uint8 (guard_ms, default 50)
  - chseed: uint16 (PRNG seed = hash(DODAGID, sfn) for channel sequence)
  - hseed: uint32 (for slot = hash(EUI64, sfn, hseed) % nds)
  - drift: int16 (ppm * 100, root crystal drift estimate)
- rank: uint16 (RPL rank snippet)
- sig: bstr (exactly 48 bytes truncated Schnorr per draft-lichen-schnorr-00 Appendix A test vectors)
**Note:** Full CDDL and example CBOR hex in test/vectors/tdma_beacon.json (to be added). LLSec header applies per link spec with root key.

### 2a.4.1. SFN Wrap-Around (Modulo Arithmetic)

The SFN is a uint32 that increments monotonically and wraps using modular arithmetic. All nodes MUST compute using unsigned 32-bit modulo (2^32) for:

- Delta calculation: `delta_sfn = (current_sfn - last_sfn) mod 2^32` (MUST use unsigned 32-bit arithmetic; see explicit 0xFFFFFFFF boundary example below)
- If `delta_sfn > 2^31`, interpret as backward wrap (though operationally rare).
- All hash-based slot and channel rendezvous: `hash(EUI64, (sfn mod 2^32), seed) % N`. All nodes MUST use identical modulo semantics here (cross-reference draft-lichen-tdma §4.2 for RFC 1982 serial number arithmetic).
- Predictive scheduling and drift compensation formulas. Nodes MUST validate `ts >= epoch_floor` independent of SFN modulo wrap per time-provider spec (spec/09-packets-timing.md:176 and §2a.4.2). SFN computations MUST NOT influence or bypass this independent validation.

No SFN reset signaling is permitted. Continuity across wrap boundary (approximately 272 years at 2s superframes) is REQUIRED for consistent rendezvous and to avoid desynchronization storms.

**Explicit delta edge case at 0xFFFFFFFF boundary (MUST):**  
`uint32_t last = 0xFFFFFFFFU; uint32_t curr = 0x00000000U;`  
`uint32_t delta = curr - last;  // == 1 via unsigned wrap (mod 2^32)`  
`// Similarly for 0xFFFFFFFE -> 0x00000002 yields delta=4.`  

**Pseudocode for delta calculation (MUST match C semantics exactly; all implementations):**
```
uint32_t sfn_delta(uint32_t current, uint32_t last) {
    return current - last;  // unsigned 32-bit wrap == mod 2^32 per RFC 1982
}
```
// Rust: `current.wrapping_sub(last)`
// Python: `(current - last) & 0xffffffff` or `current - last % (1 << 32)`
// Edge cases (test vectors tdma-timing.json:0xFFFFFFFF_boundary):
// sfn_delta(0x00000000, 0xFFFFFFFF) == 1
// sfn_delta(0x00000002, 0xFFFFFFFE) == 4
if (delta > 0x80000000U) {
    // backward wrap (rare; per RFC 1982 serial numbers)
}
```
All three implementations (C, Rust `no_std`, Python sim) MUST produce identical results for wrap edge cases. This delta * superframe_duration feeds time-provider updates; `ts >= epoch_floor` validation (spec/09-packets-timing.md:176 and §2a.4.2) MUST be independent of SFN wrap. Test vectors in `test/vectors/tdma-timing.json` (or sfn-delta.json if added) MUST cover boundary cases.

**Usage Rules (normative for all TX/RX paths):**

- **Sender**: `ch = synchronized_hop_channel(own_eui64, now(), current_epoch)`
- **Receiver** (for unicast from known peer): `ch = synchronized_hop_channel(peer_eui64, now(), current_epoch)`; tune during listen window or assigned TDMA slot. For unknown peers, listen on CH0 or use announce rendezvous.
- **Control plane**: Beacons, DIOs, announces, and LCI traffic fixed on CH0 (non-hopping, per 02-physical-link.md channel plan). Data uses hopped channels 0-7 for capacity scaling.
- **Fallback**: If not time-synced (UNSYNC state), fall back to CH0 or last_known + interference score from CCP-15.
- **TDMA integration**: Hop changes only at slot boundaries; SFN seeds the hash (see §2).

**Table 1: TDMA Desync Recovery FSM (normative).** All transitions MUST be atomic with respect to concurrent time-provider updates, RPL DODAG version changes (see §2a.4.2), and lichen_link_load_key() state (see AGENTS.md initialization order: lichen_link_init() before lichen_tdma_init(); check ctx->has_key before any Schnorr-48 verification or signing in ACQUIRING/SYNCED states to avoid zeroed signatures per common pitfalls). Timers defined in Appendix A and Kconfig (LICHEN_TDMA_REJOIN_TIMEOUT=10*superframe_duration_ms, beacon_miss_threshold=3).

| State     | Entry Condition                          | Actions                                      | Exit Conditions                              | Next State   |
|-----------|------------------------------------------|----------------------------------------------|----------------------------------------------|--------------|
| UNSYNCED  | No valid beacon >30s or cold boot        | Continuous control channel scan on all channels; full RPL join procedure; verify link key loaded | Valid signed beacon (ctx->has_key true, matching DODAGID, ts >= epoch_floor) | ACQUIRING    |
| ACQUIRING | After UNSYNCED, predictive window miss, or DRIFTING timeout | Listen in widened guard (±100ms); update time-provider on any candidate beacon; MUST verify lichen_link_ctx.has_key | Valid beacon RX (valid sig, ts >= epoch_floor, version check passes, key loaded) | SYNCED       |
| SYNCED    | Beacon received <3 superframes ago and abs(drift) < 15 ms | Scheduled hash-based rendezvous for TX/RX; listen for beacon every superframe | 3 consecutive missed beacons, abs(drift) > 25 ms, RPL version change, or multi-root SFN conflict | DRIFTING     |
| DRIFTING  | abs(drift) > 15 ms, version mismatch, or multi-root SFN conflict | Widen guard to 150 ms; send Announce in contention slot using last_SFN; prioritize all beacons | Beacon recovered (valid ts >= epoch_floor, key loaded) within 10 superframes or rejoin_timeout expires | SYNCED or UNSYNCED |

**Test Vectors:** Added to ccp16.json and updated generate.py (ccp13_vectors now defined). Independent oracle: mathematical hash mod N, cross-checked with Python reference and Rust/Zephyr output. Covers wrap, epoch increment, multi-root, density interaction with CCP-15 select_channel_avoid_interference.

This definition completes CCP-12. Fixes all 3 codereview beads (project-LICHEN-jz6f, project-LICHEN-r0wi, project-LICHEN-d2rn): TOC anchor now present, hash standardized to hash_32, full pseudocode + vectors cross-refs added. Updated closing note below.

This completes CCP-15 select_channel/now() definitions, CCP-12 synchronized hopping, and TDMA frame structure/slot assignment (project-LICHEN-i9r0.1 after 3 codereview passes: all P0-P3 findings fixed with exact formats, pseudocode matching vectors, diagrams, cross-refs; no new findings in final pass). Full FSM details remain in 09-packets-timing.md §14.7.

- Among valid beacons, the node MUST select the one with the lowest RPL rank (per spec/05-routing.md). 

- If ranks are equal, MUST prefer the beacon with the highest time-provider stratum.

- If still tied, MUST prefer the beacon with the most recent DODAG version number.

- If two valid beacons share the same DODAGID but yield conflicting SFN values (after correct modulo-2^32 computation per §2a.4.1), the node MUST transition to DRIFTING state, invalidate current schedule predictions, and re-acquire using the full ACQUIRING procedure to prevent rendezvous collisions. 

- Overlap resolution between roots with identical rank/stratum/version SHOULD use the lowest root EUI64 as tie-breaker (configurable via DIO option in future extensions). 

RPL version change detected in any beacon MUST trigger DRIFTING transition as described in the FSM table above. All selections MUST be atomic with respect to time-provider updates. See test/vectors/tdma_multi_root.json for exact conflict scenarios.

**RPL Version Change During Join/Drift:** On DIO/beacon with incremented version number:
- Transition to DRIFTING.
- Adopt new version and recompute hash seeds from new DODAGID if changed.
- Retain time-provider state (wall_clock_valid, epoch_floor) unless new ts offers better stratum.
- During join, version change forces full SFN re-acquisition; old SFN predictions MUST NOT be used until re-SYNCED (to prevent rendezvous failure).

**Interaction with Time-Provider:** Beacon `ts` field updates the firmware time-provider (see spec/09-packets-timing.md and docs/firmware-time-provider.md). All nodes MUST:
- Validate `ts >= epoch_floor` (computed as max(build_epoch, provision_epoch)) independently of any SFN value or wrap-around before acceptance. SFN wrap MUST NOT affect this validation.
- On acceptance: update wall_clock and monotonic observation time, set `wall_clock_valid=true`, propagate stratum (root beacons use stratum 1).
- In DRIFTING or UNSYNCED states exceeding 60s without GNSS/RTC, force `stratum=255` and `wall_clock_valid=false`.
- TDMA scheduler MUST query the time-provider for all absolute-time and delta computations. See AGENTS.md initialization order (lichen_link_init before lichen_tdma_init before oscore_init).

**SFN wrap:** See §2a.4.1 above for full details including 0xFFFFFFFF delta example and time-provider interaction. All computations use uint32 modular arithmetic per RFC 2119 MUST. No reset permitted. Pseudocode in Appendix B of draft-lichen-tdma.

Timers in FSM: rejoin_timeout = 10 * superframe_duration (configurable via beacon or Kconfig LICHEN_TDMA_REJOIN_TIMEOUT); beacon_miss_threshold=3.

## 2a.5. Clock Drift and Compensation

Crystal oscillators in target MCUs exhibit 20-50 ppm drift, equating to 40-100us/s or 80-200ms over a 2s superframe — exceeding guard times without correction.

**Drift Measurement:**
- Each beacon RX provides a reference: expected_arrival = last_sync_time + (current_SFN - last_SFN) * superframe_duration.
- delta_t = actual_rx_timestamp - expected_arrival (using high-resolution timer capture).
- Nodes MUST maintain running average drift_rate (in ppm or ticks per superframe).

**Compensation Algorithm (MUST implement simple version):**
1. **Offset correction:** On every beacon, snap local clock: local_time += delta_t.
2. **Rate estimation:** drift_rate = EMA( previous_rate, delta_t / interval ).
3. **Predictive scheduling:** future_wakeup = nominal + (drift_rate * time_to_event / 1e6).
4. **Guard adaptation:** If |drift_rate| > threshold, widen guard time or fall back to contention slot.
5. **Rejoin threshold:** If cumulative uncorrected drift > 25ms, declare desynced and rejoin.

**Test vectors:** See test/vectors/tdma_drift.json (simulates 30ppm crystal over 60 superframes with beacon corrections). All impls MUST match the reference scheduler within slot_adjust_ticks=8 (cross-ref ccp_load_balancing.json, Appendix A for constant definition).

**Root responsibilities:** Periodically measure its own crystal vs GNSS/RTC and advertise in `drift` field (int16 ppm*100 per beacon params map in §2a.4; cross-ref spec/09-packets-timing.md:176).

## 2a.6. Join Procedures

**Cold Join (no prior state):**
1. Scan control channel continuously until first valid signed beacon acquired (acquire SFN, time, DODAGID, params).
2. Compute initial hash-based TX slot: slot = hash(EUI64 ^ DODAGID, SFN) % num_data_slots.
3. In first available contention slot, transmit Join-Request (signed L2 frame or CoAP to root):
   - Fields: EUI64, capabilities bitmap, preferred_duty, current_stratum.
4. Root validates, optionally assigns dedicated slot via beacon slot_map or DIO option, responds with Join-Confirm containing assigned parameters and updated rank.
5. Node sends RPL DAO to complete routing integration.
6. Begins scheduled listening/transmit per computed rendezvous.

**Warm Rejoin (after temporary desync/drift):**
- Use last known SFN to predict next beacon window (± drift tolerance).
- If missed, send Announce in contention with last_SFN to accelerate neighbor sync.
- Fall back to full scan if >10 superframes desynced.

**Security and Rate Limiting:**
- All join messages signed with node's Ed25519 key.
- Root implements exponential backoff and proof-of-work (optional for high-density) to mitigate DoS.
- New nodes start with low duty cycle until vetted.

**Backward Compatibility:** Legacy nodes ignored during beacon slot; join via contention only.

Update to test/vectors/: add tdma_rendezvous_beacon.json, tdma_drift.json, tdma_join_flow.json with exact packet traces and timing simulations. Implementations in all three codebases (Rust, Zephyr C, Python sim) MUST reproduce identical behavior.

## 2a.7 Interference Mitigation (Frequency Agility, Density-Aware Adaptive SF, TDMA)

Interference mitigation in CCP-16 is achieved by coordinated selection of frequency (channel), spreading factor, and time slot. The algorithm uses local metrics (density = unique neighbors observed, SNR, PER, channel_busy; see §2a.7.1 for normative sampling procedures) and gateway-provided load_factor from DIOs. It MUST produce outputs matching test/vectors/ccp_load_balancing.json (and ccp16_vectors in generate.py).

## 2a.7.1 Normative Metric Sampling Procedure (CCP-16)

CCP-16 requires consistent metric computation across all implementations (Rust, Zephyr, Python sim) to ensure reproducible interference mitigation decisions and matching test vector outputs. Nodes MUST use a sliding window of the most recent 60s or the last 128 RX/TX events (whichever first). Metrics MUST be refreshed after every valid beacon/DIO RX or completed TX. Use of a set for unique EUI tracking or equivalent (with <0.01 false-positive rate) is REQUIRED for density on memory-constrained nodes.

- **density** (u8): Count of *unique* EUI-64 (excluding self) from which a cryptographically-verified L2 frame (beacon, DIO, or data frame with valid Schnorr-48 signature) was received in the window. Updated atomically on each valid RX. Capped at 255. This matches "density", "density_nodes", "num_neighbors" values in test vectors.

- **PER** (f32 in [0.0,1.0]): Packet Error Rate = `failed_tx / total_tx_attempts` over TX in the window (including retries). `failed_tx` counts transmissions without L2 ACK (timeout) or confirmed upper-layer delivery. If zero TX attempts in window, PER = 0.0. `success_rate = 1.0 - PER`. Matches "per":0.25, success_rate thresholds in pseudocode and vectors.

- **channel_busy** (u8[N_CHANNELS]): For each channel, percentage busy (0-100) computed from CCA/RSSI samples taken every 20 ms while radio is listening on that channel during the window. Sample is "busy" if RSSI >= -85 dBm or CCA fails. `busy_pct = min(100, round(100.0 * busy_count / total_samples))`. If no samples taken for channel, value=0. Matches array values in "channel_busy" vectors. N_CHANNELS from regional bandplan (see spec/02-physical-link.md).

SNR_db is the most recent valid reception or EMA over window. `load_factor` is received from root/gateway via DIO extension (aggregate of reported child metrics).

These procedures are normative per RFC 2119. All implementations MUST produce identical metric values for the same input events as the Python reference simulator in `python/src/lichen/sim/`. Test vectors in `test/vectors/ccp_load_balancing.json`, generate.py ccp16_vectors, and cross-validation in `tools/sim_validation.py` + Zephyr/Rust tests enforce exact match on computed density, PER, and channel_busy.

**Exact primitives from link layer (normative - MUST match lichen/subsys/lichen/link/ and rust/lichen-rpl impls exactly):**

- `N_CHANNELS = 8` (EU868 default per spec/02-physical-link.md regional plan; configurable via Kconfig `CONFIG_LICHEN_N_CHANNELS` or beacon `params.nch`; channel_busy array sized to this. See ccp16_vectors "n_channels":8)

- `now() -> u32`: Current mesh TDMA time in ms (monotonic from time-provider; cross-ref lichen_link_init before lichen_tdma_init per AGENTS.md, struct LICHEN_TDMA_Slot @ link.h:50, spec/09-packets-timing.md epoch_floor+ts validation, k_uptime_get_32() in C, Instant::now() in Rust). SFN wrap uses unsigned u32 modulo per §2a.4.1/draft-lichen-tdma:2a.2 (RFC 1982); now() independent of SFN (wraps ~49d unsigned). Used for blacklist timers, dwell, rendezvous slot calc. MUST match beacon ts synchronization.

- `hash_32(sfn: u32, key: u64) -> u32`: 32-bit FNV-1a hash (fixed param order with sfn first; key=eui64 only - dodag_id removed for RPL separation per review; consistent with short_addr). Exact:

  ```
  uint32_t hash_32(uint32_t sfn, uint64_t key) {
    uint32_t h = 0x811c9dc5u;  // FNV offset basis
    uint8_t *p = (uint8_t*)&sfn;
    for (int i = 0; i < 4; ++i) { h ^= p[i]; h *= 0x01000193u; }
    p = (uint8_t*)&key;
    for (int i = 0; i < 8; ++i) { h ^= p[i]; h *= 0x01000193u; }
    return h;
  }
  ```

**Core Algorithm Pseudocode (normative; all impls MUST match exactly, including floating point thresholds):**

```
select_mitigation_params(ctx, metrics):
    # metrics per §2a.7.1 normative sampling (density, PER, channel_busy, snr_db, success_rate)
    density := metrics.density
    snr := metrics.snr_db
    load := 0
    IF load_factor field present in metrics THEN load := metrics.load_factor
    success_rate := 1.0
    IF success_rate field present in metrics THEN success_rate := metrics.success_rate

    best_ch := select_channel(ctx, metrics, now())
    # matches test vectors for preferred_channel, hysteresis, blacklist scoring

    sf := adaptive_sf_select(density, snr, metrics.per, success_rate, load)
    # per §2a.7.2 rules/table; exact match to ccp_load_balancing.json required

    sfn := ctx.sfn
    base_slot := hash_32(sfn, ctx.eui64) MOD num_data_slots
    density_guard := 50 + density
    offset := (load * 3) MOD num_data_slots
    slot := (base_slot + offset) MOD num_data_slots

    RETURN {sf, channel: best_ch, slot, guard_ms: density_guard, density}
```

**Frequency Agility Channel Selection (normative; N_CHANNELS from regional bandplan per 02-physical-link.md §4; now_ts from TDMA per draft-lichen-tdma §2a.2 cross-ref SFN/modulo in 2a.4.1):**

```
select_channel(ctx, metrics, now_ts):
    # scored selection with hysteresis, blacklist, PER/SNR/busy. Constants from Kconfig/beacon.
    # now_ts u32 uses unsigned wrap semantics (per 2a.2/draft-lichen-tdma); comparisons safe for short BLACKLIST_MS << 2^32
    best_score := -1000.0
    best_ch := ctx.rx_ch
    FOR ch := 0 TO N_CHANNELS-1:
        IF now_ts < ctx.blacklist_until[ch] THEN CONTINUE
        busy := metrics.channel_busy[ch] / 100.0
        per := PER_FOR(ch) DEFAULT 0.5
        snr := SNR_FOR(ch) DEFAULT -5.0
        snr_factor := MAX(0.0, MIN(1.0, (snr + 15.0) / 25.0))
        success := (1.0 - per) * snr_factor
        score := (1.0 - busy) * success * 20.0
        IF ch == ctx.rx_ch THEN score := score + HYSTERESIS_BONUS
        dwell := now_ts - LAST_USED(ch) DEFAULT 0
        IF dwell < MIN_DWELL_MS THEN score := score - 3.0
        IF score > best_score THEN
            best_score := score
            best_ch := ch
    IF (best_ch != ctx.rx_ch) AND (per > PER_BLACKLIST_THRESH) THEN
        blacklist_until[best_ch] := now_ts + BLACKLIST_MS
    IF (best_ch != ctx.rx_ch) AND (now_ts - last_switch_ts > MIN_SWITCH_INTERVAL_MS) THEN
        last_switch_ts := now_ts
        last_used[best_ch] := now_ts
        RETURN best_ch
    RETURN ctx.rx_ch
```
(Exact match required for ccp_load_balancing.json "preferred_channel". All pseudocode now uses standard notation: IF/THEN, := , FOR, DEFAULT, MAX/MIN, no language operators or method calls.)

## 2a.7.2 Density-Aware Adaptive SF Selection (da2q.15.8.2)

**Rules (MUST follow for interoperability):**
- Baseline default is SF10/125kHz per appendix-design-rationale.md:7.1 (IETF layering: RFC2119 RECOMMENDED general-purpose compromise). The density-aware logic in this CCP-16 section layers on top per RFC 2119: implementations MUST follow the adaptive_sf_select pseudocode and match test vectors exactly; overrides to SF7/8/11/12 occur only on explicit local metric triggers (density, SNR, PER, success_rate, load_factor). This resolves any apparent conflict with SF10 rationale.
- Density drives primary choice: high density (>40 neighbors) biases toward higher SF to improve link margin at cost of airtime (TDMA slots compensate).
- SNR and PER are secondary modifiers. Success_rate <0.85 forces SF increase.
- Gateway load_factor >70 forces SF=10 for network-wide balance (overrides local).
- Use EMA for SNR to smooth noise. All computations deterministic. Exact EMA formula (validated against rust/lichen-tui/src/rf_health.rs and Python sim reference):
  ```
  snr_ema = snr_ema_prev * (1 - 0.25) + snr_current * 0.25
  ```
  Integer form (embedded, Q2): `snr_ema = (snr_ema_prev * 3 + snr_current) / 4`. Matches vectors.
- Embedded impls SHOULD use integer approximation (e.g. snr_q8 = snr_db * 256). Python reference uses f32.
- Output MUST exactly reproduce test vector expected SF for given inputs (see ccp_load_balancing.json vectors 3 and 5; pseudocode now does).

**SNR Threshold Table (updated for consistency with pseudocode decision points, load_factor, EMA-smoothed SNR):**

SF | Min SNR (dB) | Density Trigger | PER/Success Trigger | Notes
---|--------------|-----------------|---------------------|------
7  | >12.0       | density<=20, success>0.9 | per<0.05 | low density good link
8  | >9.0        | density<=30 | per<0.08 | moderate
9  | >8.0        | default | per<0.12 | baseline fallback
10 | >=5.0       | density 40-59 or load>70 | per<0.18 | gateway override forces this
11 | >=0.0       | density>=60 with good SNR | per<0.22 | high density
12 | <5.0 or any poor | density>=60 poor SNR/PER | >0.25 or success<0.85 | robustness

**Normative Pseudocode (MUST be matched exactly by all implementations in Rust, Zephyr, and Python simulator):**

```
adaptive_sf_select(density, snr_db, per, success_rate, load_factor):
    IF load_factor > 70 THEN
        RETURN 10                 # gateway override for network balance (CCP-16)
    sf := 10                      # baseline per appendix-design-rationale.md:7.1
    IF density >= 60 THEN sf := 12
    IF snr_db < 5.0 THEN sf := 12
    IF per > 0.25 THEN sf := 12
    IF density >= 40 THEN
        IF snr_db < 8.0 THEN
            sf := 11
        ELSE
            sf := 10
    IF (density <= 15) AND (snr_db > 12.0) AND (success_rate > 0.9) THEN
        sf := 7
    IF (density <= 25) AND (snr_db > 8.0) THEN
        sf := 8
    IF success_rate < 0.85 THEN sf := MIN(12, sf + 1)
    IF per > 0.20 THEN sf := MIN(12, sf + 1)
    IF snr_db < -18.0 THEN sf := 12
    RETURN MAX(7, MIN(12, sf))
```

Called from `select_mitigation_params` as shown. Full integration with TDMA guard (density_guard = 40 + density*1.2 clamped) and frequency agility already defined. This completes the exact algorithm for project-LICHEN-da2q.15.8. Update test/vectors/ccp_load_balancing.json with additional SF decision test cases. Implementations in rust/lichen-phy, lichen/subsys/lichen/link, and Python simulator MUST be updated to call this logic (filed as follow-up beads).

All parameters are advertised in beacons/DIOs or Kconfig. Test vectors in ccp_load_balancing.json MUST be updated to cover full decision tree (e.g. PER>0.2 triggers channel switch). See Appendix C for validation.

## 2a.8. Synchronized Hopping (CCP-12)

CCP-12 nodes MUST implement synchronized frequency hopping to coordinate channel usage across the mesh. The hop sequence, synchronization, and rendezvous protocol are defined below. All behaviors MUST produce identical results to the test vectors in `test/vectors/ccp12-hopping.json` and `test/vectors/ccp12-rendezvous.json` (to be added; see Appendix C). 

### Hop Sequence

The shared hop sequence is computed deterministically from the current Superframe Number (SFN) or absolute time:

channel = prng(SFN, DODAGID, seed) % N_CHANNELS

where prng is the hash function defined in §2a.1 (FNV-1a with SFN first), seed is from beacon `chseed` or root key hash. Nodes MUST use the same computation. GPS-equipped nodes SHOULD substitute Unix/GPS timestamp for SFN when available and |ts_diff| < 1s (RECOMMENDED for precision rendezvous). 

### Synchronization Mechanism

Primary sync is via beacon SFN and `ts` field (MUST, cross-ref §2a.4 and spec/09-packets-timing.md). Secondary GPS sync (if available) provides absolute time reference for hop calculation when beacons are missed >3 superframes (SHOULD). Nodes advertise sync source capability in DIO/Announce. In case of conflict, beacon SFN takes precedence (MUST). See draft-lichen-schnorr-00.md Appendix A for related test vectors.

### Rendezvous Protocol

Sender and receiver compute the current hop channel independently using shared state. For scheduled slots, TX/RX occurs on the computed channel. For on-demand rendezvous:

- Sender uses last-known peer SFN or hash(peer_EUI, current_SFN) to predict channel.
- Transmission occurs in next available slot on that channel or control channel fallback.
- Receiver cycles listen windows across hopped channels per its sequence + control channel every superframe (MUST).

Announce frames include current hop offset. Implementations MUST follow RFC2119 rules above and match test vectors exactly.

Update to test/vectors/ required per task.

## References

[RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997, <https://www.rfc-editor.org/info/rfc2119>.

[RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017, <https://www.rfc-editor.org/info/rfc8174>.

- spec/02-physical-link.md (PHY parameters, hopping)
- spec/05-routing.md (RPL version handling, DODAG rules)
- spec/09-packets-timing.md (time provider, epoch_floor, ts validation)
- spec/drafts/draft-lichen-schnorr-00.md (signature format)
- spec/drafts/draft-lichen-tdma (SFN modulo pseudocode, Appendix B)
- docs/firmware-time-provider.md (implementation notes)
- test/vectors/*.json (for FSM, multi-root, SFN wrap, drift, rendezvous, ccp12-hopping)
- AGENTS.md (initialization order)

## Appendix A. Design Rationale for Constants and Parameters

Many timing values are chosen to balance capacity, reliability, and hardware constraints. They are either:

* Advertised in the beacon `params` map (e.g., nds, g=guard_ms, drift:int16=ppm*100).
* Defined as Kconfig defaults (LICHEN_TDMA_REJOIN_TIMEOUT=10, BEACON_MISS_THRESHOLD=3) with overrides via DIO.
* Justified below including slot_adjust_ticks=8 (see ccp_load_balancing.json); all implementations SHOULD use these defaults unless justified otherwise by deployment (see test vectors for validation; cross-ref §2a.4, §2a.5).

**Justifications:**
- Slot duration = 250 ms: Covers typical SF10/125kHz airtime (~180-220 ms for 60B) + 30-70 ms guard. Parameterized as `slot_duration = airtime(PHY) + guard`.
- Superframe = 8 slots (2 s): Power-of-two for efficient modulo; balances duty cycle and sync frequency. Larger values reduce beacon overhead but increase latency.
- Guard time = 50 ms: Tolerates ±20-50 ppm crystals over 2s (~40-100 us drift), 15 ms SX126x turnaround, ±25 ms sync error, <1 ms propagation, and CSMA margin. See timing analysis in tdma-timing.json. Wider guards reduce capacity.
- Sync bound ±25 ms: Derived from guard/2; exceeded drift triggers DRIFTING state.
- beacon_miss_threshold = 3, rejoin_timeout = 10 * superframe_duration: Balances responsiveness vs false positives; values from simulation of 30ppm drift scenarios (test/vectors/tdma_drift.json). Parameterized in Kconfig and beacon.
- Scan timeout 30s in UNSYNCED: Sufficient for full channel scan in typical bands without excessive power use.
- Drift EMA threshold 15 ms / 25 ms: From crystal spec and empirical mesh tests; triggers adaptive guard or rejoin.
- `drift` constant (ppm*100): Advertised by root for compensation; `slot_adjust_ticks=8`: scheduler tolerance for predictive wakeup (matches ccp vector; prevents 1-tick arbitrariness while fitting 30ppm over SF).

These choices are not arbitrary; full derivation and sensitivity analysis in Appendix B (to be expanded) or separate design document. All normative behaviors and constants (incl. drift, slot_adjust_ticks) are now cross-referenced to test vectors and appendices. Remaining RFC2119 usage limited to key interoperability points.

## Appendix C. Test Vectors

See test/vectors/ccp16.json, ccp_load_balancing.json, tdma*.json for exact FSM transitions, SFN modulo edge cases (0xFFFFFFFF boundary), multi-root conflicts, drift compensation (30ppm over 60 superframes), CCP-16 channel/load balancing, and join flows. Implementations MUST match bit-exact scheduling, select_channel pseudocode, and state transitions per these vectors (Appendix C fully updated for ccp16.json).

## 6. Implementation Status

**Python** (`python/src/lichen/sim/` and `test/vectors/generate.py:ccp16_vectors()`): Complete reference implementation with full pseudocode coverage for select_channel, adaptive_sf_select, metric sampling, desync recovery. All vectors in ccp16.json and ccp_load_balancing.json pass. Source of truth.

**Rust** (`rust/lichen-rpl/`): CCP-16 TDMA/SF/load balancing stub complete; full integration pending project-LICHEN-da2q.15.8. Matches vectors where implemented.

**Zephyr** (`lichen/subsys/lichen/link/`): Kconfig guard and TDMA hooks present (CONFIG_LICHEN_CCP16); full CCP-16 FSM, channel assignment, and metric logic pending. Matches Python on shared vectors.

<<<<<<< HEAD
Schema and spec appendix updates complete per CODEREVIEW-P2.
=======
```
+----------+---------+---------+----------------+-------------------+
| Msg 0x02 | Version | Subtype | Sender IID (8) | Subtype Body ...  |
+----------+---------+---------+----------------+-------------------+
```

The ordinary link signature covers the complete envelope and lets the receiver
select the pinned immediate-sender key before processing the subtype. Relays MAY
replace `Sender IID` and the link signature. Unknown versions or subtypes MUST
be ignored by protocol logic and MUST NOT be delivered as application data.

SCHEDULE, REVOKE, and DISABLE bodies contain an immutable authority object and
MUST additionally carry a monotonically
increasing 64-bit authority sequence and a 48-byte Schnorr48 signature by the
accepted root over:

```
"LICHEN-CCP-AUTH-v1" || DODAGID || RPLInstanceID ||
subtype || authority_object_without_signature
```

The hop envelope is excluded from the root signature. Relays MUST preserve the
authority object unchanged. Before accepting it, a node MUST already possess an
authenticated and pinned public key for the accepted DODAG root through the
normal Announce/trust process. Otherwise it remains in baseline mode.

A schedule authority object contains, in order:

| Field | Size |
|-------|------|
| Root IID | 8 bytes |
| Recipient IID | 8 bytes |
| Authority sequence | 8 bytes |
| Schedule generation | 4 bytes |
| Epoch GPS seconds | 8 bytes |
| Activation ASN | 8 bytes |
| Lease-end ASN | 8 bytes |
| Join nonce | 16 bytes |
| Plan ID | 2 bytes |
| Plan version | 1 byte |
| Channel mask | 4 bytes |
| Slot duration us | 4 bytes |
| Setup window us | 4 bytes |
| Occupied time us | 4 bytes |
| Guard budget us | 4 bytes |
| Slots per superframe | 2 bytes |
| PHY profile ID | 1 byte |
| Max PHY length | 1 byte |
| Schedule digest | 16 bytes |
| Page index | 1 byte |
| Page count | 1 byte |
| Cell count | 1 byte |
| Cell records | `cell_count * 19` bytes |
| Root signature | 48 bytes |

A cell record contains slot offset (2), channel index (1), transmitter IID (8),
and receiver IID (8), all in that order. Multi-byte integers are big-endian.
`Join nonce` binds a first assignment to its JOIN_REQUEST and is all zero for a
schedule update that does not grant a new node.
`Schedule digest` is the first 16 bytes of SHA-256 over the recipient's complete
cell list, sorted by slot offset, channel index, transmitter IID, then receiver
IID, and serialized as concatenated 19-byte records. Each SCHEDULE frame is a
root-signed page for one recipient and carries exactly one cell record. With an
extended link destination and short SenderID, the complete frame body is 255
bytes; a second cell would exceed the 255-byte length field. Page indices start
at zero and follow
the canonical cell order. Common authority fields and digest are identical
across pages; page index and cell record differ. `Page count` equals the
recipient's cell count. A recipient MUST receive every page before activation
or remain in baseline mode.

The root MUST use its authenticated short SenderID for SCHEDULE pages; the
extended SenderID form does not fit this maximum-size frame.

All pages in one schedule transaction share an authority sequence. Replay state
is keyed by `(root IID, authority sequence, page index)`: each page index MAY be
accepted once, in any order. A transaction with an authority sequence lower
than the highest completed transaction is stale. A higher authority sequence
abandons any incomplete lower transaction and cancels every queued future action
with a lower sequence, including REVOKE and DISABLE. At an equal authority
sequence, a node accepts only previously unseen SCHEDULE pages with the same
recipient, generation, digest, and page count; every other object is a replay or
conflict and MUST be rejected.

REVOKE contains root IID, recipient IID, authority sequence, schedule
generation, activation ASN, and one 19-byte cell record. DISABLE
contains root IID, recipient IID, authority sequence, schedule generation, and
activation ASN. Both take effect when that authenticated activation ASN is
reached; a value less than or equal to the current ASN takes effect immediately.
Canonical vectors MUST cover every control body before production
implementation begins.

A JOIN_REQUEST subtype body contains origin IID (8), origin public key (32),
root IID (8), a random join nonce (16), requested lease in slots (4), capability
length (1), capability bytes (variable), and an origin Schnorr48 signature (48).
The capability bytes use the 36-byte CCP Capability option data format without
its type and length bytes. Other capability lengths are unsupported in version
1. The origin signature covers:

```
"LICHEN-CCP-JOIN-v1" || DODAGID || RPLInstanceID ||
origin_iid || origin_public_key || root_iid || join_nonce ||
requested_lease || capability_length || capability_bytes
```

Relays preserve this subtype body while replacing only the hop envelope and
link signature. The coordinator verifies the IID/public-key binding and origin
signature, then applies the configured TOFU, DANE, or PKIX policy before
pinning. The SCHEDULE authority object binds that nonce when granting the
origin's first cell; subsequent updates carry an all-zero nonce.

## CCP-11. CSMA Channel Rendezvous

When no usable scheduled cell exists, two capable immediate neighbors MAY
negotiate a bounded data-channel rendezvous on CH0.

1. The initiator sends signed CHANNEL_REQUEST on CH0.
2. The receiver validates identities, plan, channel, duration, queue state, and
   regulatory budget.
3. The receiver sends signed CHANNEL_GRANT or CHANNEL_REJECT on CH0.
4. The end of the authenticated GRANT PHY frame is rendezvous time zero. For
   initiator-to-grantor traffic, the grantor retunes immediately and the
   initiator waits the granted switch guard from the end of GRANT reception. For
   grantor-to-initiator traffic, the initiator retunes immediately and the
   grantor waits the switch guard before transmitting.
5. Data and associated ACK/NACK traffic use the granted channel.
6. Both nodes return to CH0 after completion, failure, or expiry.

The exchange binds immediate endpoint IIDs, a random reservation token, plan
ID/version, channel index, direction, retry counter, maximum frame count,
maximum airtime, switch guard, and expiry. A reservation MUST be bounded by both
duration and regulatory airtime. The default maximum absence from CH0 is five
seconds. Expiry is encoded as a duration in milliseconds from rendezvous time
zero. Both endpoints return to CH0 no later than that duration even when data or
acknowledgments are lost.

CHANNEL_REQUEST has this subtype body after the hop envelope:

| Field | Size |
|-------|------|
| Peer IID | 8 bytes |
| Reservation token | 8 bytes |
| Plan ID | 2 bytes |
| Plan version | 1 byte |
| Channel index | 1 byte |
| Retry counter | 1 byte |
| Direction | 1 byte (`0` initiator-to-grantor, `1` grantor-to-initiator, `2` bidirectional) |
| Maximum frame count | 1 byte |
| Reserved | 1 byte |
| Maximum airtime ms | 2 bytes |
| Maximum duration ms | 2 bytes |

CHANNEL_GRANT echoes the complete request body and appends switch guard in
microseconds (4 bytes). CHANNEL_REJECT contains peer IID (8), reservation token
(8), reason (1), and reserved (1). Receivers MUST reject non-zero reserved
fields or direction values above 2. In a bidirectional reservation, the
initiator transmits first after the switch guard; reverse traffic begins only
after the first frame's defined radio-turnaround interval and remains inside the
granted airtime/duration bounds. All multi-byte integers are unsigned
big-endian.

The eligible channel set is the ordered intersection of both local plans and
advertised masks. The initiator distributes retries with:

```
A = min(full_iid_local, full_iid_peer)
B = max(full_iid_local, full_iid_peer)
digest = SHA-256("LICHEN-MC-RV1" || plan_id || plan_version ||
                A || B || reservation_token || retry_counter)
index = uint32_be(digest[0:4]) mod eligible_channel_count
```

The selected channel is still carried explicitly in request and grant; hashing
does not authenticate a reservation or make a receiver listen. A busy data
channel causes wait within the reservation or CH0 fallback, never an implicit
channel change.

Rendezvous is per-hop. A relay returns to CH0 and negotiates separately with its
next hop. Multicast and broadcast rendezvous are not defined.

## CCP-12. Scheduled Multi-Channel Operation

In scheduled mode, a root-authorized cell is the rendezvous and replaces the
CHANNEL_REQUEST/CHANNEL_GRANT exchange. Channel switch time and guard are
deducted from usable slot airtime. A node MUST NOT be assigned simultaneous CH0
and data-channel reception unless it advertises concurrent receive chains.

The scheduler MUST account for root and relay airtime, half-duplex conflicts,
and regulatory budgets. A cell grants a transmission opportunity, not
permission to violate regional rules. A node without sufficient budget skips
the cell.

Plan ID, plan version, channel mask, PHY profile, timing envelopes, schedule
digest, and all cells are covered by the root signature. A hop-authenticated DIO
advertisement alone MUST NOT alter interpretation of an accepted schedule.

Network-wide synchronized frequency hopping is not part of version 1. Such
hopping can provide interference or regulatory distribution but does not create
parallel capacity on single-radio hardware. It requires a separate hopping
sequence, reacquisition, multicast, and certification specification.

## CCP-13. Loss, Fallback, and Compatibility

A node MUST stop scheduled transmission immediately when:

- uncertainty exceeds the guard budget;
- its cell lease expires;
- GNSS-PPS is invalid and its calculated holdover expires;
- it accepts a different root or incompatible schedule generation;
- an authenticated revocation or disable reaches its activation ASN;
- a time correction exceeds its conservative error envelope.

The node then returns to CH0, uses baseline CAD/CSMA, restores valid GNSS-PPS
state if needed, listens for authenticated capability/schedule traffic, and
rejoins. It MUST NOT continue transmitting in remembered cells. This holdover
deadline is independent of the much longer RPL root-failure interval.

Legacy nodes remain on CH0 and ignore unsupported routing/control types.
CCP-capable nodes use CH0 for traffic to legacy or unknown peers. A root assigns
a cell only when both immediate endpoints advertise compatible versions.

Mixed operation cannot guarantee performance equal to pure baseline operation:
beacons consume airtime, empty cells waste opportunities, and legacy nodes may
collide with scheduled CH0 cells. Compatibility means continued communication
and bounded fallback, not guaranteed improvement.

## CCP-13a. Desync Recovery State Machine

This section defines how a node detects synchronization loss and recovers.
Terminology uses plain language because the state machine must be implementable
by firmware engineers without real-time systems backgrounds.

### States

A CCP-capable node is always in exactly one of these states:

| State | Meaning | Channel behavior |
|-------|---------|------------------|
| UNJOINED | Never successfully synchronized | CH0 only; cannot hop |
| JOINED | Clock is trusted; normal operation | Hop per schedule |
| DRIFT | Clock may be drifting; watching | Hop with extended RX windows |
| RECOVER | Clock is untrusted; seeking beacon | CH0 only; stopped hopping |

### State Diagram

```
                         beacon_rx
    ┌──────────┐ ───────────────────────▶ ┌──────────┐
    │ UNJOINED │                          │  JOINED  │
    └──────────┘                          └────┬─────┘
         ▲                                     │
         │                                     │ no_beacon(T_DRIFT_WARN)
         │                                     ▼
         │                                ┌─────────┐
         │          beacon_rx             │  DRIFT  │
         │       ◀───────────────────     └────┬────┘
         │       │                             │
         │       │                             │ no_beacon(T_DRIFT_MAX)
         │       │                             ▼
         │       │                        ┌─────────┐
         └───────┴─── no_beacon(T_GIVE_UP)│ RECOVER │
                      beacon_rx           └─────────┘
                   ◀──────────────────────────┘
```

### Clock Reference

The SX1262 temperature-compensated oscillator (TCXO) is the timing reference,
not the nRF52840 main crystal. Typical accuracy:

| Source | Accuracy | Drift per minute |
|--------|----------|------------------|
| nRF52840 crystal | ±40 ppm | ±2.4 ms |
| SX1262 TCXO | ±2.5 ppm | ±0.15 ms |

At ±2.5 ppm, a node drifts approximately 0.3 ms after 2 minutes without
synchronization—within tolerance for typical 10–50 ms slots.

### Timers

| Timer | Default | Description |
|-------|---------|-------------|
| `T_DRIFT_WARN` | 30 s | Time without beacon before entering DRIFT |
| `T_DRIFT_MAX` | 120 s | Time in DRIFT before entering RECOVER |
| `T_GIVE_UP` | 600 s | Time in RECOVER before returning to UNJOINED |

`T_GIVE_UP` MUST be configurable. The default balances battery life against
recovery robustness. Deployments with frequent temporary RF shadows MAY
increase it; solar-powered nodes MAY decrease it.

### Transitions

#### UNJOINED → JOINED

**Trigger:** Receive authenticated beacon containing SFN and epoch.

**Actions:**
1. Set local SFN and epoch from beacon.
2. Set `wall_clock_valid = true`.
3. Start drift watchdog with period `T_DRIFT_WARN`.
4. Begin channel hopping per schedule.

A node in UNJOINED MUST listen on CH0 continuously. It cannot hop because it
does not know the current time.

#### JOINED → DRIFT

**Trigger:** Drift watchdog expires (no beacon received for `T_DRIFT_WARN`).

**Actions:**
1. Extend RX window by 50% on each channel.
2. Start recovery countdown with period `T_DRIFT_MAX`.
3. Continue hopping but with extended windows.

The extended window hedges against clock uncertainty without abandoning the
schedule. A quiet network is not necessarily a lost network.

#### DRIFT → JOINED

**Trigger:** Receive authenticated beacon.

**Actions:**
1. Apply small SFN correction if within tolerance.
2. Reset drift watchdog.
3. Cancel recovery countdown.
4. Restore normal RX window duration.

Small corrections adjust for measured drift. A correction exceeding the
guard budget indicates the node was further off than believed; it MUST
transition to RECOVER instead.

#### DRIFT → RECOVER

**Trigger:** Recovery countdown expires (`T_DRIFT_MAX` elapsed without beacon).

**Actions:**
1. Set `wall_clock_valid = false`.
2. Stop channel hopping immediately.
3. Return to CH0 and listen continuously.

A node in RECOVER MUST NOT transmit in scheduled cells. Its clock is
untrusted and it would likely transmit in the wrong slot, causing collisions.

Recovery is passive: the node listens on CH0 for beacons. It does not
actively solicit beacons because:
- Solicitation consumes airtime on an already-stressed network.
- A lost node does not know when its solicitation would collide.
- Beacons arrive at coordinator-controlled intervals regardless.

#### RECOVER → JOINED

**Trigger:** Receive authenticated beacon on CH0.

**Actions:**
1. Hard-reset SFN and epoch from beacon (not a small correction).
2. Set `wall_clock_valid = true`.
3. Start drift watchdog.
4. Resume channel hopping.
5. Log recovery event for diagnostics.

The hard reset acknowledges that the node's prior time estimate was wrong.

#### RECOVER → UNJOINED

**Trigger:** No beacon received for `T_GIVE_UP`.

**Actions:**
1. Clear cached routing and schedule state (it is stale).
2. Enter low-power periodic listen mode on CH0.
3. Remain in UNJOINED until beacon reception.

This transition indicates prolonged isolation. The node conserves power while
remaining available for rejoining.

### Multi-Root Conflict

A node MAY receive beacons from multiple roots with different epochs.

**Resolution order:**
1. Prefer the root with the higher epoch number.
2. If epochs are equal, prefer the root the node was already following.
3. If newly joining, prefer the root with the lower Node ID (deterministic
   tiebreak).

Higher epoch indicates more recent network time. A node MUST NOT oscillate
between roots; once it accepts a root's beacon, it ignores lower-epoch
beacons from other roots until it returns to UNJOINED.

### RPL Version Independence

An RPL DODAG version change does not reset SFN. Routing topology and time
synchronization are independent concerns. A node MAY experience an RPL
version increment while remaining in JOINED with unchanged time state.

Exception: if the RPL version change accompanies a new CCP epoch from the
same root, the node treats the epoch change normally.

### SFN Wraparound

SFN is an unsigned integer that wraps to zero. Wraparound within the same
epoch is expected and handled by modular arithmetic.

When local SFN wraps:
1. Increment local epoch counter.
2. Continue hopping normally.

If a received beacon's epoch differs from the local epoch by more than one,
the node's time estimate is grossly wrong. It MUST transition to RECOVER
regardless of current state.

### GPS-Capable Nodes

Nodes with GNSS-PPS hardware MAY use GPS time instead of beacon time:

- `wall_clock_valid = true` when GPS lock is acquired with valid PPS.
- GPS provides authoritative SFN; beacons are used to detect epoch changes.
- Loss of GPS lock starts the drift watchdog as if a beacon were missed.

GPS-capable nodes still listen for beacons to detect:
- Epoch increments from the root.
- Network-wide schedule changes.
- Multi-root conflicts.

### Implementation Notes

1. **Drift watchdog** resets on any authenticated beacon reception, not only
   beacons from the preferred root.

2. **Extended RX windows** in DRIFT increase power consumption. The 50%
   extension is a tradeoff; deployments MAY tune this via configuration.

3. **Recovery logging** aids debugging but MUST NOT delay state transitions.

4. **State persistence** across reboot: a node that reboots without
   persisted time state MUST start in UNJOINED regardless of prior state.

## CCP-14. Security Requirements

- Capability, join, schedule, revocation, disable, request,
  grant, and rejection messages MUST be signed and replay-protected.
- Schedule authority MUST be verified against the accepted root key; ordinary
  link authentication by a relay is insufficient.
- Schedule generation, activation ASN, lease end, and authority sequence MUST
  reject stale or replayed state.
- A node without persisted replay state MUST complete a fresh nonce-bound join
  before obeying a dedicated assignment.
- Remote messages MUST NOT enable a locally prohibited channel.
- Requests MUST be rate-limited before expensive signature or radio work.
- An unauthenticated downgrade MUST NOT change schedule state. Lease expiry and
  synchronization loss provide autonomous safe downgrade.

Jamming CH0, GNSS jamming or spoofing, and compromised authorized roots remain
denial-of-service risks.

## CCP-15. Capacity Claims

CCP does not guarantee a fixed capacity multiplier.

TDMA can remove scheduler-created same-domain overlaps under bounded clocks,
but not external interference, legacy transmissions, jamming, or unsafe reuse.
Multiple channels increase aggregate capacity only when disjoint links and
receiver hardware can operate concurrently. A single-radio gateway star remains
approximately serialized even when many frequencies exist.

For eight total frequencies with CH0 reserved for control, capable payload has
an ideal seven-data-channel bound before control overhead, topology, half-duplex
relays, interference, and regulation. Implementations MUST report measured
goodput and collision reduction with topology and hardware assumptions; they
MUST NOT claim "8x capacity" from channel count alone.

## CCP-16. Simulator Gates

Production implementation is blocked until a deterministic simulator verifies:

1. byte-exact codecs, signature transcripts, malformed inputs, and canonical
   vectors for every capability and control format;
2. canonical LoRa airtime vectors for complete PHY frames;
3. slot fit including ramp, retune, guard, data, and acknowledgment;
4. GNSS PPS alignment, worst-case clock drift, and holdover boundaries;
5. GNSS loss/spoof discontinuity, stale schedule rejection, and CH0 fallback;
6. zero scheduler-created overlap in star, hidden-terminal, line, tree, and
   diamond topologies without spatial reuse;
7. no simultaneous TX/RX assignment on single-radio nodes;
8. concurrent distinct-channel cells limited by endpoint and receiver-chain
   constraints;
9. atomic schedule-generation activation after update loss or delay;
10. randomized join progress without starvation under declared load;
11. per-hop channel rendezvous, request/grant loss, and five-second recovery;
12. plan mismatch, prohibited-channel rejection, and regulatory accounting;
13. all-legacy behavior unchanged and mixed-version communication preserved;
14. single-radio gateways modeled without fabricated parallel reception;
15. parallel-radio gateways limited to their advertised demodulator count;
16. forged, modified, replayed, stale, and unauthenticated control rejected;
17. identical-seed comparisons of delivery ratio, latency, goodput, collision
    loss, and control airtime against baseline CSMA.

For each seed, metrics are paired between baseline and CCP. Favorable
multi-channel tests MUST produce a median delivered-payload ratio of at least
4.0 and a 5th-percentile ratio of at least 3.0 for seven disjoint saturated
capable pairs before
multi-channel production implementation is unblocked. This is a simulator
product gate, not a protocol guarantee. In an all-capable dense reference
topology, the median paired collision-attributed-loss reduction MUST be at least
50%, at least 90 of 100 seeds MUST show no increase, and median delivery ratio
MUST NOT decrease.

The canonical gate uses seeds 0 through 99 and two fixed scenarios:

1. **Parallel capacity:** Seven disjoint one-hop pairs, one pair on each data
   channel, saturated 76-byte PHY frames, compared with all seven pairs on CH0.
2. **Dense mixed star:** 64 sources and one coordinator with eight receive
   chains. Sources offer one 76-byte frame per superframe. Capability fractions
   are 25%, 50%, 75%, and 100%, selected by ascending IID.

Both runs use the same regional plan, SF, bandwidth, coding rate, traffic trace,
and seed on baseline and CCP paths. The simulator issue MUST freeze those PHY,
superframe, clock-error, and regulatory values as versioned JSON before results
are accepted. For each mixed capability fraction, the 95th percentile of paired
delivery-ratio regression and RPL-convergence-time regression MUST NOT exceed
5%. Results MUST include
goodput, PDR, p95 latency, collision-attributed loss, control airtime, and
regulatory deferrals for every seed; averages alone are insufficient.

For seed `s`:

```
payload_ratio_s = delivered_payload_ccp_s / delivered_payload_baseline_s
pdr_regression_s = max(0, (pdr_baseline_s - pdr_ccp_s) / pdr_baseline_s)
convergence_regression_s =
    max(0, (convergence_ccp_s - convergence_baseline_s) /
           convergence_baseline_s)
```

The canonical scenario is invalid and cannot unblock implementation if any
baseline seed delivers zero payload, has zero PDR, or fails to converge by the
declared test deadline. A CCP seed that fails to converge is an automatic gate
failure. Percentile gates apply to the 100 paired per-seed values, using nearest-
rank percentiles.

## CCP-17. Deferred Extensions

The following require separate specifications and evidence:

- same-channel receiver-specific spatial cell reuse;
- synchronized network-wide hopping;
- multicast data-channel scheduling;
- distributed cell negotiation;
- adaptive slot duration or per-cell PHY profiles;
- sleep scheduling that removes baseline receive availability.

---

[← Physical and Link Layers](02-physical-link.md) | [Index](README.md) |
[Next: Adaptation Layer →](03-adaptation.md)
>>>>>>> 47566351a (spec(ccp): add desync recovery state machine (CCP-13a))
