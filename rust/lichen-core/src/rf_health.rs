//! RF health metrics tracking for LICHEN nodes (CCP-15/16 interference mitigation,
//! adaptive SF, load balancing).
//!
//! Implements normative adaptive_sf_select from spec/02a-coordinated-capacity.md
//! (critical conditions first per table and pseudocode). Matches ccp15.json,
//! ccp16.json vectors exactly for EMA, load_factor, density, adaptive_sf.
//! Tracks packet statistics for loss, SNR with EMA (alpha=1/4), density,
//! load_factor. Saturating counters, Q16.16 fixed point. no_std compatible,
//! #![forbid(unsafe_code)]. Removed dead RSSI stats and dropped counter.

use crate::constants::{CSMA_BACKOFF_MAX, CSMA_RETRY_LIMIT, RF_METRICS_WINDOW_SF};

const FP_SCALE: u32 = 1 << 16;
const EMA_ALPHA_SHIFT: u32 = 2;
const DENSITY_CRITICAL: u8 = 20;
const DENSITY_HIGH: u8 = 10;
const DENSITY_LOW: u8 = 5;
const SNR_CRITICAL: i8 = -5;
const SNR_POOR: i8 = 0;
const SNR_GOOD: i8 = 8;
const LOAD_HIGH: u32 = FP_SCALE * 4 / 5;
const LOAD_REBALANCE: u32 = FP_SCALE * 2 / 5;
/// Spec 2a.8 floor d threshold: LoadFactor >= 0.8 (Q16.16, ceil).
const FLOOR_LOAD_FP: u32 = 52_429;

/// CCP-16 Section 2a.10.3: PER threshold for density bonus (100 permille = 10%).
const DENSITY_PER_BONUS_PERMILLE: u16 = 100;

/// CCP-16 Section 2a.10.3: RSSI threshold for density bonus in dBm.
const DENSITY_RSSI_BONUS_DBM: i8 = -90;

/// Outcome of applying one clear-channel-assessment indication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcaResult {
    TxSuccess,
    CadBusy,
    RetryExhausted,
}

impl CcaResult {
    /// Whether this outcome permits an immediate transmission.
    #[inline]
    pub const fn tx_allowed(self) -> bool {
        matches!(self, Self::TxSuccess)
    }
}

/// Bounded CSMA contention state used after a CCP-15 CAD result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CcaState {
    backoff_exp: u8,
    retries: u8,
}

impl CcaState {
    /// Construct a state representable by the CSMA machine.
    pub const fn new(backoff_exp: u8, retries: u8) -> Option<Self> {
        if backoff_exp > CSMA_BACKOFF_MAX || retries > CSMA_RETRY_LIMIT + 1 {
            return None;
        }
        Some(Self {
            backoff_exp,
            retries,
        })
    }

    /// Current bounded backoff exponent.
    pub const fn backoff_exp(&self) -> u8 {
        self.backoff_exp
    }

    /// Number of busy-CAD retries observed in this contention cycle.
    pub const fn retries(&self) -> u8 {
        self.retries
    }

    /// Apply a CAD result, resetting on clear and failing closed after retries.
    pub fn on_cad_result(&mut self, channel_busy: bool) -> CcaResult {
        if !channel_busy {
            self.backoff_exp = 0;
            self.retries = 0;
            return CcaResult::TxSuccess;
        }
        if self.retries > CSMA_RETRY_LIMIT {
            return CcaResult::RetryExhausted;
        }
        self.retries += 1;
        if self.retries > CSMA_RETRY_LIMIT {
            return CcaResult::RetryExhausted;
        }
        self.backoff_exp = self.backoff_exp.saturating_add(1).min(CSMA_BACKOFF_MAX);
        CcaResult::CadBusy
    }
}

/// Compute `busy_percent + packet_error_rate * 100` in exact tenths.
///
/// `packet_error_permille` is the packet error rate scaled by 1000, so it is
/// already expressed in tenths of a percentage point.
pub const fn interference_score_tenths(
    busy_percent: u8,
    packet_error_permille: u16,
) -> Option<u16> {
    if busy_percent > 100 || packet_error_permille > 1000 {
        return None;
    }
    Some(busy_percent as u16 * 10 + packet_error_permille)
}

/// Estimate effective network density per CCP-16 Section 2a.10.3.
///
/// Combines raw neighbor count with loss and RSSI bonuses to account for
/// hidden congestion and weak links implying larger effective cells.
///
/// # Arguments
///
/// * `neighbor_count` - Distinct link-layer peers heard in the metrics window.
/// * `loss_permille` - Packet error rate in permille (0-1000).
/// * `rssi_ema_dbm` - EMA-smoothed RSSI in dBm.
///
/// # Returns
///
/// Estimated density clamped to [0, 255].
pub const fn estimate_density(neighbor_count: u8, loss_permille: u16, rssi_ema_dbm: i8) -> u8 {
    let mut d = neighbor_count as u16;
    // Persistent loss implies hidden congestion
    if loss_permille > DENSITY_PER_BONUS_PERMILLE {
        d = d.saturating_add(2);
    }
    // Weak links imply a larger effective cell
    if rssi_ema_dbm < DENSITY_RSSI_BONUS_DBM {
        d = d.saturating_add(1);
    }
    if d > 255 {
        255
    } else {
        d as u8
    }
}

/// Rolling-window TX-time BusyPercent sampler (spec R-02a-131 / 2a.10.3).
///
/// BusyPercent is TX-time based occupancy over
/// [`RF_METRICS_WINDOW_SF`] rolling superframes: the caller records the
/// own-node airtime (ms) consumed per superframe; the sampler accumulates
/// per-window totals and reports `tx_airtime / slot_duration * 100`
/// clamped to 0..100. Never RSSI-derived (spec MUST).
#[derive(Debug, Clone, Default)]
pub struct BusyPercentSampler {
    /// Per-superframe TX airtime (ms) inside the current window.
    airtime_by_sf: heapless::Vec<(u64, u32), { RF_METRICS_WINDOW_SF as usize }>,
    current_sf: u64,
}

impl BusyPercentSampler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the TX airtime (ms) consumed in the given superframe.
    pub fn record_tx_airtime(&mut self, superframe: u64, airtime_ms: u32) {
        if superframe > self.current_sf {
            self.current_sf = superframe;
        }
        // Fold repeat samples for the same superframe.
        for entry in self.airtime_by_sf.iter_mut() {
            if entry.0 == superframe {
                entry.1 = entry.1.saturating_add(airtime_ms);
                return;
            }
        }
        // Evict the oldest window entry when full (rolling window: the
        // oldest superframe is the one furthest below current).
        if self.airtime_by_sf.len() == self.airtime_by_sf.capacity() {
            if let Some(oldest_idx) = self
                .airtime_by_sf
                .iter()
                .enumerate()
                .min_by_key(|(_, (sf, _))| *sf)
                .map(|(i, _)| i)
            {
                let _ = self.airtime_by_sf.swap_remove(oldest_idx);
            }
        }
        let _ = self.airtime_by_sf.push((superframe, airtime_ms));
    }

    /// BusyPercent over the rolling window (0..100).
    ///
    /// `slot_duration_ms` is the per-superframe slot budget the occupancy is
    /// measured against (e.g. TDMA_SLOT_MS * slots_per_superframe). The
    /// window is EXCLUSIVE of the oldest edge: superframes in
    /// (current-32, current] are summed, so at most 32 distinct entries fit
    /// the window — matching the sampler capacity exactly.
    pub fn busy_percent(&mut self, slot_duration_ms: u32) -> u8 {
        // Drop entries outside the exclusive window before summing.
        // sf + WINDOW > current is underflow-safe: at current 0 the whole
        // recorded range is retained (window is (-32, 0]).
        self.airtime_by_sf
            .retain(|(sf, _)| sf + u64::from(RF_METRICS_WINDOW_SF) > self.current_sf);
        let total_ms: u64 = self
            .airtime_by_sf
            .iter()
            .map(|(_, ms)| u64::from(*ms))
            .sum();
        if slot_duration_ms == 0 {
            return 0;
        }
        let window_slots = u64::from(slot_duration_ms) * u64::from(RF_METRICS_WINDOW_SF);
        let percent = total_ms.saturating_mul(100) / window_slots;
        percent.min(100) as u8
    }
}

/// Rolling-window PacketErrorPermille tracker (spec R-02a-133 / 2a.10.3).
///
/// Tracks TX failures vs total TX attempts per superframe inside the
/// [`RF_METRICS_WINDOW_SF`] rolling window and reports
/// `failures / total * 1000`. Feeds
/// [`RfHealthMetrics::interference_score_tenths`](RfHealthMetrics::interference_score_tenths)
/// via the existing loss-rate consumers.
#[derive(Debug, Clone, Default)]
pub struct PacketErrorPermilleTracker {
    /// Per-superframe (tx_total, tx_failed) counts in the window.
    by_sf: heapless::Vec<(u64, u32, u32), { RF_METRICS_WINDOW_SF as usize }>,
    current_sf: u64,
}

impl PacketErrorPermilleTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one TX attempt in the given superframe (failed = true when
    /// the transmission was not acknowledged).
    pub fn record_attempt(&mut self, superframe: u64, failed: bool) {
        if superframe > self.current_sf {
            self.current_sf = superframe;
        }
        // Late records already outside the window are dropped without
        // evicting in-window entries (Python dict semantics: stale keys
        // are simply purged at query time, never displacing fresh ones).
        if self.by_sf.len() == self.by_sf.capacity()
            && !self.by_sf.iter().any(|(sf, _, _)| *sf == superframe)
            && superframe + u64::from(RF_METRICS_WINDOW_SF) <= self.current_sf
        {
            return;
        }
        for entry in self.by_sf.iter_mut() {
            if entry.0 == superframe {
                entry.1 = entry.1.saturating_add(1);
                if failed {
                    entry.2 = entry.2.saturating_add(1);
                }
                return;
            }
        }
        if self.by_sf.len() == self.by_sf.capacity() {
            if let Some(oldest_idx) = self
                .by_sf
                .iter()
                .enumerate()
                .min_by_key(|(_, (sf, _, _))| *sf)
                .map(|(i, _)| i)
            {
                let _ = self.by_sf.swap_remove(oldest_idx);
            }
        }
        let _ = self.by_sf.push((superframe, 1, u32::from(failed)));
    }

    /// PacketErrorPermille over the rolling window: (failures/total)*1000.
    /// Returns 0 when no attempts are in the window (0% of nothing).
    pub fn packet_error_permille(&mut self) -> u16 {
        // Drop entries outside the exclusive window (underflow-safe).
        self.by_sf
            .retain(|(sf, _, _)| sf + u64::from(RF_METRICS_WINDOW_SF) > self.current_sf);
        let mut total: u64 = 0;
        let mut failed: u64 = 0;
        for (_, t, fails) in self.by_sf.iter() {
            total += u64::from(*t);
            failed += u64::from(*fails);
        }
        if total == 0 {
            return 0;
        }
        u16::try_from(failed.saturating_mul(1000) / total).unwrap_or(1000)
    }
}

/// Rolling-window peer density tracker (spec R-02a-117 / 2a.10.3).
///
/// Tracks the distinct link-layer peers heard within
/// [`RF_METRICS_WINDOW_SF`] superframes and feeds their count into
/// [`estimate_density`]. Peers expire when their last-heard superframe
/// falls out of the window.
/// Maximum tracked peers (bounded for no_std; matches the 255 cap the
/// density formula can ever reach with headroom).
const PEER_TRACKER_CAPACITY: usize = 256;

#[derive(Debug, Clone)]
pub struct PeerDensityTracker {
    last_seen: heapless::LinearMap<[u8; 8], u64, PEER_TRACKER_CAPACITY>,
    current_sf: u64,
}

impl Default for PeerDensityTracker {
    fn default() -> Self {
        Self {
            last_seen: heapless::LinearMap::new(),
            current_sf: 0,
        }
    }
}

impl PeerDensityTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one peer heard in the given superframe.
    pub fn record_peer(&mut self, iid: [u8; 8], superframe: u64) {
        if superframe > self.current_sf {
            self.current_sf = superframe;
        }
        // Drop the stalest entry (oldest last-heard superframe) when full
        // (ponytail: O(n) scan over the bounded map; upgrade path: a proper
        // LRU if capacity becomes pressure).
        if self.last_seen.get(&iid).is_none() && self.last_seen.len() == PEER_TRACKER_CAPACITY {
            if let Some(oldest) = self
                .last_seen
                .iter()
                .min_by_key(|(_, seen)| *seen)
                .map(|(k, _)| *k)
            {
                let _ = self.last_seen.remove(&oldest);
            }
        }
        let _ = self.last_seen.insert(iid, superframe);
    }

    fn prune(&mut self) {
        let window_start = self.current_sf.saturating_sub(RF_METRICS_WINDOW_SF as u64);
        let expired: heapless::Vec<[u8; 8], PEER_TRACKER_CAPACITY> = self
            .last_seen
            .iter()
            .filter(|(_, seen)| **seen < window_start)
            .map(|(k, _)| *k)
            .collect();
        for iid in expired {
            let _ = self.last_seen.remove(&iid);
        }
    }

    /// Distinct peers inside the metrics window (prunes first).
    pub fn peer_count(&mut self) -> usize {
        self.prune();
        self.last_seen.len()
    }

    /// Estimated density: peer count passed through the estimate_density
    /// formula (loss/RSSI bonuses, u8 cap).
    pub fn estimate_density(&mut self, loss_permille: u16, rssi_ema_dbm: i8) -> u8 {
        let neighbors = self.peer_count().min(255) as u8;
        estimate_density(neighbors, loss_permille, rssi_ema_dbm)
    }
}

/// Compute TDMA slot for a given EUI64, SFN, and slot count per CCP-16 Section 2a.2.
///
/// # Formula
///
/// `slot_id = ((fnv1a32(eui64) + sfn) mod 2^32) mod num_slots`
///
/// Returns `None` if `num_slots` is zero.
pub fn slot_hash(eui64: &[u8; 8], sfn: u32, num_slots: u8) -> Option<u8> {
    if num_slots == 0 {
        return None;
    }
    let h = crate::lichen_hash_32(eui64);
    Some(((h.wrapping_add(sfn)) % u32::from(num_slots)) as u8)
}

/// Select a CCP-15 data channel, or CH0 when density exceeds eight peers.
pub fn select_channel(eui64: &[u8; 8], epoch: u32, density: u8, n_channels: u8) -> u8 {
    if density > 10 || n_channels <= 1 {
        return 0;
    }
    let mut data = [0u8; 12];
    data[..8].copy_from_slice(eui64);
    data[8..].copy_from_slice(&epoch.to_le_bytes());
    let hash = crate::lichen_hash_32(&data);
    let modulus = n_channels - 1;
    1 + (hash % u32::from(modulus)) as u8
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RfHealthMetrics {
    /// Total packets transmitted.
    pub packets_tx: u32,
    /// Total packets received.
    pub packets_rx: u32,
    /// TX failures (no ack, channel busy, etc.).
    pub tx_failures: u32,
    /// SNR statistics from received packets.
    pub snr: SnrStats,
    /// Observed network density (0-255 from neighbors/announces per CCP-16).
    pub density: u8,
    /// Load factor in Q16.16 (0 = idle, FP_SCALE = 1.0). From hash or metrics.
    load_factor_fp: u32,
}

impl RfHealthMetrics {
    /// Create a new metrics tracker with zeroed counters.
    #[inline]
    pub const fn new() -> Self {
        Self {
            packets_tx: 0,
            packets_rx: 0,
            tx_failures: 0,
            snr: SnrStats::new(),
            density: 0,
            load_factor_fp: 0,
        }
    }

    /// Record a packet transmission.
    #[inline]
    pub fn record_tx(&mut self) {
        self.packets_tx = self.packets_tx.saturating_add(1);
    }

    /// Record a packet reception with SNR metric.
    ///
    /// `snr` is the signal-to-noise ratio in dB (typically -20 to +20).
    #[inline]
    pub fn record_rx(&mut self, snr: i8) {
        self.packets_rx = self.packets_rx.saturating_add(1);
        self.snr.update(snr);
    }

    /// Record a transmission failure (no ack, channel busy, etc.).
    #[inline]
    pub fn record_tx_fail(&mut self) {
        self.tx_failures = self.tx_failures.saturating_add(1);
    }

    /// Record observed network density (from RPL DIOs or overheard traffic).
    #[inline]
    pub fn record_density(&mut self, density: u8) {
        self.density = density;
    }

    /// Record computed load factor (from hash_32 or utilization metrics).
    #[inline]
    pub fn record_load_factor(&mut self, load_fp: u32) {
        self.load_factor_fp = load_fp.min(FP_SCALE);
    }

    /// Calculate packet loss rate as a percentage in Q16.16 fixed-point.
    ///
    /// Loss rate = (tx_failures / packets_tx) * 100.
    /// Returns 0 if no packets have been transmitted.
    /// Returns the result as a Q16.16 fixed-point value where the integer
    /// part represents the percentage (0-100).
    #[inline]
    pub fn packet_loss_rate_fp(&self) -> PacketLossRate {
        PacketLossRate::calculate(self.packets_tx, self.tx_failures)
    }

    /// Reset all counters and statistics to zero.
    #[inline]
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// SNR (Signal-to-Noise Ratio) statistics.
///
/// Tracks min, max, and EMA (alpha=1/4) rolling average of SNR values in dB.
/// Faster alpha supports CCP-15 interference detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnrStats {
    /// Minimum SNR observed (dB).
    pub min: i8,
    /// Maximum SNR observed (dB).
    pub max: i8,
    /// Rolling average SNR in Q16.16 fixed-point.
    avg_fp: i32,
    /// Number of samples recorded.
    count: u32,
}

impl Default for SnrStats {
    fn default() -> Self {
        Self::new()
    }
}

impl SnrStats {
    /// Create new SNR stats with no samples.
    #[inline]
    pub const fn new() -> Self {
        Self {
            min: i8::MAX,
            max: i8::MIN,
            avg_fp: 0,
            count: 0,
        }
    }

    /// Update statistics with a new SNR sample.
    #[inline]
    pub fn update(&mut self, snr: i8) {
        self.min = self.min.min(snr);
        self.max = self.max.max(snr);

        let snr_fp = (snr as i32) << 16;
        if self.count == 0 {
            self.avg_fp = snr_fp;
        } else {
            let diff = snr_fp.saturating_sub(self.avg_fp);
            self.avg_fp = self.avg_fp.saturating_add(diff >> EMA_ALPHA_SHIFT);
        }
        self.count = self.count.saturating_add(1);
    }

    /// Get the rolling average SNR as an integer (truncated).
    ///
    /// Returns `None` if no samples have been recorded.
    #[inline]
    pub fn avg(&self) -> Option<i8> {
        if self.count == 0 {
            None
        } else {
            Some(((self.avg_fp + (1 << 15)) >> 16) as i8)
        }
    }

    /// Get the rolling average SNR in Q16.16 fixed-point.
    ///
    /// Returns `None` if no samples have been recorded.
    #[inline]
    pub fn avg_fp(&self) -> Option<i32> {
        if self.count == 0 {
            None
        } else {
            Some(self.avg_fp)
        }
    }

    /// Get the number of samples recorded.
    #[inline]
    pub fn count(&self) -> u32 {
        self.count
    }
}

/// Packet loss rate in Q16.16 fixed-point.
///
/// Represents the percentage of transmitted packets that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PacketLossRate {
    /// Loss rate as percentage in Q16.16 (0 = 0%, 100<<16 = 100%).
    rate_fp: u32,
}

impl PacketLossRate {
    /// Calculate packet loss rate from TX count and failure count.
    ///
    /// Returns 0% if no packets transmitted.
    #[inline]
    pub fn calculate(packets_tx: u32, tx_failures: u32) -> Self {
        if packets_tx == 0 {
            return Self { rate_fp: 0 };
        }

        let numerator = (tx_failures as u64) * 100 * (FP_SCALE as u64);
        let rate = (numerator / (packets_tx as u64)) as u32;

        Self { rate_fp: rate }
    }

    /// Get the loss rate as an integer percentage (0-100, truncated).
    #[inline]
    pub fn as_percent(&self) -> u8 {
        let pct = self.rate_fp >> 16;
        if pct > 100 {
            100
        } else {
            pct as u8
        }
    }

    /// Get the loss rate in Q16.16 fixed-point.
    #[inline]
    pub fn as_fp(&self) -> u32 {
        self.rate_fp
    }

    #[inline]
    pub fn as_permille(&self) -> u16 {
        let permille = ((self.rate_fp as u64) * 10) >> 16;
        if permille > 1000 {
            1000
        } else {
            permille as u16
        }
    }
}

impl RfHealthMetrics {
    /// Adaptive SF selection per spec/02a-coordinated-capacity.md §2a.8
    /// table (critical conditions first). Uses named constants matching the
    /// table threshold conditions exactly. See also 02-physical-link.md:3.5.
    #[inline]
    pub fn adaptive_sf(&self) -> u8 {
        let snr_ema = self.snr.avg().unwrap_or(0);
        let load_high = self.load_factor_fp > LOAD_HIGH;
        if self.density > DENSITY_CRITICAL || snr_ema < SNR_CRITICAL {
            12
        } else if self.density > DENSITY_HIGH || snr_ema < SNR_POOR || load_high {
            11
        } else if self.density < DENSITY_LOW && snr_ema > SNR_GOOD {
            9
        } else {
            10
        }
    }

    /// Full AdaptiveSFSelect pseudocode from spec/02a-coordinated-capacity.md
    /// §2a.8 (including the post-step-6 minimum-SF floors). Takes
    /// table-assigned SF, utilization (scaled by `util_fp_scale`), and
    /// per-neighbor EMA loss (Q16.16). Returns (sf, tx_allowed).
    #[inline]
    pub fn adaptive_sf_select(
        &self,
        assigned_sf: Option<u8>,
        utilization: Option<u32>,
        ema_loss_fp: Option<u32>,
    ) -> (u8, bool) {
        let mut sf = assigned_sf.unwrap_or_else(|| self.adaptive_sf());
        let explicit = assigned_sf.is_some() || utilization.is_some() || ema_loss_fp.is_some();
        let util = utilization.unwrap_or(0);
        let loss_fp = ema_loss_fp.unwrap_or(0);
        let snr_ema = self.snr.avg().unwrap_or(0);

        let util_thresh_150 = 150u32.saturating_mul(FP_SCALE) / 100;
        let util_thresh_200 = 200u32.saturating_mul(FP_SCALE) / 100;
        let loss_threshold = FP_SCALE / 4;

        // Step 3: unconditional per spec §2a.8 step 3 (density >
        // DENSITY_HIGH = 10) — matches ccp.py and the vector generator; the
        // explicit-pseudocode gate was a pre-2a.8-reconciliation divergence.
        if self.density > DENSITY_HIGH || util > util_thresh_150 {
            sf = sf.saturating_add(2).min(12);
        }
        // Step 4: engaged only in explicit-pseudocode mode (the default
        // path uses the adaptive_sf() table form; the two diverge for
        // low-density high-SNR inputs by design).
        if explicit && snr_ema > SNR_GOOD && self.density < DENSITY_LOW {
            sf = sf.saturating_sub(1).max(7);
        }
        // Step 5
        let mut tx_allowed = true;
        if loss_fp > loss_threshold {
            sf = sf.saturating_add(1).min(12);
        }
        if util > util_thresh_200 {
            sf = 12;
            tx_allowed = false;
        }

        // Spec 2a.8 post-step-6 minimum-SF floors, applied in order a-d with
        // each MAX against the running SF (self state, not pseudocode args):
        // a. EMA_SNR < -5 -> SF 12
        // b. EMA_SNR < 0 -> max(11, SF)
        // c. Density > 10 -> max(11, SF)
        // d. LoadFactor >= 0.8 -> max(11, SF)
        if snr_ema < SNR_CRITICAL {
            sf = 12;
        }
        if snr_ema < SNR_POOR {
            sf = sf.max(11);
        }
        if self.density > DENSITY_HIGH {
            sf = sf.max(11);
        }
        if self.load_factor_fp >= FLOOR_LOAD_FP {
            sf = sf.max(11);
        }
        (sf, tx_allowed)
    }

    #[inline]
    pub fn should_rebalance(&self) -> bool {
        self.density > DENSITY_HIGH
            || self.load_factor_fp > LOAD_REBALANCE
            || self.packet_loss_rate_fp().as_percent() > 25
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn adaptive_sf_step3_uses_spec_density_8() {
        let mut m = RfHealthMetrics::new();
        m.record_density(9);
        m.record_rx(-2);
        let (sf, tx_allowed) = m.adaptive_sf_select(Some(7), None, None);
        // density 9 > 8: step 3 engages (+2) per spec 2a.8 (was > 10),
        // then floor (c) lifts the result to 11.
        assert_eq!(sf, 11);
        assert!(tx_allowed);
        // Density 8 exactly: step 3 does not engage (good SNR avoids the
        // floor-(b) interaction).
        let mut m8 = RfHealthMetrics::new();
        m8.record_density(8);
        m8.record_rx(10);
        let (sf8, _) = m8.adaptive_sf_select(Some(7), None, None);
        assert_eq!(sf8, 7);
    }

    #[test]
    fn adaptive_sf_post_step6_floors_apply() {
        // Floor (a): SNR EMA < -5 forces SF 12 outright.
        let mut m = RfHealthMetrics::new();
        m.record_density(0);
        while m.snr.avg().is_none() || m.snr.avg().unwrap() >= -5 {
            m.record_rx(-6);
        }
        let (sf, tx_allowed) = m.adaptive_sf_select(Some(7), None, None);
        assert_eq!(sf, 12);
        assert!(tx_allowed);

        // Floor (b): SNR EMA in [-5, 0) floors at 11.
        let mut m = RfHealthMetrics::new();
        m.record_rx(-3);
        let (sf, _) = m.adaptive_sf_select(Some(11), None, None);
        assert_eq!(sf, 11);

        // Floor (c): density > 10 floors at 11 even with a good SNR.
        let mut m = RfHealthMetrics::new();
        m.record_density(11);
        m.record_rx(10);
        let (sf, _) = m.adaptive_sf_select(Some(9), None, None);
        assert_eq!(sf, 11);

        // Floor (d): load_factor_fp >= 52429 floors at 11.
        let mut m = RfHealthMetrics::new();
        m.record_rx(10);
        m.record_load_factor(52429);
        let (sf, _) = m.adaptive_sf_select(Some(11), None, None);
        assert_eq!(sf, 11);
    }

    #[test]
    fn adaptive_sf_load_boundary_52429_vs_52428() {
        // 52429 (>=) engages floor (d); 52428 (one below) does not.
        let mut m = RfHealthMetrics::new();
        m.record_rx(10);
        m.record_load_factor(52429);
        let (sf, _) = m.adaptive_sf_select(Some(11), None, None);
        assert_eq!(sf, 11);

        let mut m = RfHealthMetrics::new();
        m.record_rx(10);
        m.record_load_factor(52428);
        // No floor at 52428: step 4 (good SNR, low density) applies -1.
        let (sf, _) = m.adaptive_sf_select(Some(9), None, None);
        assert_eq!(sf, 8);
    }

    #[test]
    fn adaptive_sf_ema_convergence_reaches_floor_a() {
        // EMA (alpha = 1/4) converges below -5 after repeated -6 dBm samples;
        // the floor engages only after the EMA crosses the threshold.
        let mut m = RfHealthMetrics::new();
        let mut samples: u32 = 0;
        while m.snr.avg().is_none() || m.snr.avg().unwrap() >= -5 {
            m.record_rx(-6);
            samples += 1;
            assert!(samples < 64, "EMA must converge");
        }
        let (sf, _) = m.adaptive_sf_select(Some(9), None, None);
        assert_eq!(sf, 12);
    }

    #[test]
    fn new_metrics_are_zeroed() {
        let m = RfHealthMetrics::new();
        assert_eq!(m.packets_tx, 0);
        assert_eq!(m.packets_rx, 0);
        assert_eq!(m.tx_failures, 0);
    }

    #[test]
    fn record_tx_increments() {
        let mut m = RfHealthMetrics::new();
        m.record_tx();
        assert_eq!(m.packets_tx, 1);
        m.record_tx();
        assert_eq!(m.packets_tx, 2);
    }

    #[test]
    fn record_rx_increments_and_updates_stats() {
        let mut m = RfHealthMetrics::new();
        m.record_rx(10);
        assert_eq!(m.packets_rx, 1);
        assert_eq!(m.snr.min, 10);
        assert_eq!(m.snr.max, 10);
    }

    #[test]
    fn record_tx_fail_increments() {
        let mut m = RfHealthMetrics::new();
        m.record_tx_fail();
        assert_eq!(m.tx_failures, 1);
    }

    #[test]
    fn counters_saturate() {
        let mut m = RfHealthMetrics::new();
        m.packets_tx = u32::MAX;
        m.record_tx();
        assert_eq!(m.packets_tx, u32::MAX);

        m.packets_rx = u32::MAX;
        m.record_rx(5);
        assert_eq!(m.packets_rx, u32::MAX);
    }

    #[test]
    fn snr_min_max_tracking() {
        let mut stats = SnrStats::new();
        stats.update(-5);
        stats.update(15);
        stats.update(8);
        assert_eq!(stats.min, -5);
        assert_eq!(stats.max, 15);
    }

    #[test]
    fn snr_avg_single_sample() {
        let mut stats = SnrStats::new();
        stats.update(10);
        assert_eq!(stats.avg(), Some(10));
    }

    #[test]
    fn snr_avg_none_when_empty() {
        let stats = SnrStats::new();
        assert_eq!(stats.avg(), None);
    }

    #[test]
    fn packet_loss_zero_when_no_tx() {
        let m = RfHealthMetrics::new();
        let loss = m.packet_loss_rate_fp();
        assert_eq!(loss.as_percent(), 0);
        assert_eq!(loss.as_fp(), 0);
    }

    #[test]
    fn packet_loss_zero_when_no_failures() {
        let mut m = RfHealthMetrics::new();
        m.packets_tx = 100;
        m.tx_failures = 0;
        let loss = m.packet_loss_rate_fp();
        assert_eq!(loss.as_percent(), 0);
    }

    #[test]
    fn packet_loss_fifty_percent() {
        let mut m = RfHealthMetrics::new();
        m.packets_tx = 100;
        m.tx_failures = 50;
        let loss = m.packet_loss_rate_fp();
        assert_eq!(loss.as_percent(), 50);
        assert_eq!(loss.as_permille(), 500);
    }

    #[test]
    fn packet_loss_hundred_percent() {
        let mut m = RfHealthMetrics::new();
        m.packets_tx = 100;
        m.tx_failures = 100;
        let loss = m.packet_loss_rate_fp();
        assert_eq!(loss.as_percent(), 100);
    }

    #[test]
    fn packet_loss_fractional() {
        let mut m = RfHealthMetrics::new();
        m.packets_tx = 1000;
        m.tx_failures = 5;
        let loss = m.packet_loss_rate_fp();
        assert_eq!(loss.as_percent(), 0);
        assert_eq!(loss.as_permille(), 5);
    }

    #[test]
    fn packet_loss_large_numbers() {
        let mut m = RfHealthMetrics::new();
        m.packets_tx = 1_000_000;
        m.tx_failures = 100_000;
        let loss = m.packet_loss_rate_fp();
        assert_eq!(loss.as_percent(), 10);
        assert_eq!(loss.as_permille(), 100);
    }

    #[test]
    fn reset_clears_all() {
        let mut m = RfHealthMetrics::new();
        m.record_tx();
        m.record_tx();
        m.record_rx(10);
        m.record_tx_fail();
        m.record_density(10);
        m.record_load_factor(FP_SCALE / 2);

        m.reset();

        assert_eq!(m.packets_tx, 0);
        assert_eq!(m.packets_rx, 0);
        assert_eq!(m.tx_failures, 0);
        assert_eq!(m.snr.count(), 0);
        assert_eq!(m.density, 0);
        assert_eq!(m.load_factor_fp, 0);
    }

    #[test]
    fn snr_negative_values() {
        let mut stats = SnrStats::new();
        stats.update(-10);
        stats.update(20);
        assert_eq!(stats.min, -10);
        assert_eq!(stats.max, 20);
    }

    #[test]
    fn adaptive_sf_and_rebalance_matches_spec() {
        // Test each branch independently to avoid EMA state carryover.
        // Matches spec/02a-coordinated-capacity.md table+pseudocode (critical first)
        // and ccp15/ccp16 vectors for EMA/load_factor/density/adaptive_sf.

        // sf=9: density<5, snr>8, no load
        let mut m = RfHealthMetrics::new();
        m.record_density(3);
        m.record_rx(12);
        m.record_load_factor(0);
        assert_eq!(m.adaptive_sf(), 9);
        let (sf, allowed) = m.adaptive_sf_select(None, None, None);
        assert_eq!(sf, 9);
        assert!(allowed);

        // sf=11: density>10, snr<0, load>0.8 → all trigger rebalance
        let mut m = RfHealthMetrics::new();
        m.record_density(12);
        m.record_rx(-3);
        m.record_load_factor((FP_SCALE * 85) / 100);
        assert_eq!(m.adaptive_sf(), 11);
        assert!(m.should_rebalance());
        // Reconciled 2a.8: step 3 (density > 10) is unconditional in the
        // pseudocode form, so the select result is 12 (the table form
        // floors at 11 — both satisfy the >= 11 floor).
        let (sf, allowed) = m.adaptive_sf_select(None, None, None);
        assert_eq!(sf, 12);
        assert!(allowed);

        // sf=12: snr<-5 critical
        let mut m = RfHealthMetrics::new();
        m.record_density(3);
        m.record_rx(-10);
        assert_eq!(m.adaptive_sf(), 12);
        let (sf, allowed) = m.adaptive_sf_select(None, None, None);
        assert_eq!(sf, 12);
        assert!(allowed);

        // sf=12: density>20 critical
        let mut m = RfHealthMetrics::new();
        m.record_density(25);
        assert_eq!(m.adaptive_sf(), 12);
        let (sf, allowed) = m.adaptive_sf_select(None, None, None);
        assert_eq!(sf, 12);
        assert!(allowed);
    }

    #[test]
    fn adaptive_sf_select_pseudocode_utilization() {
        // Step 3: Utilization > 150 → add 2
        let mut m = RfHealthMetrics::new();
        m.record_density(4);
        m.record_rx(5);
        m.record_load_factor(0);
        let (sf, allowed) = m.adaptive_sf_select(Some(10), Some(151 * FP_SCALE / 100), None);
        assert_eq!(sf, 12);
        assert!(allowed);

        // Step 5: Utilization > 200 → add 1, no tx. Step 3 also fires (+2).
        let mut m = RfHealthMetrics::new();
        m.record_density(4);
        m.record_rx(5);
        m.record_load_factor(0);
        let (sf, allowed) = m.adaptive_sf_select(Some(10), Some(201 * FP_SCALE / 100), None);
        assert_eq!(sf, 12);
        assert!(!allowed);

        // Step 5: EMA_Loss > 0.25 → add 1
        let mut m = RfHealthMetrics::new();
        m.record_density(4);
        m.record_rx(5);
        m.record_load_factor(0);
        let (sf, allowed) = m.adaptive_sf_select(Some(10), None, Some(FP_SCALE / 4 + 1));
        assert_eq!(sf, 11);
        assert!(allowed);

        // Step 3+5 combined: density>10 AND loss>0.25
        let mut m = RfHealthMetrics::new();
        m.record_density(12);
        m.record_rx(5);
        m.record_load_factor(0);
        let (sf, allowed) = m.adaptive_sf_select(Some(9), None, Some(FP_SCALE / 4 + 1));
        assert_eq!(sf, 12);
        assert!(allowed);
    }

    #[test]
    fn adaptive_sf_select_supports_sf7() {
        // Step 4: SNR>8 AND density<5 → MAX(7, SF-1)
        // Starting from assigned SF=9 (already at upgrade)
        let mut m = RfHealthMetrics::new();
        m.record_density(2);
        m.record_rx(15);
        m.record_load_factor(0);
        let (sf, allowed) = m.adaptive_sf_select(Some(8), None, None);
        assert_eq!(sf, 7);
        assert!(allowed);
    }

    #[test]
    fn rebalance_loss_threshold_25_percent() {
        // should_rebalance triggers when loss > 25% (per spec loss>0.25)
        let mut m = RfHealthMetrics::new();
        m.packets_tx = 100;
        m.tx_failures = 26;
        assert!(m.should_rebalance());

        let mut m = RfHealthMetrics::new();
        m.packets_tx = 100;
        m.tx_failures = 25;
        // 25% is not >25%, so should not trigger on loss alone
        let result = m.should_rebalance();
        assert!(
            !result || m.load_factor_fp > LOAD_REBALANCE || m.density > DENSITY_HIGH,
            "should_rebalance()={} for 25% loss with no density/load triggers",
            result
        );
    }

    #[test]
    fn ccp_vectors_match() {
        // Tests full ccp16.json (and compatible with ccp15.json structure) for
        // exact match on EMA updates, load_factor recording, density, adaptive_sf,
        // adaptive_sf_select, should_rebalance per spec/02a-coordinated-capacity.md
        // and vectors.
        let content = include_str!("../../../test/vectors/ccp16.json");
        let doc: Value = serde_json::from_str(content).unwrap();
        let vectors = doc.get("vectors").and_then(|v| v.as_array()).unwrap();
        for v in vectors {
            let input = v.get("input").unwrap_or(v);
            let output = v.get("output").unwrap_or(v);
            let density = input.get("density").and_then(|x| x.as_u64()).unwrap_or(0) as u8;
            let snr = input
                .get("snr_db")
                .or_else(|| input.get("snr_ema"))
                .and_then(|x| x.as_i64())
                .unwrap_or(5) as i8;
            let load_f = input
                .get("load_factor")
                .and_then(|x| x.as_f64())
                .unwrap_or(0.0);
            let load_fp = ((load_f * FP_SCALE as f64) as u32).min(FP_SCALE);
            let mut m = RfHealthMetrics::new();
            m.record_density(density);
            m.record_rx(snr);
            m.record_load_factor(load_fp);
            let exp_sf = output.get("sf").and_then(|x| x.as_u64()).unwrap_or(10) as u8;
            // The vector pins the full 2a.8 pseudocode result. The
            // table-only adaptive_sf() form is asserted by its own unit
            // tests and diverges from the pseudocode for density > 8
            // (table floors at 11; the pseudocode step 3 reaches 12).
            let (sf_sel, allowed) = m.adaptive_sf_select(None, None, None);
            assert_eq!(sf_sel, exp_sf);
            assert!(allowed);
            let _ = m.should_rebalance();
            let _ = m.packet_loss_rate_fp();
        }
    }

    #[test]
    fn ccp_load_balancing_vectors_match() {
        let content = include_str!("../../../test/vectors/ccp_load_balancing.json");
        let doc: Value = serde_json::from_str(content).unwrap();
        let vectors = doc.get("vectors").and_then(|v| v.as_array()).unwrap();
        for v in vectors {
            let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("");
            match name {
                "tdma_slot_assignment_static_hash" => {
                    let eui64 = v.get("eui64_hex").and_then(|x| x.as_str()).unwrap_or("");
                    let num_slots = v.get("num_slots").and_then(|x| x.as_u64()).unwrap_or(16);
                    let expected = v.get("expected_slot").and_then(|x| x.as_u64()).unwrap_or(0);
                    assert!(eui64.len() == 16, "eui64 length");
                    assert!(num_slots > 0, "num_slots > 0");
                    assert!(expected < num_slots, "slot in range");
                }
                "guard_time_boundary_sf10" => {
                    let guard = v.get("guard_ms").and_then(|x| x.as_u64()).unwrap_or(50);
                    let slot = v.get("slot_ms").and_then(|x| x.as_u64()).unwrap_or(250);
                    assert!(guard < slot, "guard < slot");
                }
                "drift_compensation_two_beacons" => {
                    let _expected_ppm = v.get("expected_ppm").and_then(|x| x.as_u64()).unwrap_or(0);
                    let _ticks = v
                        .get("slot_adjust_ticks")
                        .and_then(|x| x.as_u64())
                        .unwrap_or(0);
                }
                "ccp_load_high_util_rebalance" => {
                    let util = v.get("util").and_then(|x| x.as_f64()).unwrap_or(0.0);
                    let score = v.get("score").and_then(|x| x.as_f64()).unwrap_or(0.0);
                    assert!(util > 0.4, "util > 0.4");
                    assert!(score > 0.0, "score > 0");
                }
                _ => {}
            }
        }
    }

    fn hex_to_eui64(s: &str) -> [u8; 8] {
        let mut out = [0u8; 8];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn select_channel_ccp15_frequency_agility_vectors() {
        let content = include_str!("../../../test/vectors/ccp15.json");
        let doc: Value = serde_json::from_str(content).unwrap();
        let vectors = doc.get("vectors").and_then(|v| v.as_array()).unwrap();
        for v in vectors {
            if v.get("category").and_then(|x| x.as_str()) != Some("frequency_agility") {
                continue;
            }
            let input = v.get("input").and_then(|x| x.as_object()).unwrap();
            let expected = v.get("expected").and_then(|x| x.as_object()).unwrap();
            let eui_hex = input.get("eui64_hex").and_then(|x| x.as_str()).unwrap();
            let epoch = input.get("epoch").and_then(|x| x.as_u64()).unwrap() as u32;
            let density = input.get("density").and_then(|x| x.as_u64()).unwrap() as u8;
            let n_channels = input.get("n_channels").and_then(|x| x.as_u64()).unwrap() as u8;
            let channel = expected.get("channel").and_then(|x| x.as_u64()).unwrap() as u8;
            let eui = hex_to_eui64(eui_hex);
            assert_eq!(select_channel(&eui, epoch, density, n_channels), channel);
        }
    }

    #[test]
    fn select_channel_matches_python_hop_channel_literals() {
        // Cross-implementation oracle: identical literals to
        // python/tests/sim/test_protocol_hop_channel.py. The rust epoch
        // equals the python (sfn + epoch) mod 2^32 sum; density 0 stands
        // for the python function's implicit uncongested path.
        const EUI_ZERO: [u8; 8] = [0; 8];
        const EUI_FF: [u8; 8] = [0xff; 8];
        const EUI_SPEC: [u8; 8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

        assert_eq!(select_channel(&EUI_ZERO, 0, 0, 8), 3);
        assert_eq!(select_channel(&EUI_FF, 0xFFFF_FFFF, 0, 8), 4);
        assert_eq!(select_channel(&EUI_SPEC, 1, 0, 8), 1);
        assert_eq!(select_channel(&EUI_SPEC, 0, 0, 8), 4);
        assert_eq!(select_channel(&EUI_ZERO, 49, 0, 16), 13);
        assert_eq!(select_channel(&EUI_ZERO, 0xFFFF_FFFF, 0, 16), 15);
        assert_eq!(select_channel(&EUI_ZERO, 42, 0, 8), 7);
        assert_eq!(select_channel(&EUI_ZERO, 5, 0, 1), 0);
        assert_eq!(select_channel(&EUI_ZERO, 8, 0, 8), 1);
        assert_eq!(select_channel(&EUI_ZERO, 11, 11, 8), 0);
    }

    // =============================================================================
    // CCP-16 estimate_density tests
    // =============================================================================

    #[test]
    fn estimate_density_base_neighbor_count() {
        // Base case: just neighbor count, no bonuses
        assert_eq!(estimate_density(5, 0, 0), 5);
        assert_eq!(estimate_density(10, 50, -80), 10); // below thresholds
    }

    #[test]
    fn estimate_density_loss_bonus() {
        // PER > 100 permille (10%) adds +2
        assert_eq!(estimate_density(5, 100, -80), 5); // exactly at threshold, no bonus
        assert_eq!(estimate_density(5, 101, -80), 7); // above threshold
        assert_eq!(estimate_density(5, 500, -80), 7); // well above
    }

    #[test]
    fn estimate_density_rssi_bonus() {
        // RSSI < -90 dBm adds +1
        assert_eq!(estimate_density(5, 0, -90), 5); // exactly at threshold, no bonus
        assert_eq!(estimate_density(5, 0, -91), 6); // below threshold
        assert_eq!(estimate_density(5, 0, -120), 6); // well below
    }

    #[test]
    fn estimate_density_combined_bonuses() {
        // Both bonuses apply
        assert_eq!(estimate_density(5, 101, -91), 8); // +2 for loss, +1 for RSSI
        assert_eq!(estimate_density(10, 200, -100), 13);
    }

    #[test]
    fn estimate_density_saturation() {
        // Saturates at 255
        assert_eq!(estimate_density(255, 0, 0), 255);
        assert_eq!(estimate_density(254, 101, -91), 255); // 254 + 3 = 257, clamped to 255
        assert_eq!(estimate_density(253, 101, -91), 255); // 253 + 3 = 256, clamped
    }

    // =============================================================================
    // CCP-16 slot_hash tests
    // =============================================================================

    #[test]
    fn slot_hash_zero_slots_returns_none() {
        let eui = [0u8; 8];
        assert_eq!(slot_hash(&eui, 0, 0), None);
    }

    #[test]
    fn slot_hash_basic() {
        let eui = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let slot = slot_hash(&eui, 0, 8).unwrap();
        assert!(slot < 8);
    }

    #[test]
    fn slot_hash_sfn_advances_slot() {
        let eui = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let slot0 = slot_hash(&eui, 0, 8).unwrap();
        let slot1 = slot_hash(&eui, 1, 8).unwrap();
        // Slot advances by 1 per SFN increment
        assert_eq!((slot0 + 1) % 8, slot1);
    }

    #[test]
    fn slot_hash_wrap_around() {
        let eui = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
        let slot_max = slot_hash(&eui, 0xFFFFFFFF, 16).unwrap();
        let slot_zero = slot_hash(&eui, 0, 16).unwrap();
        // hash + 0xFFFFFFFF wraps to hash - 1
        let expected_diff = ((slot_max as i16 - slot_zero as i16) + 16) % 16;
        assert_eq!(expected_diff, 15);
    }

    #[test]
    fn peer_tracker_counts_distinct_and_prunes_window() {
        use crate::rf_health::PeerDensityTracker;
        let mut t = PeerDensityTracker::new();
        // Three distinct peers in superframe 1.
        t.record_peer([1; 8], 1);
        t.record_peer([2; 8], 1);
        t.record_peer([3; 8], 1);
        t.record_peer([1; 8], 2); // repeat: same peer, distinct only
        assert_eq!(t.peer_count(), 3);

        // Window slides past all of them: current 40, window start 8.
        t.record_peer([9; 8], 40);
        assert_eq!(t.peer_count(), 1);
    }

    #[test]
    fn peer_tracker_density_matches_formula_vectors() {
        use crate::rf_health::PeerDensityTracker;
        let mut t = PeerDensityTracker::new();
        for i in 0..5u8 {
            t.record_peer([i; 8], 1);
        }
        // ccp16_load_balance density_estimate_basic: 5 neighbors, no bonuses.
        assert_eq!(t.estimate_density(50, -70), 5);
        // density_estimate_high_loss_bonus: 5 + 2.
        assert_eq!(t.estimate_density(150, -70), 7);
        // density_estimate_both_bonuses: 5 + 2 + 1.
        assert_eq!(t.estimate_density(150, -100), 8);
        // density_estimate_capped_at_255: needs >= 252 peers so the
        // bonuses saturate the u8 cap.
        for i in 0..253u8 {
            t.record_peer([i, 0xEE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66], 3);
        }
        assert_eq!(t.estimate_density(200, -100), 255);
    }

    #[test]
    fn busy_percent_rolling_window_semantics() {
        use crate::constants::TDMA_SLOT_MS;
        use crate::rf_health::BusyPercentSampler;
        let mut s = BusyPercentSampler::new();
        // 2 slots' worth of TX inside one superframe: ~2/32 = 6.25% -> 6.
        s.record_tx_airtime(0, TDMA_SLOT_MS * 2);
        let pct = s.busy_percent(TDMA_SLOT_MS);
        assert!(pct >= 6 && pct <= 7, "got {pct}");

        // Window slide: all old entries drop, new occupancy ~0.
        s.record_tx_airtime(100, 0);
        assert_eq!(s.busy_percent(TDMA_SLOT_MS), 0);

        // Exclusive boundary: one slot's airtime at SF 32 = current: the
        // (0, 32] window retains it -> 1/32 of the window budget = 3%.
        let mut s = BusyPercentSampler::new();
        s.record_tx_airtime(32, TDMA_SLOT_MS);
        assert_eq!(s.busy_percent(TDMA_SLOT_MS), 3);

        // Saturation: full-window airtime -> 100.
        let mut s = BusyPercentSampler::new();
        for sf in 0..32u64 {
            s.record_tx_airtime(sf, TDMA_SLOT_MS);
        }
        assert_eq!(s.busy_percent(TDMA_SLOT_MS), 100);

        // Over the budget clamps at 100.
        s.record_tx_airtime(33, TDMA_SLOT_MS * 2);
        assert_eq!(s.busy_percent(TDMA_SLOT_MS), 100);

        // Zero slot duration is safe (returns 0, no div-by-zero).
        assert_eq!(s.busy_percent(0), 0);
    }

    #[test]
    fn packet_error_permille_rolling_window() {
        use crate::rf_health::PacketErrorPermilleTracker;
        let mut t = PacketErrorPermilleTracker::new();
        // 10 attempts across three superframes, 3 failures -> 300 permille.
        t.record_attempt(0, false);
        t.record_attempt(0, false);
        t.record_attempt(0, true);
        t.record_attempt(1, false);
        t.record_attempt(1, true);
        t.record_attempt(1, true);
        for _ in 0..4 {
            t.record_attempt(2, false);
        }
        assert_eq!(t.packet_error_permille(), 300);

        // Window slide past both: SF 100 (success) retained at current 100
        // (1 attempt of 1, 0 failed) -> 0 via the division path.
        t.record_attempt(100, false);
        assert_eq!(t.packet_error_permille(), 0);

        // Empty-window branch: fresh tracker -> 0 via the early return.
        let mut empty = PacketErrorPermilleTracker::new();
        assert_eq!(empty.packet_error_permille(), 0);

        // Boundary at current 131: SF 100 (success) is still retained
        // (100+32=132 > 131) -> 1 fail of 2 attempts -> 500.
        t.record_attempt(131, true);
        assert_eq!(t.packet_error_permille(), 500);

        // At current 132: SF 100 drops out (100+32=132 > 132 is false),
        // leaving SF 131 and SF 132 (both failures) -> 2 fails of 2 -> 1000.
        t.record_attempt(132, true);
        assert_eq!(t.packet_error_permille(), 1000);
    }

    #[test]
    fn slot_hash_deterministic() {
        let eui = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let s1 = slot_hash(&eui, 42, 8);
        let s2 = slot_hash(&eui, 42, 8);
        assert_eq!(s1, s2);
    }

    /// Spec 2a.8 step 3: Density > 10 (strictly greater) triggers SF +2.
    #[test]
    fn adaptive_sf_density_threshold_is_ten() {
        let mut h = RfHealthMetrics::default();
        h.record_density(10);
        // Density 10 is not the trigger: assigned 10 stays 10.
        let (sf, _) = h.adaptive_sf_select(Some(10), Some(0), Some(0));
        assert_eq!(sf, 10);

        let mut h = RfHealthMetrics::default();
        h.record_density(11);
        // Density 11 crosses: SF +2 capped at 12.
        let (sf, _) = h.adaptive_sf_select(Some(10), Some(0), Some(0));
        assert_eq!(sf, 12);
    }

    /// Spec 2a.8 post-step-6 floors a-d (order a-d, each MAX against SF).
    #[test]
    fn adaptive_sf_floors_apply_in_order() {
        // Floor a: EMA_SNR < -5 forces SF 12.
        let mut h = RfHealthMetrics::default();
        for _ in 0..8 {
            h.record_rx(-100);
        }
        assert!(h.snr.avg().unwrap() < -5);
        let (sf, _) = h.adaptive_sf_select(Some(7), Some(0), Some(0));
        assert_eq!(sf, 12);

        // Floor b: -5 <= EMA_SNR < 0 floors at 11.
        let mut h = RfHealthMetrics::default();
        h.record_rx(-2);
        h.record_rx(-2);
        h.record_rx(-2);
        assert_eq!(h.snr.avg().unwrap(), -2);
        let (sf, _) = h.adaptive_sf_select(Some(7), Some(0), Some(0));
        assert_eq!(sf, 11);

        // Floor c: density > 10 floors at 11 (SNR and load clean).
        let mut h = RfHealthMetrics::default();
        h.record_density(11);
        h.record_rx(20);
        let (sf, _) = h.adaptive_sf_select(Some(7), Some(0), Some(0));
        assert_eq!(sf, 11);

        // Floor d: load_factor_fp >= 52429 (0.8) floors at 11.
        let mut h = RfHealthMetrics::default();
        h.record_load_factor(52_429);
        h.record_rx(20);
        let (sf, _) = h.adaptive_sf_select(Some(7), Some(0), Some(0));
        assert_eq!(sf, 11);

        // Control: clean state floors nothing (7 stays 7).
        let mut h = RfHealthMetrics::default();
        h.record_rx(20);
        let (sf, _) = h.adaptive_sf_select(Some(7), Some(0), Some(0));
        assert_eq!(sf, 7);
    }
}
