use lichen_core::{constants::{TDMA_GUARD_MS, TDMA_SLOT_MS}, lichen_hash_32, lichen_select_channel};
pub struct TdmaScheduler;
impl TdmaScheduler {
    pub fn new() -> Self {
        TdmaScheduler
    }
    pub fn slot_for(eui: &[u8; 8]) -> u16 {
        let h = lichen_hash_32(eui);
        (h % 16) as u16
    }
    pub fn select_channel(eui: &[u8; 8], sfn: u32, density: u8, n_channels: u8) -> u8 {
        lichen_select_channel(eui, sfn, density, n_channels)
    }
    pub fn guard_ms() -> u32 {
        TDMA_GUARD_MS
    }
    pub fn slot_ms() -> u32 {
        TDMA_SLOT_MS
    }
}
impl Default for TdmaScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tdma_slot_guard_drift_independent() {
        assert_eq!(TdmaScheduler::guard_ms(), 100);
        assert_eq!(TdmaScheduler::slot_ms(), 250);

        let eui1 = [0u8, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(TdmaScheduler::slot_for(&eui1), 2);
    }

    #[test]
    fn test_select_channel_hop_sfn0_8ch() {
        let eui64 = [0u8; 8];
        assert_eq!(TdmaScheduler::select_channel(&eui64, 0, 0, 8), 6);
    }
}
