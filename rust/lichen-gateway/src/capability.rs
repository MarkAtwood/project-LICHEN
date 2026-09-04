//! Capability table for root-validated capability announcements
//! (spec/06-security.md 8.12:949-1008).
//!
//! Maps announcer IIDs to their announced capabilities. Bounded at 256
//! entries with LRU eviction; up to 25% of capacity is reserved for entries
//! carrying the egress capability bit (bit 0), so non-egress announcement
//! flooding cannot evict critical egress nodes.

/// Table capacity (spec 8.12: recommended 256).
pub const CAPABILITY_TABLE_CAPACITY: usize = 256;
/// Reserved partition for egress-bit entries (25% of capacity).
pub const CAPABILITY_RESERVED: usize = CAPABILITY_TABLE_CAPACITY / 4;

/** Egress capability bit (spec 8.12: bit 0). */
pub const CAPABILITY_EGRESS_BIT: u32 = 1 << 0;

use std::collections::HashMap;

/// One validated capability announcement.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilityEntry {
    pub iid: [u8; 8],
    pub capabilities: u32,
    pub prefix: [u8; 16],
    pub prefix_len: u8,
    pub expiry_unix: u32,
    pub seq: u64,
}

impl CapabilityEntry {
    /// Egress capability (bit 0) grants the reserved partition.
    pub fn is_egress(&self) -> bool {
        self.capabilities & CAPABILITY_EGRESS_BIT != 0
    }
}

#[derive(Debug)]
struct Slot {
    entry: CapabilityEntry,
    tick: u64,
}

/// Bounded LRU capability table with an egress-reserved partition.
///
/// Non-egress entries occupy at most `capacity - reserved` slots; egress
/// entries may use the whole table. Eviction is strict LRU over the
/// eligible partition. Inserting an existing IID refreshes it in place.
///
/// Replay floors: LRU eviction must not lower an announcer's anti-replay
/// floor (spec 8.12 seq must strictly exceed the cached seq). Evicting an
/// entry records its seq in a bounded monotone ledger; [`Self::cached_seq`]
/// then reports max(entry.seq, floor) so an evicted announcer cannot replay
/// an older announcement to roll the table back (bead fawm).
#[derive(Debug, Default)]
pub struct CapabilityTable {
    slots: HashMap<[u8; 8], Slot>,
    /// Monotone per-IID seq floors captured at eviction. Floors for IIDs
    /// still present in `slots` are redundant (their entry.seq already
    /// satisfies the floor) but kept until the bound requires dropping
    /// stale ones.
    seq_floors: HashMap<[u8; 8], u64>,
    tick: u64,
}

impl CapabilityTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Raise the monotone replay floor for `iid` to at least `seq`.
    fn raise_seq_floor(&mut self, iid: [u8; 8], seq: u64) {
        let floor = self.seq_floors.entry(iid).or_insert(seq);
        if *floor < seq {
            *floor = seq;
        }
    }

    /// Keep the floor ledger bounded: while over capacity, drop the
    /// lowest-IID floor whose IID is no longer in the table (its
    /// protection only matters while the announcer is absent). Floors
    /// belonging to active entries are always retained; if every floor
    /// is active the ledger equals the table and cannot exceed capacity.
    fn bound_seq_floors(&mut self) {
        while self.seq_floors.len() > CAPABILITY_TABLE_CAPACITY {
            let stale = self
                .seq_floors
                .iter()
                .filter(|(iid, _)| !self.slots.contains_key(*iid))
                .min_by_key(|(iid, _)| *iid)
                .map(|(iid, _)| *iid);
            match stale {
                Some(iid) => {
                    self.seq_floors.remove(&iid);
                }
                None => break,
            }
        }
    }

    /// Insert or refresh an announcement. Returns `false` when the entry
    /// could not be admitted (non-egress and only reserved slots free).
    pub fn insert(&mut self, entry: CapabilityEntry) -> bool {
        self.tick += 1;
        let tick = self.tick;
        // A refresh that clears the egress bit moves the entry out of the
        // reserved partition; reject it when the regular partition is
        // already full (the previous announcement stays cached).
        let refresh_violates_reservation = match self.slots.get(&entry.iid) {
            Some(slot) => {
                slot.entry.is_egress()
                    && !entry.is_egress()
                    && self.regular_count() >= CAPABILITY_TABLE_CAPACITY - CAPABILITY_RESERVED
            }
            None => false,
        };
        if refresh_violates_reservation {
            return false;
        }
        if let Some(slot) = self.slots.get_mut(&entry.iid) {
            let iid = entry.iid;
            let seq = entry.seq;
            slot.entry = entry;
            slot.tick = tick;
            self.raise_seq_floor(iid, seq);
            return true;
        }
        let egress = entry.is_egress();
        if self.slots.len() >= CAPABILITY_TABLE_CAPACITY {
            if !self.evict_lru(egress) {
                return false;
            }
        } else if !egress && self.regular_count() >= CAPABILITY_TABLE_CAPACITY - CAPABILITY_RESERVED
        {
            // The regular partition is full: evict LRU non-egress only.
            if !self.evict_lru(false) {
                return false;
            }
        }
        self.raise_seq_floor(entry.iid, entry.seq);
        self.bound_seq_floors();
        self.slots.insert(entry.iid, Slot { entry, tick });
        true
    }

    /// Lookup refreshes the entry's LRU position.
    pub fn lookup(&mut self, iid: &[u8; 8]) -> Option<&CapabilityEntry> {
        self.tick += 1;
        let tick = self.tick;
        self.slots.get_mut(iid).map(|slot| {
            slot.tick = tick;
            &slot.entry
        })
    }

    /// Cached sequence for an announcer (replay check: new seq must exceed).
    ///
    /// Reports max(entry.seq, eviction-captured floor): the anti-replay
    /// floor survives LRU eviction, so an evicted announcer cannot replay
    /// an older (still-valid) announcement to roll the table back.
    pub fn cached_seq(&self, iid: &[u8; 8]) -> Option<u64> {
        let entry_seq = self.slots.get(iid).map(|slot| slot.entry.seq);
        let floor = self.seq_floors.get(iid).copied();
        match (entry_seq, floor) {
            (Some(entry), Some(floor)) => Some(entry.max(floor)),
            (Some(entry), None) => Some(entry),
            (None, Some(floor)) => Some(floor),
            (None, None) => None,
        }
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    fn regular_count(&self) -> usize {
        self.slots
            .values()
            .filter(|slot| !slot.entry.is_egress())
            .count()
    }

    /// Evict the least-recently-used entry among the eligible partition
    /// (`egress == true` allows evicting egress entries too). Returns false
    /// when no eligible entry exists.
    fn evict_lru(&mut self, allow_egress: bool) -> bool {
        let victim = self
            .slots
            .iter()
            .filter(|(_, slot)| allow_egress || !slot.entry.is_egress())
            .min_by_key(|(_, slot)| slot.tick)
            .map(|(iid, _)| *iid);
        match victim {
            Some(iid) => {
                // Capture the victim's seq as a monotone replay floor so
                // eviction cannot enable a seq rollback (bead fawm).
                if let Some(slot) = self.slots.get(&iid) {
                    let seq = slot.entry.seq;
                    self.raise_seq_floor(iid, seq);
                    self.bound_seq_floors();
                }
                self.slots.remove(&iid);
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iid(v: u16) -> [u8; 8] {
        [0, 0, 0, 0, 0, 0, (v >> 8) as u8, v as u8]
    }

    fn entry(iid: [u8; 8], capabilities: u32) -> CapabilityEntry {
        CapabilityEntry {
            iid,
            capabilities,
            prefix: [0u8; 16],
            prefix_len: 128,
            expiry_unix: 2000,
            seq: 1,
        }
    }

    #[test]
    fn insert_lookup_refreshes_lru() {
        let mut t = CapabilityTable::new();
        assert!(t.insert(entry([1; 8], 0)));
        assert!(t.insert(entry([2; 8], 0)));
        let e = t.lookup(&[1; 8]).unwrap();
        assert_eq!(e.iid, [1; 8]);
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn lru_evicts_least_recently_used() {
        let mut t = CapabilityTable::new();
        // Non-egress partition is 256 - 64 = 192; fill exactly it.
        for i in 0..(CAPABILITY_TABLE_CAPACITY - CAPABILITY_RESERVED) {
            assert!(t.insert(entry(iid(i as u16), 0)));
        }
        // Touch IID 0 so it becomes most recently used.
        assert!(t.lookup(&iid(0)).is_some());
        // Overflow: the LRU non-egress entry (IID 1) is evicted, not IID 0.
        assert!(t.insert(entry(iid(300), 0)));
        assert!(t.lookup(&iid(0)).is_some());
        assert!(t.lookup(&iid(1)).is_none());
    }

    #[test]
    fn reserved_partition_protects_egress_entries() {
        let mut t = CapabilityTable::new();
        let regular = CAPABILITY_TABLE_CAPACITY - CAPABILITY_RESERVED;
        // Fill the regular partition + the whole reserved one with egress.
        for i in 0..regular {
            assert!(t.insert(entry(iid(i as u16), 0)));
        }
        for i in 0..CAPABILITY_RESERVED {
            assert!(t.insert(entry(iid(300 + i as u16), CAPABILITY_EGRESS_BIT)));
        }
        assert_eq!(t.len(), CAPABILITY_TABLE_CAPACITY);

        // A non-egress insert evicts LRU non-egress (IID 0), never egress.
        assert!(t.insert(entry(iid(600), 0)));
        assert!(t.lookup(&iid(0)).is_none());
        assert!(t.lookup(&iid(300)).is_some());

        // Repeated non-egress flooding never evicts the egress partition.
        for i in 0..64 {
            assert!(t.insert(entry(iid(700 + i as u16), 0)));
        }
        assert!(t.lookup(&iid(300)).is_some());
        assert!(t.lookup(&iid(363)).is_some());
    }

    #[test]
    fn refresh_clearing_egress_bit_rejected_when_regular_full() {
        let mut t = CapabilityTable::new();
        let regular = CAPABILITY_TABLE_CAPACITY - CAPABILITY_RESERVED;
        for i in 0..regular {
            assert!(t.insert(entry(iid(i as u16), 0)));
        }
        // One egress announcement in the reserved partition.
        assert!(t.insert(entry(iid(300), CAPABILITY_EGRESS_BIT)));
        assert_eq!(t.len(), regular + 1);

        // Refreshing IID 300 WITHOUT the egress bit would move it out of
        // the reserved partition while the regular partition is full.
        assert!(!t.insert(entry(iid(300), 0)));
        assert_eq!(t.cached_seq(&iid(300)), Some(1));
        assert!(t
            .lookup(&iid(300))
            .expect("previous announcement preserved")
            .is_egress());
    }

    #[test]
    fn egress_update_in_place_and_cached_seq() {
        let mut t = CapabilityTable::new();
        assert!(t.insert(entry([5; 8], CAPABILITY_EGRESS_BIT)));
        assert_eq!(t.cached_seq(&[5; 8]), Some(1));
        let mut newer = entry([5; 8], CAPABILITY_EGRESS_BIT);
        newer.seq = 2;
        assert!(t.insert(newer));
        assert_eq!(t.len(), 1);
        assert_eq!(t.cached_seq(&[5; 8]), Some(2));
    }

    #[test]
    fn eviction_preserves_replay_floor() {
        // Bead fawm: an evicted announcer must not be able to replay an
        // older (still-unexpired) announcement to roll the table back.
        let mut t = CapabilityTable::new();
        let mut current = entry(iid(1), 0);
        current.seq = 500;
        assert!(t.insert(current));
        assert_eq!(t.cached_seq(&iid(1)), Some(500));

        // Flood the regular partition so IID 1 is LRU-evicted.
        for i in 2..(CAPABILITY_TABLE_CAPACITY - CAPABILITY_RESERVED + 2) {
            assert!(t.insert(entry(iid(i as u16), 0)));
        }
        assert!(t.lookup(&iid(1)).is_none());

        // The floor survived eviction: cached_seq still reports 500, so a
        // replay of seq <= 500 is refused by the dispatch gate.
        assert_eq!(t.cached_seq(&iid(1)), Some(500));

        // Re-admission with a stale seq keeps the floor and must NOT
        // lower it; a strictly newer seq re-enters the table.
        let mut stale = entry(iid(1), 0);
        stale.seq = 499;
        assert!(t.insert(stale));
        assert_eq!(t.cached_seq(&iid(1)), Some(500));
        let mut fresh = entry(iid(1), 0);
        fresh.seq = 501;
        assert!(t.insert(fresh));
        assert_eq!(t.cached_seq(&iid(1)), Some(501));
    }

    #[test]
    fn floor_ledger_stays_bounded() {
        // The floor ledger never grows past capacity: stale floors (IIDs
        // no longer in the table) are dropped lowest-IID-first.
        let mut t = CapabilityTable::new();
        // More distinct evicted IIDs than capacity: force repeated
        // eviction + floor capture, then assert the ledger bound.
        let total = CAPABILITY_TABLE_CAPACITY + CAPABILITY_RESERVED;
        for i in 0..total {
            let mut e = entry(iid(i as u16), CAPABILITY_EGRESS_BIT);
            e.seq = i as u64;
            assert!(t.insert(e));
        }
        // Every insert either lands or evicts+floors; the loop-bounded
        // ledger never exceeds capacity.
        assert!(t.seq_floors.len() <= CAPABILITY_TABLE_CAPACITY);
    }
}
