#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
use std::cell::RefCell;
#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::rc::Rc;
#[cfg(feature = "std")]
use std::vec::Vec;

use lichen_core::announce::Announce;
use lichen_link::identity::{iid_from_pubkey, PeerIdentity};
use lichen_link::keys::PublicKey;
use lichen_link::schnorr;

use crate::announce_store::{AnnounceStoreError, AnnounceTrustState, AnnounceTrustStore};
use crate::gradient::{
    GeoCoords, GradientEntry, GradientSource, GradientTable, GRADIENT_TIMEOUT_MS,
};

pub const MAX_TRACKED_ORIGINATORS: usize = 64;
const SEQ_HALF: u16 = 1 << 15;

#[inline]
pub fn seq_gt(a: u16, b: u16) -> bool {
    a != b && a.wrapping_sub(b) < SEQ_HALF
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnnounceRejectReason {
    InvalidSignature,
    IidMismatch,
    StaleSeqNum,
    HopLimitExceeded,
    Malformed,
    KeyChangeDetected,
    /// Durable trust state could not be read or committed; admission fails
    /// closed (no route/gradient mutation) per persist-first ordering.
    PersistenceError,
    /// The durable store is at its lifetime originator capacity
    /// (MAX_TRACKED_ORIGINATORS) and the IID is new. Distinct from
    /// PersistenceError so operators can diagnose store-full admission
    /// bricks instead of suspecting corruption.
    StoreFull,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceResult {
    pub accepted: bool,
    pub should_relay: bool,
    pub reject_reason: Option<AnnounceRejectReason>,
    pub peer: Option<PeerIdentity>,
    pub congestion: Option<u8>,
    pub evicted_iid: Option<[u8; 8]>,
    pub rx_channel: u8,
}

impl AnnounceResult {
    fn rejected(reason: AnnounceRejectReason) -> Self {
        Self {
            accepted: false,
            should_relay: false,
            reject_reason: Some(reason),
            peer: None,
            congestion: None,
            evicted_iid: None,
            rx_channel: 0,
        }
    }

    fn accepted(
        should_relay: bool,
        peer: PeerIdentity,
        congestion: Option<u8>,
        evicted_iid: Option<[u8; 8]>,
        rx_channel: u8,
    ) -> Self {
        Self {
            accepted: true,
            should_relay,
            reject_reason: None,
            peer: Some(peer),
            congestion,
            evicted_iid,
            rx_channel,
        }
    }
}

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
struct SeenEntry {
    seq_num: u16,
    last_access: u64,
}

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
struct PinnedKeyEntry {
    pubkey: [u8; 32],
    last_access: u64,
}

#[cfg(feature = "std")]
#[derive(Clone)]
pub struct AnnounceProcessor {
    gradient_table: GradientTable,
    prefix: [u8; 8],
    seen: HashMap<[u8; 8], SeenEntry>,
    pinned_keys: HashMap<[u8; 8], PinnedKeyEntry>,
    /// Durable TOFU pin/floor state, shared with clones so a staged admission
    /// (receive-path clone-process-commit) still persists before applying.
    trust_store: Rc<RefCell<AnnounceTrustStore>>,
    access_counter: u64,
    max_entries: usize,
}

#[cfg(feature = "std")]
impl AnnounceProcessor {
    pub fn new(gradient_table: GradientTable, prefix: [u8; 8]) -> Self {
        Self::with_trust_store(gradient_table, prefix, AnnounceTrustStore::ephemeral())
    }

    /// Build a processor whose admission decisions commit to `store` before
    /// any in-memory state is applied (persist-first, spec GCP-6.5).
    pub fn with_trust_store(
        gradient_table: GradientTable,
        prefix: [u8; 8],
        store: AnnounceTrustStore,
    ) -> Self {
        Self {
            gradient_table,
            prefix,
            seen: HashMap::new(),
            pinned_keys: HashMap::new(),
            trust_store: Rc::new(RefCell::new(store)),
            access_counter: 0,
            max_entries: MAX_TRACKED_ORIGINATORS,
        }
    }

    /// Process an incoming announce message (spec 9.3 pseudocode).
    ///
    /// # Arguments
    /// * `announce` - The parsed announce message.
    /// * `from_neighbor` - Link-local address of the neighbor who sent this.
    ///   This becomes the next_hop in our gradient (not the originator).
    /// * `now_ms` - Current time in milliseconds.
    ///
    /// # Returns
    /// `AnnounceResult` indicating what happened.
    pub fn process(
        &mut self,
        announce: &Announce<'_>,
        from_neighbor: [u8; 16],
        now_ms: u32,
    ) -> AnnounceResult {
        let pubkey = PublicKey::new(*announce.pubkey);
        let expected_iid = iid_from_pubkey(&pubkey);
        if *announce.originator_iid != expected_iid {
            return AnnounceResult::rejected(AnnounceRejectReason::IidMismatch);
        }

        let mut signed_buf = [0u8; 256];
        let signed_len = announce.write_signed_data(&mut signed_buf).unwrap_or(0);
        if signed_len == 0 {
            return AnnounceResult::rejected(AnnounceRejectReason::Malformed);
        }
        if !schnorr::verify(&pubkey, &signed_buf[..signed_len], announce.signature) {
            return AnnounceResult::rejected(AnnounceRejectReason::InvalidSignature);
        }

        let iid = *announce.originator_iid;

        if let Some(entry) = self.pinned_keys.get(&iid) {
            if entry.pubkey != *announce.pubkey {
                return AnnounceResult::rejected(AnnounceRejectReason::KeyChangeDetected);
            }
        }

        // Durable trust state is authoritative for both the pin and the
        // sequence floor, including after eviction or restart (the in-memory
        // tables above can lag the store). Ephemeral stores mirror memory and
        // are not consulted. Any durable failure rejects the announce before
        // any state is touched.
        let durable = {
            let mut store = self.trust_store.borrow_mut();
            if !store.is_persistent() {
                None
            } else {
                match store.load(&iid) {
                    Ok(state) => state,
                    Err(_) => {
                        return AnnounceResult::rejected(AnnounceRejectReason::PersistenceError)
                    }
                }
            }
        };
        if let Some(state) = durable {
            if state.pubkey != *announce.pubkey {
                return AnnounceResult::rejected(AnnounceRejectReason::KeyChangeDetected);
            }
            if !seq_gt(announce.seq_num, state.seq) {
                return AnnounceResult::rejected(AnnounceRejectReason::StaleSeqNum);
            }
        }

        if let Some(entry) = self.seen.get(&iid) {
            if !seq_gt(announce.seq_num, entry.seq_num) {
                return AnnounceResult::rejected(AnnounceRejectReason::StaleSeqNum);
            }
        }

        self.access_counter += 1;
        let access = self.access_counter;

        let mut destination = [0u8; 16];
        destination[..8].copy_from_slice(&self.prefix);
        destination[8..].copy_from_slice(&iid);

        let coords = GeoCoords::from_app_data(announce.app_data);

        let congestion = parse_congestion(announce.app_data);

        let entry = GradientEntry {
            destination,
            next_hop: from_neighbor,
            hop_count: announce.hop_count,
            seq_num: announce.seq_num,
            source: GradientSource::Announce,
            expires_ms: now_ms.wrapping_add(GRADIENT_TIMEOUT_MS),
            coords,
        };

        // Persist-first (spec GCP-6.5): commit the exact pin and the new
        // sequence floor to the store before mutating any in-memory state.
        // If the durable commit fails, admission fails closed with the
        // gradient, pin, and replay tables untouched. A surviving floor after
        // a crash forces the legitimate sender to increment its sequence.
        if self.trust_store.borrow().is_persistent() {
            let accept_result = self
                .trust_store
                .borrow_mut()
                .accept(
                    &iid,
                    AnnounceTrustState {
                        pubkey: *announce.pubkey,
                        seq: announce.seq_num,
                    },
                );
            if let Err(err) = accept_result {
                // Full (lifetime originator cap) is an operator-diagnosable
                // capacity condition, not corruption: surface it distinctly.
                let reason = match err {
                    AnnounceStoreError::Full => AnnounceRejectReason::StoreFull,
                    _ => AnnounceRejectReason::PersistenceError,
                };
                return AnnounceResult::rejected(reason);
            }
        }

        self.gradient_table.update(entry, now_ms);

        self.pinned_keys.insert(
            iid,
            PinnedKeyEntry {
                pubkey: *announce.pubkey,
                last_access: access,
            },
        );
        let evicted_iid = self.evict_pinned_if_needed();

        self.seen.insert(
            iid,
            SeenEntry {
                seq_num: announce.seq_num,
                last_access: access,
            },
        );
        self.evict_seen_if_needed();

        let should_relay = announce.should_relay();

        let peer = PeerIdentity::from_pubkey(pubkey);
        AnnounceResult::accepted(
            should_relay,
            peer,
            congestion,
            evicted_iid,
            announce.rx_channel,
        )
    }

    pub fn pinned_pubkey_for(&self, iid: &[u8; 8]) -> Option<PublicKey> {
        if let Some(entry) = self.pinned_keys.get(iid) {
            let public_key = PublicKey::new(entry.pubkey);
            return (iid_from_pubkey(&public_key) == *iid).then_some(public_key);
        }
        // Durable fallback: an evicted or restarted-over pin still binds the
        // exact stored key, so Announce TOFU and DAO origin admission share
        // one trust base. Ephemeral stores are not consulted; a corrupt or
        // missing durable record fails closed (no pin).
        if !self.trust_store.borrow().is_persistent() {
            return None;
        }
        let state = self.trust_store.borrow_mut().load(iid).ok().flatten()?;
        let public_key = PublicKey::new(state.pubkey);
        (iid_from_pubkey(&public_key) == *iid).then_some(public_key)
    }

    /// Return a bounded, canonical snapshot for security-sensitive fallback
    /// resolution when an indexed claimed-IID lookup misses.
    ///
    /// `None` fails closed if internal capacity or key/IID invariants are not
    /// satisfied. Callers must still cryptographically identify exactly one
    /// matching key; snapshot order has no semantic meaning.
    pub fn pinned_pubkeys_snapshot(&self) -> Option<Vec<PublicKey>> {
        if self.pinned_keys.len() > self.max_entries
            || self.pinned_keys.len() > MAX_TRACKED_ORIGINATORS
        {
            return None;
        }
        let mut snapshot = Vec::with_capacity(self.pinned_keys.len());
        for (iid, entry) in &self.pinned_keys {
            let public_key = PublicKey::new(entry.pubkey);
            if iid_from_pubkey(&public_key) != *iid {
                return None;
            }
            snapshot.push(public_key);
        }
        Some(snapshot)
    }

    #[cfg(test)]
    pub(crate) fn pin_for_test(&mut self, pubkey: PublicKey) {
        let iid = iid_from_pubkey(&pubkey);
        self.pinned_keys.insert(
            iid,
            PinnedKeyEntry {
                pubkey: *pubkey.as_bytes(),
                last_access: 0,
            },
        );
    }

    pub fn known_originators(&self) -> Vec<[u8; 8]> {
        self.seen.keys().copied().collect()
    }

    pub fn build_relay_hop_count(&self, announce: &Announce<'_>) -> Option<u8> {
        if announce.should_relay() {
            Some(announce.hop_count + 1)
        } else {
            None
        }
    }

    pub fn gradient_table(&self) -> &GradientTable {
        &self.gradient_table
    }

    pub fn gradient_table_mut(&mut self) -> &mut GradientTable {
        &mut self.gradient_table
    }

    fn evict_pinned_if_needed(&mut self) -> Option<[u8; 8]> {
        let mut evicted = None;
        while self.pinned_keys.len() > self.max_entries {
            let oldest_iid = self
                .pinned_keys
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| *k);
            if let Some(iid) = oldest_iid {
                self.pinned_keys.remove(&iid);
                evicted = Some(iid);
            }
        }
        evicted
    }

    fn evict_seen_if_needed(&mut self) {
        while self.seen.len() > self.max_entries {
            let oldest_iid = self
                .seen
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| *k);
            if let Some(iid) = oldest_iid {
                self.seen.remove(&iid);
            }
        }
    }
}

const CONGESTION_TLV: u8 = 0x02;

fn parse_congestion(app_data: &[u8]) -> Option<u8> {
    for i in 0..app_data.len().saturating_sub(1) {
        if app_data[i] == CONGESTION_TLV {
            return Some(app_data[i + 1]);
        }
    }
    None
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use lichen_core::announce::{write_announce_signed_data, AnnounceBuilder};
    use lichen_link::identity::Identity;
    use lichen_link::keys::Seed;
    use lichen_link::schnorr::sign;
    use std::format;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn make_identity(seed_byte: u8) -> Identity {
        Identity::from_seed(Seed::new([seed_byte; 32]))
    }

    fn link_local(iid: u8) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[0] = 0xfe;
        addr[1] = 0x80;
        addr[15] = iid;
        addr
    }

    fn ula_prefix() -> [u8; 8] {
        [0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    }

    fn make_signed_announce(
        identity: &Identity,
        seq_num: u16,
        hop_count: u8,
        rx_channel: u8,
        app_data: &[u8],
        buf: &mut [u8],
    ) -> usize {
        let mut signed_data = [0u8; 256];
        let signed_len = write_announce_signed_data(
            &identity.iid,
            identity.pubkey.as_bytes(),
            seq_num,
            rx_channel,
            app_data,
            &mut signed_data,
        )
        .unwrap();

        let sig = sign(
            &identity.privkey,
            &identity.pubkey,
            &signed_data[..signed_len],
        );

        let builder = AnnounceBuilder {
            originator_iid: &identity.iid,
            pubkey: identity.pubkey.as_bytes(),
            seq_num,
            hop_count,
            rx_channel,
            signature: &sig,
            app_data,
        };
        builder.write_to(buf).unwrap()
    }

    #[test]
    fn canonical_signed_data_vectors_match_production_codec_and_verifier() {
        let document: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test/vectors/announce_signed_data.json"
        ))
        .unwrap();
        let vectors = document["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 4);

        for vector in vectors {
            let frame = hex::decode(vector["announce_frame"].as_str().unwrap()).unwrap();
            let expected_transcript =
                hex::decode(vector["signed_data_transcript"].as_str().unwrap()).unwrap();
            let announce = Announce::from_bytes(&frame).unwrap();
            let mut transcript = [0u8; 256];
            let transcript_len = announce.write_signed_data(&mut transcript).unwrap();
            assert_eq!(
                &transcript[..transcript_len],
                expected_transcript,
                "{}",
                vector["name"]
            );

            let public_key = PublicKey::new(*announce.pubkey);
            assert!(
                schnorr::verify(
                    &public_key,
                    &transcript[..transcript_len],
                    announce.signature
                ),
                "{}",
                vector["name"]
            );
        }
    }

    // Hardcoded hex literals from test/vectors/announce_signed_data.json
    // (format_version 2). Independent oracle: PyNaCl-backed reference generator.
    // Never derive these bytes from the Rust implementation.
    const VECTOR_NAME: [&str; 4] = [
        "announce_signed_data_transcript",
        "announce_minimal_no_app_data",
        "announce_rx_channel_7_max",
        "announce_seq_num_boundary_max",
    ];
    const VECTOR_FRAME: [&str; 4] = [
        "01030012347159bd633b2e9120207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab68fb8026560205a281405ca544742aab41f72ff9ebbbcc61fd493f0a4ad7264839149ea51ca842ef1bf823c24dffa5e0ddeadbeef",
        "01000000017159bd633b2e9120207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab625e348c05c8fbd085e57ff7c615a4bd233bb00f3056e7d102850076699fbdb349c656cc7f5db68b09eaa343c8d4cb605",
        "01070000647159bd633b2e9120207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab68a2c48c664af377c420542300b4de6cb4806f1d53d1d24a6169e9c19c6123d0307cce9c507c5b3230357f5d0b2af3207",
        "010000ffff7159bd633b2e9120207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6e85c70acee77bb8a93b7236b542c26fa019a1746936f06af4b4b565fca80ec4931c80ddab51ae04cc1234c289bd64a02",
    ];
    const VECTOR_TRANSCRIPT: [&str; 4] = [
        "4c494348454e2d414e4e4f554e43452d7631007159bd633b2e9120207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab61234030004deadbeef",
        "4c494348454e2d414e4e4f554e43452d7631007159bd633b2e9120207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab60001000000",
        "4c494348454e2d414e4e4f554e43452d7631007159bd633b2e9120207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab60064070000",
        "4c494348454e2d414e4e4f554e43452d7631007159bd633b2e9120207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6ffff000000",
    ];
    const VECTOR_SIGNATURE: [&str; 4] = [
        "8fb8026560205a281405ca544742aab41f72ff9ebbbcc61fd493f0a4ad7264839149ea51ca842ef1bf823c24dffa5e0d",
        "25e348c05c8fbd085e57ff7c615a4bd233bb00f3056e7d102850076699fbdb349c656cc7f5db68b09eaa343c8d4cb605",
        "8a2c48c664af377c420542300b4de6cb4806f1d53d1d24a6169e9c19c6123d0307cce9c507c5b3230357f5d0b2af3207",
        "e85c70acee77bb8a93b7236b542c26fa019a1746936f06af4b4b565fca80ec4931c80ddab51ae04cc1234c289bd64a02",
    ];
    const VECTOR_PUBKEY: &str = "207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6";
    const VECTOR_SIGNING_SEED: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn vector_oracle_key() -> (Identity, PublicKey) {
        let seed_bytes: [u8; 32] = hex::decode(VECTOR_SIGNING_SEED)
            .unwrap()
            .try_into()
            .unwrap();
        let identity = Identity::from_seed(Seed::new(seed_bytes));
        let pubkey_bytes: [u8; 32] = hex::decode(VECTOR_PUBKEY).unwrap().try_into().unwrap();
        (identity, PublicKey::new(pubkey_bytes))
    }

    #[test]
    fn hardcoded_canonical_vectors_match_production_codec_and_verifier() {
        let (identity, pubkey) = vector_oracle_key();
        assert_eq!(
            identity.pubkey, pubkey,
            "signing seed must derive the oracle public key"
        );

        for i in 0..4 {
            let frame = hex::decode(VECTOR_FRAME[i]).unwrap();
            let expected_transcript = hex::decode(VECTOR_TRANSCRIPT[i]).unwrap();
            let signature: [u8; 48] = hex::decode(VECTOR_SIGNATURE[i])
                .unwrap()
                .try_into()
                .unwrap();

            let announce = Announce::from_bytes(&frame).unwrap();
            let mut transcript = [0u8; 256];
            let transcript_len = announce.write_signed_data(&mut transcript).unwrap();
            assert_eq!(
                &transcript[..transcript_len],
                expected_transcript,
                "{}",
                VECTOR_NAME[i]
            );
            assert!(
                schnorr::verify(&pubkey, &transcript[..transcript_len], &signature),
                "{}",
                VECTOR_NAME[i]
            );
        }
    }

    #[test]
    fn hardcoded_vector_frame_accepted_by_production_processor() {
        let frame = hex::decode(VECTOR_FRAME[0]).unwrap();
        let announce = Announce::from_bytes(&frame).unwrap();
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(result.accepted, "{:?}", result.reject_reason);
        let peer = result.peer.unwrap();
        assert_eq!(
            peer.iid, *announce.originator_iid,
            "peer IID must match the oracle vector IID"
        );
    }

    /// Verify the oracle signature fails against a mutated canonical transcript.
    fn oracle_signature_fails(mutated: &[u8]) -> bool {
        let (_, pubkey) = vector_oracle_key();
        let signature: [u8; 48] = hex::decode(VECTOR_SIGNATURE[0])
            .unwrap()
            .try_into()
            .unwrap();
        !schnorr::verify(&pubkey, mutated, &signature)
    }

    #[test]
    fn oracle_signature_rejected_over_wrong_domain() {
        let mut transcript = hex::decode(VECTOR_TRANSCRIPT[0]).unwrap();
        assert_eq!(&transcript[..19], b"LICHEN-ANNOUNCE-v1\0");
        transcript[18] = b'2'; // LICHEN-ANNOUNCE-v2
        assert!(oracle_signature_fails(&transcript));
    }

    #[test]
    fn oracle_signature_rejected_over_wrong_app_len() {
        let mut transcript = hex::decode(VECTOR_TRANSCRIPT[0]).unwrap();
        transcript[62] = 0x00;
        transcript[63] = 0x05; // declared 5, actual app is 4 bytes
        assert!(oracle_signature_fails(&transcript));
    }

    #[test]
    fn oracle_signature_rejected_over_truncated_app() {
        let transcript = hex::decode(VECTOR_TRANSCRIPT[0]).unwrap();
        assert!(oracle_signature_fails(&transcript[..transcript.len() - 1]));
    }

    #[test]
    fn oracle_signature_rejected_over_seq_endianness_flip() {
        let mut transcript = hex::decode(VECTOR_TRANSCRIPT[0]).unwrap();
        transcript[59] = 0x34;
        transcript[60] = 0x12; // seq 0x1234 read little-endian
        assert!(oracle_signature_fails(&transcript));
    }

    #[test]
    fn oracle_signature_rejected_over_legacy_transcript_layout() {
        // Legacy layout: IID || pubkey || seq || channel || app, with no
        // domain separator and no app-data length. The canonical oracle
        // signature must not verify over it, and the production builder
        // must never emit it.
        let canonical = hex::decode(VECTOR_TRANSCRIPT[0]).unwrap();
        let mut legacy = Vec::with_capacity(47);
        legacy.extend_from_slice(&canonical[19..62]); // iid || pubkey || seq || channel
        legacy.extend_from_slice(&canonical[64..]); // app data, no length prefix
        assert_eq!(legacy.len(), 47);
        assert_ne!(legacy, canonical);
        assert!(oracle_signature_fails(&legacy));
    }

    #[test]
    fn processor_rejects_signature_over_legacy_transcript() {
        // Canonical-only verification: an announce signed over the legacy
        // IID||pubkey||seq||channel||app transcript is rejected (no
        // accept-both migration path, mirroring the Python reference).
        let (identity, _) = vector_oracle_key();
        let canonical = hex::decode(VECTOR_TRANSCRIPT[0]).unwrap();
        let mut legacy = Vec::with_capacity(47);
        legacy.extend_from_slice(&canonical[19..62]);
        legacy.extend_from_slice(&canonical[64..]);
        let signature = sign(&identity.privkey, &identity.pubkey, &legacy);

        let app_data = &canonical[64..];
        let seq_num = u16::from_be_bytes([canonical[59], canonical[60]]);
        let rx_channel = canonical[61];
        let builder = AnnounceBuilder {
            originator_iid: &identity.iid,
            pubkey: identity.pubkey.as_bytes(),
            seq_num,
            hop_count: 0,
            rx_channel,
            signature: &signature,
            app_data,
        };
        let mut buf = [0u8; 256];
        let len = builder.write_to(&mut buf).unwrap();
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());
        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(!result.accepted);
        assert_eq!(
            result.reject_reason,
            Some(AnnounceRejectReason::InvalidSignature)
        );
    }

    #[test]
    fn seq_gt_normal() {
        assert!(seq_gt(10, 5));
        assert!(!seq_gt(5, 10));
        assert!(!seq_gt(5, 5));
    }

    #[test]
    fn seq_gt_wraparound() {
        // 0 is newer than 65535 (just wrapped)
        assert!(seq_gt(0, 65535));
        assert!(seq_gt(1, 65535));
        assert!(seq_gt(100, 65535));

        // RFC 1982: a > b iff (a - b) mod 2^16 < 32768
        // 65535 - 32768 = 32767 < 32768, so 65535 > 32768
        assert!(seq_gt(65535, 32768));
        // But 32768 - 65535 mod 2^16 = 32769 >= 32768, so 32768 is NOT > 65535
        assert!(!seq_gt(32768, 65535));
    }

    #[test]
    fn accept_valid_announce() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let from_neighbor = link_local(0xAA);
        let result = processor.process(&announce, from_neighbor, 1000);

        assert!(result.accepted);
        assert!(result.should_relay);
        assert_eq!(result.reject_reason, None);
        assert!(result.peer.is_some());
        let peer = result.peer.unwrap();
        assert_eq!(peer.iid, identity.iid);
    }

    #[test]
    fn reject_iid_mismatch() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        let wrong_iid = [0xAA; 8];
        let mut signed_data = [0u8; 64];
        write_announce_signed_data(
            &identity.iid,
            identity.pubkey.as_bytes(),
            100,
            0,
            &[],
            &mut signed_data,
        )
        .unwrap();
        let sig = sign(&identity.privkey, &identity.pubkey, &signed_data);

        let builder = AnnounceBuilder {
            originator_iid: &wrong_iid,
            pubkey: identity.pubkey.as_bytes(),
            seq_num: 100,
            hop_count: 3,
            rx_channel: 0,
            signature: &sig,
            app_data: &[],
        };
        let mut buf = [0u8; 256];
        let len = builder.write_to(&mut buf).unwrap();
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(!result.accepted);
        assert_eq!(
            result.reject_reason,
            Some(AnnounceRejectReason::IidMismatch)
        );
    }

    #[test]
    fn reject_invalid_signature() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        let bad_sig = [0xFF; 48];
        let builder = AnnounceBuilder {
            originator_iid: &identity.iid,
            pubkey: identity.pubkey.as_bytes(),
            seq_num: 100,
            hop_count: 3,
            rx_channel: 0,
            signature: &bad_sig,
            app_data: &[],
        };
        let mut buf = [0u8; 256];
        let len = builder.write_to(&mut buf).unwrap();
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(!result.accepted);
        assert_eq!(
            result.reject_reason,
            Some(AnnounceRejectReason::InvalidSignature)
        );
    }

    #[test]
    fn reject_stale_seqnum() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        // Accept first announce with seq_num 100
        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(result.accepted);

        // Reject announce with same seq_num
        let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 2000);
        assert!(!result.accepted);
        assert_eq!(
            result.reject_reason,
            Some(AnnounceRejectReason::StaleSeqNum)
        );

        // Reject announce with lower seq_num
        let len = make_signed_announce(&identity, 50, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 3000);
        assert!(!result.accepted);
        assert_eq!(
            result.reject_reason,
            Some(AnnounceRejectReason::StaleSeqNum)
        );

        // Accept announce with higher seq_num
        let len = make_signed_announce(&identity, 200, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 4000);
        assert!(result.accepted);
    }

    #[test]
    fn reject_key_change() {
        let identity1 = make_identity(0x01);
        let identity2 = make_identity(0x02);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        // Accept first announce from identity1
        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity1, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(result.accepted);

        let mut signed_data = [0u8; 64];
        write_announce_signed_data(
            &identity1.iid,
            identity2.pubkey.as_bytes(),
            200,
            0,
            &[],
            &mut signed_data,
        )
        .unwrap();
        let sig = sign(&identity2.privkey, &identity2.pubkey, &signed_data);

        let builder = AnnounceBuilder {
            originator_iid: &identity1.iid,
            pubkey: identity2.pubkey.as_bytes(),
            seq_num: 200,
            hop_count: 3,
            rx_channel: 0,
            signature: &sig,
            app_data: &[],
        };
        let len = builder.write_to(&mut buf).unwrap();
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let result = processor.process(&announce, link_local(0xAA), 2000);
        assert!(!result.accepted);
        assert_eq!(
            result.reject_reason,
            Some(AnnounceRejectReason::IidMismatch)
        );
    }

    #[test]
    fn key_pinning_tofu() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        // No pinned key yet
        assert!(processor.pinned_pubkey_for(&identity.iid).is_none());

        // Accept announce - pins the key
        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        processor.process(&announce, link_local(0xAA), 1000);

        // Key is now pinned
        let pinned = processor.pinned_pubkey_for(&identity.iid);
        assert!(pinned.is_some());
        assert_eq!(pinned.unwrap(), identity.pubkey);
    }

    #[test]
    fn exhaustive_pin_snapshot_is_bounded_and_revalidates_canonical_iids() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());
        processor.pin_for_test(identity.pubkey);
        assert_eq!(processor.pinned_pubkeys_snapshot().unwrap().len(), 1);

        processor.max_entries = 0;
        assert!(processor.pinned_pubkeys_snapshot().is_none());
        processor.max_entries = MAX_TRACKED_ORIGINATORS;

        let entry = processor.pinned_keys.remove(&identity.iid).unwrap();
        processor.pinned_keys.insert([0xff; 8], entry);
        assert!(processor.pinned_pubkey_for(&[0xff; 8]).is_none());
        assert!(processor.pinned_pubkeys_snapshot().is_none());
    }

    #[test]
    fn gradient_table_updated() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let from_neighbor = link_local(0xAA);
        processor.process(&announce, from_neighbor, 1000);

        // Build expected destination address
        let mut expected_dst = [0u8; 16];
        expected_dst[..8].copy_from_slice(&ula_prefix());
        expected_dst[8..].copy_from_slice(&identity.iid);

        let entry = processor.gradient_table_mut().lookup(&expected_dst, 1000);
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.next_hop, from_neighbor);
        assert_eq!(entry.hop_count, 3);
        assert_eq!(entry.seq_num, 100);
        assert_eq!(entry.source, GradientSource::Announce);
    }

    #[test]
    fn hop_limit_prevents_relay() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        // Announce at max hops (15)
        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 15, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(result.accepted);
        assert!(!result.should_relay); // At max hops, don't relay

        // Announce below max hops should relay
        let len = make_signed_announce(&identity, 101, 14, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let result = processor.process(&announce, link_local(0xAA), 2000);
        assert!(result.accepted);
        assert!(result.should_relay);
    }

    #[test]
    fn congestion_parsing() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        let app_data = [0x02, 42];
        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 3, 0, &app_data, &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(result.accepted);
        assert_eq!(result.congestion, Some(42));
    }

    #[test]
    fn congestion_parsing_skips_unknown_types() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        let app_data = [0xFF, 0xAA, 0xBB, 0x02, 77];
        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 3, 0, &app_data, &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(result.accepted);
        assert_eq!(result.congestion, Some(77));
    }

    #[test]
    fn lru_eviction() {
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());
        processor.max_entries = 3; // Small capacity for testing

        // Fill with 3 originators
        let mut buf = [0u8; 256];
        for i in 1..=3 {
            let identity = make_identity(i);
            let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
            let announce = Announce::from_bytes(&buf[..len]).unwrap();
            processor.process(&announce, link_local(0xAA), 1000 + i as u32);
        }
        assert_eq!(processor.known_originators().len(), 3);

        // Add a 4th - should evict the oldest (identity 1)
        let identity4 = make_identity(4);
        let len = make_signed_announce(&identity4, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        processor.process(&announce, link_local(0xAA), 5000);

        assert_eq!(processor.known_originators().len(), 3);
        let identity1 = make_identity(1);
        assert!(!processor.known_originators().contains(&identity1.iid));
        assert!(processor.known_originators().contains(&identity4.iid));
    }

    #[test]
    fn seqnum_wraparound_accepted() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        // Start near max seq_num
        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 65534, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(result.accepted);

        // Wrapped seq_num (0) is newer than 65534
        let len = make_signed_announce(&identity, 0, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 2000);
        assert!(result.accepted);

        // And 1 is newer than 0
        let len = make_signed_announce(&identity, 1, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 3000);
        assert!(result.accepted);
    }

    // --- Durable trust store integration (persist-first admission) ---

    fn unique_test_roots(
        name: &str,
        counter: &AtomicU64,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let suffix = counter.fetch_add(1, Ordering::Relaxed);
        let state = std::env::temp_dir().join(format!(
            "lichen-node-announce-integration-{name}-{}-{suffix}",
            std::process::id()
        ));
        let floor = state.with_extension("floors");
        for path in [&state, &floor] {
            std::fs::create_dir_all(path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        (state, floor)
    }

    fn remove_roots(state: &std::path::Path, floor: &std::path::Path) {
        std::fs::remove_dir_all(state).unwrap();
        std::fs::remove_dir_all(floor).unwrap();
    }

    #[test]
    fn durable_commit_failure_fails_admission_closed() {
        let counter = AtomicU64::new(3000);
        let (state_root, floor_root) = unique_test_roots("capacity", &counter);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::with_trust_store(
            gradient_table,
            ula_prefix(),
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x4A; 32]).unwrap(),
        );

        // Exhaust the durable store's lifetime capacity so the next admission
        // cannot commit. The store is shared with the processor via the same Rc.
        for i in 0..MAX_TRACKED_ORIGINATORS {
            let mut iid = [0u8; 8];
            iid[0] = i as u8;
            processor
                .trust_store
                .borrow_mut()
                .accept(
                    &iid,
                    AnnounceTrustState {
                        pubkey: [i as u8; 32],
                        seq: 1,
                    },
                )
                .unwrap();
        }

        let identity = make_identity(0x7E);
        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(!result.accepted);
        assert_eq!(
            result.reject_reason,
            Some(AnnounceRejectReason::StoreFull)
        );

        // Fail closed: the route/gradient state for the originator was not
        // mutated and nothing was pinned or replay-tracked in memory.
        let mut destination = [0u8; 16];
        destination[..8].copy_from_slice(&ula_prefix());
        destination[8..].copy_from_slice(&identity.iid);
        assert!(processor
            .gradient_table_mut()
            .lookup(&destination, 1000)
            .is_none());
        assert!(processor.pinned_pubkey_for(&identity.iid).is_none());
        assert!(!processor.known_originators().contains(&identity.iid));
        drop(processor);
        remove_roots(&state_root, &floor_root);
    }

    #[test]
    fn eviction_respects_durable_pin_and_floor() {
        let counter = AtomicU64::new(1000);
        let (state_root, floor_root) = unique_test_roots("eviction", &counter);
        let identity = make_identity(0x11);

        let mut processor = AnnounceProcessor::with_trust_store(
            GradientTable::new(64),
            ula_prefix(),
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x5A; 32]).unwrap(),
        );
        processor.max_entries = 2;

        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        assert!(
            processor
                .process(&announce, link_local(0xAA), 1000)
                .accepted
        );

        // Push the pinned entry out of the in-memory cache.
        for i in 2..=3 {
            let identity = make_identity(i);
            let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
            let announce = Announce::from_bytes(&buf[..len]).unwrap();
            assert!(
                processor
                    .process(&announce, link_local(0xAA), 2000)
                    .accepted
            );
        }
        assert!(!processor.known_originators().contains(&identity.iid));

        // The pin survives eviction through the durable store and still
        // binds the exact TOFU pubkey.
        assert_eq!(
            processor.pinned_pubkey_for(&identity.iid),
            Some(identity.pubkey)
        );

        // The durable floor survived eviction: the old sequence replays no more.
        let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 3000);
        assert!(!result.accepted);
        assert_eq!(
            result.reject_reason,
            Some(AnnounceRejectReason::StaleSeqNum)
        );

        // A strictly newer announce re-admits and re-applies in memory.
        let len = make_signed_announce(&identity, 105, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 4000);
        assert!(result.accepted, "{:?}", result.reject_reason);

        drop(processor);

        // Restart: a fresh processor over the same roots restores the pin
        // and floor; the accepted sequence is now the durable floor.
        let mut reopened = AnnounceProcessor::with_trust_store(
            GradientTable::new(64),
            ula_prefix(),
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x5A; 32]).unwrap(),
        );
        assert_eq!(
            reopened.pinned_pubkey_for(&identity.iid),
            Some(identity.pubkey)
        );
        let len = make_signed_announce(&identity, 105, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = reopened.process(&announce, link_local(0xAA), 5000);
        assert_eq!(
            result.reject_reason,
            Some(AnnounceRejectReason::StaleSeqNum)
        );

        remove_roots(&state_root, &floor_root);
    }

    #[test]
    fn relayed_replay_rejected_after_restart_regardless_of_relay_addr() {
        let counter = AtomicU64::new(4000);
        let (state_root, floor_root) = unique_test_roots("relay-replay", &counter);
        let identity = make_identity(0x31);

        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        {
            let mut processor = AnnounceProcessor::with_trust_store(
                GradientTable::new(64),
                ula_prefix(),
                AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x7C; 32]).unwrap(),
            );
            // Direct delivery pins the origin and raises the floor to 100.
            assert!(processor.process(&announce, link_local(0xAA), 1000).accepted);
        }

        // Restart: the pin and the seq-100 floor are durable.
        let mut restarted = AnnounceProcessor::with_trust_store(
            GradientTable::new(64),
            ula_prefix(),
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x7C; 32]).unwrap(),
        );
        assert_eq!(
            restarted.pinned_pubkey_for(&identity.iid),
            Some(identity.pubkey)
        );

        // The same origin-signed announce replayed as a relayed frame
        // (hop_count incremented in transit, signature untouched since
        // hop_count is outside the signed data) from a DIFFERENT
        // authenticated relay is still rejected: the durable floor binds
        // the originator IID, not the receiving address.
        let relayed_len = make_signed_announce(&identity, 100, 4, 0, &[], &mut buf);
        let relayed = Announce::from_bytes(&buf[..relayed_len]).unwrap();
        let result = restarted.process(&relayed, link_local(0x77), 2000);
        assert!(!result.accepted);
        assert_eq!(
            result.reject_reason,
            Some(AnnounceRejectReason::StaleSeqNum)
        );

        // A strictly newer announce arriving through the same relay admits.
        let newer_len = make_signed_announce(&identity, 101, 4, 0, &[], &mut buf);
        let newer = Announce::from_bytes(&buf[..newer_len]).unwrap();
        let result = restarted.process(&newer, link_local(0x77), 3000);
        assert!(result.accepted, "{:?}", result.reject_reason);

        remove_roots(&state_root, &floor_root);
    }

    #[test]
    fn corrupt_durable_record_fails_admission_closed() {
        let counter = AtomicU64::new(2000);
        let (state_root, floor_root) = unique_test_roots("corrupt", &counter);
        let identity = make_identity(0x21);

        let mut processor = AnnounceProcessor::with_trust_store(
            GradientTable::new(64),
            ula_prefix(),
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x6B; 32]).unwrap(),
        );
        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        assert!(
            processor
                .process(&announce, link_local(0xAA), 1000)
                .accepted
        );
        drop(processor);

        // A foreign sealing seed cannot verify the sealed records: pin
        // lookups fail closed and admission is refused outright.
        let mut foreign = AnnounceProcessor::with_trust_store(
            GradientTable::new(64),
            ula_prefix(),
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x6B ^ 0xFF; 32]).unwrap(),
        );
        assert!(foreign.pinned_pubkey_for(&identity.iid).is_none());

        let len = make_signed_announce(&identity, 200, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = foreign.process(&announce, link_local(0xAA), 2000);
        assert!(!result.accepted);
        assert_eq!(
            result.reject_reason,
            Some(AnnounceRejectReason::PersistenceError)
        );
        let mut destination = [0u8; 16];
        destination[..8].copy_from_slice(&ula_prefix());
        destination[8..].copy_from_slice(&identity.iid);
        assert!(foreign
            .gradient_table_mut()
            .lookup(&destination, 2000)
            .is_none());

        drop(foreign);
        remove_roots(&state_root, &floor_root);
    }
}
