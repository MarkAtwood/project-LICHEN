//! SOS origin signature (spec 18.4.1).
//!
//! Hop-by-hop link signatures are replaced on relay. The origin signature
//! persists so receivers can still authenticate who started the SOS.
//!
//! Wire format (`test/vectors/sos_signature.json`):
//! `8-byte big-endian origin sequence || 48-byte Schnorr48`.
//!
//! Transcript (hashed with SHA-512, then signed):
//! `LICHEN-SOS-ORIGIN-v1` || origin IPv6 (16) || sequence (u64 BE) ||
//! canonical CBOR payload.
//!
//! The origin IPv6 MUST be the upstream Yggdrasil `AddrForKey` of the
//! signer (spec decisions `upstream-yggdrasil-addressing`), not an
//! IID-embedded `0200::` synthesis; [`origin_addr_from_pubkey`] derives it,
//! [`sign_sos_origin_for_key`] signs against it, and
//! [`verify_sos_origin_gated`] additionally rejects non-advancing sequences
//! per origin ([`OriginSequenceTracker`]).

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Domain separator; 20 ASCII octets, no terminating NUL.
pub const SOS_ORIGIN_DOMAIN: &[u8; 20] = b"LICHEN-SOS-ORIGIN-v1";

/// Wire length: 8-byte sequence + 48-byte Schnorr48.
pub const SOS_ORIGIN_SIGNATURE_LENGTH: usize = 8 + 48;

/// Default bound on tracked origins (matches the Python gate).
#[cfg(feature = "alloc")]
pub const SOS_ORIGIN_GATE_DEFAULT_CAPACITY: usize = 256;

/// Per-origin monotonic sequence gate (spec 18.4.1 replay protection),
/// mirroring `python/coap/sos_origin.py OriginSequenceTracker`.
///
/// A sequence is accepted only when strictly greater than the highest
/// sequence previously accepted from that origin. The set of tracked
/// origins is bounded by `capacity`; a full set evicts the
/// least-recently-accepted origin (touch order), never arbitrary entries.
/// A zero capacity rejects every new origin (fail closed).
#[cfg(feature = "alloc")]
#[derive(Debug, Default)]
pub struct OriginSequenceTracker {
    // (origin addr, last accepted seq); most-recently-accepted is last.
    entries: Vec<([u8; 16], u64)>,
    capacity: usize,
}

#[cfg(feature = "alloc")]
impl OriginSequenceTracker {
    /// Create a gate tracking at most `capacity` origins.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::new(),
            capacity,
        }
    }

    /// Return `true` and record `seq` iff it strictly advances `origin`.
    ///
    /// ponytail: linear scan over a capacity-bounded set (default 256);
    /// a hash map is the upgrade path only if this ever shows in profiles.
    pub fn accept(&mut self, origin: &[u8; 16], seq: u64) -> bool {
        if let Some(pos) = self.entries.iter().position(|e| &e.0 == origin) {
            if seq <= self.entries[pos].1 {
                return false;
            }
            let mut entry = self.entries.remove(pos);
            entry.1 = seq;
            self.entries.push(entry); // touch: most-recently-accepted last
            return true;
        }
        if self.capacity == 0 {
            return false; // fail closed: no slots, unknown origin
        }
        if self.entries.len() >= self.capacity {
            self.entries.remove(0); // evict least-recently-accepted origin
        }
        self.entries.push((*origin, seq));
        true
    }

    /// Highest accepted sequence for `origin`, or `None` if unseen.
    pub fn last_seen(&self, origin: &[u8; 16]) -> Option<u64> {
        self.entries.iter().find(|e| &e.0 == origin).map(|e| e.1)
    }
}

/// Origin IPv6 for SOS signature transcripts: upstream Yggdrasil
/// `AddrForKey` of the signer's raw public-key bytes (bit-packs the inverted
/// pubkey in `0200::/8`; no IID synthesis, no hashing). Decoupled from the
/// `schnorr` feature so non-signing stacks can derive it too.
pub fn origin_addr_from_pubkey(pubkey: &[u8; 32]) -> [u8; 16] {
    lichen_core::addr::ygg_addr_from_pubkey(pubkey)
}

/// Parsed SOS origin signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SosOriginSignature {
    origin_sequence: u64,
    signature: [u8; 48],
}

/// Origin-signature wire parse failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SosOriginSignatureError {
    /// Input was not exactly [`SOS_ORIGIN_SIGNATURE_LENGTH`] bytes.
    WrongLength,
}

impl SosOriginSignature {
    /// Construct from a sequence and 48-byte Schnorr48 signature.
    pub const fn new(origin_sequence: u64, signature: [u8; 48]) -> Self {
        Self {
            origin_sequence,
            signature,
        }
    }

    pub const fn origin_sequence(&self) -> u64 {
        self.origin_sequence
    }

    pub const fn signature(&self) -> &[u8; 48] {
        &self.signature
    }

    /// Serialize: 8-byte big-endian sequence + 48-byte signature.
    pub fn to_bytes(&self) -> [u8; SOS_ORIGIN_SIGNATURE_LENGTH] {
        let mut out = [0u8; SOS_ORIGIN_SIGNATURE_LENGTH];
        out[..8].copy_from_slice(&self.origin_sequence.to_be_bytes());
        out[8..].copy_from_slice(&self.signature);
        out
    }

    /// Parse the 56-byte wire encoding.
    pub fn from_bytes(data: &[u8]) -> Result<Self, SosOriginSignatureError> {
        if data.len() != SOS_ORIGIN_SIGNATURE_LENGTH {
            return Err(SosOriginSignatureError::WrongLength);
        }
        let mut seq = [0u8; 8];
        seq.copy_from_slice(&data[..8]);
        let mut signature = [0u8; 48];
        signature.copy_from_slice(&data[8..]);
        Ok(Self {
            origin_sequence: u64::from_be_bytes(seq),
            signature,
        })
    }
}

/// SHA-512(domain || origin IPv6 || seq BE || canonical CBOR).
#[cfg(feature = "schnorr")]
pub fn compute_sos_transcript(
    origin_addr: &[u8; 16],
    origin_sequence: u64,
    payload_cbor: &[u8],
) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(SOS_ORIGIN_DOMAIN);
    hasher.update(origin_addr);
    hasher.update(origin_sequence.to_be_bytes());
    hasher.update(payload_cbor);
    hasher.finalize().into()
}

/// Sign canonical SOS payload bytes with the origin key.
#[cfg(feature = "schnorr")]
pub fn sign_sos_origin(
    privkey: &crate::keys::PrivateKey,
    pubkey: &crate::keys::PublicKey,
    origin_addr: &[u8; 16],
    origin_sequence: u64,
    payload_cbor: &[u8],
) -> SosOriginSignature {
    use crate::schnorr::sign;
    let digest = compute_sos_transcript(origin_addr, origin_sequence, payload_cbor);
    let signature = sign(privkey, pubkey, &digest);
    let mut bytes = [0u8; 48];
    bytes.copy_from_slice(signature.as_ref());
    SosOriginSignature::new(origin_sequence, bytes)
}

/// Sign against the `AddrForKey` origin address of `pubkey` (spec 18.4.1
/// origin binding; no IID synthesis).
#[cfg(feature = "schnorr")]
pub fn sign_sos_origin_for_key(
    privkey: &crate::keys::PrivateKey,
    pubkey: &crate::keys::PublicKey,
    origin_sequence: u64,
    payload_cbor: &[u8],
) -> SosOriginSignature {
    let origin_addr = origin_addr_from_pubkey(pubkey.as_bytes());
    sign_sos_origin(privkey, pubkey, &origin_addr, origin_sequence, payload_cbor)
}

/// Verify an origin signature over canonical SOS payload bytes.
#[cfg(feature = "schnorr")]
pub fn verify_sos_origin(
    pubkey: &crate::keys::PublicKey,
    origin_addr: &[u8; 16],
    payload_cbor: &[u8],
    signature: &SosOriginSignature,
) -> bool {
    use crate::schnorr::verify;
    let digest = compute_sos_transcript(origin_addr, signature.origin_sequence, payload_cbor);
    verify(pubkey, &digest, &signature.signature)
}

/// Verify and gate in one step: the signature is only accepted when both
/// the Schnorr48 check passes **and** the sequence strictly advances the
/// origin. Fail closed on a bad signature, a non-advancing sequence, or an
/// unknown origin at zero capacity. A *new* origin at capacity evicts the
/// least-recently-accepted entry and is accepted (the gate is bounded, not
/// fail-closed for new origins).
///
/// **Eviction discards replay state:** if an origin is evicted, it is
/// treated as new on reappearance — previously-seen (including lower)
/// sequences become acceptable again. Anti-replay is guaranteed only while
/// an origin remains tracked.
#[cfg(all(feature = "schnorr", feature = "alloc"))]
pub fn verify_sos_origin_gated(
    tracker: &mut OriginSequenceTracker,
    pubkey: &crate::keys::PublicKey,
    origin_addr: &[u8; 16],
    payload_cbor: &[u8],
    signature: &SosOriginSignature,
) -> bool {
    if !verify_sos_origin(pubkey, origin_addr, payload_cbor, signature) {
        return false;
    }
    tracker.accept(origin_addr, signature.origin_sequence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes<const N: usize>(hex: &str) -> [u8; N] {
        let v: std::vec::Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(v.len(), N);
        let mut out = [0u8; N];
        out.copy_from_slice(&v);
        out
    }

    #[test]
    fn domain_matches_vector() {
        assert_eq!(SOS_ORIGIN_DOMAIN.len(), 20);
        assert_eq!(SOS_ORIGIN_DOMAIN.as_slice(), b"LICHEN-SOS-ORIGIN-v1");
        let hex = "4c494348454e2d534f532d4f524947494e2d7631";
        let expected: std::vec::Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(SOS_ORIGIN_DOMAIN.as_slice(), expected.as_slice());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn tracker_accepts_strictly_advancing_sequences() {
        let mut t = OriginSequenceTracker::new(SOS_ORIGIN_GATE_DEFAULT_CAPACITY);
        let origin = [0xAA; 16];
        assert!(t.accept(&origin, 1));
        assert!(!t.accept(&origin, 1)); // equal rejected
        assert!(!t.accept(&origin, 0)); // stale rejected
        assert!(t.accept(&origin, 2));
        assert_eq!(t.last_seen(&origin), Some(2));
        assert_eq!(t.last_seen(&[0xBB; 16]), None); // unseen origin unaffected
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn tracker_bound_evicts_least_recently_accepted() {
        let mut t = OriginSequenceTracker::new(2);
        let (a, b, c) = ([1; 16], [2; 16], [3; 16]);
        assert!(t.accept(&a, 10));
        assert!(t.accept(&b, 10));
        assert!(t.accept(&c, 99)); // at capacity: evicts a (oldest)
        assert_eq!(t.last_seen(&a), None);
        assert_eq!(t.last_seen(&b), Some(10));
        assert_eq!(t.last_seen(&c), Some(99));
        // A rejoining old origin displaces the next-oldest, still fail-open-ish
        // only for advancing sequences.
        assert!(t.accept(&a, 11));
        assert_eq!(t.last_seen(&b), None);
        assert_eq!(t.last_seen(&a), Some(11));
        // Rejecting a stale seq on a tracked origin does not evict/order-shift.
        assert!(!t.accept(&c, 5));
        assert_eq!(t.last_seen(&c), Some(99));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn tracker_u64_max_first_seq_locks_origin_out() {
        // Boundary: a first-seen u64::MAX is accepted, and nothing can ever
        // strictly advance past it — the origin is locked out for good.
        let mut t = OriginSequenceTracker::new(SOS_ORIGIN_GATE_DEFAULT_CAPACITY);
        let origin = [0xCC; 16];
        assert!(t.accept(&origin, u64::MAX));
        assert!(!t.accept(&origin, u64::MAX));
        assert_eq!(t.last_seen(&origin), Some(u64::MAX));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn tracker_zero_capacity_fails_closed() {
        let mut t = OriginSequenceTracker::new(0);
        assert!(!t.accept(&[1; 16], 1));
        assert_eq!(t.last_seen(&[1; 16]), None);
    }

    #[test]
    fn origin_addr_matches_upstream_pinned_vector() {
        // External oracle: test/vectors/yggdrasil_address.json
        // `upstream_addr_for_key` — pinned upstream yggdrasil-go AddrForKey.
        let pubkey_bytes: [u8; 32] =
            hex_to_bytes("bdbacfd82240de3dcd123924cbb55256fb8dab08aa98e305528ab84f419e6efb");
        let addr: [u8; 16] = origin_addr_from_pubkey(&pubkey_bytes);
        let expected: [u8; 16] = hex_to_bytes("0200848a604fbb7e438465db8db66895");
        assert_eq!(addr, expected);
    }

    #[cfg(feature = "schnorr")]
    mod schnorr_tests {
        use super::*;

        fn make_keypair() -> (crate::keys::PrivateKey, crate::keys::PublicKey) {
            crate::schnorr::derive_keypair(&crate::keys::Seed::new([0x42; 32]))
        }

        #[test]
        fn sign_for_key_binds_addrforkey_origin() {
            let (privkey, pubkey) = make_keypair();
            let payload = b"\xa0";
            let sig = sign_sos_origin_for_key(&privkey, &pubkey, 7, payload);
            let addr = origin_addr_from_pubkey(pubkey.as_bytes());
            assert!(verify_sos_origin(&pubkey, &addr, payload, &sig));
            // An IID-synthesized origin must NOT verify (anti-synthesis guard).
            let mut iid_addr = [0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            iid_addr[8..].copy_from_slice(&pubkey.as_bytes()[..8]); // wrong on purpose
            assert!(!verify_sos_origin(&pubkey, &iid_addr, payload, &sig));
        }

        #[test]
        fn gated_verify_rejects_replays_and_advances() {
            let (privkey, pubkey) = make_keypair();
            let addr = origin_addr_from_pubkey(pubkey.as_bytes());
            let payload = b"\xa0";
            let mut tracker = OriginSequenceTracker::new(SOS_ORIGIN_GATE_DEFAULT_CAPACITY);
            // First accept records and admits.
            let s1 = sign_sos_origin_for_key(&privkey, &pubkey, 1, payload);
            assert!(verify_sos_origin_gated(
                &mut tracker,
                &pubkey,
                &addr,
                payload,
                &s1
            ));
            assert_eq!(tracker.last_seen(&addr), Some(1));
            // Same sequence again is a replay: rejected.
            assert!(!verify_sos_origin_gated(
                &mut tracker,
                &pubkey,
                &addr,
                payload,
                &s1
            ));
            // Lower sequence rejected without touching the gate.
            let s0 = sign_sos_origin_for_key(&privkey, &pubkey, 0, payload);
            assert!(!verify_sos_origin_gated(
                &mut tracker,
                &pubkey,
                &addr,
                payload,
                &s0
            ));
            // Advanced sequence accepted.
            let s2 = sign_sos_origin_for_key(&privkey, &pubkey, 2, payload);
            assert!(verify_sos_origin_gated(
                &mut tracker,
                &pubkey,
                &addr,
                payload,
                &s2
            ));
        }

        #[test]
        fn gated_verify_never_advances_gate_on_bad_signature() {
            let (privkey, pubkey) = make_keypair();
            let addr = origin_addr_from_pubkey(pubkey.as_bytes());
            let payload = b"\xa0";
            let mut tracker = OriginSequenceTracker::new(SOS_ORIGIN_GATE_DEFAULT_CAPACITY);
            let good = sign_sos_origin_for_key(&privkey, &pubkey, 5, payload);
            // Forge a 48-byte wrong signature at seq 5.
            let mut forged = good.to_bytes();
            forged[8] ^= 0xFF;
            let forged = SosOriginSignature::from_bytes(&forged).unwrap();
            assert!(!verify_sos_origin_gated(
                &mut tracker,
                &pubkey,
                &addr,
                payload,
                &forged
            ));
            assert_eq!(tracker.last_seen(&addr), None);
            // Real seq-5 signature is still admitted afterward (no lock-out).
            assert!(verify_sos_origin_gated(
                &mut tracker,
                &pubkey,
                &addr,
                payload,
                &good
            ));
            assert_eq!(tracker.last_seen(&addr), Some(5));
        }
    }

    #[test]
    fn wire_format_sequence_42() {
        let sig = SosOriginSignature::new(42, [0xab; 48]);
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), 56);
        assert_eq!(&bytes[..8], &[0, 0, 0, 0, 0, 0, 0, 0x2a]);
        assert_eq!(&bytes[8..], &[0xab; 48]);
        let parsed = SosOriginSignature::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, sig);
    }

    #[test]
    fn from_bytes_rejects_truncated() {
        assert_eq!(
            SosOriginSignature::from_bytes(&[0u8; 8]),
            Err(SosOriginSignatureError::WrongLength)
        );
        assert_eq!(
            SosOriginSignature::from_bytes(&[0u8; 57]),
            Err(SosOriginSignatureError::WrongLength)
        );
    }

    #[cfg(feature = "schnorr")]
    #[test]
    fn transcript_matches_python_oracle() {
        // Independent SHA-512 of domain || ipv6 || seq || canonical CBOR
        // for origin_transcript_format in sos_signature.json.
        let addr = decode_hex16("0200123456789abcdef0123456789abc");
        let cbor = decode_hex_vec(
            "a36274731a66536a90646e6f646573303230303a313233343a353637383a39616263647479706563736f73",
        );
        let got = compute_sos_transcript(&addr, 1, &cbor);
        let expected = decode_hex64(
            "27c558161598913e67951404055694a91a85d8448bb71d17d38da5d537f36955539b49f132895e02a524adf9423ca0379567b9dc2c9923ad6a9d42876663dd18",
        );
        assert_eq!(got, expected);
    }

    #[cfg(feature = "schnorr")]
    #[test]
    fn sign_verify_roundtrip() {
        use crate::keys::Seed;
        use crate::schnorr::derive_keypair;
        let (privkey, pubkey) = derive_keypair(&Seed::new([0x11; 32]));
        let addr = [0x02u8; 16];
        let cbor = b"\xa0";
        let signed = sign_sos_origin(&privkey, &pubkey, &addr, 7, cbor);
        assert!(verify_sos_origin(&pubkey, &addr, cbor, &signed));
        let mut bad_addr = addr;
        bad_addr[0] ^= 1;
        assert!(!verify_sos_origin(&pubkey, &bad_addr, cbor, &signed));
        let tampered = SosOriginSignature::new(8, *signed.signature());
        assert!(!verify_sos_origin(&pubkey, &addr, cbor, &tampered));
    }

    #[cfg(feature = "schnorr")]
    #[test]
    fn wrong_domain_does_not_verify() {
        use crate::keys::Seed;
        use crate::schnorr::{derive_keypair, sign, verify};
        use sha2::{Digest, Sha512};
        let (privkey, pubkey) = derive_keypair(&Seed::new([0x22; 32]));
        let addr = [0x02u8; 16];
        let cbor = b"\xa0";
        let seq = 1u64;
        let mut hasher = Sha512::new();
        hasher.update(b"LICHEN-DAO-ORIGIN-v1");
        hasher.update(addr);
        hasher.update(seq.to_be_bytes());
        hasher.update(cbor);
        let wrong: [u8; 64] = hasher.finalize().into();
        let signature = sign(&privkey, &pubkey, &wrong);
        let mut bytes = [0u8; 48];
        bytes.copy_from_slice(signature.as_ref());
        let wrapped = SosOriginSignature::new(seq, bytes);
        assert!(!verify_sos_origin(&pubkey, &addr, cbor, &wrapped));
        assert!(verify(&pubkey, &wrong, &bytes));
    }

    #[cfg(feature = "schnorr")]
    fn decode_hex16(hex: &str) -> [u8; 16] {
        let v = decode_hex_vec(hex);
        let mut out = [0u8; 16];
        out.copy_from_slice(&v);
        out
    }

    #[cfg(feature = "schnorr")]
    fn decode_hex64(hex: &str) -> [u8; 64] {
        let v = decode_hex_vec(hex);
        let mut out = [0u8; 64];
        out.copy_from_slice(&v);
        out
    }

    #[cfg(feature = "schnorr")]
    fn decode_hex_vec(hex: &str) -> std::vec::Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
