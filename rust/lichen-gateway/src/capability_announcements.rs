//! Capability announcement verification (spec/06-security.md 8.12).
//!
//! Mirrors python/src/lichen/crypto/capability_announcements.py:
//! COSE_Sign1 decode + Schnorr48 verification with the exact validation
//! ordering (reserved bits, IID match, signature, expiry, seq replay).

use ciborium::de::from_reader;
use ciborium::value::{Integer, Value};
use lichen_link::ygg_addr_from_pubkey;
use schnorr48::{self, PublicKey};
use sha2::{Digest, Sha256};

const SCHNORR48_ED25519_ALG: i64 = -65537;
const COSE_ALG_LABEL: i64 = 1;
const COSE_KID_LABEL: i64 = 4;

const PAYLOAD_CAPABILITIES: i64 = 1;
const PAYLOAD_PREFIX: i64 = 2;
const PAYLOAD_PREFIX_LEN: i64 = 3;
const PAYLOAD_EXPIRY: i64 = 4;
const PAYLOAD_SEQ: i64 = 5;
const PAYLOAD_ANNOUNCER_IID: i64 = 6;

/// Reserved capability bits (2-7) MUST be zero (spec 8.12).
const RESERVED_BITS_MASK: u32 = 0xFC;

const SIG_CONTEXT: &str = "Signature1";

/// Decoded capability payload (spec 8.12 table).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityPayload {
    pub capabilities: u32,
    pub prefix: Vec<u8>,
    pub prefix_len: u8,
    pub expiry: u64,
    pub seq: u64,
    pub announcer_iid: [u8; 8],
}

/// A decoded COSE_Sign1 announcement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityAnnouncement {
    pub protected: Vec<u8>,
    pub payload: CapabilityPayload,
    /// Raw payload bytes exactly as carried in the COSE_Sign1 — the
    /// signature transcript uses these, never a re-encoding.
    pub payload_bytes: Vec<u8>,
    pub signature: [u8; 48],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnounceError {
    Malformed,
    AlgorithmInvalid,
    KidMismatch,
    ReservedBitsSet,
    IidMismatch,
    SignatureInvalid,
    Expired,
    ReplayDetected,
}

fn as_bytes(value: &Value) -> Option<&Vec<u8>> {
    match value {
        Value::Bytes(b) => Some(b),
        _ => None,
    }
}

fn as_int(value: &Value) -> Option<i128> {
    match value {
        Value::Integer(i) => Some(i128::from(*i)),
        _ => None,
    }
}

/// Extract the unprotected `kid` (label 4) from the unprotected header map.
fn unprotected_kid(map: &Value) -> Option<[u8; 8]> {
    let pairs = match map {
        Value::Map(pairs) => pairs,
        _ => return None,
    };
    for (key, value) in pairs {
        if as_int(key) == Some(i128::from(COSE_KID_LABEL)) {
            let bytes = as_bytes(value)?;
            let iid: [u8; 8] = bytes.as_slice().try_into().ok()?;
            return Some(iid);
        }
    }
    None
}

/// Decode a CBOR-encoded COSE_Sign1 capability announcement.
pub fn from_cose_sign1(data: &[u8]) -> Result<CapabilityAnnouncement, AnnounceError> {
    let cursor = std::io::Cursor::new(data);
    let cose: Value = from_reader(cursor).map_err(|_| AnnounceError::Malformed)?;
    // COSE_Sign1 may be wrapped in CBOR tag 18 (RFC 9052).
    let cose = match &cose {
        Value::Tag(_, inner) => inner.as_ref(),
        other => other,
    };

    let parts = match &cose {
        Value::Array(parts) if parts.len() == 4 => parts,
        _ => return Err(AnnounceError::Malformed),
    };

    let protected_bytes = as_bytes(&parts[0]).ok_or(AnnounceError::Malformed)?.clone();
    let unprotected = &parts[1];
    let payload_bytes = as_bytes(&parts[2]).ok_or(AnnounceError::Malformed)?.clone();
    let signature: [u8; 48] = as_bytes(&parts[3])
        .ok_or(AnnounceError::Malformed)?
        .as_slice()
        .try_into()
        .map_err(|_| AnnounceError::Malformed)?;

    // Protected header: {1: -65537} (Schnorr48-Ed25519).
    let protected: Value = from_reader(std::io::Cursor::new(&protected_bytes))
        .map_err(|_| AnnounceError::Malformed)?;
    let alg = match &protected {
        Value::Map(pairs) => pairs.iter().find_map(|(key, value)| {
            if as_int(key) == Some(i128::from(COSE_ALG_LABEL)) {
                as_int(value)
            } else {
                None
            }
        }),
        _ => None,
    };
    if alg != Some(i128::from(SCHNORR48_ED25519_ALG)) {
        return Err(AnnounceError::AlgorithmInvalid);
    }

    // Payload: CBOR map with integer keys (1..6).
    let payload_value: Value =
        from_reader(std::io::Cursor::new(&payload_bytes)).map_err(|_| AnnounceError::Malformed)?;
    let pairs = match &payload_value {
        Value::Map(pairs) => pairs,
        _ => return Err(AnnounceError::Malformed),
    };
    let mut capabilities = None;
    let mut prefix = None;
    let mut prefix_len = None;
    let mut expiry = None;
    let mut seq = None;
    let mut announcer_iid = None;
    for (key, value) in pairs {
        let key_int = as_int(key);
        if key_int == Some(i128::from(PAYLOAD_CAPABILITIES)) {
            capabilities = Some(
                u32::try_from(as_int(value).ok_or(AnnounceError::Malformed)?)
                    .map_err(|_| AnnounceError::Malformed)?,
            );
        } else if key_int == Some(i128::from(PAYLOAD_PREFIX)) {
            prefix = Some(as_bytes(value).ok_or(AnnounceError::Malformed)?.clone());
        } else if key_int == Some(i128::from(PAYLOAD_PREFIX_LEN)) {
            prefix_len = Some(
                u8::try_from(as_int(value).ok_or(AnnounceError::Malformed)?)
                    .map_err(|_| AnnounceError::Malformed)?,
            );
        } else if key_int == Some(i128::from(PAYLOAD_EXPIRY)) {
            expiry = Some(
                u64::try_from(as_int(value).ok_or(AnnounceError::Malformed)?)
                    .map_err(|_| AnnounceError::Malformed)?,
            );
        } else if key_int == Some(i128::from(PAYLOAD_SEQ)) {
            seq = Some(
                u64::try_from(as_int(value).ok_or(AnnounceError::Malformed)?)
                    .map_err(|_| AnnounceError::Malformed)?,
            );
        } else if key_int == Some(i128::from(PAYLOAD_ANNOUNCER_IID)) {
            announcer_iid = Some(
                as_bytes(value)
                    .ok_or(AnnounceError::Malformed)?
                    .as_slice()
                    .try_into()
                    .map_err(|_| AnnounceError::Malformed)?,
            );
        }
    }
    let payload = CapabilityPayload {
        capabilities: capabilities.ok_or(AnnounceError::Malformed)?,
        prefix: prefix.ok_or(AnnounceError::Malformed)?,
        prefix_len: prefix_len.ok_or(AnnounceError::Malformed)?,
        expiry: expiry.ok_or(AnnounceError::Malformed)?,
        seq: seq.ok_or(AnnounceError::Malformed)?,
        announcer_iid: announcer_iid.ok_or(AnnounceError::Malformed)?,
    };

    // kid in the unprotected header must match the payload announcer IID.
    let kid = unprotected_kid(unprotected).ok_or(AnnounceError::KidMismatch)?;
    if kid != payload.announcer_iid {
        return Err(AnnounceError::KidMismatch);
    }

    Ok(CapabilityAnnouncement {
        protected: protected_bytes,
        payload,
        payload_bytes,
        signature,
    })
}

impl CapabilityAnnouncement {
    /// Build the capability-table entry for this announcement.
    pub fn into_entry(self) -> crate::capability::CapabilityEntry {
        let mut prefix = [0u8; 16];
        let n = self.payload.prefix.len().min(16);
        prefix[..n].copy_from_slice(&self.payload.prefix[..n]);
        crate::capability::CapabilityEntry {
            iid: self.payload.announcer_iid,
            capabilities: self.payload.capabilities,
            prefix,
            prefix_len: self.payload.prefix_len,
            expiry_unix: u32::try_from(self.payload.expiry).unwrap_or(u32::MAX),
            seq: self.payload.seq,
        }
    }
}

/// Derive the announcer IID from a public key (native 02xx profile).
fn pubkey_to_iid(pubkey: &[u8; 32]) -> [u8; 8] {
    let address = ygg_addr_from_pubkey(pubkey);
    let mut iid = [0u8; 8];
    iid.copy_from_slice(&address[8..]);
    iid
}

/// Encode the protected header map {1: -65537} (Schnorr48-Ed25519).
fn encode_protected_header() -> Vec<u8> {
    let mut out = Vec::new();
    let header = Value::Map(vec![(
        Value::Integer(Integer::from(COSE_ALG_LABEL)),
        Value::Integer(Integer::from(SCHNORR48_ED25519_ALG)),
    )]);
    ciborium::ser::into_writer(&header, &mut out).expect("in-memory CBOR serialization");
    out
}

/// Encode the payload CBOR map (integer keys 1..6, insertion order).
fn payload_cbor(payload: &CapabilityPayload) -> Vec<u8> {
    let map = vec![
        (
            Value::Integer(Integer::from(PAYLOAD_CAPABILITIES)),
            Value::Integer(Integer::from(i64::from(payload.capabilities))),
        ),
        (
            Value::Integer(Integer::from(PAYLOAD_PREFIX)),
            Value::Bytes(payload.prefix.clone()),
        ),
        (
            Value::Integer(Integer::from(PAYLOAD_PREFIX_LEN)),
            Value::Integer(Integer::from(i64::from(payload.prefix_len))),
        ),
        (
            Value::Integer(Integer::from(PAYLOAD_EXPIRY)),
            Value::Integer(Integer::from(payload.expiry)),
        ),
        (
            Value::Integer(Integer::from(PAYLOAD_SEQ)),
            Value::Integer(Integer::from(payload.seq)),
        ),
        (
            Value::Integer(Integer::from(PAYLOAD_ANNOUNCER_IID)),
            Value::Bytes(payload.announcer_iid.to_vec()),
        ),
    ];
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&Value::Map(map), &mut encoded)
        .expect("in-memory CBOR serialization");
    encoded
}

/// Build the RFC 9052 Sig_structure and hash it (SHA-256).
fn sig_structure_digest(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let sig_structure = Value::Array(vec![
        Value::Text(SIG_CONTEXT.to_string()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&sig_structure, &mut encoded).expect("in-memory CBOR serialization");
    Sha256::digest(&encoded).to_vec()
}

/// Verify a decoded announcement (spec 8.12 validation ordering).
///
/// Errors mirror python: RESERVED_BITS_SET, IID_MISMATCH, SIGNATURE_INVALID,
/// EXPIRED, REPLAY_DETECTED.
pub fn verify_announcement(
    announcement: &CapabilityAnnouncement,
    pubkey: &[u8; 32],
    now: u64,
    cached_seq: Option<u64>,
) -> Result<(), AnnounceError> {
    let payload = &announcement.payload;

    if payload.capabilities & RESERVED_BITS_MASK != 0 {
        return Err(AnnounceError::ReservedBitsSet);
    }

    if payload.announcer_iid != pubkey_to_iid(pubkey) {
        return Err(AnnounceError::IidMismatch);
    }

    let digest = sig_structure_digest(&announcement.protected, &announcement.payload_bytes);
    let key = PublicKey::new(*pubkey);
    if !schnorr48::verify(&key, &digest, &announcement.signature) {
        return Err(AnnounceError::SignatureInvalid);
    }

    if payload.expiry <= now {
        return Err(AnnounceError::Expired);
    }

    if let Some(cached) = cached_seq {
        if payload.seq <= cached {
            return Err(AnnounceError::ReplayDetected);
        }
    }
    Ok(())
}

/// Build and sign a capability announcement (COSE_Sign1, untagged).
///
/// Mirrors python create_capability_announcement: the signature is Schnorr48
/// over SHA-256 of the Sig_structure.
pub fn create_announcement(
    payload: &CapabilityPayload,
    private: &schnorr48::PrivateKey,
    public: &schnorr48::PublicKey,
) -> Vec<u8> {
    let protected = encode_protected_header();
    let payload_bytes = payload_cbor(payload);
    let digest = sig_structure_digest(&protected, &payload_bytes);
    let signature = schnorr48::sign(private, public, &digest);

    // COSE_Sign1: [protected, {4: kid}, payload, signature]
    let unprotected = Value::Map(vec![(
        Value::Integer(Integer::from(COSE_KID_LABEL)),
        Value::Bytes(payload.announcer_iid.to_vec()),
    )]);
    let mut cose = Vec::new();
    let cose_value = Value::Array(vec![
        Value::Bytes(protected),
        unprotected,
        Value::Bytes(payload_bytes),
        Value::Bytes(signature.to_vec()),
    ]);
    ciborium::ser::into_writer(&cose_value, &mut cose).expect("in-memory CBOR serialization");
    cose
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS_JSON: &str = include_str!("../../../test/vectors/capability_announcements.json");

    fn vectors() -> Vec<serde_json::Value> {
        let doc: serde_json::Value = serde_json::from_str(VECTORS_JSON).unwrap();
        doc["vectors"].as_array().expect("vector list").clone()
    }

    fn iid_match_of(vector: &serde_json::Value) -> bool {
        vector["expected"]
            .get("iid_match")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true)
    }

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn hex32(value: &str) -> [u8; 32] {
        hex(value).try_into().unwrap()
    }

    #[test]
    fn vectors_decode_verify_and_encode() {
        for vector in vectors() {
            let name = vector["name"].as_str().unwrap();
            let wire = hex(vector["cose_sign1"].as_str().unwrap());
            // capability_iid_mismatch fails at DECODE: python's
            // from_cose_sign1 raises when kid != announcer_iid.
            let announcement = match from_cose_sign1(&wire) {
                Ok(announcement) => announcement,
                Err(AnnounceError::KidMismatch) => {
                    assert!(!iid_match_of(&vector), "{name}");
                    continue;
                }
                Err(error) => panic!("decode {name} failed: {error:?}"),
            };

            let payload = &announcement.payload;
            assert_eq!(
                payload.capabilities,
                u32::try_from(vector["capabilities"].as_i64().unwrap()).unwrap(),
                "{name}"
            );
            assert_eq!(
                payload.announcer_iid.to_vec(),
                hex(vector["announcer_iid"].as_str().unwrap()),
                "{name}"
            );
            assert_eq!(payload.expiry, vector["expiry"].as_u64().unwrap(), "{name}");
            assert_eq!(payload.seq, vector["seq"].as_u64().unwrap(), "{name}");

            // Payload re-encoding must be byte-identical to the vector's
            // recorded payload_cbor (cross-implementation CBOR contract).
            assert_eq!(
                payload_cbor(payload),
                hex(vector["payload_cbor"].as_str().unwrap()),
                "{name}"
            );

            // The recorded Sig_structure hash matches our reconstruction.
            let digest = sig_structure_digest(&announcement.protected, &announcement.payload_bytes);
            assert_eq!(
                digest.to_vec(),
                hex(vector["sig_structure_hash"].as_str().unwrap()),
                "{name}"
            );

            let pubkey = hex32(vector["public_key"].as_str().unwrap());
            let result = verify_announcement(&announcement, &pubkey, 0, None);
            let reserved_zero = vector["expected"]["reserved_bits_zero"].as_bool().unwrap();
            let iid_match = iid_match_of(&vector);
            match (reserved_zero, iid_match) {
                (true, true) => assert_eq!(result, Ok(()), "{name}"),
                (false, _) => assert_eq!(result, Err(AnnounceError::ReservedBitsSet), "{name}"),
                (_, false) => assert_eq!(result, Err(AnnounceError::IidMismatch), "{name}"),
            }
        }
    }

    #[test]
    fn malformed_cose_is_rejected() {
        assert_eq!(from_cose_sign1(&[]), Err(AnnounceError::Malformed));
        assert_eq!(from_cose_sign1(&[0x80]), Err(AnnounceError::Malformed));
    }

    #[test]
    fn expiry_and_replay_semantics() {
        let vector = &vectors()[0];
        let wire = hex(vector["cose_sign1"].as_str().unwrap());
        let announcement = from_cose_sign1(&wire).expect("decode");
        let pubkey = hex32(vector["public_key"].as_str().unwrap());

        // Expiry 1735689600: valid strictly before, expired at/after.
        assert!(verify_announcement(&announcement, &pubkey, 1735689599, None).is_ok());
        assert_eq!(
            verify_announcement(&announcement, &pubkey, 1735689600, None),
            Err(AnnounceError::Expired)
        );

        // Replay: the payload seq must strictly exceed the cached seq.
        let cached = announcement.payload.seq;
        assert!(verify_announcement(&announcement, &pubkey, 0, Some(cached - 1)).is_ok());
        assert_eq!(
            verify_announcement(&announcement, &pubkey, 0, Some(cached)),
            Err(AnnounceError::ReplayDetected)
        );
    }
}
