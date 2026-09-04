// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Root DIO Signature COSE decoding and structural validation.
//!
//! Spec 06-security §8.10.1. This layer decodes the COSE_Sign1 wire blob
//! (see [`lichen_rpl::message::RootDioSignature`] for the transport option)
//! and enforces the checks that do not require the signature or replay
//! state: algorithm, `kid` length, signature length, `kid`-to-pubkey IID
//! binding, DODAGID-to-pubkey binding, expiry, and DIO field cross-checks.
//! Signature verification and replay consumption are layered on top (bead
//! b7z9.37.1.2(b)); error strings match the cross-implementation vectors in
//! `test/vectors/root_dio_signature.json`.
//!
//! Interim `dead_code` expectation: the receiver call site lands with bead
//! b7z9.37.1.2(b); the expectation then stops being fulfilled and must be
//! removed.
#![cfg_attr(not(test), expect(dead_code))]

use ciborium::value::Value;
use lichen_core::addr::{iid_from_pubkey_bytes, ygg_addr_from_pubkey};
#[cfg(feature = "std")]
use lichen_rpl::root_seq_cache::RootSeqCache;

/// COSE algorithm ID for Schnorr48-Ed25519 (private use range).
pub const SCHNORR48_ED25519_ALG: i128 = -65537;

/// COSE_Sign1 is a tagged array (tag 18 per RFC 9052).
const COSE_SIGN1_TAG: u64 = 18;

/// COSE header label for the algorithm.
const COSE_ALG_LABEL: i128 = 1;

/// COSE unprotected-header label for the key identifier.
const COSE_KID_LABEL: i128 = 4;

/// Decoded Root DIO Signature payload (CBOR map keys 1-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootSigPayload {
    pub dodag_id: [u8; 16],
    pub instance: u8,
    pub version: u8,
    pub rank: u16,
    pub expiry: u64,
    pub root_seq: u64,
    pub mop: u8,
}

/// A COSE_Sign1 Root DIO Signature decoded into its fixed parts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedRootSig {
    pub root_iid: [u8; 8],
    pub payload: RootSigPayload,
    pub signature: [u8; 48],
}

/// Validation failure reasons; strings match the cross-impl vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootSigError {
    Decode,
    Algorithm,
    KidMismatch,
    DodagIdMismatch,
    SignatureLength,
    SignatureInvalid,
    Expired,
    ReplayDetected,
    InstanceMismatch,
    VersionMismatch,
    RankMismatch,
    MopMismatch,
}

impl RootSigError {
    /// Vector-oracle error string (test/vectors/root_dio_signature.json).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Decode => "decode_error",
            Self::Algorithm => "algorithm_invalid",
            Self::KidMismatch => "kid_mismatch",
            Self::DodagIdMismatch => "dodagid_mismatch",
            Self::SignatureLength => "signature_length",
            Self::SignatureInvalid => "signature_invalid",
            Self::Expired => "expired",
            Self::ReplayDetected => "replay_detected",
            Self::InstanceMismatch => "instance_mismatch",
            Self::VersionMismatch => "version_mismatch",
            Self::RankMismatch => "rank_mismatch",
            Self::MopMismatch => "mop_mismatch",
        }
    }
}

/// DIO header fields for cross-checking the signed payload against the
/// carrying DIO (all optional per the Python oracle; `None` skips).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DioFields {
    pub dodag_id: Option<[u8; 16]>,
    pub instance: Option<u8>,
    pub version: Option<u8>,
    pub rank: Option<u16>,
    pub mop: Option<u8>,
}

fn as_bytes(value: &Value) -> Option<&[u8]> {
    match value {
        Value::Bytes(bytes) => Some(bytes),
        _ => None,
    }
}

fn as_u64(value: &Value) -> Option<u64> {
    // CBOR negatives are not valid for any unsigned payload field.
    match value {
        Value::Integer(int) => u64::try_from(*int).ok(),
        _ => None,
    }
}

/// CBOR maps with duplicate labels are rejected fail closed: the Python
/// oracle decodes to a dict (last-wins), so accepting duplicates here would
/// let crafted headers diverge between implementations.
fn reject_duplicate_labels(entries: &[(Value, Value)]) -> Result<(), RootSigError> {
    for (index, (key, _)) in entries.iter().enumerate() {
        if entries[..index].iter().any(|(other, _)| other == key) {
            return Err(RootSigError::Decode);
        }
    }
    Ok(())
}

/// Decode one CBOR value consuming the WHOLE input: Python `cbor2.loads`
/// rejects trailing bytes, so accepting `valid || garbage` here would be a
/// cross-implementation accept/reject divergence.
fn decode_exact(data: &[u8]) -> Result<Value, RootSigError> {
    let mut rest = data;
    let value =
        ciborium::de::from_reader::<Value, _>(&mut rest).map_err(|_| RootSigError::Decode)?;
    if !rest.is_empty() {
        return Err(RootSigError::Decode);
    }
    Ok(value)
}

fn decode_payload(payload: &[u8]) -> Result<RootSigPayload, RootSigError> {
    let map = decode_exact(payload).map_err(|_| RootSigError::Decode)?;
    let Value::Map(entries) = map else {
        return Err(RootSigError::Decode);
    };
    let mut fields: [Option<u64>; 6] = [None; 6];
    let mut dodag_id: Option<[u8; 16]> = None;
    reject_duplicate_labels(&entries)?;
    for (key, value) in entries {
        let key = i128::from(key.into_integer().map_err(|_| RootSigError::Decode)?);
        match key {
            1 => {
                dodag_id = Some(
                    as_bytes(&value)
                        .and_then(|b| <[u8; 16]>::try_from(b).ok())
                        .ok_or(RootSigError::Decode)?,
                );
            }
            2..=7 => {
                let index = usize::from(u8::try_from(key).map_err(|_| RootSigError::Decode)?);
                fields[index - 2] = Some(as_u64(&value).ok_or(RootSigError::Decode)?);
            }
            _ => return Err(RootSigError::Decode),
        }
    }
    let [instance, version, rank, expiry, root_seq, mop] = fields;
    Ok(RootSigPayload {
        dodag_id: dodag_id.ok_or(RootSigError::Decode)?,
        instance: u8::try_from(instance.ok_or(RootSigError::Decode)?)
            .map_err(|_| RootSigError::Decode)?,
        version: u8::try_from(version.ok_or(RootSigError::Decode)?)
            .map_err(|_| RootSigError::Decode)?,
        rank: u16::try_from(rank.ok_or(RootSigError::Decode)?).map_err(|_| RootSigError::Decode)?,
        expiry: expiry.ok_or(RootSigError::Decode)?,
        root_seq: root_seq.ok_or(RootSigError::Decode)?,
        mop: u8::try_from(mop.ok_or(RootSigError::Decode)?).map_err(|_| RootSigError::Decode)?,
    })
    .and_then(|payload| {
        // Range rules from the Python oracle RootDioSignaturePayload.
        if payload.mop > 7 {
            return Err(RootSigError::Decode);
        }
        if payload.expiry == 0 {
            return Err(RootSigError::Decode);
        }
        Ok(payload)
    })
}

impl DecodedRootSig {
    /// Decode a CBOR-encoded COSE_Sign1 Root DIO Signature.
    ///
    /// Enforces the decode-time rules of the Python oracle
    /// `RootDioSignature.from_cose_sign1`: 4-element (tag 18) array,
    /// protected-header algorithm `-65537`, 8-byte `kid`, 48-byte signature.
    pub fn from_cose_sign1(data: &[u8]) -> Result<Self, RootSigError> {
        let value = decode_exact(data).map_err(|_| RootSigError::Decode)?;
        let Value::Tag(COSE_SIGN1_TAG, inner) = value else {
            return Err(RootSigError::Decode);
        };
        let items = inner.into_array().map_err(|_| RootSigError::Decode)?;
        if items.len() != 4 {
            return Err(RootSigError::Decode);
        }
        let [protected, unprotected, payload, signature] =
            <[Value; 4]>::try_from(items).map_err(|_| RootSigError::Decode)?;
        let protected_bytes = as_bytes(&protected).ok_or(RootSigError::Decode)?;
        let payload_bytes = as_bytes(&payload).ok_or(RootSigError::Decode)?;
        let signature = as_bytes(&signature).ok_or(RootSigError::Decode)?;

        let protected = decode_exact(protected_bytes).map_err(|_| RootSigError::Decode)?;
        let Value::Map(protected_entries) = protected else {
            return Err(RootSigError::Decode);
        };
        // Strict map semantics: Python's cbor2 decodes to a dict (duplicate
        // labels collapse, last-wins). Reject duplicates outright so no
        // ordering can smuggle a second algorithm past the check.
        reject_duplicate_labels(&protected_entries)?;
        let alg = protected_entries
            .iter()
            .find_map(|(key, value)| {
                let Value::Integer(key) = key else {
                    return None;
                };
                (i128::from(*key) == COSE_ALG_LABEL)
                    .then(|| match value {
                        Value::Integer(alg) => Some(i128::from(*alg)),
                        _ => None,
                    })
                    .flatten()
            })
            .ok_or(RootSigError::Algorithm)?;
        if alg != SCHNORR48_ED25519_ALG {
            return Err(RootSigError::Algorithm);
        }

        let Value::Map(unprotected_entries) = unprotected else {
            return Err(RootSigError::Decode);
        };
        reject_duplicate_labels(&unprotected_entries)?;
        let root_iid = unprotected_entries
            .iter()
            .find_map(|(key, value)| {
                let Value::Integer(key) = key else {
                    return None;
                };
                if i128::from(*key) != COSE_KID_LABEL {
                    return None;
                }
                as_bytes(value).and_then(|b| <[u8; 8]>::try_from(b).ok())
            })
            .ok_or(RootSigError::KidMismatch)?;

        let signature =
            <[u8; 48]>::try_from(signature).map_err(|_| RootSigError::SignatureLength)?;

        Ok(Self {
            root_iid,
            payload: decode_payload(payload_bytes)?,
            signature,
        })
    }

    /// Binding checks that need only the signer pubkey: `kid`-to-IID and
    /// DODAGID-to-pubkey. Signature verification and expiry layer on top in
    /// the oracle's order (see [`Self::verify`]).
    pub fn verify_structural(&self, pubkey: &[u8; 32]) -> Result<(), RootSigError> {
        if self.root_iid != iid_from_pubkey_bytes(pubkey) {
            return Err(RootSigError::KidMismatch);
        }
        if self.payload.dodag_id != ygg_addr_from_pubkey(pubkey) {
            return Err(RootSigError::DodagIdMismatch);
        }
        Ok(())
    }

    /// Canonical CBOR re-encoding of the payload (Python oracle signs
    /// `payload.to_cbor()` — a re-encoding from the parsed fields — not the
    /// wire bytes, so non-canonical wire payload diverges from the oracle
    /// and MUST be re-encoded here for parity).
    fn canonical_payload(&self) -> Result<std::vec::Vec<u8>, RootSigError> {
        let value = Value::Map(std::vec![
            (
                Value::Integer(1.into()),
                Value::Bytes(self.payload.dodag_id.to_vec())
            ),
            (
                Value::Integer(2.into()),
                Value::Integer(self.payload.instance.into())
            ),
            (
                Value::Integer(3.into()),
                Value::Integer(self.payload.version.into())
            ),
            (
                Value::Integer(4.into()),
                Value::Integer(self.payload.rank.into())
            ),
            (
                Value::Integer(5.into()),
                Value::Integer(self.payload.expiry.into())
            ),
            (
                Value::Integer(6.into()),
                Value::Integer(self.payload.root_seq.into())
            ),
            (
                Value::Integer(7.into()),
                Value::Integer(self.payload.mop.into())
            ),
        ]);

        let mut out = std::vec::Vec::new();
        ciborium::ser::into_writer(&value, &mut out).map_err(|_| RootSigError::Decode)?;
        Ok(out)
    }

    /// Rebuild the COSE Sig_structure with the CANONICAL protected header
    /// (matching the Python oracle, which ignores any extra fields a forged
    /// header may carry) and verify the Schnorr48 signature over
    /// SHA-256(Sig_structure).
    #[cfg(feature = "std")]
    pub fn verify_signature(&self, pubkey: &[u8; 32]) -> Result<(), RootSigError> {
        use sha2::{Digest, Sha256};

        const CANONICAL_PROTECTED: [u8; 7] = [0xa1, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00];
        let payload = self.canonical_payload()?;
        // payload is ~40-90 bytes, always in the two-byte 0x58 length form
        // and always under 256.
        if payload.len() > 255 {
            return Err(RootSigError::Decode);
        }
        let mut sig_structure = std::vec::Vec::with_capacity(15 + payload.len());
        sig_structure.extend_from_slice(&[0x84, 0x6a]);
        sig_structure.extend_from_slice(b"Signature1");
        sig_structure.push(0x40 | CANONICAL_PROTECTED.len() as u8); // bstr header
        sig_structure.extend_from_slice(&CANONICAL_PROTECTED);
        sig_structure.push(0x40);
        sig_structure.push(0x58);
        sig_structure.push(payload.len() as u8);
        sig_structure.extend_from_slice(&payload);
        let digest = Sha256::digest(&sig_structure);
        if lichen_link::schnorr::verify(
            &lichen_link::keys::PublicKey::new(*pubkey),
            &digest,
            &self.signature,
        ) {
            Ok(())
        } else {
            Err(RootSigError::SignatureInvalid)
        }
    }

    /// Full receiver verification in the Python oracle's order: bindings,
    /// signature, expiry, replay (consuming the RootSeqCache), then DIO
    /// cross-checks. Only a fully verified signature is admitted into the
    /// cache (caller contract from b7z9.37.3.1).
    #[cfg(feature = "std")]
    pub fn verify(
        &self,
        pubkey: &[u8; 32],
        current_time: u64,
        dio: Option<&DioFields>,
        seq_cache: &mut RootSeqCache,
    ) -> Result<RootSigPayload, RootSigError> {
        self.verify_structural(pubkey)?;
        self.verify_signature(pubkey)?;
        if self.payload.expiry <= current_time {
            return Err(RootSigError::Expired);
        }
        match seq_cache.cached(self.payload.dodag_id, self.payload.instance) {
            Some(cached) if self.payload.root_seq <= cached => {
                return Err(RootSigError::ReplayDetected);
            }
            _ => {}
        }
        if let Some(dio) = dio {
            self.cross_check(dio)?;
        }
        seq_cache
            .accept(
                self.payload.dodag_id,
                self.payload.instance,
                self.payload.root_seq,
            )
            .map_err(|_| RootSigError::ReplayDetected)?;
        Ok(self.payload)
    }

    /// Cross-check the signed payload against the carrying DIO header.
    /// `None` fields are skipped, per the Python oracle.
    pub fn cross_check(&self, dio: &DioFields) -> Result<(), RootSigError> {
        if let Some(dodag_id) = dio.dodag_id {
            if self.payload.dodag_id != dodag_id {
                return Err(RootSigError::DodagIdMismatch);
            }
        }
        if let Some(instance) = dio.instance {
            if self.payload.instance != instance {
                return Err(RootSigError::InstanceMismatch);
            }
        }
        if let Some(version) = dio.version {
            if self.payload.version != version {
                return Err(RootSigError::VersionMismatch);
            }
        }
        if let Some(rank) = dio.rank {
            if self.payload.rank != rank {
                return Err(RootSigError::RankMismatch);
            }
        }
        if let Some(mop) = dio.mop {
            if self.payload.mop != mop {
                return Err(RootSigError::MopMismatch);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use lichen_rpl::root_seq_cache::RootSeqCache;
    use std::vec;
    use std::vec::Vec;

    // Fixtures from test/vectors/root_dio_signature.json (external oracle).
    pub(crate) const VALID_COSE_SIGN1: &str = "d28447a1013a00010000a10448203df4662ab81f5a5825a7015002203df4662ab81f203df4662ab81f5a0200030104190100051a677485800601070258304f9a6d7554edcaf70301635bddb2618a5e7165bb02e9ff1ec86f276bcfff356ba61171e0cef7861ce3a6be76c6d7fd00";
    pub(crate) const VALID_PUBKEY: [u8; 32] = [
        0xe7, 0xa9, 0x6e, 0xf0, 0x7e, 0x66, 0xea, 0x92, 0x37, 0xf0, 0x3a, 0x46, 0x74, 0xbb, 0xf4,
        0x3a, 0x8c, 0x1c, 0x9e, 0xb2, 0x7e, 0xdd, 0x23, 0x9f, 0xb5, 0xac, 0x09, 0x87, 0x35, 0xaf,
        0xb0, 0xdf,
    ];
    const WRONG_ALG_COSE_SIGN1: &str = "d28443a10126a10448203df4662ab81f5a5825a7015002203df4662ab81f203df4662ab81f5a0200030104190100051a67748580060107025830662873f441c225a8742545cb11cdede5d8e00215c18e1b48e90ae630ce1fed508a46d9f0b77bcedeec3381e774ff080a";
    const KID_MISMATCH_COSE_SIGN1: &str = "d28447a1013a00010000a1044801020304050607085825a7015002203df4662ab81f203df4662ab81f5a0200030104190100051a677485800601070258304f9a6d7554edcaf70301635bddb2618a5e7165bb02e9ff1ec86f276bcfff356ba61171e0cef7861ce3a6be76c6d7fd00";
    const IMPERSONATION_COSE_SIGN1: &str = "d28447a1013a00010000a10448b0b6498d1d3694865825a7015002203df4662ab81f203df4662ab81f5a0200030104190100051a677485800601070258308e2006480ffd1f55ffeada2d21f07660a4a435d6f6d9fbf09ce35a90f9526549251dbb74620e6082fea81aac01933502";
    const ATTACKER_PUBKEY: [u8; 32] = [
        0x68, 0xae, 0x16, 0xcc, 0x01, 0xf1, 0xe7, 0x40, 0xb2, 0x57, 0x53, 0xba, 0x11, 0x73, 0x6c,
        0xfb, 0x65, 0x74, 0x84, 0x60, 0x65, 0x8e, 0x67, 0xd1, 0x3b, 0x75, 0xed, 0xf5, 0xf2, 0xf5,
        0x04, 0x87,
    ];

    pub(crate) fn vector_cose() -> std::vec::Vec<u8> {
        decode_hex(VALID_COSE_SIGN1)
    }

    pub(crate) fn vector_pubkey() -> lichen_link::keys::PublicKey {
        lichen_link::keys::PublicKey::new(VALID_PUBKEY)
    }

    pub(crate) fn decode_hex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn valid_vector_decodes_and_passes_structural_checks() {
        let decoded = DecodedRootSig::from_cose_sign1(&decode_hex(VALID_COSE_SIGN1)).unwrap();
        assert_eq!(
            decoded.root_iid,
            [0x20, 0x3d, 0xf4, 0x66, 0x2a, 0xb8, 0x1f, 0x5a]
        );
        assert_eq!(decoded.payload.instance, 0);
        assert_eq!(decoded.payload.version, 1);
        assert_eq!(decoded.payload.rank, 256);
        assert_eq!(decoded.payload.expiry, 1_735_689_600);
        assert_eq!(decoded.payload.root_seq, 1);
        assert_eq!(decoded.payload.mop, 2);

        decoded.verify_structural(&VALID_PUBKEY).unwrap();

        let dio = DioFields {
            dodag_id: Some(decoded.payload.dodag_id),
            instance: Some(0),
            version: Some(1),
            rank: Some(256),
            mop: Some(2),
        };
        let mut cache = RootSeqCache::default();
        let payload = decoded
            .verify(&VALID_PUBKEY, 1_735_689_599, Some(&dio), &mut cache)
            .unwrap();
        assert_eq!(payload.root_seq, 1);
        assert_eq!(cache.cached(decoded.payload.dodag_id, 0), Some(1));
    }

    #[test]
    fn expiry_boundary_rejects_equal_timestamp() {
        let decoded = DecodedRootSig::from_cose_sign1(&decode_hex(VALID_COSE_SIGN1)).unwrap();
        let mut cache = RootSeqCache::default();
        assert_eq!(
            decoded.verify(&VALID_PUBKEY, 1_735_689_600, None, &mut cache),
            Err(RootSigError::Expired)
        );
    }

    #[test]
    fn wrong_algorithm_is_rejected_at_decode() {
        assert_eq!(
            DecodedRootSig::from_cose_sign1(&decode_hex(WRONG_ALG_COSE_SIGN1)),
            Err(RootSigError::Algorithm)
        );
    }

    #[test]
    fn kid_mismatch_is_rejected_by_structural_check() {
        // The vector's kid is a valid 8-byte IID with the wrong VALUE, so
        // decode succeeds (Python oracle only rejects missing/wrong-length
        // kid at decode) and the binding check catches the mismatch.
        let decoded =
            DecodedRootSig::from_cose_sign1(&decode_hex(KID_MISMATCH_COSE_SIGN1)).unwrap();
        assert_eq!(decoded.root_iid, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            decoded.verify_structural(&VALID_PUBKEY),
            Err(RootSigError::KidMismatch)
        );
    }

    #[test]
    fn impersonated_dodag_id_fails_binding() {
        let decoded =
            DecodedRootSig::from_cose_sign1(&decode_hex(IMPERSONATION_COSE_SIGN1)).unwrap();
        assert_eq!(
            decoded.verify_structural(&ATTACKER_PUBKEY),
            Err(RootSigError::DodagIdMismatch)
        );
    }

    #[test]
    fn dio_cross_checks_report_each_field() {
        let decoded = DecodedRootSig::from_cose_sign1(&decode_hex(VALID_COSE_SIGN1)).unwrap();
        assert_eq!(
            decoded.cross_check(&DioFields {
                instance: Some(1),
                ..DioFields::default()
            }),
            Err(RootSigError::InstanceMismatch)
        );
        assert_eq!(
            decoded.cross_check(&DioFields {
                version: Some(2),
                ..DioFields::default()
            }),
            Err(RootSigError::VersionMismatch)
        );
        assert_eq!(
            decoded.cross_check(&DioFields {
                rank: Some(512),
                ..DioFields::default()
            }),
            Err(RootSigError::RankMismatch)
        );
        assert_eq!(
            decoded.cross_check(&DioFields {
                mop: Some(3),
                ..DioFields::default()
            }),
            Err(RootSigError::MopMismatch)
        );
        assert_eq!(
            decoded.cross_check(&DioFields {
                dodag_id: Some([0u8; 16]),
                ..DioFields::default()
            }),
            Err(RootSigError::DodagIdMismatch)
        );
    }

    #[test]
    fn garbage_is_rejected_as_decode_error() {
        for garbage in [
            &[][..],
            &[0xd2, 0x84][..],
            &[0x01, 0x02, 0x03][..],
            VALID_COSE_SIGN1[..64].as_bytes(),
        ] {
            assert_eq!(
                DecodedRootSig::from_cose_sign1(garbage),
                Err(RootSigError::Decode)
            );
        }
    }
    #[test]
    fn duplicate_labels_are_rejected_fail_closed() {
        // Craft a protected header carrying alg twice: {1: -65537, 1: -7}.
        // Python (dict last-wins) would see whichever came last; Rust must
        // reject the ambiguity outright instead of picking a winner.
        let mut blob = decode_hex(VALID_COSE_SIGN1);
        // protected header bytes live at offset 5..12 (a1 01 3a 00 01 00 00)
        let protected_start = 3usize;
        let protected_len = (blob[2] & 0x1f) as usize; // short bstr header
        assert_eq!(
            &blob[protected_start..protected_start + protected_len],
            &[0xa1, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00]
        );
        // Rebuild the COSE with a two-entry protected header:
        // {1: -65537, 1: -7} = a2 01 3a 00010000 01 26
        let dup_protected: Vec<u8> = vec![0xa2, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x01, 0x26];
        let payload_start = protected_start + protected_len;
        let rest = blob[payload_start..].to_vec();
        let mut rebuilt: Vec<u8> = vec![0xd2, 0x84];
        rebuilt.push((dup_protected.len()) as u8);
        rebuilt.extend_from_slice(&dup_protected);
        rebuilt.extend_from_slice(&rest);
        assert_eq!(
            DecodedRootSig::from_cose_sign1(&rebuilt),
            Err(RootSigError::Decode)
        );
    }
    #[test]
    fn trailing_bytes_are_rejected_like_cbor2() {
        // Python cbor2.loads rejects trailing bytes; ciborium's reader stops
        // after one value, so the whole-input decode must enforce it too.
        let mut blob = decode_hex(VALID_COSE_SIGN1);
        blob.push(0xFF);
        assert_eq!(
            DecodedRootSig::from_cose_sign1(&blob),
            Err(RootSigError::Decode)
        );
    }

    #[test]
    fn deeply_nested_cbor_is_rejected_not_panicking() {
        // ciborium's recursion limit (256) must surface as Decode, keeping
        // hostile inputs fail-closed. Pin the mapping against future
        // ciborium upgrades.
        // Wrap an empty array in 600 array(1) wrappers: 600 > ciborium's
        // default recursion limit of 256.
        let mut nested: Vec<u8> = std::vec![0x80];
        for _ in 0..600 {
            nested.insert(0, 0x81);
        }
        assert_eq!(
            DecodedRootSig::from_cose_sign1(&nested),
            Err(RootSigError::Decode)
        );
    }
}

#[cfg(test)]
mod full_verify_tests {
    use super::tests::*;
    use super::*;
    use lichen_rpl::root_seq_cache::RootSeqCache;

    #[test]
    fn replay_is_rejected_and_cache_is_not_regressed() {
        let decoded = DecodedRootSig::from_cose_sign1(&decode_hex(VALID_COSE_SIGN1)).unwrap();
        let mut cache = RootSeqCache::default();
        decoded
            .verify(&VALID_PUBKEY, 1_735_689_599, None, &mut cache)
            .unwrap();
        assert_eq!(
            decoded.verify(&VALID_PUBKEY, 1_735_689_599, None, &mut cache),
            Err(RootSigError::ReplayDetected)
        );
        assert_eq!(cache.cached(decoded.payload.dodag_id, 0), Some(1));
    }

    #[test]
    fn tampered_signature_is_rejected_and_does_not_touch_cache() {
        // Vector root_dio_signature_tampered: signature byte 0 flipped.
        let decoded = DecodedRootSig::from_cose_sign1(&decode_hex("d28447a1013a00010000a10448203df4662ab81f5a5825a7015002203df4662ab81f203df4662ab81f5a0200030104190100051a677485800601070258304e9a6d7554edcaf70301635bddb2618a5e7165bb02e9ff1ec86f276bcfff356ba61171e0cef7861ce3a6be76c6d7fd00")).unwrap();
        decoded.verify_structural(&VALID_PUBKEY).unwrap();
        assert_eq!(
            decoded.verify_signature(&VALID_PUBKEY),
            Err(RootSigError::SignatureInvalid)
        );
        let mut cache = RootSeqCache::default();
        assert_eq!(
            decoded.verify(&VALID_PUBKEY, 1_735_689_599, None, &mut cache),
            Err(RootSigError::SignatureInvalid)
        );
        assert_eq!(cache.cached(decoded.payload.dodag_id, 0), None);
    }

    #[test]
    fn zero_signature_is_rejected() {
        // Vector root_dio_signature_zero: the valid vector with an
        // all-zero signature (last 48 bytes zeroed).
        let mut blob = decode_hex(VALID_COSE_SIGN1);
        let sig_start = blob.len() - 48;
        blob[sig_start..].fill(0);
        let decoded = DecodedRootSig::from_cose_sign1(&blob).unwrap();
        assert_eq!(
            decoded.verify_signature(&VALID_PUBKEY),
            Err(RootSigError::SignatureInvalid)
        );
    }

    #[test]
    fn cross_check_failure_does_not_consume_cache() {
        let decoded = DecodedRootSig::from_cose_sign1(&decode_hex(VALID_COSE_SIGN1)).unwrap();
        let mut cache = RootSeqCache::default();
        let dio = DioFields {
            version: Some(2),
            ..DioFields::default()
        };
        assert_eq!(
            decoded.verify(&VALID_PUBKEY, 1_735_689_599, Some(&dio), &mut cache),
            Err(RootSigError::VersionMismatch)
        );
        assert_eq!(cache.cached(decoded.payload.dodag_id, 0), None);
    }
}
