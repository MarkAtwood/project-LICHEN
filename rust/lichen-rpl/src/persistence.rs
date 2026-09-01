//! DAO TX/RX state, admission control persistence.
//!
//! Durable state for DAO sending (TX), receiving (RX), and origin admission.
//!
//! DTX2, DRX2, and DAD1 are provisional, unshipped scope-bound formats. There
//! is intentionally no migration between format versions.
//!
//! # Security Boundary: corruption detection, not tamper resistance
//!
//! Slot integrity for all three formats is the bare CRC-32 of
//! `lichen_hal::storage`: it detects corruption only, NOT tampering. An
//! attacker with flash-write access can roll back both slots, delete the
//! newer slot so the older generation is opened, or forge a minimal record
//! (origin sequence floor 1) with a recomputed CRC; `DaoManager::open_root`
//! would then trust the forged generation as the origin high-water mark, and
//! replay checks would accept captured signature-valid DAOs as fresh.
//!
//! This is bounded: the same flash-write capability is already total
//! compromise (identity keys live in the same storage), and these formats are
//! provisional and unshipped. The anti-rollback anchor is physical possession
//! of the flash. Defense-in-depth future work, intentionally not implemented
//! here: a device-key MAC over records plus an independent monotonic NVS
//! counter outside the record itself.

#[cfg(feature = "std")]
use std::{
    collections::{HashMap, HashSet},
    vec,
    vec::Vec,
};

#[cfg(feature = "std")]
use crate::message::SignedDaoEnvelope;
#[cfg(feature = "std")]
use lichen_hal::{
    storage::{
        open_redundant, provision_redundant, update_redundant, RedundantOpenError,
        RedundantProvisionError, RedundantUpdateError, RedundantValue,
    },
    NonVolatile,
};
#[cfg(feature = "std")]
use lichen_link::keys::PublicKey;

// ── Constants ────────────────────────────────────────────────────────────────

#[cfg(feature = "std")]
pub(crate) const DAO_TX_KEYS: [&str; 2] = ["rpl.tx.a", "rpl.tx.b"];
#[cfg(feature = "std")]
pub(crate) const DAO_RX_KEYS: [&str; 2] = ["rpl.rx.a", "rpl.rx.b"];
#[cfg(feature = "std")]
pub(crate) const DAO_ADMISSION_KEYS: [&str; 2] = ["rpl.admit.a", "rpl.admit.b"];
#[cfg(feature = "std")]
// Provisional, unshipped scope-bound format. No migration from DTX1 is supported.
pub(crate) const DAO_TX_MAGIC: [u8; 4] = *b"DTX2";
#[cfg(feature = "std")]
// Provisional, unshipped scope-bound format. DRX1 records fail closed; scope and
// high-water state must never be fabricated or discarded by automatic migration.
pub(crate) const DAO_RX_MAGIC: [u8; 4] = *b"DRX2";
#[cfg(feature = "std")]
// Provisional, unshipped scope-bound format. There is intentionally no migration
// or admission-removal path: an operator must explicitly reprovision invalid state.
pub(crate) const DAO_ADMISSION_MAGIC: [u8; 4] = *b"DAD1";
#[cfg(feature = "std")]
pub(crate) const HIGH_WATER_ENTRY_LEN: usize = 72;
#[cfg(feature = "std")]
pub(crate) const HIGH_WATER_SCOPE_LEN: usize = 16 + 1 + 16;
#[cfg(feature = "std")]
pub(crate) const HIGH_WATER_HEADER_LEN: usize = HIGH_WATER_SCOPE_LEN + 2;
#[cfg(feature = "std")]
pub(crate) const HIGH_WATER_PAYLOAD_LEN: usize =
    HIGH_WATER_HEADER_LEN + crate::routing::MAX_DAO_ORIGINS * HIGH_WATER_ENTRY_LEN;
#[cfg(feature = "std")]
pub(crate) const SLOT_OVERHEAD: usize = 24;
#[cfg(feature = "std")]
pub(crate) const DAO_TX_HEADER_LEN: usize = 75;
/// Maximum complete signed DAO retained for exact retransmission.
#[cfg(feature = "std")]
pub const MAX_SIGNED_DAO_LEN: usize = 255;
#[cfg(feature = "std")]
pub(crate) const DAO_TX_PAYLOAD_LEN: usize = DAO_TX_HEADER_LEN + MAX_SIGNED_DAO_LEN;
#[cfg(feature = "std")]
pub(crate) const DAO_ADMISSION_HEADER_LEN: usize = HIGH_WATER_SCOPE_LEN + 2;
#[cfg(feature = "std")]
pub(crate) const DAO_ADMISSION_PAYLOAD_LEN: usize =
    DAO_ADMISSION_HEADER_LEN + crate::routing::MAX_DAO_ORIGINS * 32;
#[cfg(feature = "std")]
pub(crate) type HighWaterMap = HashMap<[u8; 32], ([u8; 32], u64)>;

// ── Error types ──────────────────────────────────────────────────────────────

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaoPersistentOpenError<E> {
    Missing,
    Corrupt,
    AlreadyProvisioned,
    Storage(E),
    KeyMismatch,
    ScopeMismatch,
}

#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq)]
pub enum DaoProvisionError<E> {
    Open(DaoPersistentOpenError<E>),
    Storage(E),
}

#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq)]
pub enum DaoTxError<E> {
    Persistence(E),
    Stale,
    Corrupt,
    Exhausted,
    Oversized,
    InvalidState,
    KeyMismatch,
    NotJoined,
    InvalidOrigin,
    Encoding,
}

#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq)]
pub enum DaoAdmissionUpdateError<E> {
    Persistence(E),
    Stale,
    Exhausted,
    Corrupt,
    Capacity,
}

// ── TX State ─────────────────────────────────────────────────────────────────

#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq)]
pub struct DaoTxState {
    pub(crate) current: RedundantValue,
    pub(crate) public_key: [u8; 32],
    pub(crate) local_origin: [u8; 16],
    pub(crate) rpl_instance_id: u8,
    pub(crate) dodag_id: [u8; 16],
    pub(crate) last_reserved: u64,
    pub(crate) last_signed_dao: Vec<u8>,
}

#[cfg(feature = "std")]
impl DaoTxState {
    pub fn provision<S: NonVolatile>(
        storage: &mut S,
        expected_key: PublicKey,
        local_origin: [u8; 16],
        rpl_instance_id: u8,
        dodag_id: [u8; 16],
    ) -> Result<Self, DaoProvisionError<S::Error>> {
        match Self::open(
            storage,
            expected_key,
            local_origin,
            rpl_instance_id,
            dodag_id,
        ) {
            Ok(_) => {
                return Err(DaoProvisionError::Open(
                    DaoPersistentOpenError::AlreadyProvisioned,
                ))
            }
            Err(DaoPersistentOpenError::Missing) => {}
            Err(DaoPersistentOpenError::Storage(error)) => {
                return Err(DaoProvisionError::Storage(error))
            }
            Err(error) => return Err(DaoProvisionError::Open(error)),
        }
        let payload = encode_tx_state(
            expected_key.as_bytes(),
            local_origin,
            rpl_instance_id,
            dodag_id,
            0,
            &[],
        )
        .unwrap();
        let mut record = vec![0u8; DAO_TX_HEADER_LEN + SLOT_OVERHEAD];
        provision_redundant(storage, DAO_TX_KEYS, DAO_TX_MAGIC, &payload, &mut record).map_err(
            |error| match error {
                RedundantProvisionError::Exists => {
                    DaoProvisionError::Open(DaoPersistentOpenError::Corrupt)
                }
                RedundantProvisionError::Storage(error) => DaoProvisionError::Storage(error),
            },
        )?;
        Self::open(
            storage,
            expected_key,
            local_origin,
            rpl_instance_id,
            dodag_id,
        )
        .map_err(DaoProvisionError::Open)
    }

    pub fn open<S: NonVolatile>(
        storage: &S,
        expected_key: PublicKey,
        local_origin: [u8; 16],
        rpl_instance_id: u8,
        dodag_id: [u8; 16],
    ) -> Result<Self, DaoPersistentOpenError<S::Error>> {
        let mut a = vec![0u8; DAO_TX_PAYLOAD_LEN + SLOT_OVERHEAD];
        let mut b = vec![0u8; DAO_TX_PAYLOAD_LEN + SLOT_OVERHEAD];
        let mut payload = vec![0u8; DAO_TX_PAYLOAD_LEN];
        let current = open_redundant(
            storage,
            DAO_TX_KEYS,
            DAO_TX_MAGIC,
            &mut a,
            &mut b,
            &mut payload,
        )
        .map_err(map_open_error)?;
        if current.len < DAO_TX_HEADER_LEN {
            return Err(DaoPersistentOpenError::Corrupt);
        }
        let public_key: [u8; 32] = payload[..32].try_into().unwrap();
        if public_key != *expected_key.as_bytes() {
            return Err(DaoPersistentOpenError::KeyMismatch);
        }
        if payload[32..48] != local_origin
            || payload[48] != rpl_instance_id
            || payload[49..65] != dodag_id
        {
            return Err(DaoPersistentOpenError::ScopeMismatch);
        }
        let signed_len = u16::from_be_bytes(payload[73..75].try_into().unwrap()) as usize;
        if signed_len > MAX_SIGNED_DAO_LEN || current.len != DAO_TX_HEADER_LEN + signed_len {
            return Err(DaoPersistentOpenError::Corrupt);
        }
        Ok(Self {
            current,
            public_key,
            local_origin,
            rpl_instance_id,
            dodag_id,
            last_reserved: u64::from_be_bytes(payload[65..73].try_into().unwrap()),
            last_signed_dao: payload[DAO_TX_HEADER_LEN..current.len].to_vec(),
        })
    }

    pub fn is_for_scope(
        &self,
        public_key: &PublicKey,
        local_origin: [u8; 16],
        rpl_instance_id: u8,
        dodag_id: [u8; 16],
    ) -> bool {
        self.public_key == *public_key.as_bytes()
            && self.local_origin == local_origin
            && self.rpl_instance_id == rpl_instance_id
            && self.dodag_id == dodag_id
    }

    /// Last complete signed DAO durably finalized for exact retransmission.
    pub fn last_signed_dao(&self) -> Option<&[u8]> {
        (!self.last_signed_dao.is_empty()).then_some(self.last_signed_dao.as_slice())
    }

    pub fn reserve_next<S: NonVolatile>(
        &mut self,
        storage: &mut S,
    ) -> Result<u64, DaoTxError<S::Error>> {
        let next = self
            .last_reserved
            .checked_add(1)
            .ok_or(DaoTxError::Exhausted)?;
        let payload = encode_tx_state(
            &self.public_key,
            self.local_origin,
            self.rpl_instance_id,
            self.dodag_id,
            next,
            &self.last_signed_dao,
        )
        .ok_or(DaoTxError::Oversized)?;
        let mut record = vec![0u8; DAO_TX_PAYLOAD_LEN + SLOT_OVERHEAD];
        self.current = update_redundant(
            storage,
            DAO_TX_KEYS,
            DAO_TX_MAGIC,
            self.current,
            &payload,
            &mut record,
        )
        .map_err(map_tx_update_error)?;
        self.last_reserved = next;
        Ok(next)
    }

    /// Persist exact signed bytes for `sequence` before they may be transmitted.
    pub fn finalize_signed<S: NonVolatile>(
        &mut self,
        storage: &mut S,
        sequence: u64,
        signed_dao: &[u8],
    ) -> Result<(), DaoTxError<S::Error>> {
        if sequence != self.last_reserved {
            return Err(DaoTxError::InvalidState);
        }
        if signed_dao.len() > MAX_SIGNED_DAO_LEN {
            return Err(DaoTxError::Oversized);
        }
        let envelope =
            SignedDaoEnvelope::from_bytes(signed_dao).map_err(|_| DaoTxError::Encoding)?;
        if envelope.origin.origin_sequence != sequence {
            return Err(DaoTxError::InvalidState);
        }
        if SignedDaoEnvelope::from_bytes(&self.last_signed_dao)
            .ok()
            .is_some_and(|envelope| envelope.origin.origin_sequence == sequence)
        {
            return Err(DaoTxError::InvalidState);
        }
        let payload = encode_tx_state(
            &self.public_key,
            self.local_origin,
            self.rpl_instance_id,
            self.dodag_id,
            sequence,
            signed_dao,
        )
        .ok_or(DaoTxError::Oversized)?;
        let mut record = vec![0u8; DAO_TX_PAYLOAD_LEN + SLOT_OVERHEAD];
        self.current = update_redundant(
            storage,
            DAO_TX_KEYS,
            DAO_TX_MAGIC,
            self.current,
            &payload,
            &mut record,
        )
        .map_err(map_tx_update_error)?;
        self.last_signed_dao.clear();
        self.last_signed_dao.extend_from_slice(signed_dao);
        Ok(())
    }

    /// Clear exact retry bytes after successful transmission.
    pub fn clear_transmitted<S: NonVolatile>(
        &mut self,
        storage: &mut S,
    ) -> Result<(), DaoTxError<S::Error>> {
        if self.last_signed_dao.is_empty() {
            return Err(DaoTxError::InvalidState);
        }
        let payload = encode_tx_state(
            &self.public_key,
            self.local_origin,
            self.rpl_instance_id,
            self.dodag_id,
            self.last_reserved,
            &[],
        )
        .ok_or(DaoTxError::Oversized)?;
        let mut record = vec![0u8; DAO_TX_PAYLOAD_LEN + SLOT_OVERHEAD];
        self.current = update_redundant(
            storage,
            DAO_TX_KEYS,
            DAO_TX_MAGIC,
            self.current,
            &payload,
            &mut record,
        )
        .map_err(map_tx_update_error)?;
        self.last_signed_dao.clear();
        Ok(())
    }
}

// ── RX State ─────────────────────────────────────────────────────────────────

#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq)]
pub struct DaoRxState {
    pub(crate) current: RedundantValue,
}

// ── Admission State ──────────────────────────────────────────────────────────

#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq)]
pub struct DaoAdmissionState {
    current: RedundantValue,
    node_address: [u8; 16],
    rpl_instance_id: u8,
    dodag_id: [u8; 16],
    admitted: HashSet<[u8; 32]>,
}

#[cfg(feature = "std")]
impl DaoAdmissionState {
    pub fn provision<S: NonVolatile>(
        storage: &mut S,
        node_address: [u8; 16],
        rpl_instance_id: u8,
        dodag_id: [u8; 16],
    ) -> Result<Self, DaoProvisionError<S::Error>> {
        match Self::open(storage, node_address, rpl_instance_id, dodag_id) {
            Ok(_) => {
                return Err(DaoProvisionError::Open(
                    DaoPersistentOpenError::AlreadyProvisioned,
                ))
            }
            Err(DaoPersistentOpenError::Missing) => {}
            Err(DaoPersistentOpenError::Storage(error)) => {
                return Err(DaoProvisionError::Storage(error))
            }
            Err(error) => return Err(DaoProvisionError::Open(error)),
        }
        let payload = encode_admissions(node_address, rpl_instance_id, dodag_id, &HashSet::new())
            .expect("empty admission set fits fixed header");
        let mut record = vec![0u8; payload.len() + SLOT_OVERHEAD];
        provision_redundant(
            storage,
            DAO_ADMISSION_KEYS,
            DAO_ADMISSION_MAGIC,
            &payload,
            &mut record,
        )
        .map_err(|error| match error {
            RedundantProvisionError::Exists => {
                DaoProvisionError::Open(DaoPersistentOpenError::Corrupt)
            }
            RedundantProvisionError::Storage(error) => DaoProvisionError::Storage(error),
        })?;
        Self::open(storage, node_address, rpl_instance_id, dodag_id)
            .map_err(DaoProvisionError::Open)
    }

    pub fn open<S: NonVolatile>(
        storage: &S,
        node_address: [u8; 16],
        rpl_instance_id: u8,
        dodag_id: [u8; 16],
    ) -> Result<Self, DaoPersistentOpenError<S::Error>> {
        let mut a = vec![0u8; DAO_ADMISSION_PAYLOAD_LEN + SLOT_OVERHEAD];
        let mut b = vec![0u8; DAO_ADMISSION_PAYLOAD_LEN + SLOT_OVERHEAD];
        let mut payload = vec![0u8; DAO_ADMISSION_PAYLOAD_LEN];
        let current = open_redundant(
            storage,
            DAO_ADMISSION_KEYS,
            DAO_ADMISSION_MAGIC,
            &mut a,
            &mut b,
            &mut payload,
        )
        .map_err(map_open_error)?;
        let admitted = decode_admissions(
            &payload[..current.len],
            node_address,
            rpl_instance_id,
            dodag_id,
        )
        .map_err(|error| match error {
            AdmissionDecodeError::ScopeMismatch => DaoPersistentOpenError::ScopeMismatch,
            AdmissionDecodeError::Corrupt => DaoPersistentOpenError::Corrupt,
        })?;
        Ok(Self {
            current,
            node_address,
            rpl_instance_id,
            dodag_id,
            admitted,
        })
    }

    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.admitted.contains(key)
    }

    pub fn len(&self) -> usize {
        self.admitted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.admitted.is_empty()
    }

    pub fn admit<S: NonVolatile>(
        &mut self,
        storage: &mut S,
        key: [u8; 32],
    ) -> Result<(), DaoAdmissionUpdateError<S::Error>> {
        if self.admitted.contains(&key) {
            return Ok(());
        }
        if self.admitted.len() == crate::routing::MAX_DAO_ORIGINS {
            return Err(DaoAdmissionUpdateError::Capacity);
        }
        let mut proposed = self.admitted.clone();
        proposed.insert(key);
        let payload = encode_admissions(
            self.node_address,
            self.rpl_instance_id,
            self.dodag_id,
            &proposed,
        )
        .ok_or(DaoAdmissionUpdateError::Corrupt)?;
        let mut record = vec![0u8; DAO_ADMISSION_PAYLOAD_LEN + SLOT_OVERHEAD];
        let current = update_redundant(
            storage,
            DAO_ADMISSION_KEYS,
            DAO_ADMISSION_MAGIC,
            self.current,
            &payload,
            &mut record,
        )
        .map_err(|error| match error {
            RedundantUpdateError::Storage(error) => DaoAdmissionUpdateError::Persistence(error),
            RedundantUpdateError::Stale => DaoAdmissionUpdateError::Stale,
            RedundantUpdateError::Exhausted => DaoAdmissionUpdateError::Exhausted,
            RedundantUpdateError::Corrupt => DaoAdmissionUpdateError::Corrupt,
        })?;
        self.current = current;
        self.admitted = proposed;
        Ok(())
    }
}

// ── Helper functions ─────────────────────────────────────────────────────────

#[cfg(feature = "std")]
pub(crate) fn encode_tx_state(
    public_key: &[u8; 32],
    local_origin: [u8; 16],
    rpl_instance_id: u8,
    dodag_id: [u8; 16],
    sequence: u64,
    signed_dao: &[u8],
) -> Option<Vec<u8>> {
    if signed_dao.len() > MAX_SIGNED_DAO_LEN {
        return None;
    }
    let mut payload = vec![0u8; DAO_TX_HEADER_LEN + signed_dao.len()];
    payload[..32].copy_from_slice(public_key);
    payload[32..48].copy_from_slice(&local_origin);
    payload[48] = rpl_instance_id;
    payload[49..65].copy_from_slice(&dodag_id);
    payload[65..73].copy_from_slice(&sequence.to_be_bytes());
    payload[73..75].copy_from_slice(&(signed_dao.len() as u16).to_be_bytes());
    payload[DAO_TX_HEADER_LEN..].copy_from_slice(signed_dao);
    Some(payload)
}

#[cfg(feature = "std")]
pub(crate) fn map_tx_update_error<E>(error: RedundantUpdateError<E>) -> DaoTxError<E> {
    match error {
        RedundantUpdateError::Storage(error) => DaoTxError::Persistence(error),
        RedundantUpdateError::Stale => DaoTxError::Stale,
        RedundantUpdateError::Exhausted => DaoTxError::Exhausted,
        RedundantUpdateError::Corrupt => DaoTxError::Corrupt,
    }
}

#[cfg(feature = "std")]
pub(crate) fn map_rx_update_error<E>(
    error: RedundantUpdateError<E>,
) -> crate::routing::DaoProcessError<E> {
    use crate::routing::DaoProcessError;
    match error {
        RedundantUpdateError::Storage(error) => DaoProcessError::Persistence(error),
        RedundantUpdateError::Stale => DaoProcessError::Stale,
        RedundantUpdateError::Exhausted => DaoProcessError::Exhausted,
        RedundantUpdateError::Corrupt => DaoProcessError::Corrupt,
    }
}

#[cfg(feature = "std")]
pub(crate) fn map_open_error<E>(error: RedundantOpenError<E>) -> DaoPersistentOpenError<E> {
    match error {
        RedundantOpenError::Missing => DaoPersistentOpenError::Missing,
        RedundantOpenError::Corrupt | RedundantOpenError::BufferTooSmall => {
            DaoPersistentOpenError::Corrupt
        }
        RedundantOpenError::Storage(error) => DaoPersistentOpenError::Storage(error),
    }
}

#[cfg(feature = "std")]
pub(crate) fn encode_admissions(
    node_address: [u8; 16],
    rpl_instance_id: u8,
    dodag_id: [u8; 16],
    admitted: &HashSet<[u8; 32]>,
) -> Option<Vec<u8>> {
    if admitted.len() > crate::routing::MAX_DAO_ORIGINS {
        return None;
    }
    let mut keys: Vec<_> = admitted.iter().copied().collect();
    keys.sort_unstable();
    let mut payload = vec![0u8; DAO_ADMISSION_HEADER_LEN + keys.len() * 32];
    payload[..16].copy_from_slice(&node_address);
    payload[16] = rpl_instance_id;
    payload[17..33].copy_from_slice(&dodag_id);
    payload[33..35].copy_from_slice(&(keys.len() as u16).to_be_bytes());
    for (index, key) in keys.iter().enumerate() {
        let start = DAO_ADMISSION_HEADER_LEN + index * 32;
        payload[start..start + 32].copy_from_slice(key);
    }
    Some(payload)
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionDecodeError {
    ScopeMismatch,
    Corrupt,
}

#[cfg(feature = "std")]
pub(crate) fn decode_admissions(
    payload: &[u8],
    node_address: [u8; 16],
    rpl_instance_id: u8,
    dodag_id: [u8; 16],
) -> Result<HashSet<[u8; 32]>, AdmissionDecodeError> {
    if payload.len() < DAO_ADMISSION_HEADER_LEN {
        return Err(AdmissionDecodeError::Corrupt);
    }
    if payload[..16] != node_address
        || payload[16] != rpl_instance_id
        || payload[17..33] != dodag_id
    {
        return Err(AdmissionDecodeError::ScopeMismatch);
    }
    let count = u16::from_be_bytes(
        payload[33..35]
            .try_into()
            .map_err(|_| AdmissionDecodeError::Corrupt)?,
    ) as usize;
    if count > crate::routing::MAX_DAO_ORIGINS
        || payload.len() != DAO_ADMISSION_HEADER_LEN + count * 32
    {
        return Err(AdmissionDecodeError::Corrupt);
    }
    let mut admitted = HashSet::with_capacity(count);
    for index in 0..count {
        let start = DAO_ADMISSION_HEADER_LEN + index * 32;
        let key = payload[start..start + 32]
            .try_into()
            .map_err(|_| AdmissionDecodeError::Corrupt)?;
        if !admitted.insert(key) {
            return Err(AdmissionDecodeError::Corrupt);
        }
    }
    Ok(admitted)
}

#[cfg(feature = "std")]
pub(crate) fn encode_high_water(
    node_address: [u8; 16],
    rpl_instance_id: u8,
    dodag_id: [u8; 16],
    map: &HighWaterMap,
    out: &mut [u8],
) -> Option<usize> {
    if map.len() > crate::routing::MAX_DAO_ORIGINS {
        return None;
    }
    let len = HIGH_WATER_HEADER_LEN + map.len() * HIGH_WATER_ENTRY_LEN;
    if out.len() < len {
        return None;
    }
    out[..16].copy_from_slice(&node_address);
    out[16] = rpl_instance_id;
    out[17..HIGH_WATER_SCOPE_LEN].copy_from_slice(&dodag_id);
    out[HIGH_WATER_SCOPE_LEN..HIGH_WATER_HEADER_LEN]
        .copy_from_slice(&(map.len() as u16).to_be_bytes());
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_unstable_by_key(|(key, _)| **key);
    for (index, (key, (hash, sequence))) in entries.into_iter().enumerate() {
        let offset = HIGH_WATER_HEADER_LEN + index * HIGH_WATER_ENTRY_LEN;
        out[offset..offset + 32].copy_from_slice(key);
        out[offset + 32..offset + 40].copy_from_slice(&sequence.to_be_bytes());
        out[offset + 40..offset + 72].copy_from_slice(hash);
    }
    Some(len)
}

#[cfg(feature = "std")]
pub(crate) fn decode_high_water(data: &[u8]) -> Option<HighWaterMap> {
    if data.len() < HIGH_WATER_HEADER_LEN {
        return None;
    }
    let count = u16::from_be_bytes(
        data[HIGH_WATER_SCOPE_LEN..HIGH_WATER_HEADER_LEN]
            .try_into()
            .ok()?,
    ) as usize;
    if count > crate::routing::MAX_DAO_ORIGINS
        || data.len() != HIGH_WATER_HEADER_LEN + count * HIGH_WATER_ENTRY_LEN
    {
        return None;
    }
    let mut map = HashMap::with_capacity(count);
    for index in 0..count {
        let offset = HIGH_WATER_HEADER_LEN + index * HIGH_WATER_ENTRY_LEN;
        let key = data[offset..offset + 32].try_into().ok()?;
        let sequence = u64::from_be_bytes(data[offset + 32..offset + 40].try_into().ok()?);
        let hash = data[offset + 40..offset + 72].try_into().ok()?;
        if sequence == 0 || map.insert(key, (hash, sequence)).is_some() {
            return None;
        }
    }
    Some(map)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::routing::DaoManager;
    use lichen_hal::storage::{mem::MemStorage, provision_redundant, update_redundant};

    const INSTANCE: u8 = 7;

    fn node() -> [u8; 16] {
        let mut address = [0u8; 16];
        address[15] = 1;
        address
    }

    fn dodag() -> [u8; 16] {
        let mut dodag_id = [0u8; 16];
        dodag_id[0] = 0xfd;
        dodag_id[15] = 1;
        dodag_id
    }

    fn origin_key(index: u8) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = 0xa1;
        key[31] = index;
        key
    }

    fn sample_map() -> HighWaterMap {
        let mut map = HighWaterMap::new();
        map.insert(origin_key(1), (origin_key(2), 41));
        map.insert(origin_key(3), (origin_key(4), u64::MAX));
        map
    }

    /// DRX2 payload head: node, instance, DODAGID, entry count.
    fn scoped_header(count: u16) -> Vec<u8> {
        let mut payload = vec![0u8; HIGH_WATER_HEADER_LEN];
        payload[..16].copy_from_slice(&node());
        payload[16] = INSTANCE;
        payload[17..HIGH_WATER_SCOPE_LEN].copy_from_slice(&dodag());
        payload[HIGH_WATER_SCOPE_LEN..HIGH_WATER_HEADER_LEN].copy_from_slice(&count.to_be_bytes());
        payload
    }

    /// Persist `map` through the same DRX2 record path `DaoManager` uses.
    fn persist_map(storage: &mut MemStorage, rx_state: &mut DaoRxState, map: &HighWaterMap) {
        let mut payload = vec![0u8; HIGH_WATER_PAYLOAD_LEN];
        let len = encode_high_water(node(), INSTANCE, dodag(), map, &mut payload).unwrap();
        let mut record = vec![0u8; HIGH_WATER_PAYLOAD_LEN + SLOT_OVERHEAD];
        rx_state.current = update_redundant(
            storage,
            DAO_RX_KEYS,
            DAO_RX_MAGIC,
            rx_state.current,
            &payload[..len],
            &mut record,
        )
        .unwrap();
    }

    #[test]
    fn high_water_payload_roundtrips_bit_exact() {
        let map = sample_map();
        let mut payload = vec![0u8; HIGH_WATER_PAYLOAD_LEN];
        let len = encode_high_water(node(), INSTANCE, dodag(), &map, &mut payload).unwrap();
        let decoded = decode_high_water(&payload[..len]).unwrap();
        let mut reencoded = vec![0u8; HIGH_WATER_PAYLOAD_LEN];
        let reencoded_len =
            encode_high_water(node(), INSTANCE, dodag(), &decoded, &mut reencoded).unwrap();
        assert_eq!(&reencoded[..reencoded_len], &payload[..len]);

        // Scope head binds the record to node, instance, and DODAGID.
        assert_eq!(&payload[..16], &node()[..]);
        assert_eq!(payload[16], INSTANCE);
        assert_eq!(&payload[17..HIGH_WATER_SCOPE_LEN], &dodag()[..]);
        assert_eq!(
            &payload[HIGH_WATER_SCOPE_LEN..HIGH_WATER_HEADER_LEN],
            &2u16.to_be_bytes()[..]
        );
    }

    #[test]
    fn drx2_record_round_trips_scope_and_high_water() {
        let map = sample_map();
        let mut storage = MemStorage::new();
        let (_, mut rx_state) =
            DaoManager::provision_root(&mut storage, node().into(), INSTANCE, dodag().into())
                .unwrap();
        let (fresh, _) =
            DaoManager::open_root(&storage, node().into(), INSTANCE, dodag().into()).unwrap();
        assert!(fresh.origin_high_water().is_empty());

        persist_map(&mut storage, &mut rx_state, &map);

        // Both redundant slots carry DRX2 framing with slot version 1.
        for key in DAO_RX_KEYS {
            let raw = storage.raw(key).unwrap();
            assert_eq!(&raw[..4], &DAO_RX_MAGIC[..]);
            assert_eq!(raw[4], 1);
        }

        let (manager, _) =
            DaoManager::open_root(&storage, node().into(), INSTANCE, dodag().into()).unwrap();
        let snapshot = manager.origin_high_water();
        assert_eq!(snapshot.len(), map.len());
        for entry in &snapshot {
            let expected = map.get(&entry.public_key).unwrap();
            assert_eq!(entry.origin_sequence, expected.1);
            assert_eq!(entry.signed_dao_sha256, expected.0);
        }
    }

    #[test]
    fn old_format_and_wrong_magic_records_fail_closed() {
        // DRX1 (predecessor receive format) and the TX-side DTX2 magic must
        // never open as receive state; there is no migration by design.
        for magic in [*b"DRX1", DAO_TX_MAGIC] {
            let mut storage = MemStorage::new();
            let mut record = vec![0u8; HIGH_WATER_PAYLOAD_LEN + SLOT_OVERHEAD];
            provision_redundant(&mut storage, DAO_RX_KEYS, magic, &[], &mut record).unwrap();
            let error = DaoManager::open_root(&storage, node().into(), INSTANCE, dodag().into())
                .unwrap_err();
            assert_eq!(error, DaoPersistentOpenError::Corrupt);
        }
    }

    #[test]
    fn unversioned_drx2_record_fails_closed() {
        let mut storage = MemStorage::new();
        DaoManager::provision_root(&mut storage, node().into(), INSTANCE, dodag().into()).unwrap();
        let mut raw = storage.raw(DAO_RX_KEYS[0]).unwrap().to_vec();
        raw[4] = 0;
        storage.set_raw(DAO_RX_KEYS[0], &raw);
        let error =
            DaoManager::open_root(&storage, node().into(), INSTANCE, dodag().into()).unwrap_err();
        assert_eq!(error, DaoPersistentOpenError::Corrupt);
    }

    #[test]
    fn garbage_and_short_records_fail_closed() {
        let mut storage = MemStorage::new();
        storage.set_raw(DAO_RX_KEYS[0], &[0xff; 64]);
        storage.set_raw(DAO_RX_KEYS[1], &[0x00; 10]);
        let error =
            DaoManager::open_root(&storage, node().into(), INSTANCE, dodag().into()).unwrap_err();
        assert_eq!(error, DaoPersistentOpenError::Corrupt);
    }

    #[test]
    fn absent_record_reports_missing_without_fabricating_state() {
        let storage = MemStorage::new();
        let error =
            DaoManager::open_root(&storage, node().into(), INSTANCE, dodag().into()).unwrap_err();
        assert_eq!(error, DaoPersistentOpenError::Missing);
    }

    #[test]
    fn well_framed_drx2_with_malformed_payload_fails_closed() {
        // Correct scope head, but a zero origin sequence is never valid state.
        let mut payload = scoped_header(1);
        payload.extend_from_slice(&[0u8; HIGH_WATER_ENTRY_LEN]);
        let mut storage = MemStorage::new();
        let mut record = vec![0u8; payload.len() + SLOT_OVERHEAD];
        provision_redundant(
            &mut storage,
            DAO_RX_KEYS,
            DAO_RX_MAGIC,
            &payload,
            &mut record,
        )
        .unwrap();
        let error =
            DaoManager::open_root(&storage, node().into(), INSTANCE, dodag().into()).unwrap_err();
        assert_eq!(error, DaoPersistentOpenError::Corrupt);
    }

    #[test]
    fn malformed_high_water_payloads_fail_closed() {
        assert!(decode_high_water(&[]).is_none());
        assert!(decode_high_water(&[0u8; HIGH_WATER_HEADER_LEN - 1]).is_none());

        // Entry count beyond the payload length.
        let mut short = scoped_header(1);
        short.extend_from_slice(&[0u8; HIGH_WATER_ENTRY_LEN - 1]);
        assert!(decode_high_water(&short).is_none());

        // Zero sequence is never valid state.
        let mut zeroed = scoped_header(1);
        zeroed.extend_from_slice(&[0u8; HIGH_WATER_ENTRY_LEN]);
        assert!(decode_high_water(&zeroed).is_none());

        // Duplicate origins cannot appear twice in one record.
        let mut duplicate = scoped_header(2);
        duplicate.extend_from_slice(&origin_key(1));
        duplicate.extend_from_slice(&1u64.to_be_bytes());
        duplicate.extend_from_slice(&origin_key(2));
        duplicate.extend_from_slice(&origin_key(1));
        duplicate.extend_from_slice(&2u64.to_be_bytes());
        duplicate.extend_from_slice(&origin_key(2));
        assert!(decode_high_water(&duplicate).is_none());

        // A valid empty record decodes.
        assert!(decode_high_water(&scoped_header(0)).is_some());
    }

    #[test]
    fn scope_change_invalidates_record() {
        let map = sample_map();
        let mut storage = MemStorage::new();
        let (_, mut rx_state) =
            DaoManager::provision_root(&mut storage, node().into(), INSTANCE, dodag().into())
                .unwrap();
        persist_map(&mut storage, &mut rx_state, &map);

        let mut other_dodag = dodag();
        other_dodag[15] = 2;
        let mut other_node = node();
        other_node[15] = 2;

        let errors = [
            DaoManager::open_root(&storage, node().into(), INSTANCE, other_dodag.into())
                .unwrap_err(),
            DaoManager::open_root(&storage, node().into(), INSTANCE + 1, dodag().into())
                .unwrap_err(),
            DaoManager::open_root(&storage, other_node.into(), INSTANCE, dodag().into())
                .unwrap_err(),
        ];
        for error in errors {
            assert_eq!(error, DaoPersistentOpenError::ScopeMismatch);
        }
    }
}
