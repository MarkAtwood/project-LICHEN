// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Regression tests for exclusive OSCORE receiver ownership.
//!
//! Bead project-LICHEN-v0ee: repeated activation of the same durable record
//! (the same [`ContextId`]) must not produce concurrent receiver contexts
//! with independent replay windows, or the same authenticated packet is
//! accepted once per instance (a double-accept defeating replay protection).

use lichen_oscore::{
    Context, ContextId, OwnershipError, OwnershipRegistry, SenderSequenceState, ContextStateStore, RecipientReplayState,
};

const SECRET: [u8; 16] = [0x77; 16];

struct MemoryStore(Option<SenderSequenceState>);

impl ContextStateStore for MemoryStore {
    type Error = core::convert::Infallible;

    fn load_sender(
        &mut self,
        _context_id: &ContextId,
    ) -> Result<Option<SenderSequenceState>, Self::Error> {
        Ok(self.0)
    }

    fn compare_exchange_sender(
        &mut self,
        _context_id: &ContextId,
        expected: Option<SenderSequenceState>,
        next: SenderSequenceState,
    ) -> Result<bool, Self::Error> {
        if self.0 != expected {
            return Ok(false);
        }
        self.0 = Some(next);
        Ok(true)
    }

    fn load_recipient(&mut self, _: &ContextId) -> Result<Option<RecipientReplayState>, Self::Error> { Ok(None) }
    fn save_recipient(&mut self, _: &ContextId, _: &RecipientReplayState) -> Result<(), Self::Error> { Ok(()) }
}

/// Context of the peer whose requests the receiver unprotects.
fn sender_context() -> Context {
    Context::new(&SECRET, None, None, &[0x01], &[0x00]).unwrap()
}

/// Receiver context for packets sent by `sender_context`.
fn receiver_context() -> Context {
    Context::new(&SECRET, None, None, &[0x00], &[0x01]).unwrap()
}

fn restored_sender_state() -> SenderSequenceState {
    SenderSequenceState {
        next_sequence: 1,
        exhausted: false,
    }
}

#[test]
fn live_record_cannot_gain_a_second_receiver_context() {
    let mut sender_store = MemoryStore(None);
    let mut sender_registry: OwnershipRegistry = OwnershipRegistry::new();
    let mut sender = sender_registry
        .register_fresh(sender_context(), &mut sender_store)
        .unwrap();

    // The peer protects its first request (Partial IV N).
    let (payload, option) = sender
        .reserve_sender(&mut sender_store)
        .unwrap()
        .protect_request(0x01, &[], &[])
        .unwrap();

    let mut receiver_store = MemoryStore(Some(restored_sender_state()));
    let mut registry: OwnershipRegistry = OwnershipRegistry::new();

    // Instance 1 accepts the authenticated packet at sequence N.
    let mut receiver = registry
        .restore_existing(receiver_context(), &mut receiver_store)
        .unwrap();
    receiver
        .unprotect_request(&option, &payload)
        .expect("instance 1 accepts sequence N");

    // A second activation for the same durable record must not produce a
    // second receiver with a fresh replay window: the double-accept is
    // refused at construction time.
    let duplicate = registry.restore_existing(receiver_context(), &mut receiver_store);
    assert_eq!(duplicate.unwrap_err(), OwnershipError::AlreadyOwned);

    // After the sole owner releases the record it may be reactivated
    // (process-restart semantics).
    assert!(registry.release(&receiver));
    let reactivated = registry
        .restore_existing(receiver_context(), &mut receiver_store)
        .unwrap();
    assert_eq!(reactivated.context_id(), receiver.context_id());
}

#[test]
fn activation_failure_rolls_back_the_claim() {
    let mut registry: OwnershipRegistry = OwnershipRegistry::new();
    // No durable sender state: restore_existing fails with Missing.
    let mut empty_store = MemoryStore(None);
    let failed = registry.restore_existing(receiver_context(), &mut empty_store);
    assert!(matches!(
        failed,
        Err(OwnershipError::ContextStore(
            lichen_oscore::ContextStoreError::Missing
        ))
    ));
    // The rolled-back claim must not block a later activation.
    let mut store = MemoryStore(Some(restored_sender_state()));
    assert!(registry
        .restore_existing(receiver_context(), &mut store)
        .is_ok());
}

#[test]
fn distinct_records_own_independently() {
    let mut registry: OwnershipRegistry = OwnershipRegistry::new();
    let mut store_a = MemoryStore(Some(restored_sender_state()));
    let mut store_b = MemoryStore(Some(restored_sender_state()));

    // Both directional records of one session (node and gateway sides).
    let a = registry
        .restore_existing(receiver_context(), &mut store_a)
        .unwrap();
    let b = registry
        .restore_existing(sender_context(), &mut store_b)
        .unwrap();
    assert_ne!(a.context_id(), b.context_id());
}

#[test]
fn capacity_exhaustion_fails_closed() {
    let mut registry: OwnershipRegistry<1> = OwnershipRegistry::new();
    let mut store = MemoryStore(Some(restored_sender_state()));

    let owned = registry
        .restore_existing(receiver_context(), &mut store)
        .unwrap();

    // A distinct record cannot be claimed once the registry is full.
    let second = Context::new(&SECRET, None, None, &[0x03], &[0x00]).unwrap();
    let refused = registry.restore_existing(second, &mut store);
    assert_eq!(refused.unwrap_err(), OwnershipError::Full);

    // The live owner is unaffected and can still release.
    assert!(registry.release(&owned));
}

#[test]
fn register_fresh_is_exclusive() {
    let mut registry: OwnershipRegistry = OwnershipRegistry::new();
    let mut store = MemoryStore(None);

    let first = registry
        .register_fresh(sender_context(), &mut store)
        .unwrap();
    let again = registry.register_fresh(sender_context(), &mut store);
    assert_eq!(again.unwrap_err(), OwnershipError::AlreadyOwned);
    assert!(registry.release(&first));
}

#[test]
fn claim_survives_context_drop_until_release() {
    let mut registry: OwnershipRegistry = OwnershipRegistry::new();
    let mut store = MemoryStore(Some(restored_sender_state()));

    let receiver = registry
        .restore_existing(receiver_context(), &mut store)
        .unwrap();
    drop(receiver);

    // Fail closed: dropping without release keeps the claim, so no second
    // receiver can appear for the record.
    let refused = registry.restore_existing(receiver_context(), &mut store);
    assert_eq!(refused.unwrap_err(), OwnershipError::AlreadyOwned);

    // Releasing by record (a fresh context with identical material carries
    // the same ContextId) restores availability.
    assert!(registry.release(&receiver_context()));
    assert!(registry
        .restore_existing(receiver_context(), &mut store)
        .is_ok());
}

#[test]
fn release_of_unowned_record_is_false() {
    let mut registry: OwnershipRegistry = OwnershipRegistry::new();
    assert!(!registry.release(&receiver_context()));
}
