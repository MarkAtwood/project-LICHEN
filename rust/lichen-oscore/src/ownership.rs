// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Exclusive live ownership of OSCORE receiver contexts by receiver record.
//!
//! [`Context::restore_existing`](crate::Context::restore_existing) and
//! [`Context::register_fresh`](crate::Context::register_fresh) can be called
//! repeatedly for the same durable record (the same
//! [`ContextId`]). Each call yields an independent context whose recipient
//! replay window starts empty, so two concurrent instances can each accept the
//! same authenticated packet once (a double-accept that defeats replay
//! protection). The durable [`SenderStateStore`] only fences the sender
//! sequence, not the receiver replay window.
//!
//! [`OwnershipRegistry`] enforces a documented single-owner contract: while a
//! receiver record is claimed, further activation attempts for it fail with
//! [`OwnershipError::AlreadyOwned`]. Claims are released explicitly with
//! [`OwnershipRegistry::release`]. Dropping a claimed context without
//! releasing intentionally keeps the claim (fail closed): a stuck claim
//! refuses new activations for that record instead of allowing a second
//! receiver. After release, reactivation yields a fresh context with an empty
//! replay window (process-restart semantics).
//!
//! The ownership unit is the [`ContextId`]. The `oscore` crate derives one
//! stable [`ContextId`] per directional context, so the identifier pins the
//! replay window of exactly one recipient; two directional contexts of one
//! session (local sender side and peer receiver side) hold distinct
//! [`ContextId`]s and own independently.
//!
//! The registry is fixed-capacity and allocation-free (`no_std` compatible).
//! Capacity exhaustion refuses new claims ([`OwnershipError::Full`]) rather
//! than evicting a live owner.

use oscore::{ContextStateStore};
use heapless::Vec;

use crate::{Context, ContextId, ContextStoreError, SenderStateStore};

/// Default maximum number of concurrently owned context records.
const DEFAULT_CAPACITY: usize = 8;

/// Failure to claim or activate a context record through
/// [`OwnershipRegistry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipError<E> {
    /// A live context already owns this durable record.
    AlreadyOwned,
    /// The registry is at capacity; the live owners were left untouched.
    Full,
    /// Context activation failed; the record claim was rolled back.
    ContextStore(ContextStoreError<E>),
}

/// Fixed-capacity registry enforcing exclusive live ownership of OSCORE
/// contexts by durable record ([`ContextId`]).
///
/// See the [module documentation](self) for the ownership contract.
#[derive(Debug)]
pub struct OwnershipRegistry<const N: usize = DEFAULT_CAPACITY> {
    live: Vec<ContextId, N>,
}

impl<const N: usize> Default for OwnershipRegistry<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimError {
    AlreadyOwned,
    Full,
}

impl<const N: usize> OwnershipRegistry<N> {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self { live: Vec::new() }
    }

    fn claim(&mut self, context_id: &ContextId) -> Result<(), ClaimError> {
        if self.live.iter().any(|owned| owned == context_id) {
            return Err(ClaimError::AlreadyOwned);
        }
        self.live.push(*context_id).map_err(|_| ClaimError::Full)
    }

    fn unclaim(&mut self, context_id: &ContextId) {
        if let Some(position) = self.live.iter().position(|owned| owned == context_id) {
            self.live.remove(position);
        }
    }

    /// Atomically register a newly established context and claim its record.
    ///
    /// The claim is taken before the store compare-and-swap and rolled back
    /// if activation fails.
    pub fn register_fresh<S: ContextStateStore>(
        &mut self,
        context: Context,
        store: &mut S,
    ) -> Result<Context, OwnershipError<S::Error>> {
        let context_id = context.context_id();
        self.claim(&context_id).map_err(|error| match error {
            ClaimError::AlreadyOwned => OwnershipError::AlreadyOwned,
            ClaimError::Full => OwnershipError::Full,
        })?;
        match context.register_fresh(store) {
            Ok(activated) => Ok(activated),
            Err(error) => {
                self.unclaim(&context_id);
                Err(OwnershipError::ContextStore(error))
            }
        }
    }

    /// Restore an existing context and claim its record.
    ///
    /// Fails with [`OwnershipError::AlreadyOwned`] while another instance is
    /// live for the same durable record, preventing a second receiver with an
    /// independent replay window.
    pub fn restore_existing<S: ContextStateStore>(
        &mut self,
        context: Context,
        store: &mut S,
    ) -> Result<Context, OwnershipError<S::Error>> {
        let context_id = context.context_id();
        self.claim(&context_id).map_err(|error| match error {
            ClaimError::AlreadyOwned => OwnershipError::AlreadyOwned,
            ClaimError::Full => OwnershipError::Full,
        })?;
        match context.restore_existing(store) {
            Ok(activated) => Ok(activated),
            Err(error) => {
                self.unclaim(&context_id);
                Err(OwnershipError::ContextStore(error))
            }
        }
    }

    /// Release the record owned by `context`, making it available for future
    /// activation. Returns `false` if the record was not claimed.
    pub fn release(&mut self, context: &Context) -> bool {
        let context_id = context.context_id();
        let owned = self.live.iter().any(|owned| owned == &context_id);
        if owned {
            self.unclaim(&context_id);
        }
        owned
    }
}
