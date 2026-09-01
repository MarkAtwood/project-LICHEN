// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! DAO TX timing state machine (spec 09 14.2 R-09-017..019).
//!
//! Drives the RPL DAO transmission schedule for a Leaf node using the
//! cross-language oracle in [`crate::dao_timing`] as the single source of
//! timing constants: one random initial DAO 0-2 s after joining, exponential
//! retry backoff 4/8/16 s while unacknowledged, and periodic refresh
//! re-emission every 900 s (half the 30-minute soft-state lifetime). All
//! deadlines derive from caller-supplied monotonic milliseconds; nothing here
//! redefines the constants or introduces wall-clock dependence.

use core::time::Duration;

use crate::dao_timing::{
    checked_dao_refresh_deadline, dao_initial_delay_ms, dao_retry_delay, DaoRefreshTimer,
};

/// Phase of the DAO origination TX state machine.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DaoTimingPhase {
    /// Not joined; nothing scheduled.
    #[default]
    Idle,
    /// Joined; waiting out the random 0-2 s initial delay.
    InitialPending,
    /// Sent unacknowledged; backoff until the next retry (4/8/16 s).
    RetryPending,
    /// Last exchange acknowledged; refresh due in 900 s.
    RefreshPending,
    /// All retry slots exhausted; the parent is unresponsive.
    Exhausted,
}

/// DAO TX timing state machine consuming the dao_timing oracle.
///
/// The runtime polls [`Self::next_action`] with monotonic `now_ms`, reports
/// each send via [`Self::on_sent`], and reports a DAO-ACK via
/// [`Self::on_ack`]. A DAO-ACK resets retries and arms the refresh timer;
/// the retry backoff is exhausted after the initial send plus three retries.
#[derive(Clone, Copy, Debug)]
pub struct DaoTimingState {
    /// Random initial delay drawn at join time (ms).
    initial_delay_ms: Option<u16>,
    /// Retry slot index (0..=3); also the ACK latched flag when in
    /// RefreshPending.
    attempts: u8,
    /// Monotonic deadline (ms) of the currently pending transition.
    deadline_ms: u64,
    phase: DaoTimingPhase,
    /// Periodic refresh timer armed after a successful exchange.
    refresh_timer: DaoRefreshTimer,
}

impl Default for DaoTimingState {
    fn default() -> Self {
        Self {
            initial_delay_ms: None,
            attempts: 0,
            deadline_ms: 0,
            phase: DaoTimingPhase::Idle,
            refresh_timer: DaoRefreshTimer::new(),
        }
    }
}

impl DaoTimingState {
    /// Join the DODAG: draw the random initial delay from `random_word` and
    /// schedule the initial DAO (R-09-017).
    ///
    /// `random_word` is hashed into the inclusive 0-2 s window by the oracle
    /// ([`dao_initial_delay_ms`]); a `None` draw (reserved word) schedules
    /// immediately.
    pub fn on_join(&mut self, now_ms: u64, random_word: u32) -> u64 {
        self.initial_delay_ms = Some(dao_initial_delay_ms(random_word).unwrap_or(0));
        self.attempts = 0;
        self.phase = DaoTimingPhase::InitialPending;
        self.deadline_ms = now_ms + u64::from(self.initial_delay_ms.unwrap_or(0));
        self.deadline_ms
    }

    /// Whether the DODAG join has armed the timing state.
    #[must_use]
    pub fn is_joined(&self) -> bool {
        self.initial_delay_ms.is_some()
    }

    /// Current phase.
    #[must_use]
    pub const fn phase(&self) -> DaoTimingPhase {
        self.phase
    }

    /// Whether a send (initial, retry, or refresh) is due at `now_ms`.
    #[must_use]
    pub fn next_action(&self, now_ms: u64) -> Option<DaoTxDue> {
        match self.phase {
            DaoTimingPhase::Idle | DaoTimingPhase::Exhausted => None,
            DaoTimingPhase::InitialPending | DaoTimingPhase::RetryPending => {
                (now_ms >= self.deadline_ms).then_some(DaoTxDue::Transmit)
            }
            DaoTimingPhase::RefreshPending => {
                if self.refresh_timer.is_due(Duration::from_millis(now_ms)) {
                    Some(DaoTxDue::Transmit)
                } else {
                    None
                }
            }
        }
    }

    /// Record one DAO transmission (R-09-018).
    ///
    /// In InitialPending/RefreshPending the send is the start of a new
    /// exchange (retries reset). In RetryPending the retry slot is consumed.
    /// Returns the next deadline, or `None` when retries are exhausted.
    pub fn on_sent(&mut self, now_ms: u64) -> Option<u64> {
        match self.phase {
            DaoTimingPhase::InitialPending | DaoTimingPhase::RefreshPending => {
                self.attempts = 0;
            }
            DaoTimingPhase::RetryPending | DaoTimingPhase::Exhausted => {}
            DaoTimingPhase::Idle => return None,
        }
        let delay = crate::dao_timing::dao_retry_delay(self.attempts);
        self.attempts = self.attempts.saturating_add(1);
        match delay {
            Some(d) => {
                self.phase = DaoTimingPhase::RetryPending;
                self.deadline_ms = now_ms.saturating_add(d.as_millis() as u64);
                Some(self.deadline_ms)
            }
            None => {
                self.phase = DaoTimingPhase::Exhausted;
                None
            }
        }
    }

    /// Record a DAO-ACK: retries reset, refresh timer armed (R-09-019).
    ///
    /// Returns the refresh deadline, or `None` if the refresh deadline
    /// overflowed (caller fails closed).
    pub fn on_ack(&mut self, now_ms: u64) -> Option<u64> {
        if matches!(self.phase, DaoTimingPhase::Idle | DaoTimingPhase::Exhausted) {
            return None;
        }
        self.attempts = 0;
        let now = Duration::from_millis(now_ms);
        match checked_dao_refresh_deadline(now) {
            Ok(deadline) => {
                self.refresh_timer = DaoRefreshTimer::checked_start(now).ok()?;
                self.phase = DaoTimingPhase::RefreshPending;
                self.deadline_ms = deadline.as_millis() as u64;
                Some(self.deadline_ms)
            }
            Err(_) => None,
        }
    }

    /// Route invalidated (parent lost, DODAG left): reset to Idle.
    pub fn on_leave(&mut self) {
        *self = Self::default();
    }
}

/// Action the runtime should take for DAO TX timing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaoTxDue {
    /// A DAO send (initial or refresh) is due.
    Transmit,
}
