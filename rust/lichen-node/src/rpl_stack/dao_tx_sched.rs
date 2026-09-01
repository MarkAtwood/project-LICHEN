// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! DAO TX scheduler state (spec 09 14.2, R-09-017..019).
//!
//! Tracks when the leaf must send its DAO: an initial DAO 0-2 s after
//! DODAG join, retries on the 4/8/16 s exponential ladder, and periodic
//! refresh at half the soft-state lifetime. All timing constants come from
//! [`lichen_rpl::dao_timing`] — the single oracle; nothing is duplicated
//! here. The TX path (send_dao) consumes [`DaoTxScheduler::advance`].

use lichen_rpl::dao_timing::{
    dao_initial_delay_ms, dao_retry_delay_ms, dao_retry_exhausted, DAO_REFRESH_INTERVAL_SECONDS,
};

/// Refresh interval in ms (half the 30-min soft-state lifetime). Consumed
/// by on_dao_sent; dead in non-test builds until b7z9.16.1(b) wires the TX
/// path.
const DAO_REFRESH_INTERVAL_MS: u64 = DAO_REFRESH_INTERVAL_SECONDS * 1000 / 2;
/// Fixed hourly-window length for the wall-clock-independent refresh floor.
const _DAO_REFRESH_FLOOR_MS: u64 = DAO_REFRESH_INTERVAL_MS;

/// DAO TX scheduler phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaoTxPhase {
    /// Not joined (or no DAO pending).
    Idle,
    /// Initial DAO due at `deadline_ms` (join time + 0-2 s).
    Initial { deadline_ms: u64 },
    /// Retry `attempt` (1-based) due at `deadline_ms`.
    Retry { attempt: u8, deadline_ms: u64 },
    /// Periodic refresh due at `deadline_ms`.
    Refresh { deadline_ms: u64 },
    /// Retry ladder exhausted (R-09-019 ceiling); refresh continues.
    Exhausted,
}

/// Outcome of one scheduler advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaoTxAdvance {
    /// A DAO transmission is due now.
    Due,
    /// Not yet due; `remaining_ms` until the deadline.
    NotYet { remaining_ms: u64 },
    /// Retry ladder exhausted — the TX path stops retrying.
    Exhausted,
    /// Idle (not joined).
    Idle,
}

/// Scheduler for leaf DAO transmissions.
#[derive(Debug)]
pub(crate) struct DaoTxScheduler {
    phase: DaoTxPhase,
}

impl DaoTxScheduler {
    pub(crate) const fn new() -> Self {
        Self {
            phase: DaoTxPhase::Idle,
        }
    }

    pub(crate) const fn phase(&self) -> &DaoTxPhase {
        &self.phase
    }

    /// Schedule the initial DAO: `now_ms + 0-2 s` derived from
    /// `random_word` via the oracle's `dao_initial_delay_ms`.
    ///
    /// Called when the DODAG join transition is detected by the caller.
    /// Returns the scheduled deadline.
    pub(crate) fn schedule_initial(&mut self, now_ms: u64, random_word: u32) -> u64 {
        let offset = u64::from(dao_initial_delay_ms(random_word).unwrap_or(0));
        let deadline = now_ms.saturating_add(offset);
        self.phase = DaoTxPhase::Initial {
            deadline_ms: deadline,
        };
        deadline
    }

    /// Evaluate the phase against `now_ms`.
    pub(crate) fn advance(&mut self, now_ms: u64) -> DaoTxAdvance {
        let deadline = match self.phase {
            DaoTxPhase::Idle => return DaoTxAdvance::Idle,
            DaoTxPhase::Exhausted => return DaoTxAdvance::Exhausted,
            DaoTxPhase::Initial { deadline_ms }
            | DaoTxPhase::Retry { deadline_ms, .. }
            | DaoTxPhase::Refresh { deadline_ms } => deadline_ms,
        };
        if now_ms >= deadline {
            DaoTxAdvance::Due
        } else {
            DaoTxAdvance::NotYet {
                remaining_ms: deadline - now_ms,
            }
        }
    }

    /// Record a successful DAO transmission: move to periodic refresh
    /// (half the soft-state lifetime, per R-09-019).
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "DAO TX consumer lands in b7z9.16.1(b)")
    )]
    pub(crate) fn on_dao_sent(&mut self, now_ms: u64) {
        self.phase = DaoTxPhase::Refresh {
            deadline_ms: now_ms.saturating_add(DAO_REFRESH_INTERVAL_MS),
        };
    }

    /// Record a failed/lost DAO transmission: advance the retry ladder
    /// (4/8/16 s). Exhausted after the final rung (R-09-019 ceiling) —
    /// refresh-mode emissions continue from the TX path.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "DAO TX consumer lands in b7z9.16.1(b)")
    )]
    pub(crate) fn on_dao_failed(&mut self, now_ms: u64) {
        // 0-indexed against DAO_RETRY_DELAYS_MS: the first retry (after
        // the initial DAO) uses delays[0] = 4 s.
        let attempt = match self.phase {
            DaoTxPhase::Retry { attempt, .. } => attempt + 1,
            _ => 0,
        };
        if dao_retry_exhausted(attempt) {
            self.phase = DaoTxPhase::Exhausted;
            return;
        }
        match dao_retry_delay_ms(attempt) {
            Some(delay) => {
                self.phase = DaoTxPhase::Retry {
                    attempt,
                    deadline_ms: now_ms.saturating_add(delay),
                };
            }
            None => {
                self.phase = DaoTxPhase::Exhausted;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_until_join_schedules_initial() {
        let mut sched = DaoTxScheduler::new();
        assert_eq!(sched.advance(1_000), DaoTxAdvance::Idle);
        let deadline = sched.schedule_initial(1_000, 0);
        assert_eq!(deadline, 1_000); // random_word 0 -> 0 ms delay
        assert!(matches!(sched.phase(), DaoTxPhase::Initial { .. }));
    }

    #[test]
    fn initial_delay_spans_zero_to_two_seconds() {
        let mut sched = DaoTxScheduler::new();
        let deadline = sched.schedule_initial(5_000, u32::MAX);
        // oracle: offset = max_ms * rand / u32::MAX, clamped to max
        assert!(deadline >= 5_000 && deadline <= 7_000);
    }

    #[test]
    fn initial_due_then_refresh_on_success() {
        let mut sched = DaoTxScheduler::new();
        sched.schedule_initial(1_000, 0);
        assert_eq!(sched.advance(1_000), DaoTxAdvance::Due);
        sched.on_dao_sent(1_100);
        assert!(matches!(sched.phase(), DaoTxPhase::Refresh { .. }));
        // 900 s / 2 = 450 s = 450_000 ms
        assert_eq!(
            sched.advance(1_100 + 449_999),
            DaoTxAdvance::NotYet { remaining_ms: 1 }
        );
        assert_eq!(sched.advance(1_100 + 450_000), DaoTxAdvance::Due);
    }

    #[test]
    fn retry_ladder_4_8_16_then_exhausted() {
        let mut sched = DaoTxScheduler::new();
        sched.schedule_initial(0, 0);
        sched.on_dao_failed(0);
        assert!(matches!(
            sched.phase(),
            DaoTxPhase::Retry { attempt: 0, .. }
        ));
        assert_eq!(
            sched.advance(3_999),
            DaoTxAdvance::NotYet { remaining_ms: 1 }
        );
        assert_eq!(sched.advance(4_000), DaoTxAdvance::Due);
        sched.on_dao_failed(4_000);
        assert!(matches!(
            sched.phase(),
            DaoTxPhase::Retry { attempt: 1, .. }
        ));
        assert_eq!(
            sched.advance(11_999),
            DaoTxAdvance::NotYet { remaining_ms: 1 }
        );
        assert_eq!(sched.advance(12_000), DaoTxAdvance::Due);
        sched.on_dao_failed(12_000);
        assert!(matches!(
            sched.phase(),
            DaoTxPhase::Retry { attempt: 2, .. }
        ));
        assert_eq!(
            sched.advance(27_999),
            DaoTxAdvance::NotYet { remaining_ms: 1 }
        );
        assert_eq!(sched.advance(28_000), DaoTxAdvance::Due);
        sched.on_dao_failed(28_000);
        assert_eq!(sched.phase(), &DaoTxPhase::Exhausted);
        assert_eq!(sched.advance(28_001), DaoTxAdvance::Exhausted);
    }
}
