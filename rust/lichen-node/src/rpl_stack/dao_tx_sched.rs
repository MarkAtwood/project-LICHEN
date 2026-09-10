// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! DAO TX scheduler state (spec 09 14.2, R-09-017..019).
//!
//! Tracks when the leaf must send its DAO: an initial DAO 0-2 s after
//! DODAG join, retries on the 4/8/16 s exponential ladder, and periodic
//! refresh at half the soft-state lifetime. All timing constants come from
//! [`lichen_rpl::dao_timing`] — the single oracle; nothing is duplicated
//! here. The owner runtime consumes [`DaoTxScheduler::advance`].

use lichen_rpl::dao_timing::{
    dao_initial_delay_ms, dao_retry_delay_ms, dao_retry_exhausted, DAO_REFRESH_INTERVAL_SECONDS,
};

/// Refresh interval in ms (half the 30-min soft-state lifetime).
const DAO_REFRESH_INTERVAL_MS: u64 = DAO_REFRESH_INTERVAL_SECONDS * 1000;
/// Wall-clock-independent refresh floor, aliasing the DAO refresh interval.
const _DAO_REFRESH_FLOOR_MS: u64 = DAO_REFRESH_INTERVAL_MS;

/// DAO TX scheduler phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaoTxPhase {
    /// Not joined (or no DAO pending).
    Idle,
    /// Initial DAO due at `deadline_ms` (join time + 0-2 s).
    Initial { deadline_ms: u64 },
    /// Retry `attempt` (zero-based) due at `deadline_ms`.
    Retry { attempt: u8, deadline_ms: u64 },
    /// Periodic refresh due at `deadline_ms`.
    Refresh { deadline_ms: u64 },
    /// Clock exhausted: no future transmission deadline is representable.
    Exhausted,
}

/// Outcome of one scheduler advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaoTxAdvance {
    /// A DAO transmission is due now.
    Due,
    /// Not yet due; `remaining_ms` until the deadline.
    NotYet { remaining_ms: u64 },
    /// Clock exhausted — the TX path stops retrying.
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
    pub(crate) fn on_dao_sent(&mut self, now_ms: u64) {
        self.phase = match now_ms.checked_add(DAO_REFRESH_INTERVAL_MS) {
            Some(deadline_ms) => DaoTxPhase::Refresh { deadline_ms },
            None => DaoTxPhase::Exhausted,
        };
    }

    /// Record a failed/lost DAO transmission: advance the retry ladder
    /// (4/8/16 s). After the final rung, wait for the next periodic refresh
    /// instead of retrying immediately or disabling refresh while joined.
    pub(crate) fn on_dao_failed(&mut self, now_ms: u64) {
        // 0-indexed against DAO_RETRY_DELAYS_MS: the first retry (after
        // the initial DAO) uses delays[0] = 4 s.
        let attempt = match self.phase {
            DaoTxPhase::Retry { attempt, .. } => attempt + 1,
            _ => 0,
        };
        if dao_retry_exhausted(attempt) {
            self.phase = match now_ms.checked_add(DAO_REFRESH_INTERVAL_MS) {
                Some(deadline_ms) => DaoTxPhase::Refresh { deadline_ms },
                None => DaoTxPhase::Exhausted,
            };
            return;
        }
        match dao_retry_delay_ms(attempt).and_then(|delay| now_ms.checked_add(delay)) {
            Some(deadline_ms) => {
                self.phase = DaoTxPhase::Retry {
                    attempt,
                    deadline_ms,
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
        assert!((5_000..=7_000).contains(&deadline));
    }

    #[test]
    fn initial_due_then_refresh_on_success() {
        let mut sched = DaoTxScheduler::new();
        sched.schedule_initial(1_000, 0);
        assert_eq!(sched.advance(1_000), DaoTxAdvance::Due);
        sched.on_dao_sent(1_100);
        assert!(matches!(sched.phase(), DaoTxPhase::Refresh { .. }));
        // refresh interval is the 900 s half-life itself (not halved again)
        assert_eq!(
            sched.advance(1_100 + 899_999),
            DaoTxAdvance::NotYet { remaining_ms: 1 }
        );
        assert_eq!(sched.advance(1_100 + 900_000), DaoTxAdvance::Due);
    }

    #[test]
    fn retry_ladder_4_8_16_then_periodic_refresh() {
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
        assert_eq!(
            sched.phase(),
            &DaoTxPhase::Refresh {
                deadline_ms: 928_000
            }
        );
        assert_eq!(
            sched.advance(28_001),
            DaoTxAdvance::NotYet {
                remaining_ms: 899_999
            }
        );
        assert_eq!(
            sched.advance(927_999),
            DaoTxAdvance::NotYet { remaining_ms: 1 }
        );
        assert_eq!(sched.advance(928_000), DaoTxAdvance::Due);
        // A failed periodic attempt starts a new bounded burst at the 4s rung.
        sched.on_dao_failed(928_000);
        assert_eq!(
            sched.phase(),
            &DaoTxPhase::Retry {
                attempt: 0,
                deadline_ms: 932_000
            }
        );
    }

    #[test]
    fn exhausted_burst_with_unrepresentable_refresh_deadline_stays_exhausted() {
        let mut sched = DaoTxScheduler::new();
        sched.schedule_initial(0, 0);
        for now in [0, 4_000, 12_000, u64::MAX - 899_999] {
            assert_eq!(sched.advance(now), DaoTxAdvance::Due);
            sched.on_dao_failed(now);
        }
        assert_eq!(sched.advance(u64::MAX), DaoTxAdvance::Exhausted);
    }

    #[test]
    fn unrepresentable_retry_deadline_exhausts_without_saturating() {
        let mut sched = DaoTxScheduler::new();
        sched.schedule_initial(0, 0);
        sched.on_dao_failed(u64::MAX - 4_000);
        assert_eq!(
            sched.advance(u64::MAX - 1),
            DaoTxAdvance::NotYet { remaining_ms: 1 }
        );
        assert_eq!(sched.advance(u64::MAX), DaoTxAdvance::Due);
        sched.on_dao_failed(u64::MAX);
        assert_eq!(sched.advance(u64::MAX), DaoTxAdvance::Exhausted);
    }
}
