// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Slot-claim rate limiter tests (spec 08 GCP-6.5: 10/min/peer, 60/min
//! global, exceeding claims silently dropped — bead l1qw.22).

use lichen_gateway::slot::SlotClaimRateLimiter;

#[test]
fn per_peer_limit_enforced() {
    let mut limiter = SlotClaimRateLimiter::new();
    let iid = [0x11u8; 8];
    for i in 0..10u64 {
        assert!(
            limiter.allow(iid, i * 1000),
            "claim {i} within per-peer limit must be allowed"
        );
    }
    // 11th claim inside the same minute window: silently dropped.
    assert!(!limiter.allow(iid, 10_000));
}

#[test]
fn per_peer_limit_resets_after_window() {
    let mut limiter = SlotClaimRateLimiter::new();
    let iid = [0x22u8; 8];
    for i in 0..10u64 {
        assert!(limiter.allow(iid, i * 1000));
    }
    assert!(!limiter.allow(iid, 10_000));
    // 61s later: the window has slid, the peer may claim again.
    assert!(limiter.allow(iid, 61_000));
}

#[test]
fn global_limit_enforced_across_peers() {
    let mut limiter = SlotClaimRateLimiter::new();
    // 60 claims from 10 distinct peers (6 each, under the per-peer cap).
    for peer in 0..10u8 {
        let iid = [peer; 8];
        for _ in 0..6u64 {
            assert!(limiter.allow(iid, 0));
        }
    }
    // Global cap reached: a new claim from any peer is dropped.
    assert!(!limiter.allow([0xEE; 8], 1000));
}

#[test]
fn distinct_peers_do_not_share_per_peer_window() {
    let mut limiter = SlotClaimRateLimiter::new();
    let a = [0x01u8; 8];
    let b = [0x02u8; 8];
    assert!(limiter.allow(a, 0));
    assert!(limiter.allow(b, 0));
}
