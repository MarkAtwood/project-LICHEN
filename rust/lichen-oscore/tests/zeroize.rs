// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Type-level and smoke tests for zeroization of owned key material.
//!
//! The zeroization itself happens inside the `oscore` crate's `Drop`
//! implementations and cannot be observed from safe Rust; these tests pin
//! the guarantees at the type level (a regression in a dependency would fail
//! compilation of these assertions, mirroring `src/zeroize_asserts.rs`) and
//! exercise the zeroizing drop code paths.
//!
//! `Context` zeroizes on drop via its `Drop` impl but does not (yet) carry
//! the `ZeroizeOnDrop` marker trait — the deprecated `#[zeroize(drop)]`
//! attribute upstream does not emit it. It is therefore pinned as `Zeroize`
//! here, matching `src/zeroize_asserts.rs`.

use aes::Aes128;
use hmac::Hmac;
use lichen_oscore::{Context, KeyUpdateContext};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

fn assert_zeroize<T: Zeroize>() {}

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

/// The EDHOC transcript hasher state must be `ZeroizeOnDrop`, pinned by the
/// `sha2/zeroize` dependency feature.
#[test]
fn sha256_implements_zeroize_on_drop() {
    assert_zeroize_on_drop::<Sha256>();
}

/// The AES-128 cipher state (round keys) used by AES-CCM-16-64-128 must be
/// `ZeroizeOnDrop`, pinned by the `aes/zeroize` dependency feature.
#[test]
fn aes128_implements_zeroize_on_drop() {
    assert_zeroize_on_drop::<Aes128>();
}

/// The HMAC-SHA-256 tag output inside HKDF-SHA-256 must be `ZeroizeOnDrop`,
/// pinned by the `hmac/zeroize` dependency feature. Upstream `hmac` 0.13
/// does not mark the `Hmac` instance type itself `ZeroizeOnDrop` (see
/// `src/zeroize_asserts.rs`); its key-derived digest cores still zeroize
/// transitively.
#[test]
fn hmac_sha256_output_implements_zeroize_on_drop() {
    assert_zeroize_on_drop::<hmac::digest::CtOutput<Hmac<Sha256>>>();
}

/// The context must expose the `Zeroize` impl (manual wipe before an
/// intentional drop, and the `Drop` impl's target).
#[test]
fn context_implements_zeroize() {
    assert_zeroize::<Context>();
}

/// Exercise the zeroize code path on a live context.
#[test]
fn context_zeroize_wipes_without_panicking() {
    let master_secret = [0x0Au8; 16];
    let mut context = Context::new(&master_secret, None, None, &[0x00], &[0x01]).expect("context");
    context.zeroize();
    drop(context);
}

/// `KeyUpdateContext` is not itself `ZeroizeOnDrop` (it permits moving the
/// context out via `into_context`), but dropping it must run the inner
/// context's zeroizing drop.
#[test]
fn key_update_context_drop_wipes_inner_context() {
    let master_secret = [0x0Bu8; 16];
    let context = Context::new(&master_secret, None, None, &[0x00], &[0x01]).expect("context");
    let slot = KeyUpdateContext::new(context, 0);
    drop(slot);
}
