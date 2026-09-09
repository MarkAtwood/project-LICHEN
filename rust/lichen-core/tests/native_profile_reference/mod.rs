// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Test-local reference of the REJECTED `lichen_native_sha512` address
//! profile (transcribed from the pre-migration LICHEN implementation, git
//! history before the upstream AddrForKey migration).
//!
//! The live routable-address profile is upstream Yggdrasil `AddrForKey`
//! (spec/decisions.jsonl upstream-yggdrasil-addressing). This reference is
//! NOT a conformance oracle: it exists only so the QUARANTINED legacy
//! corpora (test/vectors/legacy/*.json) stay byte-pinned as data integrity
//! pins without the live implementation deriving the rejected profile.

use sha2::{Digest, Sha512};

/// The rejected native profile: `addr = [0x02] || SHA512(pubkey)[0:7] ||
/// SHA512(pubkey)[0:8]` with the U/L bit cleared in byte 8.
pub fn native_sha512_addr(pubkey: &[u8; 32]) -> [u8; 16] {
    let hash512 = Sha512::digest(pubkey);
    let mut addr = [0u8; 16];
    addr[0] = 0x02;
    addr[1..8].copy_from_slice(&hash512[0..7]);
    addr[8..16].copy_from_slice(&native_sha512_iid(pubkey));
    addr
}

/// The SHA-512 link-local IID (`SHA512(pubkey)[0:8]`, U/L bit cleared).
pub fn native_sha512_iid(pubkey: &[u8; 32]) -> [u8; 8] {
    let hash512 = Sha512::digest(pubkey);
    let mut iid = [0u8; 8];
    iid.copy_from_slice(&hash512[0..8]);
    iid[0] &= 0b1111_1101;
    iid
}
