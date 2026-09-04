// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! DTN store-and-forward IPv6 hop-by-hop option (spec/05-routing.md 9.8).
//!
//! Option Type=0x03, Length=5: one flags byte (S=0x80, reserved bits MUST be
//! ignored on receive) followed by the absolute expiry as a 4-byte big-endian
//! Unix timestamp. Clockless nodes MUST NOT drop messages based on expiry
//! alone (spec/05-routing.md 9.8 clockless rule;
//! docs/firmware-time-provider.md).
//!
//! Vectors: test/vectors/dtn_sflag_hbh.json (spec-derived independent
//! oracle). Mirrors python/src/lichen/routing/dtn_option.py byte for byte.

/// S flag: store-and-forward requested (spec 9.8).
pub const DTN_FLAG_S: u8 = 0x80;
/// Option length for the DTN option body (flags + 4-byte expiry).
const DTN_OPTION_LEN: usize = 5;
const OPT_PAD1: u8 = 0x00;
const OPT_PADN: u8 = 0x01;
const OPT_DTN: u8 = 0x03;

/// One parsed DTN intent option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtnOption {
    pub s_flag: bool,
    pub expiry_unix: u64,
}

/// Expiry decision per spec/05-routing.md 9.8 clockless rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryAction {
    /// Wall clock valid and the message has expired.
    DropSilently,
    /// Clockless node (MUST NOT drop on expiry alone) or not yet expired.
    StoreOrForward,
}

impl ExpiryAction {
    pub fn as_str(self) -> &'static str {
        match self {
            ExpiryAction::DropSilently => "drop_silently",
            ExpiryAction::StoreOrForward => "store_or_forward",
        }
    }
}

/// Extract the DTN intent from Hop-by-Hop option data.
///
/// Returns `None` when the DTN option is absent, duplicated, malformed
/// (wrong length), or carries a zero expiry — the caller cannot distinguish
/// "no DTN intent" from "malformed", and both mean "no store-and-forward
/// for this packet".
pub fn parse_dtn_option(hbh_data: &[u8]) -> Option<DtnOption> {
    let mut found: Option<DtnOption> = None;
    let mut pos = 0;
    while pos < hbh_data.len() {
        let opt_type = hbh_data[pos];
        if opt_type == OPT_PAD1 {
            pos += 1;
            continue;
        }
        if pos + 2 > hbh_data.len() {
            return None;
        }
        let opt_len = hbh_data[pos + 1] as usize;
        let end = pos + 2 + opt_len;
        if end > hbh_data.len() {
            return None;
        }
        if opt_type == OPT_DTN {
            if found.is_some() || opt_len != DTN_OPTION_LEN {
                return None;
            }
            let flags = hbh_data[pos + 2];
            // expiry==0 is the C fail-open "no validated deadline" sentinel
            // (routing/dtn.h) and never a valid wire expiry; rejecting it
            // keeps Rust parity with the C parser.
            let expiry = u64::from(u32::from_be_bytes([
                hbh_data[pos + 3],
                hbh_data[pos + 4],
                hbh_data[pos + 5],
                hbh_data[pos + 6],
            ]));
            if expiry == 0 {
                return None;
            }
            found = Some(DtnOption {
                s_flag: flags & DTN_FLAG_S != 0,
                expiry_unix: expiry,
            });
        }
        pos = end;
    }
    found
}

/// Expiry decision per the spec 9.8 clockless rule: a node without a valid
/// wall clock MUST NOT drop messages based on expiry alone.
pub fn decide_expiry_action(
    expiry_unix: u64,
    now_unix: u64,
    wall_clock_valid: bool,
) -> ExpiryAction {
    if wall_clock_valid && expiry_unix < now_unix {
        ExpiryAction::DropSilently
    } else {
        ExpiryAction::StoreOrForward
    }
}
