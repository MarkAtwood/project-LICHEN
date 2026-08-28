//! DIO Time Option (provisional type 0x15) — time-source stratum + timestamp.
//!
//! Byte-exact with the Python reference `DioTimeOption` in
//! python/src/lichen/timing/time_sync.py and the `dio_time_option` vector in
//! test/vectors/packets-timing.json. The option is 8 bytes total:
//!
//! ```text
//!  0        1        2         3         4..8
//! +--------+--------+---------+---------+--------------------+
//! |  0x15  | len=6  | stratum | res = 0 | timestamp (BE u32) |
//! +--------+--------+---------+---------+--------------------+
//! ```
//!
//! The type is project-local and not IANA-assigned. `Stratum` covers values
//! 0-4 only; the 255 "unset" sentinel used by `multi_instance::TimeProvider`
//! is not representable in this option.

#![forbid(unsafe_code)]

use crate::message::RplError;
use lichen_core::error::BufferTooSmall;

/// Provisional DIO Time Option type byte (not IANA-assigned).
pub const OPT_DIO_TIME: u8 = 0x15;
/// Option payload length: stratum(1) + reserved(1) + timestamp(4).
pub const DIO_TIME_OPTION_DATA_LEN: usize = 6;
/// Total option length on the wire: type(1) + length(1) + payload(6).
pub const DIO_TIME_OPTION_LEN: usize = 8;

// ── Stratum ───────────────────────────────────────────────────────────────────

/// Time-source stratum carried in the DIO Time Option.
///
/// Mirrors `Stratum` in the Python reference (lower value = less authoritative
/// time source). `NoSync` must always carry a zero timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Stratum {
    NoSync = 0,
    MeshDerived = 1,
    Roughtime = 2,
    Nts = 3,
    GnssGpsd = 4,
}

impl Stratum {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::NoSync),
            1 => Some(Self::MeshDerived),
            2 => Some(Self::Roughtime),
            3 => Some(Self::Nts),
            4 => Some(Self::GnssGpsd),
            _ => None,
        }
    }
}

impl From<Stratum> for u8 {
    fn from(stratum: Stratum) -> Self {
        stratum as u8
    }
}

// ── DIO Time Option ───────────────────────────────────────────────────────────

/// Advertises the DODAG root's time-source stratum and a wall-clock timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DioTimeOption {
    pub stratum: Stratum,
    pub timestamp: u32,
}

impl DioTimeOption {
    /// Construct, enforcing the Python-reference invariant that
    /// `Stratum::NoSync` carries a zero timestamp.
    pub fn new(stratum: Stratum, timestamp: u32) -> Result<Self, RplError> {
        if stratum == Stratum::NoSync && timestamp != 0 {
            return Err(RplError::InvalidOption);
        }
        Ok(Self { stratum, timestamp })
    }

    /// Parse the full 8-byte option (type, length, payload). Byte-exact with
    /// the Python `DioTimeOption.decode`: rejects any length other than 8, a
    /// type/length byte other than 0x15/6, a non-zero reserved byte, an
    /// unknown stratum, and `NoSync` with a non-zero timestamp.
    pub fn from_bytes(data: &[u8]) -> Result<Self, RplError> {
        if data.len() != DIO_TIME_OPTION_LEN {
            return Err(RplError::InvalidOption);
        }
        if data[0] != OPT_DIO_TIME || data[1] != DIO_TIME_OPTION_DATA_LEN as u8 {
            return Err(RplError::InvalidOption);
        }
        if data[3] != 0 {
            return Err(RplError::InvalidOption); // reserved must be zero
        }
        let stratum = Stratum::from_u8(data[2]).ok_or(RplError::InvalidOption)?;
        let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        Self::new(stratum, timestamp)
    }

    /// Parse the 6-byte payload only (stratum, reserved, timestamp), e.g.
    /// from [`crate::message::OptionIter`] where the type/length bytes have
    /// already been consumed by the iterator.
    pub fn from_option_data(data: &[u8]) -> Result<Self, RplError> {
        if data.len() != DIO_TIME_OPTION_DATA_LEN {
            return Err(RplError::InvalidOption);
        }
        if data[1] != 0 {
            return Err(RplError::InvalidOption); // reserved must be zero
        }
        let stratum = Stratum::from_u8(data[0]).ok_or(RplError::InvalidOption)?;
        let timestamp = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        Self::new(stratum, timestamp)
    }

    /// Serialize the full 8-byte option. Rejects `NoSync` with a non-zero
    /// timestamp (the Python reference cannot construct such a value).
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, RplError> {
        if self.stratum == Stratum::NoSync && self.timestamp != 0 {
            return Err(RplError::InvalidOption);
        }
        let required = DIO_TIME_OPTION_LEN;
        if out.len() < required {
            return Err(BufferTooSmall::new(required, out.len()).into());
        }
        out[0] = OPT_DIO_TIME;
        out[1] = DIO_TIME_OPTION_DATA_LEN as u8;
        out[2] = self.stratum as u8;
        out[3] = 0; // reserved
        out[4..required].copy_from_slice(&self.timestamp.to_be_bytes());
        Ok(required)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::OptionIter;

    /// Byte strings computed from the Python oracle
    /// (python/src/lichen/timing/time_sync.py::DioTimeOption.encode) via
    /// python3 — NOT derived from this Rust implementation.
    const ORACLE: &[(Stratum, u32, &str)] = &[
        (Stratum::NoSync, 0, "1506000000000000"),
        (Stratum::MeshDerived, 1735689600, "1506010067748580"),
        (Stratum::Roughtime, 1735689600, "1506020067748580"),
        (Stratum::Nts, 1700000000, "150603006553f100"),
        (Stratum::GnssGpsd, 1700000000, "150604006553f100"),
        (Stratum::Roughtime, u32::MAX, "15060200ffffffff"),
        (Stratum::GnssGpsd, 0, "1506040000000000"),
    ];

    fn decode_hex(value: &str) -> std::vec::Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    fn encode(option: &DioTimeOption) -> std::vec::Vec<u8> {
        let mut buf = [0u8; DIO_TIME_OPTION_LEN];
        let written = option.write_to(&mut buf).unwrap();
        assert_eq!(written, DIO_TIME_OPTION_LEN);
        buf.to_vec()
    }

    fn wire_from_hex(value: &str) -> [u8; DIO_TIME_OPTION_LEN] {
        let mut wire = [0u8; DIO_TIME_OPTION_LEN];
        wire.copy_from_slice(&decode_hex(value));
        wire
    }

    // ── Round-trip across every stratum ───────────────────────────────────────

    #[test]
    fn roundtrip_all_strata() {
        for stratum in [
            Stratum::NoSync,
            Stratum::MeshDerived,
            Stratum::Roughtime,
            Stratum::Nts,
            Stratum::GnssGpsd,
        ] {
            let timestamp = if stratum == Stratum::NoSync {
                0
            } else {
                1735689600
            };
            let option = DioTimeOption::new(stratum, timestamp).unwrap();
            let wire = encode(&option);
            assert_eq!(wire[0], OPT_DIO_TIME);
            assert_eq!(wire[1], DIO_TIME_OPTION_DATA_LEN as u8);
            assert_eq!(wire[2], stratum as u8);
            assert_eq!(wire[3], 0); // reserved
            assert_eq!(DioTimeOption::from_bytes(&wire).unwrap(), option);
        }
    }

    #[test]
    fn timestamp_boundaries_roundtrip() {
        for stratum in [
            Stratum::MeshDerived,
            Stratum::Roughtime,
            Stratum::Nts,
            Stratum::GnssGpsd,
        ] {
            for timestamp in [0, u32::MAX] {
                let option = DioTimeOption::new(stratum, timestamp).unwrap();
                let wire = encode(&option);
                assert_eq!(DioTimeOption::from_bytes(&wire).unwrap(), option);
            }
        }
        // NoSync is only valid with timestamp 0.
        let no_sync = DioTimeOption::new(Stratum::NoSync, 0).unwrap();
        let wire = encode(&no_sync);
        assert_eq!(DioTimeOption::from_bytes(&wire).unwrap(), no_sync);
    }

    // ── Cross-check against hardcoded Python-oracle encodings ─────────────────

    #[test]
    fn encode_matches_python_oracle_bytes() {
        for (stratum, timestamp, hex) in ORACLE {
            let option = DioTimeOption::new(*stratum, *timestamp).unwrap();
            assert_eq!(encode(&option), decode_hex(hex), "{}", hex);
        }
    }

    #[test]
    fn decode_matches_python_oracle_bytes() {
        for (stratum, timestamp, hex) in ORACLE {
            let decoded = DioTimeOption::from_bytes(&decode_hex(hex)).unwrap();
            assert_eq!(decoded, DioTimeOption::new(*stratum, *timestamp).unwrap());
            assert_eq!(decoded.stratum, *stratum);
            assert_eq!(decoded.timestamp, *timestamp);
        }
    }

    #[test]
    fn consumes_packets_timing_json_dio_time_option_vector() {
        let document: serde_json::Value =
            serde_json::from_str(include_str!("../../../test/vectors/packets-timing.json"))
                .unwrap();
        let vectors = document["vectors"].as_array().unwrap();
        let vector = vectors
            .iter()
            .find(|vector| vector["name"] == "dio_time_option")
            .expect("dio_time_option vector must exist");
        assert_eq!(vector["option_type"].as_u64().unwrap(), 21); // 0x15
        assert_eq!(vector["encoded_hex"].as_str().unwrap(), "150603006553f100");
        let decoded =
            DioTimeOption::from_bytes(&decode_hex(vector["encoded_hex"].as_str().unwrap()))
                .unwrap();
        assert_eq!(decoded.stratum, Stratum::Nts);
        assert_eq!(
            decoded.timestamp,
            vector["decoded_timestamp"].as_u64().unwrap() as u32
        );
        let no_sync = DioTimeOption::new(Stratum::NoSync, 0).unwrap();
        assert_eq!(
            encode(&no_sync),
            decode_hex(vector["no_sync_encoded_hex"].as_str().unwrap())
        );
    }

    // ── Rejection cases (oracle raises ValueError for all of these) ──────────

    #[test]
    fn rejects_wrong_type_or_length_byte() {
        let mut wire = wire_from_hex("150603006553f100");
        wire[0] = 0x14;
        assert_eq!(
            DioTimeOption::from_bytes(&wire),
            Err(RplError::InvalidOption)
        );
        let mut short_len = wire_from_hex("150603006553f100");
        short_len[1] = 5;
        assert_eq!(
            DioTimeOption::from_bytes(&short_len),
            Err(RplError::InvalidOption)
        );
        let mut long_len = short_len;
        long_len[1] = 7;
        assert_eq!(
            DioTimeOption::from_bytes(&long_len),
            Err(RplError::InvalidOption)
        );
    }

    #[test]
    fn rejects_nonzero_reserved() {
        let mut wire = [0u8; DIO_TIME_OPTION_LEN];
        DioTimeOption::new(Stratum::Nts, 1700000000)
            .unwrap()
            .write_to(&mut wire)
            .unwrap();
        wire[3] = 1;
        assert_eq!(
            DioTimeOption::from_bytes(&wire),
            Err(RplError::InvalidOption)
        );
    }

    #[test]
    fn rejects_invalid_stratum() {
        for bad_stratum in [5u8, 255] {
            let mut wire = [0u8; DIO_TIME_OPTION_LEN];
            DioTimeOption::new(Stratum::Nts, 1700000000)
                .unwrap()
                .write_to(&mut wire)
                .unwrap();
            wire[2] = bad_stratum;
            assert_eq!(
                DioTimeOption::from_bytes(&wire),
                Err(RplError::InvalidOption)
            );
        }
        assert!(Stratum::from_u8(5).is_none());
        assert!(Stratum::from_u8(255).is_none());
    }

    #[test]
    fn rejects_wrong_total_length() {
        let full = decode_hex("150603006553f100");
        for length in 0..DIO_TIME_OPTION_LEN {
            assert_eq!(
                DioTimeOption::from_bytes(&full.as_slice()[..length]),
                Err(RplError::InvalidOption)
            );
        }
        let mut long = [0u8; 9];
        long[..8].copy_from_slice(full.as_slice());
        assert_eq!(
            DioTimeOption::from_bytes(&long),
            Err(RplError::InvalidOption)
        );
    }

    #[test]
    fn rejects_no_sync_with_nonzero_timestamp() {
        // Constructor (mirrors Python __post_init__).
        assert_eq!(
            DioTimeOption::new(Stratum::NoSync, 1),
            Err(RplError::InvalidOption)
        );
        // write_to on a directly-constructed struct (mirrors "cannot encode").
        let invalid = DioTimeOption {
            stratum: Stratum::NoSync,
            timestamp: 1,
        };
        let mut buf = [0u8; DIO_TIME_OPTION_LEN];
        assert_eq!(invalid.write_to(&mut buf), Err(RplError::InvalidOption));
        // Decode of hand-built wire bytes (Python decode → __post_init__ error).
        let wire = wire_from_hex("1506000000000001");
        assert_eq!(
            DioTimeOption::from_bytes(&wire),
            Err(RplError::InvalidOption)
        );
    }

    #[test]
    fn write_to_requires_capacity() {
        let option = DioTimeOption::new(Stratum::Roughtime, 1735689600).unwrap();
        let mut short = [0u8; DIO_TIME_OPTION_LEN - 1];
        assert_eq!(
            option.write_to(&mut short),
            Err(RplError::BufferTooSmall(BufferTooSmall::new(
                DIO_TIME_OPTION_LEN,
                DIO_TIME_OPTION_LEN - 1
            )))
        );
        let mut exact = [0u8; DIO_TIME_OPTION_LEN];
        assert_eq!(option.write_to(&mut exact).unwrap(), DIO_TIME_OPTION_LEN);
    }

    // ── Option-iter integration (payload-only entry point) ───────────────────

    #[test]
    fn from_option_data_roundtrip_and_rejections() {
        let payload = decode_hex("020067748580"); // Roughtime, 1735689600
        let decoded = DioTimeOption::from_option_data(&payload).unwrap();
        assert_eq!(
            decoded,
            DioTimeOption::new(Stratum::Roughtime, 1735689600).unwrap()
        );
        assert_eq!(decoded.stratum, Stratum::Roughtime);
        assert_eq!(decoded.timestamp, 1735689600);

        assert_eq!(
            DioTimeOption::from_option_data(&payload[..5]),
            Err(RplError::InvalidOption)
        );
        let mut reserved = [0u8; DIO_TIME_OPTION_DATA_LEN];
        reserved.copy_from_slice(&payload);
        reserved[1] = 1;
        assert_eq!(
            DioTimeOption::from_option_data(&reserved),
            Err(RplError::InvalidOption)
        );
    }

    #[test]
    fn option_iter_finds_dio_time_option_in_dio_tail() {
        let mut tail = std::vec::Vec::new();
        tail.push(crate::message::OPT_PAD1);
        let mut buf = [0u8; DIO_TIME_OPTION_LEN];
        DioTimeOption::new(Stratum::GnssGpsd, 1700000000)
            .unwrap()
            .write_to(&mut buf)
            .unwrap();
        tail.extend_from_slice(&buf);

        let mut iter = OptionIter::new(&tail);
        let raw = iter.next().unwrap().unwrap();
        assert_eq!(raw.opt_type, OPT_DIO_TIME);
        assert_eq!(
            DioTimeOption::from_option_data(raw.data).unwrap(),
            DioTimeOption::new(Stratum::GnssGpsd, 1700000000).unwrap()
        );
        assert!(iter.next().is_none());
    }
}
