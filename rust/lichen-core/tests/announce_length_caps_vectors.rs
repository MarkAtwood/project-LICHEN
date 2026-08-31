// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Announce length-cap vectors (spec 05-routing 9.2, R-05-068).

use lichen_core::announce::{Announce, AnnounceError};
use serde::Deserialize;

const VECTORS: &str = include_str!("../../../test/vectors/announce_length_caps.json");

#[derive(Debug, Deserialize)]
struct VectorFile {
    vectors: LengthCaps,
}

#[derive(Debug, Deserialize)]
struct LengthCaps {
    length_caps: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    wire: String,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Expected {
    action: String,
    #[serde(default)]
    app_data_len: Option<usize>,
    #[serde(default)]
    reason: Option<String>,
}

#[test]
fn announce_length_caps_vectors() {
    let doc: VectorFile = serde_json::from_str(VECTORS).expect("valid vector document");
    assert!(!doc.vectors.length_caps.is_empty());
    for vector in &doc.vectors.length_caps {
        let wire: Vec<u8> = (0..vector.wire.len() / 2)
            .map(|i| u8::from_str_radix(&vector.wire[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        match Announce::from_bytes(&wire) {
            Ok(announce) => {
                assert_eq!(
                    vector.expected.action, "accept",
                    "{}: expected reject",
                    vector.name
                );
                assert_eq!(
                    announce.app_data.len(),
                    vector
                        .expected
                        .app_data_len
                        .expect("accept case carries app_data_len"),
                    "{}: app_data_len drift",
                    vector.name
                );
            }
            Err(e) => {
                assert_eq!(
                    vector.expected.action, "reject",
                    "{}: expected accept",
                    vector.name
                );
                assert_eq!(vector.expected.reason.as_deref(), Some("too_long"));
                assert!(
                    matches!(e, AnnounceError::TooLong(_)),
                    "{}: expected TooLong, got {e}",
                    vector.name
                );
            }
        }
    }
}
