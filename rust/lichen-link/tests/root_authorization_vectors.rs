//! Tests against shared test vectors from test/vectors/root_authorization.json
#![cfg(feature = "schnorr")]

use std::{fs, path::Path};

use lichen_link::{keys::PublicKey, schnorr};
use serde::Deserialize;

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<RootAuthorizationVector>,
}

#[derive(Deserialize)]
struct RootAuthorizationVector {
    name: String,
    pubkey_hex: String,
    message_hex: String,
    signature_hex: String,
    dodagid_hex: String,
    expected_valid: bool,
}

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn root_authorization_vectors_bind_signer_key_to_dodagid() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/root_authorization.json");
    let vectors: VectorFile = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    for vector in vectors.vectors {
        let pubkey = hex(&vector.pubkey_hex);
        let message = hex(&vector.message_hex);
        let signature = hex(&vector.signature_hex);
        // The corpus's dodagid_hex still encodes the rejected SHA-512 native
        // profile (i72x.6 regenerates the shared corpus once Python migrates).
        // Translate the known native DODAGIDs to their upstream AddrForKey
        // equivalents, pinned from the yggdrasil-go@422836ee reference
        // implementation (external oracle, i72x.2).
        let dodag_id = hex(&vector.dodagid_hex);
        let dodag_id = match vector.dodagid_hex.as_str() {
            // 03a107bf..5531b8
            "02ed4242ead4ac69ed4242ead4ac6948" => hex("02062f7c200618f7a0f14791738c5a1f"),
            // 248acbdb..d53dd930
            "0211e78d239a106f11e78d239a106fdb" => hex("0202dba9a122830fd7f3490c7da0ae94"),
            _ => dodag_id,
        };
        let actual = match (
            <[u8; 32]>::try_from(pubkey.as_slice()),
            <[u8; 48]>::try_from(signature.as_slice()),
            <[u8; 16]>::try_from(dodag_id.as_slice()),
        ) {
            (Ok(pubkey), Ok(signature), Ok(dodag_id)) => {
                let key = PublicKey::new(pubkey);
                lichen_link::ygg_addr_from_pubkey(&pubkey) == dodag_id
                    && schnorr::verify(&key, &message, &signature)
            }
            _ => false,
        };
        assert_eq!(actual, vector.expected_valid, "{}", vector.name);
    }
}
