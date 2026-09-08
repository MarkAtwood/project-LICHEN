// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Vector tests for the TDMA beacon acceptance gate.
//!
//! Oracles: test/vectors/ccp_beacon_format.json (beacon_wire_example,
//! independently encoded wire bytes) and ccp_beacon_sig_gate.json
//! (invalid signature MUST reject with no DODAG/TDMA state change).

use std::cell::RefCell;
use std::rc::Rc;

use lichen_core::tdma_beacon::{
    accept_beacon, cbor_options, flags, AcceptError, ParseError, TdmaBeaconHeader, HEADER_SIZE,
    MIN_BEACON_SIZE, SIG_SIZE,
};
use serde_json::Value;

const BEACON_VECTORS: &str = include_str!("../../../test/vectors/ccp_beacon_format.json");
const SIG_GATE_VECTORS: &str = include_str!("../../../test/vectors/ccp_beacon_sig_gate.json");

fn find_vector(file: &str, name: &str) -> Value {
    serde_json::from_str::<Value>(file).unwrap()["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["name"] == name)
        .unwrap_or_else(|| panic!("{name} missing from vector file"))
        .clone()
}

/// beacon_wire_example oracle fields as a typed header.
fn oracle_header() -> (TdmaBeaconHeader, Value) {
    let vector = find_vector(BEACON_VECTORS, "beacon_wire_example");
    let input = &vector["input"];
    let field = |key: &str| {
        input[key]
            .as_u64()
            .unwrap_or_else(|| panic!("{key} missing"))
    };
    let header = TdmaBeaconHeader {
        epoch: u32::try_from(field("epoch")).unwrap(),
        num_slots: u8::try_from(field("num_slots")).unwrap(),
        sfn: u32::try_from(field("sfn")).unwrap(),
        timestamp: u32::try_from(field("timestamp")).unwrap(),
        flags: u8::try_from(field("flags")).unwrap(),
        rx_chains: u8::try_from(field("rx_chains")).unwrap(),
        setup_window: u16::try_from(field("setup_window")).unwrap(),
        occupied_time: u16::try_from(field("occupied_time")).unwrap(),
        guard: u8::try_from(field("guard")).unwrap(),
        channel_mask: u32::try_from(field("channel_mask")).unwrap(),
    };
    (header, vector)
}

/// Build a full beacon from the beacon_wire_example oracle: the
/// independently encoded header + `options` bytes + a 48-byte signature
/// region whose last byte is a 0xCD canary (the vector carries no
/// signature; the region only needs to be byte-exact in captured args).
fn oracle_beacon(options: &[u8]) -> Vec<u8> {
    let (header, _) = oracle_header();
    let mut beacon = vec![0u8; HEADER_SIZE + options.len() + SIG_SIZE];
    header.serialize(&mut beacon[..HEADER_SIZE]).unwrap();
    beacon[HEADER_SIZE..HEADER_SIZE + options.len()].copy_from_slice(options);
    *beacon.last_mut().unwrap() = 0xCD;
    beacon
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Where capture_verify records the (signed_data, signature) slices.
type CapturedVerify = Rc<RefCell<Option<(Vec<u8>, Vec<u8>)>>>;

/// A verify_fn that always succeeds and records the exact
/// (signed_data, signature) slices the gate handed it.
fn capture_verify() -> (impl Fn(&[u8], &[u8]) -> bool, CapturedVerify) {
    let captured = Rc::new(RefCell::new(None));
    let sink = Rc::clone(&captured);
    let verify = move |signed: &[u8], sig: &[u8]| {
        *sink.borrow_mut() = Some((signed.to_vec(), sig.to_vec()));
        true
    };
    (verify, captured)
}

/// beacon_wire_example: serialize must reproduce the independently
/// encoded header_hex byte-for-byte, and the wire bytes must parse back
/// to the oracle input fields through the full acceptance gate.
#[test]
fn canonical_wire_example_roundtrips_through_accept() {
    let (header, vector) = oracle_header();

    // Serialize direction: our encoder matches the independent oracle.
    let beacon = oracle_beacon(&[]);
    assert_eq!(
        hex_encode(&beacon[..HEADER_SIZE]),
        vector["output"]["header_hex"].as_str().unwrap(),
        "serialized header diverges from oracle"
    );

    // Parse direction: the oracle bytes decode to the oracle fields.
    let (verify, captured) = capture_verify();
    let accepted = accept_beacon(&beacon, verify, 0xFF).expect("canonical beacon must be accepted");
    assert_eq!(
        accepted.header, header,
        "parsed header diverges from oracle input fields"
    );
    // EU868 plan (0xFF) intersected with the advertised mask.
    assert_eq!(accepted.usable_channels, 0xFF & header.channel_mask);

    // The gate handed the verifier the exact trailing 48 bytes as the
    // signature and everything before them as signed data.
    let (signed, sig) = captured
        .borrow()
        .clone()
        .expect("verify_fn must have been invoked");
    assert_eq!(signed, &beacon[..beacon.len() - SIG_SIZE]);
    assert_eq!(sig, &beacon[beacon.len() - SIG_SIZE..]);
    assert_eq!(sig[sig.len() - 1], 0xCD, "signature region lost its canary");
}

/// Signature slice split with CBOR options present: signed_data spans
/// header + options, the signature stays the trailing 48 bytes, and
/// cbor_options extracts exactly the middle (>MIN_BEACON_SIZE boundary).
#[test]
fn cbor_options_tail_is_signed_and_extractable() {
    let (header, _) = oracle_header();
    // One-byte CBOR options blob: empty array (0x80).
    let beacon = oracle_beacon(&[0x80]);
    assert!(beacon.len() > MIN_BEACON_SIZE);

    let (verify, captured) = capture_verify();
    let accepted =
        accept_beacon(&beacon, verify, 0xFF).expect("beacon with options must be accepted");
    assert_eq!(accepted.header, header);

    let (signed, sig) = captured
        .borrow()
        .clone()
        .expect("verify_fn must have been invoked");
    assert_eq!(signed, &beacon[..beacon.len() - SIG_SIZE]);
    assert_eq!(
        &signed[HEADER_SIZE..],
        &[0x80],
        "options bytes missing from signed data"
    );
    assert_eq!(sig, &beacon[beacon.len() - SIG_SIZE..]);
    assert_eq!(cbor_options(&beacon), Some(&[0x80][..]));
    // A minimal beacon has no options region.
    assert_eq!(cbor_options(&oracle_beacon(&[])), None);
}

/// ccp_beacon_sig_gate.json sig_gate_invalid_rejects_before_dio: an
/// invalid signature MUST reject before any state is produced.
#[test]
fn invalid_signature_rejects_fail_closed() {
    let vector = find_vector(SIG_GATE_VECTORS, "sig_gate_invalid_rejects_before_dio");
    assert_eq!(vector["expected"]["frame_accepted"], false);
    let beacon = oracle_beacon(&[]);
    let result = accept_beacon(&beacon, |_, _| false, 0xFF);
    assert_eq!(result, Err(AcceptError::BadSignature));
}

/// R-02a-006: empty local intersection MUST reject the beacon.
#[test]
fn empty_channel_intersection_rejects() {
    let (header, _) = oracle_header();
    // Permitted mask without CH0; sanity-check the oracle mask is
    // actually disjoint from it or this test proves nothing.
    let permitted = 0xFF00;
    assert_eq!(permitted & header.channel_mask, 0);
    let beacon = oracle_beacon(&[]);
    let result = accept_beacon(&beacon, |_, _| true, permitted);
    assert_eq!(result, Err(AcceptError::NoCommonChannel));
}

/// Shorter than header + signature fails closed at the parse gate.
#[test]
fn too_short_beacon_rejects() {
    let short = vec![0u8; MIN_BEACON_SIZE - 1];
    let result = accept_beacon(&short, |_, _| true, 0xFF);
    assert_eq!(result, Err(AcceptError::Parse(ParseError::TooShort)));
}

/// Reserved flag bits (4-7) fail closed at the parse gate.
#[test]
fn reserved_flag_beacon_rejects() {
    let mut beacon = oracle_beacon(&[]);
    beacon[13] = flags::RESERVED_MASK; // all reserved bits set
    let result = accept_beacon(&beacon, |_, _| true, 0xFF);
    assert_eq!(result, Err(AcceptError::Parse(ParseError::ReservedFlagSet)));
}

/// beacon_header_num_slots_zero_rejected: num_slots=0 (structurally
/// meaningless slot modulus, spec 02a 2a.2 default 8) fails closed at the
/// parse gate in every runtime.
#[test]
fn num_slots_zero_beacon_rejects() {
    #[allow(clippy::manual_is_multiple_of)]
    fn decode_hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd-length hex: {s}");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }
    let vector = find_vector(BEACON_VECTORS, "beacon_header_num_slots_zero_rejected");
    let header_hex = vector["input"]["header_hex"].as_str().unwrap();
    let mut beacon = oracle_beacon(&[]);
    beacon[..HEADER_SIZE].copy_from_slice(&decode_hex(header_hex));
    let result = accept_beacon(&beacon, |_, _| true, 0xFF);
    assert_eq!(result, Err(AcceptError::Parse(ParseError::NumSlotsZero)));
}

/// Replay-deferral contract (AcceptedBeacon doc): the gate proves format
/// and signature only. A stale-but-validly-signed beacon (epoch, SFN and
/// timestamp all zero) MUST still be accepted; freshness (epoch-floor /
/// SFN monotonicity) is the caller's obligation. A future change folding
/// freshness into the gate fails this test and must re-adjudicate the
/// documented contract first.
#[test]
fn stale_but_validly_signed_beacon_is_accepted() {
    let mut beacon = oracle_beacon(&[]);
    beacon[0..4].copy_from_slice(&0u32.to_be_bytes()); // epoch
    beacon[5..9].copy_from_slice(&0u32.to_be_bytes()); // sfn
    beacon[9..13].copy_from_slice(&0u32.to_be_bytes()); // timestamp
    let accepted = accept_beacon(&beacon, |_, _| true, 0xFF)
        .expect("stale-but-validly-signed beacon must pass the gate");
    assert_eq!(accepted.header.epoch, 0);
    assert_eq!(accepted.header.sfn, 0);
    assert_eq!(accepted.header.timestamp, 0);
}
