//! Vector tests for the TDMA beacon acceptance gate.
//!
//! Oracles: test/vectors/ccp_beacon_format.json (beacon_wire_example,
//! independently encoded wire bytes) and ccp_beacon_sig_gate.json
//! (invalid signature MUST reject with no DODAG/TDMA state change).

use lichen_core::tdma_beacon::{
    accept_beacon, flags, AcceptError, ParseError, TdmaBeaconHeader, HEADER_SIZE, MIN_BEACON_SIZE,
    SIG_SIZE,
};

/// Build a full beacon (header + 48-byte signature) from the
/// beacon_wire_example oracle input fields.
fn oracle_beacon(sig_byte: u8) -> Vec<u8> {
    let hdr = TdmaBeaconHeader {
        epoch: 1,
        num_slots: 16,
        sfn: 12345,
        timestamp: 1704067200,
        flags: 0,
        rx_chains: 1,
        setup_window: 20,
        occupied_time: 2300,
        guard: 50,
        channel_mask: 1,
    };
    let mut beacon = vec![0u8; MIN_BEACON_SIZE];
    hdr.serialize(&mut beacon[..HEADER_SIZE]).unwrap();
    let last = beacon.len() - 1;
    beacon[last] = sig_byte;
    beacon
}

/// beacon_wire_example: serialize must reproduce the independently
/// encoded header_hex byte-for-byte, and the wire bytes must parse back
/// to the oracle input fields.
#[test]
fn canonical_wire_example_roundtrips_through_accept() {
    let oracle_header_hex = "000000011000003039659200800001001408fc3200000001";

    // Serialize direction: our encoder matches the independent oracle.
    let beacon = oracle_beacon(0xCD);
    let mut hex = String::new();
    for b in &beacon[..HEADER_SIZE] {
        hex.push_str(&format!("{:02x}", b));
    }
    assert_eq!(
        hex, oracle_header_hex,
        "serialized header diverges from oracle"
    );

    // Parse direction: the oracle bytes decode to the oracle fields.
    let accepted = accept_beacon(
        &beacon,
        |signed, sig| signed[0] == 0x00 && sig[sig.len() - 1] == 0xCD,
        0xFF,
    )
    .expect("canonical beacon must be accepted");
    assert_eq!(accepted.header.epoch, 1);
    assert_eq!(accepted.header.num_slots, 16);
    assert_eq!(accepted.header.sfn, 12345);
    assert_eq!(accepted.header.timestamp, 1704067200);
    assert_eq!(accepted.header.flags, 0);
    assert_eq!(accepted.header.rx_chains, 1);
    assert_eq!(accepted.header.setup_window, 20);
    assert_eq!(accepted.header.occupied_time, 2300);
    assert_eq!(accepted.header.guard, 50);
    assert_eq!(accepted.header.channel_mask, 1);
    // EU868 plan (0xFF) intersected with the beacon's CH0-only mask.
    assert_eq!(accepted.usable_channels, 0x01);
}

/// ccp_beacon_sig_gate.json sig_gate_invalid_rejects_before_dio: an
/// invalid signature MUST reject before any state is produced.
#[test]
fn invalid_signature_rejects_fail_closed() {
    let beacon = oracle_beacon(0xCD);
    let result = accept_beacon(&beacon, |_, _| false, 0xFF);
    assert_eq!(result, Err(AcceptError::BadSignature));
}

/// R-02a-006: empty local intersection MUST reject the beacon.
#[test]
fn empty_channel_intersection_rejects() {
    let beacon = oracle_beacon(0xCD);
    // Permitted mask without CH0; the beacon only advertises CH0 (bit 0).
    let result = accept_beacon(&beacon, |_, _| true, 0xFF00);
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
    let mut beacon = oracle_beacon(0xCD);
    beacon[13] = flags::RESERVED_MASK; // all reserved bits set
    let result = accept_beacon(&beacon, |_, _| true, 0xFF);
    assert_eq!(result, Err(AcceptError::Parse(ParseError::ReservedFlagSet)));
}

/// SIG_SIZE sanity: the gate covers exactly the trailing 48 bytes.
#[test]
fn signature_is_trailing_48_bytes() {
    let beacon = oracle_beacon(0xCD);
    assert_eq!(beacon.len(), HEADER_SIZE + SIG_SIZE);
    assert_eq!(
        beacon[HEADER_SIZE..HEADER_SIZE + SIG_SIZE - 1],
        [0u8; SIG_SIZE - 1]
    );
    assert_eq!(beacon[beacon.len() - 1], 0xCD);
}
