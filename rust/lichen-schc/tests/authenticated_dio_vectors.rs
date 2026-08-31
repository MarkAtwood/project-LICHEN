use std::{fs, path::Path};

use lichen_link::{
    identity::{Identity, PeerIdentity},
    keys::Seed,
    link_layer::LinkLayer,
    seqnum::LinkSeqNum,
};
use lichen_schc::{AuthenticatedPeerSchcContext, ExpectedDioRole, SchcError};
use serde::Deserialize;

const DODAG_ID: [u8; 16] = [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<AuthenticatedDioVector>,
}

#[derive(Deserialize)]
struct AuthenticatedDioVector {
    name: String,
    sender_seed_hex: String,
    sender_pubkey_hex: String,
    receiver_seed_hex: String,
    receiver_pubkey_hex: String,
    wire_hex: String,
    expected_rpl_instance_id: u8,
    expected_dodag_id_hex: String,
    expected_mop: u8,
    expected_role: String,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    admitted: bool,
    compatible: Option<bool>,
    error: Option<String>,
}

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn authenticated_dio_vectors_drive_production_admission() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test/vectors/authenticated_schc_dio.json");
    let corpus: VectorFile = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    for vector in corpus.vectors {
        let sender_seed: [u8; 32] = hex(&vector.sender_seed_hex).try_into().unwrap();
        let receiver_seed: [u8; 32] = hex(&vector.receiver_seed_hex).try_into().unwrap();
        let sender = Identity::from_seed(Seed::new(sender_seed));
        let receiver_identity = Identity::from_seed(Seed::new(receiver_seed));
        assert_eq!(
            sender.pubkey.as_bytes().as_slice(),
            hex(&vector.sender_pubkey_hex)
        );
        assert_eq!(
            receiver_identity.pubkey.as_bytes().as_slice(),
            hex(&vector.receiver_pubkey_hex)
        );
        let mut receiver = LinkLayer::new(receiver_identity);
        receiver.add_peer(PeerIdentity::from_pubkey(sender.pubkey));
        let frame = receiver.receive_frame(&hex(&vector.wire_hex)).unwrap();
        let dodag_id: [u8; 16] = hex(&vector.expected_dodag_id_hex).try_into().unwrap();
        let role = match vector.expected_role.as_str() {
            "root" => ExpectedDioRole::Root,
            "peer" => ExpectedDioRole::Peer,
            other => panic!("unknown role {other}"),
        };
        let result = AuthenticatedPeerSchcContext::from_authenticated_dio_frame(
            frame,
            vector.expected_rpl_instance_id,
            &dodag_id,
            vector.expected_mop,
            role,
        );
        assert_eq!(result.is_ok(), vector.expected.admitted, "{}", vector.name);
        match result {
            Ok(peer) => {
                assert_eq!(
                    Some(peer.allows_dodag_join()),
                    vector.expected.compatible,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    vector.expected.error.as_deref(),
                    if peer.allows_dodag_join() {
                        None
                    } else {
                        Some("incompatible_rule_version")
                    },
                    "{}",
                    vector.name
                );
            }
            Err(_) => assert!(vector.expected.error.is_some(), "{}", vector.name),
        }
    }
}

/// Build a signed, link-authenticated DIO frame with the given IPv6
/// destination and hop limit (same construction as the Rule-Version harness
/// and the Python security test builder `dio_payload(...)`).
fn receive_dio_with_destination(
    receiver: &mut LinkLayer,
    sender: &LinkLayer,
    sender_iid: [u8; 8],
    destination: [u8; 16],
    hop_limit: u8,
    seqnum: u16,
) -> lichen_link::link_layer::AuthenticatedFrame {
    let mut dio = vec![0u8; 24];
    dio[2..4].copy_from_slice(&512u16.to_be_bytes());
    dio[4] = 1 << 3;
    dio[8..24].copy_from_slice(&DODAG_ID);
    dio.extend_from_slice(&[0x13, 1, 3]);
    let mut icmp = vec![155u8, 1, 0, 0];
    icmp.extend_from_slice(&dio);
    let mut src = [0u8; 16];
    src[0] = 0xfe;
    src[1] = 0x80;
    src[8..].copy_from_slice(&sender_iid);
    let dst = destination;
    let checksum = lichen_core::checksum::upper_layer_checksum(&src, &dst, 58, &icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    let mut ipv6 = vec![0u8; 40];
    ipv6[0] = 0x60;
    ipv6[4..6].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
    ipv6[6] = 58;
    ipv6[7] = hop_limit;
    ipv6[8..24].copy_from_slice(&src);
    ipv6[24..40].copy_from_slice(&dst);
    ipv6.extend_from_slice(&icmp);
    // Encode as Rule 255 explicitly so the rejection below isolates the
    // destination conjunct of the admission gate rather than the rule-byte
    // conjunct (a link-local unicast dst would otherwise compress via Rule 3
    // and be rejected for the wrong reason).
    let mut encoded = [0u8; 512];
    let encoded_len = lichen_schc::encode_rule255(&ipv6, &mut encoded, usize::MAX).unwrap();
    let mut link_payload = vec![lichen_core::constants::L2_DISPATCH_SCHC];
    link_payload.extend_from_slice(&encoded[..encoded_len]);
    let mut wire = vec![0u8; 160];
    let length = sender
        .build_frame(1, LinkSeqNum::new(seqnum), &[], &link_payload, &mut wire)
        .unwrap();
    receiver.receive_frame(&wire[..length]).unwrap()
}

const ALL_RPL_NODES: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a];

/// Spec 09 13.3 (R-09-005): a canonical multicast DIO must carry hop-limit
/// 255; admission rejects any other value (mirrors the Python reference
/// `test_authenticated_dio_rejects_noncanonical_envelope` hop_limit=64 case).
#[test]
fn authenticated_dio_admission_rejects_noncanonical_hop_limit() {
    let sender_identity = Identity::from_seed(Seed::new([0x11; 32]));
    let sender_iid = sender_identity.iid;
    let receiver_identity = Identity::from_seed(Seed::new([0x22; 32]));
    let mut receiver = LinkLayer::new(receiver_identity);
    receiver.add_peer(PeerIdentity::from_pubkey(sender_identity.pubkey));
    let sender = LinkLayer::new(sender_identity);

    let frame =
        receive_dio_with_destination(&mut receiver, &sender, sender_iid, ALL_RPL_NODES, 64, 1);
    let error = AuthenticatedPeerSchcContext::from_authenticated_dio_frame(
        frame,
        0,
        &DODAG_ID,
        1,
        ExpectedDioRole::Peer,
    )
    .unwrap_err();
    assert!(
        matches!(error, SchcError::InvalidPacket(message) if message.contains("Hop Limit")),
        "expected hop-limit rejection, got {error}"
    );

    // Control: the identical frame with the canonical hop limit is admitted.
    let frame =
        receive_dio_with_destination(&mut receiver, &sender, sender_iid, ALL_RPL_NODES, 255, 2);
    AuthenticatedPeerSchcContext::from_authenticated_dio_frame(
        frame,
        0,
        &DODAG_ID,
        1,
        ExpectedDioRole::Peer,
    )
    .unwrap();
}

/// Spec 09 13.3 (R-09-005): authenticated admission applies to the canonical
/// multicast DIO (ff02::1a) only; a DIO addressed to a unicast destination is
/// rejected before any routing mutation (mirrors the Python reference
/// `dio_payload(destination=fe80::1)` rejection case).
#[test]
fn authenticated_dio_admission_rejects_unicast_destination() {
    let sender_identity = Identity::from_seed(Seed::new([0x11; 32]));
    let sender_iid = sender_identity.iid;
    let receiver_identity = Identity::from_seed(Seed::new([0x22; 32]));
    let mut receiver = LinkLayer::new(receiver_identity);
    receiver.add_peer(PeerIdentity::from_pubkey(sender_identity.pubkey));
    let sender = LinkLayer::new(sender_identity);

    let mut unicast = [0u8; 16];
    unicast[0] = 0xfe;
    unicast[1] = 0x80;
    unicast[15] = 1;
    let frame = receive_dio_with_destination(&mut receiver, &sender, sender_iid, unicast, 255, 1);
    let error = AuthenticatedPeerSchcContext::from_authenticated_dio_frame(
        frame,
        0,
        &DODAG_ID,
        1,
        ExpectedDioRole::Peer,
    )
    .unwrap_err();
    assert!(
        matches!(error, SchcError::InvalidPeerEvidence),
        "expected unicast-destination rejection, got {error}"
    );

    // Control: the identical DIO to ff02::1a is admitted.
    let frame =
        receive_dio_with_destination(&mut receiver, &sender, sender_iid, ALL_RPL_NODES, 255, 2);
    AuthenticatedPeerSchcContext::from_authenticated_dio_frame(
        frame,
        0,
        &DODAG_ID,
        1,
        ExpectedDioRole::Peer,
    )
    .unwrap();
}

/// Regression guard for the removed unicast admission branch: an
/// Extended-addressed link frame to this receiver carrying a DIO whose IPv6
/// destination is the receiver's link-local unicast was admitted by the old
/// `authenticated_dio_destination_is_local` logic. Spec 09 13.3 parity with
/// the Python reference now rejects it before any routing mutation.
#[test]
fn authenticated_dio_admission_rejects_unicast_link_frame_to_receiver() {
    let sender_identity = Identity::from_seed(Seed::new([0x11; 32]));
    let sender_iid = sender_identity.iid;
    let receiver_identity = Identity::from_seed(Seed::new([0x22; 32]));
    let receiver_iid = receiver_identity.iid;
    let mut receiver = LinkLayer::new(receiver_identity);
    receiver.add_peer(PeerIdentity::from_pubkey(sender_identity.pubkey));
    let sender = LinkLayer::new(sender_identity);

    // Frame-level unicast: 8-byte destination (Extended addr mode) = the
    // receiver's EUI-64 (U/L-flipped IID).
    let mut receiver_eui = receiver_iid;
    receiver_eui[0] ^= 0x02;

    // IPv6 destination: the receiver's link-local unicast address.
    let mut unicast = [0u8; 16];
    unicast[0] = 0xfe;
    unicast[1] = 0x80;
    unicast[8..].copy_from_slice(&receiver_iid);

    let mut dio = vec![0u8; 24];
    dio[2..4].copy_from_slice(&512u16.to_be_bytes());
    dio[4] = 1 << 3;
    dio[8..24].copy_from_slice(&DODAG_ID);
    dio.extend_from_slice(&[0x13, 1, 3]);
    let mut icmp = vec![155u8, 1, 0, 0];
    icmp.extend_from_slice(&dio);
    let mut src = [0u8; 16];
    src[0] = 0xfe;
    src[1] = 0x80;
    src[8..].copy_from_slice(&sender_iid);
    let checksum = lichen_core::checksum::upper_layer_checksum(&src, &unicast, 58, &icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    let mut ipv6 = vec![0u8; 40];
    ipv6[0] = 0x60;
    ipv6[4..6].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
    ipv6[6] = 58;
    ipv6[7] = 255;
    ipv6[8..24].copy_from_slice(&src);
    ipv6[24..40].copy_from_slice(&unicast);
    ipv6.extend_from_slice(&icmp);
    // Rule 255 encoding so rule-byte choice cannot confound the rejection.
    // The frame is rejected by the tightened gate as a whole (the
    // Extended addr mode also fails the broadcast-addr-mode conjunct); parse
    // has no destination check, so reviving the old unicast branch or
    // removing the gate makes this test fail — that is the regression this
    // test pins.
    let mut encoded = [0u8; 512];
    let encoded_len = lichen_schc::encode_rule255(&ipv6, &mut encoded, usize::MAX).unwrap();
    let mut link_payload = vec![lichen_core::constants::L2_DISPATCH_SCHC];
    link_payload.extend_from_slice(&encoded[..encoded_len]);
    let mut wire = vec![0u8; 160];
    let length = sender
        .build_frame(
            1,
            LinkSeqNum::new(1),
            &receiver_eui,
            &link_payload,
            &mut wire,
        )
        .unwrap();
    let frame = receiver.receive_frame(&wire[..length]).unwrap();

    let error = AuthenticatedPeerSchcContext::from_authenticated_dio_frame(
        frame,
        0,
        &DODAG_ID,
        1,
        ExpectedDioRole::Peer,
    )
    .unwrap_err();
    assert!(
        matches!(error, SchcError::InvalidPeerEvidence),
        "expected unicast link-frame rejection, got {error}"
    );
}
