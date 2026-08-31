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

/// Build a signed, link-authenticated DIO frame with the given IPv6 hop limit
/// (same construction as the Rule-Version harness and the Python security
/// test builder `dio_payload(hop_limit=...)`).
fn receive_dio_with_hop_limit(
    receiver: &mut LinkLayer,
    sender: &LinkLayer,
    sender_iid: [u8; 8],
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
    let dst = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a];
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
    let mut compressed = [0u8; 128];
    let compressed_len = lichen_schc::compress(&ipv6, &mut compressed).unwrap();
    let mut recovered = [0u8; 128];
    let recovered_len =
        lichen_schc::decompress(&compressed[..compressed_len], &mut recovered).unwrap();
    assert_eq!(&recovered[..recovered_len], ipv6.as_slice());
    let mut link_payload = vec![lichen_core::constants::L2_DISPATCH_SCHC];
    link_payload.extend_from_slice(&compressed[..compressed_len]);
    let mut wire = vec![0u8; 160];
    let length = sender
        .build_frame(1, LinkSeqNum::new(seqnum), &[], &link_payload, &mut wire)
        .unwrap();
    receiver.receive_frame(&wire[..length]).unwrap()
}

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

    let frame = receive_dio_with_hop_limit(&mut receiver, &sender, sender_iid, 64, 1);
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
    let frame = receive_dio_with_hop_limit(&mut receiver, &sender, sender_iid, 255, 2);
    AuthenticatedPeerSchcContext::from_authenticated_dio_frame(
        frame,
        0,
        &DODAG_ID,
        1,
        ExpectedDioRole::Peer,
    )
    .unwrap();
}
