// SPDX-License-Identifier: GPL-3.0-only

use lichen_core::addr::iid_from_pubkey_bytes;
use lichen_gateway::tunnel_auth::{
    build_root_post, route_hash, AuthenticatedRoot, DecapsulationRequest, TunnelAuthError,
    TunnelAuthorization, TunnelAuthorizationTable, TunnelDirection,
};
use schnorr48::{derive_keypair, PublicKey, Seed};
use serde_json::Value;
use std::net::Ipv6Addr;

fn bytes<const N: usize>(hex_value: &str) -> [u8; N] {
    hex::decode(hex_value).unwrap().try_into().unwrap()
}

fn named<'a>(corpus: &'a Value, section: &str, name: &str) -> &'a Value {
    corpus[section]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == name)
        .unwrap()
}

fn identity(corpus: &Value, name: &str) -> ([u8; 8], PublicKey) {
    let value = named(corpus, "identities", name);
    (
        bytes(value["iid_hex"].as_str().unwrap()),
        PublicKey::new(bytes(value["public_key_hex"].as_str().unwrap())),
    )
}

fn denial(error: TunnelAuthError) -> &'static str {
    match error {
        TunnelAuthError::MalformedCbor
        | TunnelAuthError::NonCanonicalCbor
        | TunnelAuthError::InvalidPrefix => "malformed",
        TunnelAuthError::UnsupportedAlgorithm => "algorithm",
        TunnelAuthError::MissingOscoreAuthentication => "oscore-required",
        TunnelAuthError::WrongRoot => "wrong-root",
        TunnelAuthError::RootIdentityMismatch => "key-binding",
        TunnelAuthError::WrongEgress => "wrong-egress",
        TunnelAuthError::InvalidRoute => "invalid-route",
        TunnelAuthError::WrongDirection => "wrong-direction",
        TunnelAuthError::SourceOutsideMesh => "source-scope",
        TunnelAuthError::DestinationInMesh => "destination-scope",
        TunnelAuthError::Expired => "expired",
        TunnelAuthError::ClockRollback => "clock-regression",
        TunnelAuthError::Replay => "replay",
        TunnelAuthError::Revoked => "revoked",
        TunnelAuthError::InvalidSignature => "signature",
        TunnelAuthError::UnauthorizedTunnel => "no-authorization",
        TunnelAuthError::BufferTooSmall
        | TunnelAuthError::TableDisabled
        | TunnelAuthError::Capacity => "capacity",
    }
}

fn claim(value: &Value) -> TunnelAuthorization {
    TunnelAuthorization::new(
        bytes(value["prefix_hex"].as_str().unwrap()),
        value["prefix_len"].as_u64().unwrap() as u8,
        bytes(value["route_hash_hex"].as_str().unwrap()),
        value["path_seq"].as_u64().unwrap(),
        value["expiry"].as_u64().unwrap(),
        bytes(value["egress_iid_hex"].as_str().unwrap()),
    )
    .unwrap()
}

fn apply_setup(
    table: &mut TunnelAuthorizationTable<4>,
    corpus: &Value,
    setup: &[Value],
    own_iid: [u8; 8],
) {
    for action in setup {
        match action["action"].as_str().unwrap() {
            "receive" => {
                let message = named(
                    corpus,
                    "authorizations",
                    action["message"].as_str().unwrap(),
                );
                let wire = hex::decode(message["cose_sign1_hex"].as_str().unwrap()).unwrap();
                let (sender_iid, sender_key) = identity(corpus, action["sender"].as_str().unwrap());
                table
                    .accept_post(
                        &wire,
                        AuthenticatedRoot {
                            iid: sender_iid,
                            public_key: &sender_key,
                            oscore_authenticated: true,
                        },
                        own_iid,
                        action["now"].as_u64().unwrap(),
                    )
                    .unwrap();
            }
            "revoke" => {
                let message = named(
                    corpus,
                    "authorizations",
                    action["message"].as_str().unwrap(),
                );
                let claim = claim(message);
                table
                    .revoke(
                        claim.prefix,
                        claim.prefix_len,
                        claim.route_hash,
                        action["through_path_seq"].as_u64().unwrap(),
                    )
                    .unwrap();
            }
            "change_root" => {
                table.set_root(identity(corpus, action["identity"].as_str().unwrap()).0);
            }
            action => panic!("unsupported setup action {action}"),
        }
    }
}

#[test]
fn canonical_tunnel_authorization_vector_matches_byte_for_byte() {
    let corpus: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test/vectors/tunnel_authorization.json"
    )))
    .unwrap();
    let vector = named(&corpus, "authorizations", "valid");

    let seed = Seed::new(bytes(vector["root_seed_hex"].as_str().unwrap()));
    let (private_key, public_key) = derive_keypair(&seed);
    assert_eq!(
        public_key.as_bytes(),
        &bytes::<32>(vector["root_public_key_hex"].as_str().unwrap())
    );
    let root_iid = bytes(vector["root_iid_hex"].as_str().unwrap());
    let egress_iid = bytes(vector["egress_iid_hex"].as_str().unwrap());
    let route: Vec<[u8; 8]> = vector["route_hops_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|hop| bytes(hop.as_str().unwrap()))
        .collect();
    assert_eq!(
        route_hash(&route).unwrap(),
        bytes::<16>(vector["route_hash_hex"].as_str().unwrap())
    );

    let claim = claim(vector);
    let post = build_root_post(claim, &route, root_iid, &private_key, &public_key).unwrap();
    let canonical_wire = hex::decode(vector["cose_sign1_hex"].as_str().unwrap()).unwrap();
    assert_eq!(post.body.as_bytes(), canonical_wire);

    let now = corpus["constants"]["evaluation_time"].as_u64().unwrap();
    let mut table = TunnelAuthorizationTable::<4>::default();
    table.set_root(root_iid);
    assert_eq!(
        table.accept_post(
            &canonical_wire,
            AuthenticatedRoot {
                iid: root_iid,
                public_key: &public_key,
                oscore_authenticated: true,
            },
            egress_iid,
            now,
        ),
        Ok(claim)
    );
    assert_eq!(
        table.authorize_decapsulation(
            DecapsulationRequest {
                direction: TunnelDirection::MeshToExternal,
                inner_source: claim.prefix,
                source_is_mesh: true,
                destination_is_mesh: false,
                route: &route,
            },
            now,
        ),
        Ok(())
    );
}

#[test]
fn canonical_direct_post_cases_fail_closed() {
    let corpus: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test/vectors/tunnel_authorization.json"
    )))
    .unwrap();
    let own_iid = identity(&corpus, "egress").0;

    for case in corpus["post_cases"].as_array().unwrap() {
        let active_root = case["active_root"].as_str().unwrap();
        let (active_iid, _) = identity(&corpus, active_root);
        let mut table = TunnelAuthorizationTable::<4>::default();
        table.set_root(active_iid);
        apply_setup(
            &mut table,
            &corpus,
            case["setup"].as_array().unwrap(),
            own_iid,
        );
        let sender = case["oscore_sender"].as_str().unwrap();
        let (sender_iid, sender_key) = identity(&corpus, sender);
        let message = named(&corpus, "authorizations", case["message"].as_str().unwrap());
        let wire = hex::decode(message["cose_sign1_hex"].as_str().unwrap()).unwrap();
        let result = table.accept_post(
            &wire,
            AuthenticatedRoot {
                iid: sender_iid,
                public_key: &sender_key,
                oscore_authenticated: case["oscore_authenticated"].as_bool().unwrap(),
            },
            own_iid,
            case["now"].as_u64().unwrap(),
        );
        let expected = &case["expected"];
        assert_eq!(
            result.is_ok(),
            expected["allowed"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
        match result {
            Ok(_) => {
                assert_eq!(expected["denial"], "none");
                assert_eq!(expected["response_code"], 204);
            }
            Err(error) => {
                assert_eq!(
                    denial(error),
                    expected["denial"].as_str().unwrap(),
                    "{}",
                    case["name"]
                );
                assert_eq!(error.coap_response_code(), 0x83);
                assert_eq!(expected["response_code"], 403);
            }
        }
    }
}

#[test]
fn canonical_decapsulation_cases_enforce_least_privilege() {
    let corpus: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test/vectors/tunnel_authorization.json"
    )))
    .unwrap();
    let own_iid = identity(&corpus, "egress").0;

    for case in corpus["decapsulation_cases"].as_array().unwrap() {
        let mut table = TunnelAuthorizationTable::<4>::default();
        table.set_root(identity(&corpus, case["active_root"].as_str().unwrap()).0);
        apply_setup(
            &mut table,
            &corpus,
            case["setup"].as_array().unwrap(),
            own_iid,
        );
        let route: Vec<[u8; 8]> = case["route_hops_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|hop| bytes(hop.as_str().unwrap()))
            .collect();
        let source = case["inner_source"]
            .as_str()
            .unwrap()
            .parse::<Ipv6Addr>()
            .unwrap()
            .octets();
        let destination = case["inner_destination"]
            .as_str()
            .unwrap()
            .parse::<Ipv6Addr>()
            .unwrap()
            .octets();
        let result = table.authorize_decapsulation(
            DecapsulationRequest {
                direction: if case["direction"] == "mesh-to-external" {
                    TunnelDirection::MeshToExternal
                } else {
                    TunnelDirection::ExternalToMesh
                },
                inner_source: source,
                source_is_mesh: source[0] == 0x02,
                destination_is_mesh: matches!(destination[0], 0x02 | 0xff),
                route: &route,
            },
            case["now"].as_u64().unwrap(),
        );
        let expected = &case["expected"];
        assert_eq!(
            result.is_ok(),
            expected["allowed"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
        match result {
            Ok(()) => {
                assert_eq!(expected["denial"], "none");
                assert_eq!(expected["response_code"], 204);
            }
            Err(error) => {
                assert_eq!(
                    denial(error),
                    expected["denial"].as_str().unwrap(),
                    "{}",
                    case["name"]
                );
                assert_eq!(error.coap_response_code(), 0x83);
                assert_eq!(expected["response_code"], 403);
            }
        }
    }
}

struct OverlapFixture {
    route: Vec<[u8; 8]>,
    source: [u8; 16],
}

fn overlapping_setup(
    short: (u64, u64),
    long: (u64, u64),
) -> (TunnelAuthorizationTable<4>, OverlapFixture) {
    let seed = Seed::new(bytes(
        "3f7a9c1e5d2b8406a1c9e75b3d8042f6c5a19e2b7d4f8306952c8e1a4b7d9f63",
    ));
    let (private_key, public_key) = derive_keypair(&seed);
    let root_iid = iid_from_pubkey_bytes(public_key.as_bytes());
    let egress_iid = [0xAA; 8];
    let route = vec![[0x11; 8], egress_iid];
    let digest = route_hash(&route).unwrap();
    let source = "0200:0:0:0::1".parse::<Ipv6Addr>().unwrap().octets();
    let prefix = [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let short = TunnelAuthorization::new(prefix, 64, digest, short.0, short.1, egress_iid).unwrap();
    let long = TunnelAuthorization::new(prefix, 96, digest, long.0, long.1, egress_iid).unwrap();
    let mut table = TunnelAuthorizationTable::<4>::default();
    table.set_root(root_iid);
    for claim in [short, long] {
        let wire = build_root_post(claim, &route, root_iid, &private_key, &public_key)
            .unwrap()
            .body
            .as_bytes()
            .to_vec();
        table
            .accept_post(
                &wire,
                AuthenticatedRoot {
                    iid: root_iid,
                    public_key: &public_key,
                    oscore_authenticated: true,
                },
                egress_iid,
                100,
            )
            .unwrap();
    }
    (table, OverlapFixture { route, source })
}

fn overlap_request(fixture: &OverlapFixture) -> DecapsulationRequest<'_> {
    DecapsulationRequest {
        direction: TunnelDirection::MeshToExternal,
        inner_source: fixture.source,
        source_is_mesh: true,
        destination_is_mesh: false,
        route: &fixture.route,
    }
}

#[test]
fn longer_live_prefix_authorizes_when_earlier_shorter_entry_is_expired() {
    // Shorter /64 grant accepted first (array order) but expired; the longer
    // /96 grant is live. Python selects the longest candidate before checking
    // expiry and permits; first-match array order denied Expired.
    let (mut table, fixture) = overlapping_setup((1, 200), (2, 10_000));
    assert_eq!(
        table.authorize_decapsulation(overlap_request(&fixture), 300),
        Ok(())
    );
}

#[test]
fn expired_longest_prefix_denies_without_falling_back_to_shorter_live_grant() {
    // Expiry applies to the selected (longest) candidate: Python denies
    // EXPIRED and pops it even though a live shorter grant exists; no silent
    // fallback to the shorter entry.
    let (mut table, fixture) = overlapping_setup((1, 10_000), (2, 200));
    assert_eq!(
        table.authorize_decapsulation(overlap_request(&fixture), 300),
        Err(TunnelAuthError::Expired)
    );
}

// Merge resolution (beads-worker-5): the branch's wired-path suite was
// dropped with its API. It exercised Gateway::handle_tunnel_auth_request /
// Gateway::authorize_tunnel_egress backed by a Gateway-owned authorization
// table; the staged gateway.rs resolution removed that table in favor of the
// durable GatewayCoordinator-owned one (see the merge comment in gateway.rs:
// two tables would diverge, grants written to one and the gate consulting
// the other). The branch's spec 06-security 8.11 intents are covered below
// through the surviving surface: POST accept/replay/fail-closed cases go
// through GatewayCoordinator::handle_request, and the egress data-plane gate
// is exercised end-to-end through Gateway::ingest_mesh_frame. Wrong-route,
// scoped source/destination, and expiry denials stay pinned by the corpus
// post/decapsulation cases above.

// ---- Wired CoAP dispatch (spec 06-security 8.11, POST /.well-known/tunnel-auth) ----

use lichen_gateway::resources::{CoapMethod, GatewayCoordinator};

fn corpus() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test/vectors/tunnel_authorization.json"
    )))
    .unwrap()
}

fn ygg_addr(iid: [u8; 8]) -> [u8; 16] {
    let mut addr = [0u8; 16];
    addr[0] = 0x02;
    addr[1..8].copy_from_slice(&iid[..7]);
    addr[8..16].copy_from_slice(&iid);
    addr
}

fn egress_coordinator(corpus: &Value, egress_name: &str) -> GatewayCoordinator {
    let (egress_iid, egress_key) = identity(corpus, egress_name);
    let mut coordinator = GatewayCoordinator::new_ephemeral(
        ygg_addr(egress_iid),
        lichen_core::addr::iid_from_pubkey_bytes(egress_key.as_bytes()),
        60,
        64,
    )
    .unwrap();
    coordinator.set_tunnel_auth_root(identity(corpus, "root").0);
    coordinator
}

fn vector_envelope(vector: &Value) -> Vec<u8> {
    hex::decode(vector["cose_sign1_hex"].as_str().unwrap()).unwrap()
}

#[test]
fn wired_coap_tunnel_auth_accepts_valid_vector_then_replay_is_forbidden() {
    let corpus = corpus();
    let vector = named(&corpus, "authorizations", "valid");
    let mut coordinator = egress_coordinator(&corpus, "egress");
    let (root_iid, root_key) = identity(&corpus, "root");
    let wire = vector_envelope(vector);
    assert_eq!(root_iid, bytes(vector["kid_iid_hex"].as_str().unwrap()));

    let response = coordinator.handle_request(
        CoapMethod::Post,
        "tunnel-auth",
        &wire,
        true,
        Some(root_key.as_bytes()),
        0,
    );
    assert_eq!(response.code, 0x44);
    assert!(response.payload.is_empty());

    // An identical replayed POST hits the replay floor: 4.03, nothing cached.
    let response = coordinator.handle_request(
        CoapMethod::Post,
        "tunnel-auth",
        &wire,
        true,
        Some(root_key.as_bytes()),
        0,
    );
    assert_eq!(response.code, 0x83);
}

#[test]
fn wired_coap_tunnel_auth_fails_closed_on_missing_oscore_wrong_root_and_wrong_egress() {
    let corpus = corpus();
    let vector = named(&corpus, "authorizations", "valid");
    let (_, root_key) = identity(&corpus, "root");
    let (_, other_root_key) = identity(&corpus, "other_root");
    let wire = vector_envelope(vector);

    // A table with no bound root never accepts (WrongRoot, fail-closed).
    let (egress_iid, egress_key) = identity(&corpus, "egress");
    let mut unbound = GatewayCoordinator::new_ephemeral(
        ygg_addr(egress_iid),
        lichen_core::addr::iid_from_pubkey_bytes(egress_key.as_bytes()),
        60,
        64,
    )
    .unwrap();
    let response = unbound.handle_request(
        CoapMethod::Post,
        "tunnel-auth",
        &wire,
        true,
        Some(root_key.as_bytes()),
        0,
    );
    assert_eq!(response.code, 0x83);

    // Missing OSCORE authentication is refused before any table mutation.
    let mut coordinator = egress_coordinator(&corpus, "egress");
    let response = coordinator.handle_request(
        CoapMethod::Post,
        "tunnel-auth",
        &wire,
        false,
        Some(root_key.as_bytes()),
        0,
    );
    assert_eq!(response.code, 0x83);

    // A different root (kid binding fails against the bound root) is denied.
    let response = coordinator.handle_request(
        CoapMethod::Post,
        "tunnel-auth",
        &wire,
        true,
        Some(other_root_key.as_bytes()),
        0,
    );
    assert_eq!(response.code, 0x83);

    // The claim binds a specific egress IID; another egress is denied.
    let mut other_egress = egress_coordinator(&corpus, "other_egress");
    let response = other_egress.handle_request(
        CoapMethod::Post,
        "tunnel-auth",
        &wire,
        true,
        Some(root_key.as_bytes()),
        0,
    );
    assert_eq!(response.code, 0x83);

    // Corrupting any envelope byte fails signature verification.
    let mut corrupted = wire.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0x01;
    let response = coordinator.handle_request(
        CoapMethod::Post,
        "tunnel-auth",
        &corrupted,
        true,
        Some(root_key.as_bytes()),
        0,
    );
    assert_eq!(response.code, 0x83);

    // GET is not a tunnel-auth method.
    let response = coordinator.handle_request(CoapMethod::Get, "tunnel-auth", &wire, true, None, 0);
    assert_eq!(response.code, 0x84); // 4.04 Not Found
}

// ── Wired data-path egress gate (spec 06-security 8.11) ─────────────────────
//
// The egress half of the tunnel-auth contract: mesh-ingress unicast datagrams
// forwarded to external networks must be covered by a current-root grant
// (Gateway::ingest_mesh_frame_at_superframe → GatewayCoordinator::authorize_egress).

use lichen_core::addr::Ipv6Addr as CoreIpv6Addr;
use lichen_core::constants::L2_DISPATCH_SCHC;
use lichen_core::icmpv6;
use lichen_gateway::Gateway;
use lichen_link::identity::{Identity, PeerIdentity};
use lichen_link::keys::Seed as LinkSeed;
use lichen_link::link_layer::LinkLayer;
use lichen_link::schnorr;
use lichen_link::seqnum::LinkSeqNum;
use lichen_schc::codec;

const EXTERNAL_DST: [u8; 16] = [
    0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
];
const GRANTED_SRC: [u8; 16] = [
    0x02, 0x00, 0x12, 0x34, 0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
];
const OUTSIDE_SRC: [u8; 16] = [
    0x02, 0x00, 0x99, 0x99, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
];
const GRANT_PREFIX: [u8; 16] = [
    0x02, 0x00, 0x12, 0x34, 0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn gateway_identity() -> Identity {
    Identity::from_seed(LinkSeed::new([0x02; 32]))
}

fn fresh_gateway() -> Gateway {
    Gateway::new_ephemeral(gateway_identity(), 128).unwrap()
}

/// A mesh peer whose link keys are installed in the gateway via a signed
/// Announce (the sole unknown-key bootstrap), so subsequent SCHC frames
/// authenticate at the gateway's link layer.
struct MeshPeer {
    identity: Identity,
    link: LinkLayer,
    next_sequence: u16,
}

impl MeshPeer {
    fn new() -> Self {
        let identity = Identity::from_seed(LinkSeed::new([9; 32]));
        let mut link = LinkLayer::new(identity.clone());
        link.add_peer(PeerIdentity::from_pubkey(gateway_identity().pubkey));
        Self {
            identity,
            link,
            next_sequence: 1,
        }
    }

    fn root_eui64() -> [u8; 8] {
        let mut eui = gateway_identity().iid;
        eui[0] ^= 0x02;
        eui
    }

    fn build_wire(&mut self, l2_payload: &[u8], destination: &[u8]) -> Vec<u8> {
        let mut wire = [0u8; 255];
        let len = self
            .link
            .build_frame(
                128,
                LinkSeqNum::new(self.next_sequence),
                destination,
                l2_payload,
                &mut wire,
            )
            .unwrap();
        self.next_sequence += 1;
        wire[..len].to_vec()
    }

    fn signed_announce(&self) -> Vec<u8> {
        let rx_channel = 3;
        let sequence = 1u16;
        let mut signed = [0u8; 64];
        lichen_core::announce::write_announce_signed_data(
            &self.identity.iid,
            self.identity.pubkey.as_bytes(),
            sequence,
            rx_channel,
            &[],
            &mut signed,
        )
        .unwrap();
        let signature = schnorr::sign(&self.identity.privkey, &self.identity.pubkey, &signed);
        let mut announce = vec![0u8; 93];
        let len = lichen_core::announce::AnnounceBuilder {
            originator_iid: &self.identity.iid,
            pubkey: self.identity.pubkey.as_bytes(),
            seq_num: sequence,
            hop_count: 0,
            rx_channel,
            signature: &signature,
            app_data: &[],
        }
        .write_to(&mut announce)
        .unwrap();
        announce.truncate(len);
        let mut payload = vec![lichen_core::constants::L2_DISPATCH_ROUTING];
        payload.extend_from_slice(&announce);
        payload
    }

    async fn bootstrap(&mut self, gateway: &mut Gateway, now_ms: u64) {
        let announce = self.signed_announce();
        let wire = self.build_wire(&announce, &[]);
        gateway
            .ingest_mesh_frame(&wire, Some(-50), Some(10), now_ms)
            .await
            .unwrap();
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// POST an already-elapsed grant; the coordinator must refuse it (4.03).
fn provision_expired_grant_refused(gateway: &mut Gateway) {
    let identity = gateway_identity();
    let gw_iid = iid_from_pubkey_bytes(identity.pubkey.as_bytes());
    let route = [gw_iid];
    let claim = TunnelAuthorization::new(
        GRANT_PREFIX,
        40,
        route_hash(&route).unwrap(),
        7,
        unix_secs().saturating_sub(1),
        gw_iid,
    )
    .unwrap();
    let post = build_root_post(claim, &route, gw_iid, &identity.privkey, &identity.pubkey).unwrap();
    let response = gateway.coordinator_mut().handle_request(
        CoapMethod::Post,
        "tunnel-auth",
        post.body.as_bytes(),
        true,
        Some(identity.pubkey.as_bytes()),
        0,
    );
    assert_eq!(response.code, 0x83, "expired grant must be refused (4.03)");
}

/// SCHC-compressed ICMPv6 echo request (L2 payload) from `src` to `dst`.
fn egress_frame(src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
    let mut pkt = [0u8; 64];
    let n = icmpv6::echo_request(
        &CoreIpv6Addr(src),
        &CoreIpv6Addr(dst),
        0xaaaa,
        1,
        b"tunnel-auth",
        &mut pkt,
    );
    let ipv6 = &pkt[..n];
    let mut out = vec![0u8; ipv6.len() + 3];
    out[0] = L2_DISPATCH_SCHC;
    let compressed = codec::compress(ipv6, &mut out[1..]).expect("SCHC compress");
    out.truncate(compressed + 1);
    out
}

/// Mint a single-hop root grant over `[gateway IID]` and POST it into the
/// gateway's coordinator (0x44 expected). Root seed and address shapes follow
/// the tunnel_authorization vector corpus (root = the gateway itself).
fn provision_grant(gateway: &mut Gateway, expiry: u64) {
    let identity = gateway_identity();
    let gw_iid = iid_from_pubkey_bytes(identity.pubkey.as_bytes());
    let route = [gw_iid];
    let claim = TunnelAuthorization::new(
        GRANT_PREFIX,
        40,
        route_hash(&route).unwrap(),
        7,
        expiry,
        gw_iid,
    )
    .unwrap();
    let post = build_root_post(claim, &route, gw_iid, &identity.privkey, &identity.pubkey).unwrap();
    let response = gateway.coordinator_mut().handle_request(
        CoapMethod::Post,
        "tunnel-auth",
        post.body.as_bytes(),
        true,
        Some(identity.pubkey.as_bytes()),
        0,
    );
    assert_eq!(response.code, 0x44, "grant POST must be accepted (2.04)");
}

/// Mint a grant signed by a DODAG root that is NOT the gateway itself,
/// covering the gateway's own IID as the egress, and POST it into the
/// coordinator under that root binding (0x44 expected).
fn provision_grant_from_distinct_root(gateway: &mut Gateway) {
    let root_identity = Identity::from_seed(LinkSeed::new([0x77; 32]));
    let root_iid = iid_from_pubkey_bytes(root_identity.pubkey.as_bytes());
    gateway.coordinator_mut().set_tunnel_auth_root(root_iid);
    let gw_iid = iid_from_pubkey_bytes(gateway_identity().pubkey.as_bytes());
    let route = [gw_iid];
    let claim = TunnelAuthorization::new(
        GRANT_PREFIX,
        40,
        route_hash(&route).unwrap(),
        7,
        unix_secs() + 3600,
        gw_iid,
    )
    .unwrap();
    let post = build_root_post(
        claim,
        &route,
        root_iid,
        &root_identity.privkey,
        &root_identity.pubkey,
    )
    .unwrap();
    let response = gateway.coordinator_mut().handle_request(
        CoapMethod::Post,
        "tunnel-auth",
        post.body.as_bytes(),
        true,
        Some(root_identity.pubkey.as_bytes()),
        0,
    );
    assert_eq!(
        response.code, 0x44,
        "distinct-root grant must be accepted (2.04)"
    );
}

async fn ingest_source_to(
    peer: &mut MeshPeer,
    gateway: &mut Gateway,
    source: [u8; 16],
    destination: [u8; 16],
) -> Option<Vec<u8>> {
    let l2 = egress_frame(source, destination);
    let wire = peer.build_wire(&l2, &MeshPeer::root_eui64());
    gateway
        .ingest_mesh_frame(&wire, Some(-50), Some(10), 1000)
        .await
        .unwrap()
        .into_upstream_ipv6()
}

#[tokio::test]
async fn wired_egress_forwards_authorized_tunnel() {
    let mut gateway = fresh_gateway();
    let mut peer = MeshPeer::new();
    peer.bootstrap(&mut gateway, 0).await;
    provision_grant(&mut gateway, unix_secs() + 3600);

    let upstream = ingest_source_to(&mut peer, &mut gateway, GRANTED_SRC, EXTERNAL_DST)
        .await
        .expect("authorized tunnel must be forwarded upstream");
    assert_eq!(upstream[0] >> 4, 6, "upstream datagram is IPv6");
    assert_eq!(&upstream[8..24], &GRANTED_SRC, "inner source preserved");
    assert_eq!(
        &upstream[24..40],
        &EXTERNAL_DST,
        "inner destination preserved"
    );
}

#[tokio::test]
async fn wired_egress_matches_grant_under_distinct_root_via_own_iid_route_evidence() {
    // Root ≠ gateway: route evidence must be the gateway's own IID (it is the
    // egress), not the bound DODAG root IID, or the grant can never match.
    let mut gateway = fresh_gateway();
    let mut peer = MeshPeer::new();
    peer.bootstrap(&mut gateway, 0).await;
    provision_grant_from_distinct_root(&mut gateway);

    let upstream = ingest_source_to(&mut peer, &mut gateway, GRANTED_SRC, EXTERNAL_DST)
        .await
        .expect("grant over the gateway's own IID must be forwarded upstream");
    assert_eq!(upstream[0] >> 4, 6, "upstream datagram is IPv6");
    assert_eq!(&upstream[8..24], &GRANTED_SRC, "inner source preserved");
}

#[tokio::test]
async fn wired_egress_drops_unauthorized_tunnel() {
    let mut gateway = fresh_gateway();
    let mut peer = MeshPeer::new();
    peer.bootstrap(&mut gateway, 0).await;

    assert!(
        ingest_source_to(&mut peer, &mut gateway, GRANTED_SRC, EXTERNAL_DST)
            .await
            .is_none(),
        "no grant provisioned: egress must fail closed"
    );
}

#[tokio::test]
async fn wired_egress_drops_source_outside_granted_prefix() {
    let mut gateway = fresh_gateway();
    let mut peer = MeshPeer::new();
    peer.bootstrap(&mut gateway, 0).await;
    provision_grant(&mut gateway, unix_secs() + 3600);

    assert!(
        ingest_source_to(&mut peer, &mut gateway, OUTSIDE_SRC, EXTERNAL_DST)
            .await
            .is_none(),
        "source outside the signed prefix must be dropped"
    );
}

#[tokio::test]
async fn wired_egress_refuses_expired_grant_and_stays_closed() {
    let mut gateway = fresh_gateway();
    let mut peer = MeshPeer::new();
    peer.bootstrap(&mut gateway, 0).await;

    // accept_post refuses already-elapsed grants outright (Expired -> 4.03),
    // so an expired grant can never arm the data path. The table-level
    // Expired-on-authorize branch is covered by the corpus decapsulation
    // cases (canonical_decapsulation_cases_enforce_least_privilege).
    provision_expired_grant_refused(&mut gateway);

    assert!(
        ingest_source_to(&mut peer, &mut gateway, GRANTED_SRC, EXTERNAL_DST)
            .await
            .is_none(),
        "no live grant cached: egress must fail closed"
    );
}

#[tokio::test]
async fn wired_egress_hairpin_bypasses_gate() {
    let mut gateway = fresh_gateway();
    let mut peer = MeshPeer::new();
    peer.bootstrap(&mut gateway, 0).await;

    let mut destination = [0u8; 16];
    destination[..8].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0]);
    destination[8..].copy_from_slice(&gateway_identity().iid);

    assert!(
        ingest_source_to(&mut peer, &mut gateway, GRANTED_SRC, destination)
            .await
            .is_some(),
        "mesh-destined (hairpin) traffic is mesh-internal forwarding, not egress"
    );
}
