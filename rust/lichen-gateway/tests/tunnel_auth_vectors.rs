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

// ── Wired-path cases (m9i4): the Gateway's POST resource and egress data ──
// plane, exercised through the public post-authentication boundary methods
// (handle_tunnel_auth_request / authorize_tunnel_egress) rather than the
// bare table.

use lichen_gateway::resources::CoapMethod;
use lichen_gateway::Gateway;
use lichen_link::identity::Identity;

/// 2.04 Changed and 4.03 Forbidden on the wire (C tunnel_auth.c:24-33
/// permit/deny analog); 4.05 for non-POST methods.
const COAP_CHANGED: u8 = 0x44;
const COAP_FORBIDDEN: u8 = 0x83;
const COAP_METHOD_NOT_ALLOWED: u8 = 0x85;

fn wired_identity(seed: u8) -> Identity {
    Identity::from_seed(Seed::new([seed; 32]))
}

fn mesh_addr(last: u8) -> [u8; 16] {
    let mut addr = [0u8; 16];
    addr[0] = 0x02;
    addr[15] = last;
    addr
}

fn inner_datagram(source: [u8; 16], destination: [u8; 16]) -> Vec<u8> {
    let mut inner = vec![0u8; 40];
    inner[0] = 0x60;
    inner[6] = 59; // No Next Header
    inner[7] = 63;
    inner[8..24].copy_from_slice(&source);
    inner[24..40].copy_from_slice(&destination);
    inner
}

/// Source-routed tunnel as it arrives at the terminating egress: every
/// segment consumed (segments_left == 0), the visited hops recorded in the
/// SRH grid, and the outer destination naming this egress.
fn terminating_tunnel(
    outer_src: &[u8; 16],
    outer_dst: &[u8; 16],
    grid: &[[u8; 16]],
    segments_left: u8,
    inner: &[u8],
) -> Vec<u8> {
    let routing_len = 8 + 16 * grid.len();
    let payload_len = u16::try_from(routing_len + inner.len()).unwrap();
    let mut packet = vec![0u8; 40 + routing_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    packet[6] = 43; // Routing header
    packet[7] = 63;
    packet[8..24].copy_from_slice(outer_src);
    packet[24..40].copy_from_slice(outer_dst);
    packet[40] = 41; // next header: IPv6-in-IPv6
    packet[41] = (routing_len / 8 - 1) as u8;
    packet[42] = 3; // RH3
    packet[43] = segments_left;
    for (index, addr) in grid.iter().enumerate() {
        packet[48 + index * 16..48 + (index + 1) * 16].copy_from_slice(addr);
    }
    packet.extend_from_slice(inner);
    packet
}

struct WiredFixture {
    gateway: Gateway,
    identity: Identity,
    hop_addr: [u8; 16],
    hop_iid: [u8; 8],
    inner_source: [u8; 16],
    inner: Vec<u8>,
}

/// Gateway with a self-rooted authorization table plus a claim signed by the
/// gateway's own identity over (inner_source/128, [hop, egress]).
fn wired_setup() -> WiredFixture {
    let identity = wired_identity(0x42);
    let gateway = Gateway::new_ephemeral(identity.clone(), 128).unwrap();
    let hop_iid = [0x11; 8];
    let mut hop_addr = [0u8; 16];
    hop_addr[0] = 0x02;
    hop_addr[8..16].copy_from_slice(&hop_iid);
    let inner_source = mesh_addr(0x77);
    let inner = inner_datagram(inner_source, [0x20; 16]);
    WiredFixture {
        gateway,
        identity,
        hop_addr,
        hop_iid,
        inner_source,
        inner,
    }
}

impl WiredFixture {
    fn route(&self) -> Vec<[u8; 8]> {
        vec![self.hop_iid, self.identity.iid]
    }

    fn signed_post(&self, path_seq: u64, expiry: u64) -> Vec<u8> {
        let route = self.route();
        let claim = TunnelAuthorization::new(
            self.inner_source,
            128,
            route_hash(&route).unwrap(),
            path_seq,
            expiry,
            self.identity.iid,
        )
        .unwrap();
        build_root_post(
            claim,
            &route,
            self.identity.iid,
            &self.identity.privkey,
            &self.identity.pubkey,
        )
        .unwrap()
        .body
        .as_bytes()
        .to_vec()
    }

    fn tunnel(&self) -> Vec<u8> {
        terminating_tunnel(
            &self.identity.ygg_addr,
            &self.identity.ygg_addr,
            &[self.hop_addr],
            0,
            &self.inner,
        )
    }

    fn post(&mut self, wire: &[u8], now: u64) -> u8 {
        self.gateway
            .handle_tunnel_auth_request(
                CoapMethod::Post,
                wire,
                self.identity.iid,
                self.identity.pubkey.as_bytes(),
                now,
            )
            .code
    }
}

#[test]
fn wired_post_then_tunnel_decapsulates_and_forwards_inner() {
    let mut fixture = wired_setup();
    let wire = fixture.signed_post(1, 1_000);
    assert_eq!(fixture.post(&wire, 100), COAP_CHANGED);
    let packet = fixture.tunnel();
    let forwarded = fixture
        .gateway
        .authorize_tunnel_egress(&packet, 100)
        .expect("authorized tunnel is decapsulated");
    assert_eq!(forwarded, fixture.inner);
}

#[test]
fn wired_tunnel_without_authorization_is_dropped() {
    let mut fixture = wired_setup();
    let packet = fixture.tunnel();
    assert_eq!(fixture.gateway.authorize_tunnel_egress(&packet, 100), None);
}

#[test]
fn wired_tunnel_with_wrong_route_is_dropped() {
    let mut fixture = wired_setup();
    let wire = fixture.signed_post(1, 1_000);
    assert_eq!(fixture.post(&wire, 100), COAP_CHANGED);
    // Same claim, but the packet arrives via a different visited hop: the
    // route hash no longer matches the authorization.
    let mut other_addr = [0u8; 16];
    other_addr[0] = 0x02;
    other_addr[8..16].copy_from_slice(&[0x22; 8]);
    let packet = terminating_tunnel(
        &fixture.identity.ygg_addr,
        &fixture.identity.ygg_addr,
        &[other_addr],
        0,
        &fixture.inner,
    );
    assert_eq!(fixture.gateway.authorize_tunnel_egress(&packet, 100), None);
}

#[test]
fn wired_tunnel_to_mesh_destination_is_dropped() {
    let mut fixture = wired_setup();
    let wire = fixture.signed_post(1, 1_000);
    assert_eq!(fixture.post(&wire, 100), COAP_CHANGED);
    let inner = inner_datagram(fixture.inner_source, mesh_addr(0x99));
    let packet = terminating_tunnel(
        &fixture.identity.ygg_addr,
        &fixture.identity.ygg_addr,
        &[fixture.hop_addr],
        0,
        &inner,
    );
    assert_eq!(fixture.gateway.authorize_tunnel_egress(&packet, 100), None);
}

#[test]
fn wired_tunnel_from_external_source_is_dropped() {
    let mut fixture = wired_setup();
    let wire = fixture.signed_post(1, 1_000);
    assert_eq!(fixture.post(&wire, 100), COAP_CHANGED);
    let inner = inner_datagram([0x20; 16], [0x20; 16]);
    let packet = terminating_tunnel(
        &fixture.identity.ygg_addr,
        &fixture.identity.ygg_addr,
        &[fixture.hop_addr],
        0,
        &inner,
    );
    assert_eq!(fixture.gateway.authorize_tunnel_egress(&packet, 100), None);
}

#[test]
fn wired_expired_authorization_is_dropped() {
    let mut fixture = wired_setup();
    let wire = fixture.signed_post(1, 150);
    assert_eq!(fixture.post(&wire, 100), COAP_CHANGED);
    let packet = fixture.tunnel();
    assert_eq!(fixture.gateway.authorize_tunnel_egress(&packet, 200), None);
}

#[test]
fn wired_in_transit_source_route_is_dropped() {
    let mut fixture = wired_setup();
    let wire = fixture.signed_post(1, 1_000);
    assert_eq!(fixture.post(&wire, 100), COAP_CHANGED);
    // segments_left != 0: relay policy belongs to the node stack, never to
    // the border upstream path.
    let packet = terminating_tunnel(
        &fixture.identity.ygg_addr,
        &fixture.identity.ygg_addr,
        &[fixture.hop_addr],
        1,
        &fixture.inner,
    );
    assert_eq!(fixture.gateway.authorize_tunnel_egress(&packet, 100), None);
}

#[test]
fn wired_plain_upward_packet_passes_through() {
    let mut fixture = wired_setup();
    // Ordinary upward UDP datagram (no Routing header): not a tunnel, so the
    // authorization layer must not touch it.
    let mut packet = vec![0u8; 48];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&8u16.to_be_bytes());
    packet[6] = 17; // UDP
    packet[7] = 63;
    packet[8..24].copy_from_slice(&mesh_addr(0x77));
    packet[24..40].copy_from_slice(&[0x20; 16]);
    let forwarded = fixture.gateway.authorize_tunnel_egress(&packet, 100);
    assert_eq!(forwarded, Some(packet));
}

#[test]
fn wired_post_from_non_root_peer_is_forbidden() {
    let mut fixture = wired_setup();
    let attacker = wired_identity(0x99);
    // Well-formed self-consistent post, but signed by (and sent from) an
    // identity that is not the configured DODAG root.
    let route = fixture.route();
    let claim = TunnelAuthorization::new(
        fixture.inner_source,
        128,
        route_hash(&route).unwrap(),
        1,
        1_000,
        fixture.identity.iid,
    )
    .unwrap();
    let wire = build_root_post(
        claim,
        &route,
        attacker.iid,
        &attacker.privkey,
        &attacker.pubkey,
    )
    .unwrap()
    .body
    .as_bytes()
    .to_vec();
    assert_eq!(
        fixture
            .gateway
            .handle_tunnel_auth_request(
                CoapMethod::Post,
                &wire,
                attacker.iid,
                attacker.pubkey.as_bytes(),
                100,
            )
            .code,
        COAP_FORBIDDEN
    );
    // And the data plane stays closed afterwards.
    let packet = fixture.tunnel();
    assert_eq!(fixture.gateway.authorize_tunnel_egress(&packet, 100), None);
}

#[test]
fn wired_post_garbage_payload_is_forbidden() {
    let mut fixture = wired_setup();
    assert_eq!(fixture.post(b"not a cose sign1", 100), COAP_FORBIDDEN);
}

#[test]
fn wired_get_on_tunnel_auth_is_method_not_allowed() {
    let mut fixture = wired_setup();
    assert_eq!(
        fixture
            .gateway
            .handle_tunnel_auth_request(
                CoapMethod::Get,
                &[],
                fixture.identity.iid,
                fixture.identity.pubkey.as_bytes(),
                100,
            )
            .code,
        COAP_METHOD_NOT_ALLOWED
    );
}

#[test]
fn wired_tunnel_to_scoped_destination_is_dropped_despite_valid_grant() {
    // C tunnel_auth.c:434 / Python destination_allowed parity: unspecified,
    // loopback, multicast, and link-local destinations are out of egress
    // scope even when the (source prefix, route) grant is valid.
    let unspecified = [0u8; 16];
    let mut loopback = [0u8; 16];
    loopback[15] = 1;
    let mut multicast = [0u8; 16];
    multicast[0] = 0xff;
    multicast[1] = 0x02;
    multicast[15] = 1;
    let mut link_local = [0u8; 16];
    link_local[0] = 0xfe;
    link_local[1] = 0x80;
    for destination in [unspecified, loopback, multicast, link_local] {
        let mut fixture = wired_setup();
        let wire = fixture.signed_post(1, 1_000);
        assert_eq!(fixture.post(&wire, 100), COAP_CHANGED);
        let inner = inner_datagram(fixture.inner_source, destination);
        let packet = terminating_tunnel(
            &fixture.identity.ygg_addr,
            &fixture.identity.ygg_addr,
            &[fixture.hop_addr],
            0,
            &inner,
        );
        assert_eq!(
            fixture.gateway.authorize_tunnel_egress(&packet, 100),
            None,
            "scoped destination {destination:02x?} must be dropped"
        );
    }
}

#[test]
fn wired_tunnel_from_scoped_source_is_dropped_despite_matching_grant() {
    // C tunnel_auth.c:433 / Python source_allowed parity: a link-local (or
    // otherwise unsafe) source never rides the tunnel, even when a claim
    // prefix covers it — the grant below is over the link-local source
    // itself so the prefix match cannot be the reason for the denial.
    let mut fixture = wired_setup();
    let mut link_local_source = [0u8; 16];
    link_local_source[0] = 0xfe;
    link_local_source[1] = 0x80;
    link_local_source[15] = 0x77;
    let route = fixture.route();
    let claim = TunnelAuthorization::new(
        link_local_source,
        128,
        route_hash(&route).unwrap(),
        1,
        1_000,
        fixture.identity.iid,
    )
    .unwrap();
    let wire = build_root_post(
        claim,
        &route,
        fixture.identity.iid,
        &fixture.identity.privkey,
        &fixture.identity.pubkey,
    )
    .unwrap()
    .body
    .as_bytes()
    .to_vec();
    assert_eq!(fixture.post(&wire, 100), COAP_CHANGED);
    let inner = inner_datagram(link_local_source, [0x20; 16]);
    let packet = terminating_tunnel(
        &fixture.identity.ygg_addr,
        &fixture.identity.ygg_addr,
        &[fixture.hop_addr],
        0,
        &inner,
    );
    assert_eq!(fixture.gateway.authorize_tunnel_egress(&packet, 100), None);
}
