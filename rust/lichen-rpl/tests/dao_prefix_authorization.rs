// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Literal allow/deny matrix for prefix DAO advertisement authorization
//! (spec/05-routing.md 8.7, 8.7.1, 8.7.2).
//!
//! The `.44.7` profile allows exactly one node-owned Target: the
//! authenticated origin's own /128. Unauthorized /0, foreign host routes,
//! and undelegated broad prefixes must be rejected before any route or
//! replay-floor mutation.

use lichen_core::addr::ygg_addr_from_pubkey;
use lichen_hal::storage::mem::MemStorage;
use lichen_link::identity::Identity;
use lichen_link::keys::Seed;
use lichen_link::link_layer::LinkLayer;
use lichen_rpl::message::{DaoOriginSignature, DAO_ORIGIN_SIGNATURE_LEN, OPT_TRANSIT_INFO};
use lichen_rpl::routing::{
    dao_origin_digest, DaoAdmissionState, DaoManager, DaoProcessError, DaoProcessOutcome,
    DaoProcessTiming, SignatureVerifiedDao,
};
use lichen_rpl::verify::{DaoMalformed, DaoVerifyError};
use std::net::Ipv6Addr;

fn signed_dao(
    unsigned: &[u8],
    origin: [u8; 16],
    dodag_id: [u8; 16],
    origin_sequence: u64,
    link: &LinkLayer,
) -> Vec<u8> {
    let digest = dao_origin_digest(origin, dodag_id, origin_sequence, unsigned);
    let signature = link.sign_digest(&digest);
    let mut wire = unsigned.to_vec();
    let offset = wire.len();
    wire.resize(offset + DAO_ORIGIN_SIGNATURE_LEN, 0);
    DaoOriginSignature::write_to(origin_sequence, &signature, &mut wire[offset..]).unwrap();
    wire
}

/// Target option built with a generalized (prefix_len, prefix) shape so the
/// /0 and sub-/128 rows exercise the wire-profile rejection.
fn prefix_target_dao(
    dao_sequence: u8,
    path_sequence: u8,
    prefix_len: u8,
    prefix: &[u8],
    parent: [u8; 16],
) -> Vec<u8> {
    let mut wire = vec![
        0,
        0,
        0,
        dao_sequence,
        5,
        (2 + prefix.len()) as u8,
        0,
        prefix_len,
    ];
    wire.extend_from_slice(prefix);
    wire.extend_from_slice(&[OPT_TRANSIT_INFO, 20, 0, 0x80, path_sequence, 255]);
    wire.extend_from_slice(&parent);
    wire
}

/// One matrix row: (name, target prefix octets, prefix length, expectation).
///
/// `Ok(allowed)` rows pass signature verification and then go through root
/// ingest; `Err(wire_error)` rows are rejected by the `.44.7` wire profile
/// during signature verification itself.
type PrefixAuthCase<'a> = (&'a str, Vec<u8>, u8, Result<bool, DaoVerifyError>);

#[test]
fn dao_prefix_authorization_allow_deny_matrix() {
    let root = [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let identity = Identity::from_seed(Seed::new([0x55; 32]));
    let origin = ygg_addr_from_pubkey(identity.pubkey.as_bytes());
    let foreign_identity = Identity::from_seed(Seed::new([0x66; 32]));
    let foreign = ygg_addr_from_pubkey(foreign_identity.pubkey.as_bytes());
    let link = LinkLayer::new(identity.clone());
    let timing = DaoProcessTiming {
        now_seconds: 100,
        lifetime_unit_seconds: 1,
        max_deadline_seconds: u64::MAX,
    };

    // (name, target prefix octets, prefix length, expected outcome)
    let cases: [PrefixAuthCase; 4] = [
        ("self_host_route_allowed", origin.to_vec(), 128, Ok(true)),
        (
            "foreign_host_route_rejected",
            foreign.to_vec(),
            128,
            Ok(false),
        ),
        // /0 and sub-/128 targets fail the .44.7 wire profile (Target option
        // data length MUST be 18, spec/05-routing.md 8.7) during signature
        // verification, before any routing policy or replay state is read.
        (
            "slash_zero_rejected",
            Vec::new(),
            0,
            Err(DaoVerifyError::Malformed(DaoMalformed::InvalidOptionLength)),
        ),
        (
            "undelegated_broad_prefix_rejected",
            vec![0x02, 0, 0, 0, 0, 0, 0, 0],
            64,
            Err(DaoVerifyError::Malformed(DaoMalformed::InvalidOptionLength)),
        ),
    ];

    for (name, prefix, prefix_len, expected) in cases {
        let unsigned = prefix_target_dao(1, 241, prefix_len, &prefix, root);
        let wire = signed_dao(&unsigned, origin, root, 1, &link);

        match expected {
            Err(wire_error) => {
                let verified = SignatureVerifiedDao::verify_signature(
                    &wire,
                    origin,
                    0,
                    root,
                    Some(identity.pubkey),
                );
                assert!(
                    matches!(verified, Err(err) if err == wire_error),
                    "{name}: expected {wire_error:?}, got {verified:?}"
                );
            }
            Ok(allowed) => {
                let verified = SignatureVerifiedDao::verify_signature(
                    &wire,
                    origin,
                    0,
                    root,
                    Some(identity.pubkey),
                )
                .unwrap_or_else(|err| panic!("{name}: signature must verify: {err:?}"));
                let mut storage = MemStorage::new();
                let (mut manager, mut rx_state) =
                    DaoManager::provision_root(&mut storage, Ipv6Addr::from(root), 0, root.into())
                        .unwrap();
                let mut admission =
                    DaoAdmissionState::provision(&mut storage, root, 0, root).unwrap();
                admission
                    .admit(&mut storage, *identity.pubkey.as_bytes())
                    .unwrap();

                let outcome = manager.process_signature_verified(
                    &verified,
                    verified.origin_iid(),
                    &mut rx_state,
                    &mut storage,
                    timing,
                    &admission,
                );

                if allowed {
                    assert_eq!(outcome, Ok(DaoProcessOutcome::Applied), "{name}");
                    assert!(manager.routing_table().lookup(&origin).is_some(), "{name}");
                    assert_eq!(manager.origin_high_water().len(), 1, "{name}");
                } else {
                    assert_eq!(outcome, Err(DaoProcessError::RouteRejected), "{name}");
                    assert!(manager.routing_table().lookup(&origin).is_none(), "{name}");
                    assert!(manager.routing_table().lookup(&foreign).is_none(), "{name}");
                    assert!(manager.origin_high_water().is_empty(), "{name}");
                }
            }
        }
    }
}

use lichen_hal::NonVolatile;
use lichen_link::keys::PublicKey;
use lichen_rpl::routing::{
    DaoRxState, PrefixAuthorizationError, PrefixDelegationError, UnauthorizedPrefixReason,
};

/// Transit option with an explicit flag byte (0x80 = external reachability).
fn transit_option(flag: u8, path_sequence: u8, parent: [u8; 16]) -> Vec<u8> {
    let mut wire = vec![OPT_TRANSIT_INFO, 20, flag, 0x80, path_sequence, 255];
    wire.extend_from_slice(&parent);
    wire
}

/// Target option with a generalized (prefix_len, prefix bytes) body.
fn target_option(prefix_len: u8, prefix: &[u8]) -> Vec<u8> {
    let mut wire = vec![5, (2 + prefix.len()) as u8, 0, prefix_len];
    wire.extend_from_slice(prefix);
    wire
}

/// DAO with independent (target, transit) groups, unsigned.
fn grouped_unsigned_dao(dao_sequence: u8, groups: &[Vec<u8>]) -> Vec<u8> {
    let mut wire = vec![0, 0, 0, dao_sequence];
    for group in groups {
        wire.extend_from_slice(group);
    }
    wire
}

/// Counts durable writes so tests can prove a denial persists nothing.
#[derive(Debug, Default)]
struct CountingStorage {
    inner: MemStorage,
    writes: core::cell::Cell<usize>,
}

impl CountingStorage {
    fn writes(&self) -> usize {
        self.writes.get()
    }
}

impl NonVolatile for CountingStorage {
    type Error = <MemStorage as NonVolatile>::Error;

    fn read(&self, key: &str, buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        self.inner.read(key, buf)
    }

    fn write(&mut self, key: &str, data: &[u8]) -> Result<(), Self::Error> {
        self.writes.set(self.writes.get() + 1);
        self.inner.write(key, data)
    }

    fn delete(&mut self, key: &str) -> bool {
        self.inner.delete(key)
    }
}

/// Root with one admitted origin (`origin`) and one foreign identity (`foreign`).
struct RootHarness {
    manager: DaoManager,
    rx_state: DaoRxState,
    admission: DaoAdmissionState,
    storage: CountingStorage,
    link: LinkLayer,
    origin: Ipv6Addr,
    origin_key: PublicKey,
    foreign: Ipv6Addr,
    foreign_key: PublicKey,
    root: Ipv6Addr,
    timing: DaoProcessTiming,
}

fn harness() -> RootHarness {
    let root = Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 1);
    let identity = Identity::from_seed(Seed::new([0x55; 32]));
    let foreign_identity = Identity::from_seed(Seed::new([0x66; 32]));
    let mut storage = CountingStorage::default();
    let (manager, rx_state) = DaoManager::provision_root(&mut storage, root, 0, root).unwrap();
    let mut admission =
        DaoAdmissionState::provision(&mut storage, root.octets(), 0, root.octets()).unwrap();
    admission
        .admit(&mut storage, *identity.pubkey.as_bytes())
        .unwrap();
    RootHarness {
        manager,
        rx_state,
        admission,
        storage,
        link: LinkLayer::new(identity.clone()),
        origin: ygg_addr_from_pubkey(identity.pubkey.as_bytes()).into(),
        origin_key: identity.pubkey,
        foreign: ygg_addr_from_pubkey(foreign_identity.pubkey.as_bytes()).into(),
        foreign_key: foreign_identity.pubkey,
        root,
        timing: DaoProcessTiming {
            now_seconds: 100,
            lifetime_unit_seconds: 1,
            max_deadline_seconds: u64::MAX,
        },
    }
}

/// Self /128 plus foreign /128 transit groups, as a delegated egress would send.
fn egress_unsigned_dao(h: &RootHarness) -> Vec<u8> {
    grouped_unsigned_dao(
        241,
        &[
            [
                target_option(128, &h.origin.octets()),
                transit_option(0, 241, h.root.octets()),
            ]
            .concat(),
            [
                target_option(128, &h.foreign.octets()),
                transit_option(0, 241, h.origin.octets()),
            ]
            .concat(),
        ],
    )
}

fn sign_and_verify<'a>(
    h: &RootHarness,
    unsigned: &[u8],
    wire: &'a mut Vec<u8>,
    origin_sequence: u64,
) -> SignatureVerifiedDao<'a> {
    *wire = signed_dao(
        unsigned,
        h.origin.octets(),
        h.root.octets(),
        origin_sequence,
        &h.link,
    );
    SignatureVerifiedDao::verify_signature(
        wire,
        h.origin.octets(),
        0,
        h.root.octets(),
        Some(h.origin_key),
    )
    .unwrap_or_else(|error| panic!("signature must verify: {error:?}"))
}

#[test]
fn delegated_prefix_is_allowed_and_denial_leaves_no_state_mutation() {
    let mut h = harness();
    let unsigned = egress_unsigned_dao(&h);

    // Deny first: foreign /128 is not delegated yet.
    assert_eq!(
        h.manager
            .authorize_dao_prefixes(&unsigned, h.origin_key.as_bytes(), h.origin),
        Err(PrefixAuthorizationError::Unauthorized(
            UnauthorizedPrefixReason::ForeignPrefix
        ))
    );
    let mut wire = Vec::new();
    let verified = sign_and_verify(&h, &unsigned, &mut wire, 1);
    let writes_before = h.storage.writes();
    let rx_before = format!("{:?}", h.rx_state);
    assert_eq!(
        h.manager.process_signature_verified(
            &verified,
            verified.origin_iid(),
            &mut h.rx_state,
            &mut h.storage,
            h.timing,
            &h.admission,
        ),
        Err(DaoProcessError::RouteRejected)
    );
    assert!(h
        .manager
        .routing_table()
        .lookup(&h.origin.octets())
        .is_none());
    assert!(h
        .manager
        .routing_table()
        .lookup(&h.foreign.octets())
        .is_none());
    assert!(h.manager.origin_high_water().is_empty());
    assert_eq!(h.storage.writes(), writes_before, "denial persists nothing");
    assert_eq!(format!("{:?}", h.rx_state), rx_before);

    // Same bytes, same origin_sequence: allowed once the prefix is delegated.
    h.manager
        .delegate_prefix(*h.origin_key.as_bytes(), h.foreign, 128)
        .unwrap();
    assert_eq!(
        h.manager
            .authorize_dao_prefixes(&unsigned, h.origin_key.as_bytes(), h.origin),
        Ok(())
    );
    let verified = sign_and_verify(&h, &unsigned, &mut wire, 1);
    assert_eq!(
        h.manager.process_signature_verified(
            &verified,
            verified.origin_iid(),
            &mut h.rx_state,
            &mut h.storage,
            h.timing,
            &h.admission,
        ),
        Ok(DaoProcessOutcome::Applied)
    );
    assert!(h
        .manager
        .routing_table()
        .lookup(&h.foreign.octets())
        .is_some());
    assert!(h
        .manager
        .routing_table()
        .lookup(&h.origin.octets())
        .is_some());
    assert_eq!(h.manager.origin_high_water().len(), 1);
    assert!(h.storage.writes() > writes_before);
}

#[test]
fn delegation_is_bound_to_the_delegated_public_key() {
    let mut h = harness();
    // Same prefix delegated to a different identity must not authorize origin.
    h.manager
        .delegate_prefix(*h.foreign_key.as_bytes(), h.foreign, 128)
        .unwrap();
    let unsigned = egress_unsigned_dao(&h);
    assert_eq!(
        h.manager
            .authorize_dao_prefixes(&unsigned, h.origin_key.as_bytes(), h.origin),
        Err(PrefixAuthorizationError::Unauthorized(
            UnauthorizedPrefixReason::ForeignPrefix
        ))
    );
    let mut wire = Vec::new();
    let verified = sign_and_verify(&h, &unsigned, &mut wire, 1);
    assert_eq!(
        h.manager.process_signature_verified(
            &verified,
            verified.origin_iid(),
            &mut h.rx_state,
            &mut h.storage,
            h.timing,
            &h.admission,
        ),
        Err(DaoProcessError::RouteRejected)
    );
    assert!(h.manager.origin_high_water().is_empty());
}

#[test]
fn gate_prefix_literals_self_foreign_default_and_delegated() {
    let mut h = harness();
    let key = h.origin_key.as_bytes();

    // Self /128: allowed without delegation.
    let self_only = grouped_unsigned_dao(
        241,
        &[[
            target_option(128, &h.origin.octets()),
            transit_option(0, 241, h.root.octets()),
        ]
        .concat()],
    );
    assert_eq!(
        h.manager.authorize_dao_prefixes(&self_only, key, h.origin),
        Ok(())
    );

    // Foreign /128 host route: denied.
    let foreign_only = grouped_unsigned_dao(
        241,
        &[[
            target_option(128, &h.foreign.octets()),
            transit_option(0, 241, h.origin.octets()),
        ]
        .concat()],
    );
    assert_eq!(
        h.manager
            .authorize_dao_prefixes(&foreign_only, key, h.origin),
        Err(PrefixAuthorizationError::Unauthorized(
            UnauthorizedPrefixReason::ForeignPrefix
        ))
    );

    // /0 default route: denied even though 0 prefix bytes are well-formed.
    let default_route = grouped_unsigned_dao(
        241,
        &[[
            target_option(0, &[]),
            transit_option(0, 241, h.root.octets()),
        ]
        .concat()],
    );
    assert_eq!(
        h.manager
            .authorize_dao_prefixes(&default_route, key, h.origin),
        Err(PrefixAuthorizationError::Unauthorized(
            UnauthorizedPrefixReason::DefaultRoute
        ))
    );

    // Delegated /64: allowed, including a non-canonical encoding (host bits
    // beyond the prefix length are ignored, spec 05 §8.7.1).
    let delegated_prefix = Ipv6Addr::new(0x2001, 0xdb8, 0xaa, 0, 0, 0, 0, 0);
    h.manager
        .delegate_prefix(*key, delegated_prefix, 64)
        .unwrap();
    let canonical = grouped_unsigned_dao(
        241,
        &[[
            target_option(64, &delegated_prefix.octets()[..8]),
            transit_option(0, 241, h.origin.octets()),
        ]
        .concat()],
    );
    assert_eq!(
        h.manager.authorize_dao_prefixes(&canonical, key, h.origin),
        Ok(())
    );
    // Non-canonical encoding: host bytes beyond ceil(prefix_len/8) are ignored.
    let mut padded_prefix = delegated_prefix.octets()[..8].to_vec();
    padded_prefix.extend_from_slice(&[0xff, 0xff]);
    let non_canonical = grouped_unsigned_dao(
        241,
        &[[
            target_option(64, &padded_prefix),
            transit_option(0, 241, h.origin.octets()),
        ]
        .concat()],
    );
    assert_eq!(
        h.manager
            .authorize_dao_prefixes(&non_canonical, key, h.origin),
        Ok(())
    );

    // A /63 target is not the exact /64 delegation: denied.
    let slash63 = grouped_unsigned_dao(
        241,
        &[[
            target_option(63, &delegated_prefix.octets()[..8]),
            transit_option(0, 241, h.origin.octets()),
        ]
        .concat()],
    );
    assert_eq!(
        h.manager.authorize_dao_prefixes(&slash63, key, h.origin),
        Err(PrefixAuthorizationError::Unauthorized(
            UnauthorizedPrefixReason::ForeignPrefix
        ))
    );

    // Malformed targets: truncated prefix body, oversized length, no target.
    let truncated = grouped_unsigned_dao(
        241,
        &[[
            target_option(64, &[0x20, 0x01, 0x0d, 0xb8, 0x00, 0xaa, 0x00]),
            transit_option(0, 241, h.origin.octets()),
        ]
        .concat()],
    );
    assert_eq!(
        h.manager.authorize_dao_prefixes(&truncated, key, h.origin),
        Err(PrefixAuthorizationError::MalformedTarget)
    );
    let oversized = grouped_unsigned_dao(
        241,
        &[[
            target_option(129, &[0x20; 17]),
            transit_option(0, 241, h.origin.octets()),
        ]
        .concat()],
    );
    assert_eq!(
        h.manager.authorize_dao_prefixes(&oversized, key, h.origin),
        Err(PrefixAuthorizationError::MalformedTarget)
    );
    let targetless = vec![0, 0, 0, 241];
    assert_eq!(
        h.manager.authorize_dao_prefixes(&targetless, key, h.origin),
        Err(PrefixAuthorizationError::MalformedTarget)
    );
}

#[test]
fn delegation_api_fails_closed_on_default_route_and_capacity() {
    let mut h = harness();
    let key = *h.origin_key.as_bytes();

    // ::/0 is never delegable.
    assert_eq!(
        h.manager.delegate_prefix(key, Ipv6Addr::UNSPECIFIED, 0),
        Err(PrefixDelegationError::DefaultRoute)
    );
    assert_eq!(
        h.manager
            .delegate_prefix(key, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 129),
        Err(PrefixDelegationError::PrefixLength)
    );

    // Table is bounded; re-delegating an existing entry stays idempotent.
    for index in 0..u8::try_from(lichen_rpl::routing::MAX_PREFIX_DELEGATIONS).unwrap() {
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, u16::from(index), 0, 0, 0, 0, 0);
        h.manager.delegate_prefix(key, prefix, 64).unwrap();
        h.manager.delegate_prefix(key, prefix, 64).unwrap();
    }
    assert_eq!(
        h.manager.prefix_delegations().len(),
        lichen_rpl::routing::MAX_PREFIX_DELEGATIONS
    );
    assert_eq!(
        h.manager
            .delegate_prefix(key, Ipv6Addr::new(0x2001, 0xdb8, 0xff, 0, 0, 0, 0, 0), 64),
        Err(PrefixDelegationError::Capacity)
    );
}

#[test]
fn external_egress_transit_is_rejected_at_routing_layer_without_mutation() {
    let mut h = harness();
    let unsigned = grouped_unsigned_dao(
        241,
        &[[
            target_option(128, &h.origin.octets()),
            transit_option(0x80, 241, h.root.octets()),
        ]
        .concat()],
    );
    let mut wire = Vec::new();
    let verified = sign_and_verify(&h, &unsigned, &mut wire, 1);
    let writes_before = h.storage.writes();
    assert_eq!(
        h.manager.process_signature_verified(
            &verified,
            verified.origin_iid(),
            &mut h.rx_state,
            &mut h.storage,
            h.timing,
            &h.admission,
        ),
        Err(DaoProcessError::RouteRejected)
    );
    assert!(h
        .manager
        .routing_table()
        .lookup(&h.origin.octets())
        .is_none());
    assert!(h.manager.origin_high_water().is_empty());
    assert_eq!(h.storage.writes(), writes_before);
}
