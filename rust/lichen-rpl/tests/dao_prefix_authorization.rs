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
