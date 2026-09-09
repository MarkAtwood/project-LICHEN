#![cfg(all(feature = "std", feature = "schnorr"))]

//! Destination-admission parity with the Python reference
//! (`python/src/lichen/link/link_layer.py::_wire_is_for_local`,
//! `ReceiveError.NOT_FOR_US`, bead project-LICHEN-worker6-er31).
//!
//! Contract mirrored point by point:
//! - AddrMode::None (broadcast) is always for local.
//! - AddrMode::Extended requires an exact EUI-64 match; a signed frame
//!   addressed to a third party is rejected `NotForUs` after
//!   authentication but before replay-window/pin mutation.
//! - AddrMode::Short is rejected: this stack carries no
//!   coordinator-assigned short address (Python rejects Short when none
//!   is configured either).
//! - AddrMode::Elided is accepted at this layer; the authoritative
//!   Elided destination check is the SCHC-derived IPv6 destination,
//!   enforced by the node stack (lichen-link cannot decompress SCHC).

use lichen_link::frame::AddrMode;
use lichen_link::identity::{Identity, PeerIdentity};
use lichen_link::link_layer::LinkLayer;
use lichen_link::{LinkRxError, LinkSeqNum, Seed};

fn eui64(id: &Identity) -> [u8; 8] {
    let mut eui = id.iid;
    eui[0] ^= 0x02;
    eui
}

fn signed_frame(
    sender: &LinkLayer,
    dst: &[u8],
    destination_mode: AddrMode,
    seqnum: u16,
) -> Vec<u8> {
    let mut wire = [0u8; 256];
    let length = sender
        .build_frame_with_addr_mode(
            0,
            LinkSeqNum::new(seqnum),
            dst,
            b"parity",
            destination_mode,
            &mut wire,
        )
        .unwrap();
    wire[..length].to_vec()
}

#[test]
fn extended_frame_addressed_to_third_party_is_not_for_us() {
    let alice = Identity::from_seed(Seed::new([0xA1; 32]));
    let bob = Identity::from_seed(Seed::new([0xB2; 32]));
    let charlie = Identity::from_seed(Seed::new([0xC3; 32]));

    let mut receiver = LinkLayer::new(bob.clone());
    receiver.add_peer(PeerIdentity::from_pubkey(alice.pubkey));

    let for_charlie = signed_frame(
        &LinkLayer::new(alice.clone()),
        &eui64(&charlie),
        AddrMode::Extended,
        1,
    );
    assert!(matches!(
        receiver.receive_frame(&for_charlie),
        Err(LinkRxError::NotForUs)
    ));

    // The same sender's frame addressed to local is accepted.
    let for_bob = signed_frame(
        &LinkLayer::new(alice.clone()),
        &eui64(&bob),
        AddrMode::Extended,
        2,
    );
    assert!(receiver.receive_frame(&for_bob).is_ok());

    // The NotForUs rejection consumed no replay-window state: a frame
    // with a seqnum BELOW the rejected one is still accepted (a window
    // advance would reject it as too old).
    let below_rejected = signed_frame(
        &LinkLayer::new(alice.clone()),
        &eui64(&bob),
        AddrMode::Extended,
        0,
    );
    assert!(receiver.receive_frame(&below_rejected).is_ok());
    let still_fresh = signed_frame(
        &LinkLayer::new(alice.clone()),
        &eui64(&bob),
        AddrMode::Extended,
        3,
    );
    assert!(receiver.receive_frame(&still_fresh).is_ok());
}

#[test]
fn broadcast_is_for_local_and_short_is_not() {
    let alice = Identity::from_seed(Seed::new([0xA4; 32]));
    let bob = Identity::from_seed(Seed::new([0xB5; 32]));

    let mut receiver = LinkLayer::new(bob.clone());
    receiver.add_peer(PeerIdentity::from_pubkey(alice.pubkey));
    let sender = LinkLayer::new(alice);

    let broadcast = signed_frame(&sender, &[], AddrMode::None, 1);
    assert!(receiver.receive_frame(&broadcast).is_ok());

    let short = signed_frame(&sender, &[0x12, 0x34], AddrMode::Short, 2);
    assert!(matches!(
        receiver.receive_frame(&short),
        Err(LinkRxError::NotForUs)
    ));
}
