#![cfg(all(feature = "std", feature = "schnorr"))]

//! Conformance tests for the ratified relay-signer key-selection policy
//! (bead project-LICHEN-worker6-nxew, option (b): SIID-indexed TOFU trust
//! store, normative in spec/02-physical-link.md §4.2 "Key Selection Policy").
//!
//! Policy encoded here, point by point:
//! 1. Lookup is by the frame's 8-byte SIID into the trust store (§4.2 ¶1).
//! 2. Verification runs against the pinned key only; failure rejects the
//!    frame with no trial verification or key substitution (§4.2 ¶2).
//! 3. The (SIID, key) binding is pinned on first VERIFIED contact only, and
//!    state (pin, replay) is never allocated pre-verify (§4.2 ¶3, ¶2).
//! 4. A frame whose SIID matches a pinned entry but whose signature verifies
//!    only under a DIFFERENT key MUST be rejected fail-closed; the pinned
//!    binding and the victim's replay state are left untouched (§4.2 ¶4).
//! 5. Eviction of a trust-store entry drops the pin and invalidates replay
//!    state for that signer (§4.2 ¶5; covered in-link_layer by
//!    `lru_eviction_drops_pin_and_invalidates_replay`).
//!
//! Oracles:
//! - `test/vectors/wire_format_v2.json` entries
//!   `wf2_signed_broadcast_sender_iid_only`, `wf2_hop_resign_inputs`, and
//!   `wf2_announce_epoch_replay_hop_resigned` were produced by the
//!   independent PyNaCl reference signer (see each vector's provenance).
//! - Relay re-sign counter semantics (relay populates its OWN SIID and its
//!   OWN fresh epoch/seqnum counter; downstream pins the relay, not the
//!   origin) are asserted against those vectors.
//!
//! The announce-layer half of `wf2_announce_epoch_replay_hop_resigned`
//! (STALE_SEQNUM rejection, spec 05 §9.3) lives above this crate and is not
//! exercised here; only the link-layer acceptance half is.

use std::fs;
use std::path::Path;

use serde::Deserialize;

use lichen_link::frame::{AddrMode, Encryption, LichenFrame, MicLength, Signature};
use lichen_link::identity::{Identity, PeerIdentity};
use lichen_link::link_layer::LinkLayer;
use lichen_link::schnorr::{sign, verify_frame, LINK_SIGNATURE_DOMAIN, LLSEC_SI_BIT};
use lichen_link::{LinkRxError, LinkSeqNum, PublicKey, Seed};

// ── wire_format_v2.json corpus ──────────────────────────────────────────────

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    #[serde(default)]
    encoded: String,
    crypto: Option<CryptoMeta>,
}

#[derive(Deserialize)]
struct CryptoMeta {
    #[serde(default)]
    public_key: String,
}

fn load_wf2() -> VectorFile {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/wire_format_v2.json");
    let content = fs::read_to_string(path).expect("read wire_format_v2 vectors");
    serde_json::from_str(&content).expect("parse wire_format_v2 vectors")
}

fn vector<'a>(file: &'a VectorFile, name: &str) -> &'a Vector {
    file.vectors
        .iter()
        .find(|v| v.name == name)
        .unwrap_or_else(|| panic!("missing vector {name}"))
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn seq(n: u16) -> LinkSeqNum {
    LinkSeqNum::new(n)
}

fn eui64(id: &Identity) -> [u8; 8] {
    let mut eui = id.iid;
    eui[0] ^= 0x02;
    eui
}

/// Provision `peer` on `rx` and consume one verified frame from it so the
/// (SIID, key) binding is pinned per spec §4.2 ¶3.
fn pinned_peer(rx: &mut LinkLayer, identity: &Identity, epoch: u8, seqnum: u16) {
    rx.add_peer(PeerIdentity::from_pubkey(identity.pubkey));
    let mut wire = [0u8; 256];
    let n = LinkLayer::new(identity.clone())
        .build_frame(epoch, seq(seqnum), &[], b"bootstrap", &mut wire)
        .unwrap();
    rx.receive_frame(&wire[..n])
        .expect("bootstrap frame from provisioned peer verifies and pins");
}

// ── §4.2 ¶3: pin on first verified contact ──────────────────────────────────

#[test]
fn pin_happens_on_first_verified_contact_only() {
    let victim = Identity::from_seed(Seed::new([0x64; 32]));
    let mut rx = LinkLayer::new(Identity::from_seed(Seed::new([0x65; 32])));

    // Provisioned but never verified: no pin yet — trust-store entry alone
    // does not establish the binding.
    rx.add_peer(PeerIdentity::from_pubkey(victim.pubkey));
    assert_eq!(rx.pinned_pubkey_for(&victim.iid), None);

    let mut wire = [0u8; 256];
    let n = LinkLayer::new(victim.clone())
        .build_frame(1, seq(10), &[], b"hello", &mut wire)
        .unwrap();
    rx.receive_frame(&wire[..n])
        .expect("verified contact accepted");
    assert_eq!(rx.pinned_pubkey_for(&victim.iid), Some(&victim.pubkey));
}

// ── §4.2 ¶4: key substitution against a pinned SIID fails closed ────────────

/// Build a wire frame signed by `signer` whose transcript carries
/// `claimed_eui` as the SIID — i.e. an attacker honestly signing a frame
/// that claims the victim's signer identity.
fn substitution_wire(signer: &Identity, claimed_eui: &[u8; 8], epoch: u8, seqnum: u16) -> Vec<u8> {
    let payload = b"substitute";
    let dst_addr: [u8; 0] = [];
    let length = (4 + dst_addr.len() + 8 + payload.len() + 48) as u8;
    let llsec = (AddrMode::None as u8) | (1 << 5) | LLSEC_SI_BIT;
    let mut msg = Vec::new();
    msg.extend_from_slice(LINK_SIGNATURE_DOMAIN);
    msg.push(length);
    msg.push(llsec);
    msg.push(epoch);
    msg.extend_from_slice(&seqnum.to_be_bytes());
    msg.push(dst_addr.len() as u8);
    msg.extend_from_slice(&dst_addr);
    msg.extend_from_slice(claimed_eui);
    msg.extend_from_slice(payload);
    let sig = sign(&signer.privkey, &signer.pubkey, &msg);

    // The signature is genuinely valid — under the ATTACKER's key — for this
    // exact transcript. A verifier that trial-verifies over its peer table
    // would accept it; the SIID-indexed policy must not.
    assert!(verify_frame(
        length,
        llsec,
        epoch,
        seq(seqnum),
        &dst_addr,
        claimed_eui,
        payload,
        &sig,
        &signer.pubkey,
    ));

    let frame = LichenFrame {
        epoch,
        seqnum: seq(seqnum),
        dst_addr: &dst_addr,
        signer_eui64: claimed_eui,
        payload,
        mic: &sig,
        addr_mode: AddrMode::None,
        mic_length: MicLength::Bits32,
        signature: Signature::Present,
        encryption: Encryption::Plaintext,
    };
    let mut wire = [0u8; 256];
    let n = frame.write_to(&mut wire).unwrap();
    wire[..n].to_vec()
}

#[test]
fn substitution_with_valid_foreign_signature_is_rejected_fail_closed() {
    let victim = Identity::from_seed(Seed::new([0x64; 32]));
    let attacker = Identity::from_seed(Seed::new([0x66; 32]));
    let mut rx = LinkLayer::new(Identity::from_seed(Seed::new([0x67; 32])));
    pinned_peer(&mut rx, &victim, 1, 10);

    // Attacker's valid signature over a transcript claiming the victim's
    // SIID: SIID resolves to the pinned victim key, verification under it
    // fails, and the policy forbids trying any other key (§4.2 ¶2, ¶4).
    let forged = substitution_wire(&attacker, &eui64(&victim), 2, 11);
    assert!(
        matches!(rx.receive_frame(&forged), Err(LinkRxError::UnknownSender)),
        "key substitution against a pinned SIID must be rejected"
    );

    // Fail-closed: the pinned binding is unchanged ...
    assert_eq!(rx.pinned_pubkey_for(&victim.iid), Some(&victim.pubkey));

    // ... and the forged frame did not allocate or advance the victim's
    // replay state (the genuine next counter value is still fresh).
    let mut wire = [0u8; 256];
    let n = LinkLayer::new(victim)
        .build_frame(2, seq(11), &[], b"real", &mut wire)
        .unwrap();
    rx.receive_frame(&wire[..n])
        .expect("victim's genuine frame must still be accepted after a rejected forgery");
}

#[test]
fn no_trial_verification_fallback_when_attacker_is_also_provisioned() {
    let victim = Identity::from_seed(Seed::new([0x64; 32]));
    let attacker = Identity::from_seed(Seed::new([0x66; 32]));
    let mut rx = LinkLayer::new(Identity::from_seed(Seed::new([0x68; 32])));
    pinned_peer(&mut rx, &victim, 1, 10);
    // The attacker is ALSO a provisioned peer under its own canonical SIID.
    rx.add_peer(PeerIdentity::from_pubkey(attacker.pubkey));

    // Same substitution: SIID-indexed resolution finds the VICTIM's pinned
    // key only. The attacker's provisioned key is never tried (§4.2 ¶2).
    let forged = substitution_wire(&attacker, &eui64(&victim), 2, 11);
    assert!(matches!(
        rx.receive_frame(&forged),
        Err(LinkRxError::UnknownSender)
    ));
    assert_eq!(rx.pinned_pubkey_for(&victim.iid), Some(&victim.pubkey));

    // The attacker's own identity keeps working under its OWN SIID, so the
    // rejection above is the SIID-indexed policy, not collateral damage.
    let mut wire = [0u8; 256];
    let n = LinkLayer::new(attacker)
        .build_frame(3, seq(1), &[], b"mine", &mut wire)
        .unwrap();
    rx.receive_frame(&wire[..n])
        .expect("attacker's own honest frames under its own SIID stay accepted");
}

// ── relay re-sign conformance against wire_format_v2 oracles ────────────────

#[test]
fn relay_resign_output_matches_pynacl_oracle_and_carries_own_siid() {
    let file = load_wf2();
    let origin = vector(&file, "wf2_signed_broadcast_sender_iid_only");
    let resign = vector(&file, "wf2_hop_resign_inputs");

    // Relay B: seed 0x01*32 per the vector's crypto.seed.
    let relay_identity = Identity::from_seed(Seed::new([0x01; 32]));
    assert_eq!(
        relay_identity.pubkey.as_bytes(),
        hex(&resign.crypto.as_ref().unwrap().public_key).as_slice(),
        "relay key derivation must match the vector's recorded public key"
    );

    let mut relay = LinkLayer::new(relay_identity.clone());
    relay.add_peer(PeerIdentity::from_pubkey(PublicKey::new(
        hex(&origin.crypto.as_ref().unwrap().public_key)
            .try_into()
            .unwrap(),
    )));

    let origin_wire = hex(&origin.encoded);
    let mut out = [0u8; 256];
    let outcome = relay
        .relay_verified_frame(
            &origin_wire,
            &[],
            AddrMode::None,
            None,
            6,
            seq(200),
            &mut out,
        )
        .expect("relay verifies the origin frame and re-signs");

    // Byte-exact against the independent PyNaCl reference re-signature.
    assert_eq!(
        &out[..outcome.len],
        hex(&resign.encoded).as_slice(),
        "relay re-sign output must equal the independent reference"
    );

    // The re-signed frame carries the RELAY's own SIID (8 bytes) and its own
    // counter (epoch 6, seqnum 200), and binds the verified upstream.
    let frame = LichenFrame::from_bytes(&out[..outcome.len]).unwrap();
    assert_eq!(frame.signer_eui64, eui64(&relay_identity).as_slice());
    assert_eq!(frame.signer_eui64, hex("3784728ae7309eab").as_slice());
    assert_eq!(frame.epoch, 6);
    assert_eq!(frame.seqnum.get(), 200);
    assert_eq!(
        outcome.upstream.pubkey.as_bytes(),
        hex(&origin.crypto.as_ref().unwrap().public_key).as_slice()
    );
}

#[test]
fn relay_resigned_frame_accepts_at_next_hop_with_fresh_counter() {
    let file = load_wf2();
    let resign = vector(&file, "wf2_announce_epoch_replay_hop_resigned");
    let relay_pub = PublicKey::new(
        hex(&resign.crypto.as_ref().unwrap().public_key)
            .try_into()
            .unwrap(),
    );

    let mut next_hop = LinkLayer::new(Identity::from_seed(Seed::new([0x7E; 32])));
    next_hop.add_peer(PeerIdentity::from_pubkey(relay_pub));

    // Link-layer half of the vector: a valid relay signature with a fresh
    // link counter (epoch 7, seqnum 55) is accepted, and trust binds to the
    // RELAY's key — the origin's signature inside the payload is not the
    // link layer's concern.
    let wire = hex(&resign.encoded);
    let received = next_hop
        .receive_frame(&wire)
        .expect("relay re-sign with fresh counter accepted at the next hop");
    assert_eq!(received.sender().pubkey.as_bytes(), relay_pub.as_bytes());
    assert_eq!(received.epoch(), 7);
    assert_eq!(received.seqnum().get(), 55);

    // The relay allocated its own counter for this emission: replaying the
    // identical relayed frame is rejected (spec §4.4 per-signer window).
    assert!(matches!(
        next_hop.receive_frame(&wire),
        Err(LinkRxError::Replay)
    ));
}
