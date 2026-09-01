#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate relay signer identity and multi-hop chain vectors.

Covers the normative key-selection policy of spec/02-physical-link.md
section 4.2 (SIID-indexed TOFU trust store, option (b) of bead
project-LICHEN-worker6-nxew) for relayed frames:

  - multi-hop A->B->C relay chain: the origin A signs once; the relay B
    preserves the payload octet-for-octet, populates its own SIID and its
    own replay counter, and signs with its own key; the downstream
    receiver C pins the relay's (SIID, key) binding -- the immediate
    signer -- never the origin's,
  - RFC 6554 SRH destination-mutation variant: the relay re-signs a frame
    whose link destination changed from the inbound next hop to the
    outbound next hop; only the immediate relay's signature can cover the
    mutated transcript,
  - fail-closed substitution: an attacker reusing a victim's SIID with its
    own key MUST be rejected, including when the attacker's key is itself
    a provisioned candidate (pinned SIIDs verify against the pinned key
    only; no fallback),
  - trust-cache behavior per the decided semantics: pin on first VERIFIED
    contact, reject on pinned-SIID key mismatch, and eviction of a
    (SIID, key) binding MUST invalidate all replay state for that signer
    (a lower counter is acceptable again after eviction as a fresh first
    contact).

Oracles are independent of the implementations under test:

  - frame octets are hand-assembled from the spec 4.1 wire table and the
    spec 4.2 LLSec bit table; no production frame code is imported,
  - signatures come from reference_schnorr48.py (libsodium via PyNaCl)
    over the Link Signature Domain Version 1 transcript, never from
    lichen.crypto.schnorr48,
  - the preserved relay payload is borrowed verbatim from the committed
    wire_format_v2.json announce corpus (originator = node A), so the
    payload-origin bytes are canonical committed data rather than newly
    invented bytes.

Documented readings (also recorded in the file description):

  - "RFC 6554 SRH destination mutation" is modeled at link scope as the
    next-hop DST swap of the link frame; in-packet SRH header processing
    (RFC 6554 section 4.1 segment-left decrement and address swap) is an
    upper-layer permitted payload mutation specified by
    source_route_hop_limit.json / srh_root_insertion.json and is out of
    scope here.
  - Trust-store entries are (SIID, public key) pairs with SIID in wire
    EUI-64 form (the key-derived IID with the U/L bit toggled once).
  - Spec 4.2 rule 3's "multiple candidates verify" branch is
    cryptographically unreachable for distinct keys (a Schnorr-48
    signature verifies under at most one public key), so no vector can
    exercise it; implementations still MUST reject if their candidate
    set reports more than one verification.
  - The eviction-replay vector pins the observable consequence of rule 5:
    after eviction, a frame below the previous high-water counter is
    acceptable again as a fresh first contact (it still must carry a
    valid signature under the re-pinned key).

Regenerate after editing:
    python3 test/vectors/generate_relay_signer_chain.py
Verify without writing:
    python3 test/vectors/generate_relay_signer_chain.py --check
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

VECTORS_DIR = Path(__file__).resolve().parent
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

from atomic_json import (  # noqa: E402
    atomic_write_json_batch,
    json_bytes,
    read_bounded_exact,
)
from reference_schnorr48 import (  # noqa: E402
    ReferenceIdentity,
    sign,
    signature_transcript,
    verify,
)

FORMAT_VERSION = 2
OUTPUT = VECTORS_DIR / "relay_signer_chain.json"

# Chain identities. A and B reuse the wire_format_v2 identities so the
# relay-chain corpus stays byte-comparable with the baseline wire corpus.
SEED_A = bytes(32)  # origin (payload/DAO origin)
SEED_B = bytes([0x01]) * 32  # relay hop 1 (immediate signer seen by C)
SEED_C = bytes([0x02]) * 32  # downstream receiver (trust-cache owner)
SEED_X = bytes([0xFF]) * 32  # attacker

_SI_BIT = 0x80
_ENC_BIT = 0x40
_SIGNATURE_BIT = 0x20

# Preserved payload: the wf2_announce_fresh_counter_accept announce corpus
# from wire_format_v2.json verbatim (0x15 routing dispatch + announce whose
# originator is node A). Link-layer vectors treat it as opaque bytes.
_PRESERVED_ORIGIN_PAYLOAD_HEX = (
    "1501000000047dd5cfc679ab63423b6a27bcceb6a42d62a3a8d02a6f0d73653215771d"
    "e243a63ac048a18b59da290621c68fe37b06daa69207e9ca9bf00851d3754c7396536"
    "145a135aa70f22150b0002bb1fd0902bee74cdb89403716077766322d7265706c6179"
    "2d70726f6265"
)
_PRESERVED_ORIGIN_PAYLOAD = bytes.fromhex(_PRESERVED_ORIGIN_PAYLOAD_HEX)

# Opaque attacker payloads (not a routing dispatch; link vectors do not
# parse payloads).
_SUBSTITUTION_PAYLOAD = bytes.fromhex("7701") + b"victim-siid-probe"
_PROBE_PAYLOAD = bytes.fromhex("7701") + b"unknown-siid-probe"

_FRAME_CRYPTO_PROVENANCE = (
    "Independent PyNaCl reference signer over Link Signature Domain Version 1 "
    "and the normative transcript with non-wire DST_LEN={dst_len}. Frame octets "
    "hand-derived from the spec 4.1 wire table and spec 4.2 LLSec bit table."
)


def _llsec_byte(*, addr_mode: int) -> int:
    """Signed frame LLSec: SI=1, S=1, mic_length selector 0 (spec 4.2)."""
    return _SI_BIT | _SIGNATURE_BIT | (addr_mode & 0x3)


def _addr_mode_width(addr_mode: int) -> int:
    return {0: 0, 1: 2, 2: 8, 3: 0}[addr_mode]


def _signed_frame(
    identity: ReferenceIdentity,
    *,
    epoch: int,
    seqnum: int,
    dst_addr: bytes,
    payload: bytes,
    addr_mode: int,
    siid_override: bytes | None = None,
) -> tuple[dict[str, object], bytes]:
    """Hand-assemble one signed frame strictly from the spec 4.1/4.2 tables.

    ``siid_override`` stamps a foreign Signer Identifier (the key-substitution
    attack form: the transcript binds the victim's SIID octets while the
    signature is produced by the attacker's key).
    """
    assert 0 <= epoch <= 0xFF
    assert 0 <= seqnum <= 0xFFFF
    signer_eui64 = identity.eui64 if siid_override is None else siid_override
    assert len(signer_eui64) == 8
    width = _addr_mode_width(addr_mode)
    assert len(dst_addr) == width, "dst_addr width must match addr mode"
    max_payload = 254 - 4 - width - 8 - 48
    assert len(payload) <= max_payload, "payload exceeds signed frame bound"

    body = (
        bytes([_llsec_byte(addr_mode=addr_mode)])
        + bytes([epoch])
        + seqnum.to_bytes(2, "big")
        + dst_addr
        + signer_eui64
        + payload
    )
    # LENGTH counts the whole body after the length byte, including the
    # 48-byte signature (spec 4.1: 4-254).
    wire_prefix = bytes([len(body) + 48]) + body
    transcript = signature_transcript(wire_prefix, width)
    signature = sign(identity, transcript)
    assert verify(identity.pubkey, transcript, signature)
    encoded = wire_prefix + signature
    crypto = {
        "seed": identity.seed.hex(),
        "private_key": identity.private_scalar.hex(),
        "public_key": identity.pubkey.hex(),
        "preimage": transcript.hex(),
        "wire_prefix": wire_prefix.hex(),
        "signature": signature.hex(),
        "provenance": _FRAME_CRYPTO_PROVENANCE.format(dst_len=width),
    }
    fields = {
        "epoch": epoch,
        "seqnum": seqnum,
        "dst_addr": dst_addr.hex(),
        "payload": payload.hex(),
        "mic": signature.hex(),
        "addr_mode": addr_mode,
        "mic_length": 0,
        "signature_present": True,
        "encrypted": False,
        "signer_eui64": signer_eui64.hex(),
        "signer_eui64_present": True,
    }
    return crypto, fields, encoded


def _frame_vector(
    name: str,
    description: str,
    signer: ReferenceIdentity,
    *,
    receiver: str,
    trust_store_before: dict[bytes, bytes],
    candidate_keys: list[ReferenceIdentity],
    epoch: int,
    seqnum: int,
    dst_addr: bytes,
    payload: bytes,
    addr_mode: int,
    expect: dict[str, object],
    siid_override: bytes | None = None,
) -> dict[str, object]:
    crypto, fields, encoded = _signed_frame(
        signer,
        epoch=epoch,
        seqnum=seqnum,
        dst_addr=dst_addr,
        payload=payload,
        addr_mode=addr_mode,
        siid_override=siid_override,
    )
    return {
        "name": name,
        "kind": "frame",
        "description": description,
        "receiver": receiver,
        "scenario": {
            "trust_store_before": {
                siid.hex(): pubkey.hex() for siid, pubkey in trust_store_before.items()
            },
            "candidate_keys": [peer.pubkey.hex() for peer in candidate_keys],
        },
        "fields": fields,
        "encoded": encoded.hex(),
        "crypto": crypto,
        "expect": expect,
    }


def _expect(
    *,
    decision: str,
    verify_pubkey: bytes | None,
    must_not_verify: list[ReferenceIdentity],
    authenticated_signer: bytes | None,
    trust_store_after: dict[bytes, bytes],
    reject_reason: str | None = None,
    decoy_verifying_pubkeys: list[ReferenceIdentity] | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "decision": decision,
        "verify_pubkey": verify_pubkey.hex() if verify_pubkey else None,
        "must_not_verify_pubkeys": [peer.pubkey.hex() for peer in must_not_verify],
        "authenticated_signer": (
            authenticated_signer.hex() if authenticated_signer else None
        ),
        "trust_store_after": {
            siid.hex(): pubkey.hex() for siid, pubkey in trust_store_after.items()
        },
    }
    if reject_reason is not None:
        value["reject_reason"] = reject_reason
    if decoy_verifying_pubkeys is not None:
        value["decoy_verifying_pubkeys"] = [
            peer.pubkey.hex() for peer in decoy_verifying_pubkeys
        ]
    return value


def _sequence_vector(
    name: str,
    description: str,
    *,
    receiver: str,
    trust_store_before: dict[bytes, bytes],
    candidate_keys: list[ReferenceIdentity],
    operations: list[dict[str, object]],
    trust_store_after: dict[bytes, bytes],
) -> dict[str, object]:
    return {
        "name": name,
        "kind": "sequence",
        "description": description,
        "receiver": receiver,
        "scenario": {
            "trust_store_before": {
                siid.hex(): pubkey.hex() for siid, pubkey in trust_store_before.items()
            },
            "candidate_keys": [peer.pubkey.hex() for peer in candidate_keys],
        },
        "operations": operations,
        "expect": {
            "trust_store_after": {
                siid.hex(): pubkey.hex() for siid, pubkey in trust_store_after.items()
            }
        },
    }


def document() -> dict[str, object]:
    a = ReferenceIdentity.from_seed(SEED_A)
    b = ReferenceIdentity.from_seed(SEED_B)
    c = ReferenceIdentity.from_seed(SEED_C)
    x = ReferenceIdentity.from_seed(SEED_X)

    # Cross-file integrity: the preserved payload must be byte-identical to
    # the committed wire_format_v2 announce corpus it borrows from.
    wf2_path = VECTORS_DIR / "wire_format_v2.json"
    if wf2_path.is_file():
        with wf2_path.open("r", encoding="utf-8") as handle:
            wf2 = json.load(handle)
        committed = next(
            v
            for v in wf2["vectors"]
            if v["name"] == "wf2_announce_fresh_counter_accept"
        )
        assert committed["fields"]["payload"] == _PRESERVED_ORIGIN_PAYLOAD_HEX, (
            "preserved payload diverged from wire_format_v2.json"
        )

    a_pin = {a.eui64: a.pubkey}
    b_pin = {b.eui64: b.pubkey}
    no_pins: dict[bytes, bytes] = {}

    vectors: list[dict[str, object]] = []

    # --- Multi-hop chain: A -> B -> C ------------------------------------
    vectors.append(
        _frame_vector(
            "rsc_chain_origin_A_broadcast",
            "Hop 0: origin A signs a broadcast frame carrying the preserved "
            "announce payload (originator = A). Relay B consumes this frame; "
            "first contact pins (A SIID, A key).",
            a,
            receiver="B",
            trust_store_before=no_pins,
            candidate_keys=[a],
            epoch=5,
            seqnum=300,
            dst_addr=b"",
            payload=_PRESERVED_ORIGIN_PAYLOAD,
            addr_mode=0,
            expect=_expect(
                decision="accept",
                verify_pubkey=a.pubkey,
                must_not_verify=[b, c, x],
                authenticated_signer=a.pubkey,
                trust_store_after=a_pin,
            ),
        )
    )
    vectors.append(
        _frame_vector(
            "rsc_chain_hop1_B_resigned_broadcast",
            "Hop 1: relay B re-signs the preserved payload under its own "
            "identity (own SIID, own counter, origin MIC never forwarded). "
            "Downstream C consumes this frame on first contact and pins the "
            "relay's (B SIID, B key) binding -- the immediate signer, never "
            "the payload origin A (spec 02 4.2).",
            b,
            receiver="C",
            trust_store_before=no_pins,
            candidate_keys=[b],
            epoch=6,
            seqnum=400,
            dst_addr=b"",
            payload=_PRESERVED_ORIGIN_PAYLOAD,
            addr_mode=0,
            expect=_expect(
                decision="accept",
                verify_pubkey=b.pubkey,
                must_not_verify=[a, c, x],
                authenticated_signer=b.pubkey,
                trust_store_after=b_pin,
            ),
        )
    )

    # --- RFC 6554 SRH destination-mutation variant ------------------------
    vectors.append(
        _frame_vector(
            "rsc_srh_origin_A_unicast_to_B",
            "SRH variant hop 0: A signs a unicast frame whose link "
            "destination is relay B's canonical EUI-64 (the inbound next hop "
            "of the source route). B has already pinned A (previous vector), "
            "so this exercises the pinned-first accept path.",
            a,
            receiver="B",
            trust_store_before=a_pin,
            candidate_keys=[a],
            epoch=5,
            seqnum=301,
            dst_addr=b.eui64,
            payload=_PRESERVED_ORIGIN_PAYLOAD,
            addr_mode=2,
            expect=_expect(
                decision="accept",
                verify_pubkey=a.pubkey,
                must_not_verify=[b, c, x],
                authenticated_signer=a.pubkey,
                trust_store_after=a_pin,
            ),
        )
    )
    vectors.append(
        _frame_vector(
            "rsc_srh_hop1_B_unicast_to_C_dst_mutated",
            "SRH variant hop 1: relay B re-signs toward the outbound next "
            "hop C. The link destination mutated from B's EUI-64 (inbound, "
            "previous vector) to C's EUI-64, so the transcript differs in "
            "DST_LEN/Dst plus B's identity and counter; the payload origin "
            "A could not have produced this signature. C pins B and verifies "
            "the mutated transcript only under the pinned relay key.",
            b,
            receiver="C",
            trust_store_before=b_pin,
            candidate_keys=[b],
            epoch=6,
            seqnum=401,
            dst_addr=c.eui64,
            payload=_PRESERVED_ORIGIN_PAYLOAD,
            addr_mode=2,
            expect=_expect(
                decision="accept",
                verify_pubkey=b.pubkey,
                must_not_verify=[a, c, x],
                authenticated_signer=b.pubkey,
                trust_store_after=b_pin,
            ),
        )
    )

    # --- Fail-closed substitution -----------------------------------------
    vectors.append(
        _frame_vector(
            "rsc_substitution_unknown_attacker_own_siid",
            "Attacker X introduces its own SIID with a valid self-signed "
            "frame. C has no pin for X's SIID and X is not a provisioned "
            "candidate, so first contact has zero verifying candidates: the "
            "frame MUST be rejected and nothing may be pinned.",
            x,
            receiver="C",
            trust_store_before=no_pins,
            candidate_keys=[b],
            epoch=9,
            seqnum=900,
            dst_addr=b"",
            payload=_PROBE_PAYLOAD,
            addr_mode=0,
            expect=_expect(
                decision="reject",
                verify_pubkey=None,
                must_not_verify=[a, b, c],
                authenticated_signer=None,
                trust_store_after=no_pins,
                reject_reason="no_candidate_verified",
            ),
        )
    )
    vectors.append(
        _frame_vector(
            "rsc_substitution_victim_siid_no_fallback",
            "Key substitution: attacker X signs with its own key but reuses "
            "victim B's SIID. C has B's SIID pinned, so the receiver MUST "
            "verify only against the pinned B key, fail, and reject WITHOUT "
            "falling back to trial verification -- even though X's key is "
            "itself a provisioned candidate whose key would verify this "
            "transcript (decoy). This is spec 02 4.2 rules 2 and 4 (TOFU "
            "violation / key substitution).",
            x,
            receiver="C",
            trust_store_before=b_pin,
            candidate_keys=[a, b, c, x],
            epoch=9,
            seqnum=901,
            dst_addr=b"",
            payload=_SUBSTITUTION_PAYLOAD,
            addr_mode=0,
            siid_override=b.eui64,
            expect=_expect(
                decision="reject",
                verify_pubkey=None,
                must_not_verify=[b],
                authenticated_signer=None,
                trust_store_after=b_pin,
                reject_reason="pinned_siid_verification_failed_no_fallback",
                decoy_verifying_pubkeys=[x],
            ),
        )
    )

    # Cache-behavior reference frame: a lower counter below B's high-water.
    vectors.append(
        _frame_vector(
            "rsc_cache_B_lower_counter",
            "Reference frame for the eviction sequences: a valid B-signed "
            "broadcast whose replay counter (epoch 6, seqnum 368) sits below "
            "the high-water (400) C recorded from "
            "rsc_chain_hop1_B_resigned_broadcast. The standalone decision "
            "here assumes the pin was re-provisioned WITHOUT replay state "
            "(e.g. restored from an out-of-band trust snapshot), so 368 is a "
            "fresh first contact and MUST be accepted. With replay state "
            "intact the same frame is a replay (see "
            "rsc_seq_lower_counter_replay_rejected_without_eviction) and "
            "after eviction it is acceptable again (see "
            "rsc_seq_eviction_invalidates_replay_state).",
            b,
            receiver="C",
            trust_store_before=b_pin,
            candidate_keys=[b],
            epoch=6,
            seqnum=368,
            dst_addr=b"",
            payload=_PRESERVED_ORIGIN_PAYLOAD,
            addr_mode=0,
            expect=_expect(
                decision="accept",
                verify_pubkey=b.pubkey,
                must_not_verify=[a, c, x],
                authenticated_signer=b.pubkey,
                trust_store_after=b_pin,
            ),
        )
    )

    # --- Trust-cache sequences (decided option (b) semantics) -------------
    vectors.append(
        _sequence_vector(
            "rsc_seq_first_contact_pin_then_replay_rejected",
            "Pin on first VERIFIED contact: the first delivery of B's frame "
            "is accepted and pins (B SIID, B key); the identical frame "
            "redelivered is rejected as a replay. Nothing but a verified "
            "signature may allocate trust or replay state.",
            receiver="C",
            trust_store_before=no_pins,
            candidate_keys=[b],
            operations=[
                {
                    "op": "receive",
                    "frame": "rsc_chain_hop1_B_resigned_broadcast",
                    "expect": {
                        "decision": "accept",
                        "authenticated_signer": b.pubkey.hex(),
                    },
                },
                {
                    "op": "receive",
                    "frame": "rsc_chain_hop1_B_resigned_broadcast",
                    "expect": {
                        "decision": "reject",
                        "reject_reason": "replay",
                    },
                },
            ],
            trust_store_after=b_pin,
        )
    )
    vectors.append(
        _sequence_vector(
            "rsc_seq_eviction_invalidates_replay_state",
            "Eviction semantics (spec 02 4.2 rule 5): after C accepts B at "
            "counter 400, local policy evicts the (B SIID, B key) binding; "
            "the eviction MUST also invalidate B's replay state, so the "
            "lower-counter frame (368, below the 32-slot window under 400) is then "
            "acceptable as a fresh first contact under a re-pinned key. A "
            "receiver that retained "
            "the old high-water would wrongly reject it.",
            receiver="C",
            trust_store_before=no_pins,
            candidate_keys=[b],
            operations=[
                {
                    "op": "receive",
                    "frame": "rsc_chain_hop1_B_resigned_broadcast",
                    "expect": {
                        "decision": "accept",
                        "authenticated_signer": b.pubkey.hex(),
                    },
                },
                {"op": "evict", "siid": b.eui64.hex()},
                {
                    "op": "receive",
                    "frame": "rsc_cache_B_lower_counter",
                    "expect": {
                        "decision": "accept",
                        "authenticated_signer": b.pubkey.hex(),
                    },
                },
            ],
            trust_store_after=b_pin,
        )
    )
    vectors.append(
        _sequence_vector(
            "rsc_seq_downstream_pins_immediate_signer_not_origin",
            "Selected signer identity per hop: C (two hops from the origin) "
            "pins only the immediate relay B and accepts B's re-signed "
            "frame without any knowledge of A -- the relay chain requires "
            "and creates no trust in the payload origin at link scope. The "
            "second operation documents spec 02 4.2 rule 3's announced-"
            "candidate branch: if A's own frame physically reaches C, the "
            "zero-hop canonical Announce inside it is exactly one announced "
            "candidate key and the frame is accepted as a bootstrap first "
            "contact (relayed announces can never bootstrap their relay's "
            "outer signer). Origin authentication for relayed traffic "
            "remains the application-layer DAO Origin Signature profile's "
            "job (spec 02 4.2 final paragraph).",
            receiver="C",
            trust_store_before=no_pins,
            candidate_keys=[b],
            operations=[
                {
                    "op": "receive",
                    "frame": "rsc_chain_hop1_B_resigned_broadcast",
                    "expect": {
                        "decision": "accept",
                        "authenticated_signer": b.pubkey.hex(),
                    },
                },
                {
                    "op": "receive",
                    "frame": "rsc_chain_origin_A_broadcast",
                    "expect": {
                        "decision": "accept",
                        "authenticated_signer": a.pubkey.hex(),
                    },
                },
            ],
            trust_store_after={**b_pin, **a_pin},
        )
    )
    vectors.append(
        _sequence_vector(
            "rsc_seq_lower_counter_replay_rejected_without_eviction",
            "Control for the eviction sequence: with B's pin AND replay "
            "state intact (C accepted B at counter 400 in operation 1), the "
            "lower-counter frame (368, below the 32-slot window under 400) MUST be "
            "rejected as a replay. Contrast "
            "rsc_seq_eviction_invalidates_replay_state, where the "
            "eviction of the (SIID, key) binding invalidates the replay "
            "state and the identical frame is then acceptable.",
            receiver="C",
            trust_store_before=no_pins,
            candidate_keys=[b],
            operations=[
                {
                    "op": "receive",
                    "frame": "rsc_chain_hop1_B_resigned_broadcast",
                    "expect": {
                        "decision": "accept",
                        "authenticated_signer": b.pubkey.hex(),
                    },
                },
                {
                    "op": "receive",
                    "frame": "rsc_cache_B_lower_counter",
                    "expect": {
                        "decision": "reject",
                        "reject_reason": "replay",
                    },
                },
            ],
            trust_store_after=b_pin,
        )
    )
    vectors.append(
        _sequence_vector(
            "rsc_seq_substitution_attack_leaves_trust_store_intact",
            "A rejected substitution attempt must not mutate trust or "
            "replay state: after X's victim-SIID frame is rejected without "
            "fallback, the legitimate relay frame still verifies and the "
            "pinned binding is unchanged. Scenario note: the store holds "
            "B's pin restored without replay state (e.g. re-provisioned), "
            "so B's counter 400 is fresh.",
            receiver="C",
            trust_store_before=b_pin,
            candidate_keys=[a, b, c, x],
            operations=[
                {
                    "op": "receive",
                    "frame": "rsc_substitution_victim_siid_no_fallback",
                    "expect": {
                        "decision": "reject",
                        "reject_reason": "pinned_siid_verification_failed_no_fallback",
                    },
                },
                {
                    "op": "receive",
                    "frame": "rsc_chain_hop1_B_resigned_broadcast",
                    "expect": {
                        "decision": "accept",
                        "authenticated_signer": b.pubkey.hex(),
                    },
                },
            ],
            trust_store_after=b_pin,
        )
    )

    identities = {
        "A": {
            "role": "origin (payload/DAO origin)",
            "seed": SEED_A.hex(),
            "public_key": a.pubkey.hex(),
            "siid_eui64": a.eui64.hex(),
        },
        "B": {
            "role": "relay hop 1 (immediate signer at C)",
            "seed": SEED_B.hex(),
            "public_key": b.pubkey.hex(),
            "siid_eui64": b.eui64.hex(),
        },
        "C": {
            "role": "downstream receiver (trust-cache owner)",
            "seed": SEED_C.hex(),
            "public_key": c.pubkey.hex(),
            "siid_eui64": c.eui64.hex(),
        },
        "X": {
            "role": "attacker",
            "seed": SEED_X.hex(),
            "public_key": x.pubkey.hex(),
            "siid_eui64": x.eui64.hex(),
        },
    }

    return {
        "$schema": "./relay_signer_chain.schema.json",
        "format_version": FORMAT_VERSION,
        "name": "relay_signer_chain",
        "description": (
            "Relay signer identity, multi-hop A->B->C chain, RFC 6554 SRH "
            "destination-mutation variant, fail-closed key substitution, and "
            "SIID-indexed TOFU trust-cache behavior per the normative key "
            "selection policy of spec 02 section 4.2 (option (b), bead "
            "project-LICHEN-worker6-nxew): the receiver resolves the signer "
            "public key by looking up the frame's 8-byte Signer Identifier "
            "(wire EUI-64) in the trust store; a pinned SIID verifies ONLY "
            "against its pinned key and MUST reject without fallback on "
            "failure; an unpinned SIID MAY trial-verify provisioned or "
            "announced candidates and pins the binding when exactly one "
            "verifies; relay nodes re-sign with their own SIID and key so "
            "downstream receivers pin the immediate signer, never the "
            "payload origin; evicting a (SIID, key) binding MUST invalidate "
            "all replay state for that signer. Documented readings: SRH "
            "destination mutation is modeled at link scope as the next-hop "
            "DST swap (in-packet SRH processing is specified by "
            "source_route_hop_limit.json and srh_root_insertion.json); "
            "trust-store keys are SIIDs in wire EUI-64 form; rule 3's "
            "multiple-candidates branch is cryptographically unreachable for "
            "distinct keys and therefore not vectorized; the preserved relay "
            "payload is the wire_format_v2.json announce corpus verbatim "
            "(originator A) treated as opaque link-layer bytes. Option (b) "
            "keeps the wire format unchanged, so no signed-frame corpus "
            "regeneration is required."
        ),
        "spec": (
            "spec/02-physical-link.md 4.1-4.2 (frame format, LLSec, key "
            "selection policy); spec/05-routing.md 9 (announce origin); "
            "draft-lichen-schnorr-00; draft-lichen-link-01"
        ),
        "provenance": {
            "key_selection": (
                "Vectors derive from the spec 02 section 4.2 key-selection "
                "policy text (external truth) and the independent "
                "reference_schnorr48.py signer (libsodium/PyNaCl); "
                "lichen.crypto.schnorr48 and all Rust/C link code were never "
                "consulted."
            ),
            "frames": (
                "Frame octets hand-assembled from the spec 4.1 wire table and "
                "4.2 LLSec bit table by generate_relay_signer_chain.py; no "
                "production frame code is imported."
            ),
            "payload": (
                "The preserved relay payload is borrowed verbatim from "
                "wire_format_v2.json wf2_announce_fresh_counter_accept "
                "(cross-checked at generation time); attacker frames carry "
                "opaque non-dispatch payloads."
            ),
            "identities": (
                "A and B reuse the wire_format_v2 seeds (0x00*32, 0x01*32); "
                "C is 0x02*32 and the attacker X is 0xff*32. Seeds are fixed "
                "literals so every implementation derives identical keys "
                "offline."
            ),
        },
        "identities": identities,
        "vectors": vectors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args(argv)
    generated = document()
    if arguments.check:
        try:
            current = read_bounded_exact(OUTPUT)
        except FileNotFoundError:
            current = None
        except (OSError, RuntimeError) as error:
            # Unsafe directory / unreadable vector: report the real
            # problem instead of masquerading as a stale file.
            print(f"cannot safely read {OUTPUT.name}: {error}", file=sys.stderr)
            return 2
        if current != json_bytes(generated):
            print(f"out-of-date vector file: {OUTPUT.name}", file=sys.stderr)
            return 1
        return 0
    atomic_write_json_batch([(OUTPUT, generated)])
    vectors = generated["vectors"]
    assert isinstance(vectors, list)
    print(f"Wrote {len(vectors)} vectors in {OUTPUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
