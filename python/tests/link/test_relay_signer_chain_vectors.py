# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Conformance tests: relay signer identity chain vectors.

Drives ``lichen.link.link_layer.LinkLayer`` against
``test/vectors/relay_signer_chain.json`` (spec/02-physical-link.md 4.2
key-selection policy, beads project-LICHEN-worker6-1lgt / -gohv / -xxpn).

The vectors were produced by the independent reference oracle
(``test/vectors/reference_schnorr48.py``, libsodium via PyNaCl); these tests
prove the Python link layer reproduces the committed accept/reject decisions,
the selected immediate-signer identity per hop, the fail-closed substitution
behavior, and the TOFU trust-cache semantics (pin on first verified contact,
replay rejection, eviction invalidating replay state).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from lichen.crypto.identity import Identity, PeerIdentity
from lichen.crypto.schnorr48 import verify as schnorr48_verify
from lichen.ipv6.addr import eui64_to_iid, iid_to_eui64
from lichen.link.frame import LichenFrame
from lichen.link.link_layer import LinkLayer, ReceiveError, RxFrame

from .conftest import MockRadio

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"
VECTORS_PATH = VECTORS_DIR / "relay_signer_chain.json"
SCHEMA_PATH = VECTORS_DIR / "relay_signer_chain.schema.json"
GENERATOR_PATH = VECTORS_DIR / "generate_relay_signer_chain.py"

_REASON_TO_ERROR = {
    "replay": ReceiveError.REPLAY,
    "no_candidate_verified": ReceiveError.BAD_SIGNATURE,
    "pinned_siid_verification_failed_no_fallback": ReceiveError.BAD_SIGNATURE,
}


def _load_document() -> dict:
    return json.loads(VECTORS_PATH.read_text())


def _document_bytes_equivalent(document: dict) -> bool:
    """Byte-equivalence check against a fresh generator run."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("generate_relay_signer_chain", GENERATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return json.loads(json.dumps(document)) == module.document()


def _identity_for(document: dict, name: str) -> Identity:
    seed = bytes.fromhex(document["identities"][name]["seed"])
    return Identity.from_seed(seed)


def _build_receiver(document: dict, vector: dict) -> LinkLayer:
    """Construct the receiving LinkLayer with the vector's scenario state."""
    receiver = _identity_for(document, vector["receiver"])
    scenario = vector["scenario"]
    candidates: dict[bytes, PeerIdentity] = {}
    for pubkey_hex in scenario["candidate_keys"]:
        peer = PeerIdentity.from_pubkey(bytes.fromhex(pubkey_hex))
        candidates[peer.iid] = peer

    def peer_lookup(hint: bytes) -> PeerIdentity | None:
        return candidates.get(hint)

    def peer_lookup_all() -> list[PeerIdentity]:
        return list(candidates.values())

    link = LinkLayer(
        radio=MockRadio(),
        identity=receiver,
        peer_lookup=peer_lookup,
        peer_lookup_all=peer_lookup_all,
        cad_enabled=False,
    )
    for siid_hex, pubkey_hex in scenario["trust_store_before"].items():
        link._pinned_keys[eui64_to_iid(bytes.fromhex(siid_hex))] = bytes.fromhex(pubkey_hex)
    return link


def _trust_store_as_wire(link: LinkLayer) -> dict[str, str]:
    return {iid_to_eui64(iid).hex(): pubkey.hex() for iid, pubkey in link._pinned_keys.items()}


def _assert_frame_wire_fields(vector: dict) -> None:
    """The production parser must reproduce the reference-assembled fields."""
    frame = LichenFrame.from_bytes(bytes.fromhex(vector["encoded"]))
    fields = vector["fields"]
    assert frame.epoch == fields["epoch"]
    assert frame.seqnum == fields["seqnum"]
    assert bytes(frame.dst_addr).hex() == fields["dst_addr"]
    assert bytes(frame.payload).hex() == fields["payload"]
    assert bytes(frame.mic).hex() == fields["mic"]
    assert int(frame.addr_mode) == fields["addr_mode"]
    assert bytes(frame.signer_eui64).hex() == fields["signer_eui64"]
    assert frame.signature_present is fields["signature_present"]


def _assert_transcript_crypto(vector: dict) -> None:
    """Independent transcript checks from the vector's crypto block."""
    crypto = vector["crypto"]
    preimage = bytes.fromhex(crypto["preimage"])
    signature = bytes.fromhex(crypto["signature"])
    expect = vector["expect"]
    verify_pubkey = expect["verify_pubkey"]
    if verify_pubkey is not None:
        assert schnorr48_verify(bytes.fromhex(verify_pubkey), preimage, signature)
    for pubkey_hex in expect["must_not_verify_pubkeys"]:
        assert not schnorr48_verify(bytes.fromhex(pubkey_hex), preimage, signature)
    for pubkey_hex in expect.get("decoy_verifying_pubkeys", []):
        # The transcript verifies under the decoy key, yet the pinned-SIID
        # rule still forces rejection (spec 02 4.2 rules 2 and 4).
        assert schnorr48_verify(bytes.fromhex(pubkey_hex), preimage, signature)


def _receive(link: LinkLayer, wire: bytes) -> RxFrame | ReceiveError | None:
    link.radio.queue_rx(wire)  # type: ignore[attr-defined]
    return asyncio.run(link.receive(100))


def _assert_receive_expect(
    link: LinkLayer,
    wire: bytes,
    expect: dict,
) -> None:
    result = _receive(link, wire)
    if expect["decision"] == "accept":
        assert isinstance(result, RxFrame)
        if expect.get("authenticated_signer"):
            assert result.sender.pubkey.hex() == expect["authenticated_signer"]
    else:
        assert isinstance(result, ReceiveError)
        assert result is _REASON_TO_ERROR[expect["reject_reason"]]
    if "trust_store_after" in expect:
        assert _trust_store_as_wire(link) == expect["trust_store_after"]


def test_document_matches_closed_schema() -> None:
    schema = json.loads(SCHEMA_PATH.read_text())
    document = _load_document()
    errors = sorted(Draft7Validator(schema).iter_errors(document), key=lambda e: list(e.path))
    assert not errors, [error.message for error in errors]


def test_committed_vectors_match_generator() -> None:
    assert _document_bytes_equivalent(_load_document())


def _frame_vectors() -> list[tuple[str, dict]]:
    document = _load_document()
    return [(v["name"], v) for v in document["vectors"] if v["kind"] == "frame"]


def _sequence_vectors() -> list[tuple[str, dict]]:
    document = _load_document()
    return [(v["name"], v) for v in document["vectors"] if v["kind"] == "sequence"]


@pytest.mark.parametrize(("name", "vector"), _frame_vectors())
def test_frame_vector_decision(name: str, vector: dict) -> None:
    _assert_frame_wire_fields(vector)
    _assert_transcript_crypto(vector)
    link = _build_receiver(_load_document(), vector)
    _assert_receive_expect(link, bytes.fromhex(vector["encoded"]), vector["expect"])


@pytest.mark.parametrize(("name", "vector"), _sequence_vectors())
def test_sequence_vector_operations(name: str, vector: dict) -> None:
    document = _load_document()
    frames = {v["name"]: v for v in document["vectors"] if v["kind"] == "frame"}
    link = _build_receiver(document, vector)
    for operation in vector["operations"]:
        if operation["op"] == "receive":
            frame_vector = frames[operation["frame"]]
            _assert_receive_expect(
                link, bytes.fromhex(frame_vector["encoded"]), operation["expect"]
            )
        else:
            assert operation["op"] == "evict"
            siid = bytes.fromhex(operation["siid"])
            iid = eui64_to_iid(siid)
            pinned = link._pinned_keys[iid]
            link._retire_evicted_peer_unlocked(iid, pinned)
    assert _trust_store_as_wire(link) == vector["expect"]["trust_store_after"]
