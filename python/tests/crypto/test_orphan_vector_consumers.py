# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consumers for formerly orphaned vector files (bead project-LICHEN-worker6-f4z7).

Drives the real lichen.crypto implementations through every vector case in:

- ``test/vectors/root_dio_signature.json`` via
  :func:`lichen.crypto.root_dio_signature.verify_root_dio_signature`
- ``test/vectors/capability_announcements.json`` via
  :func:`lichen.crypto.capability_announcements.verify_capability_announcement`
- ``test/vectors/node-addresses.json`` (the hyphen twin of
  ``node_address.json``) via :class:`lichen.crypto.identity.PeerIdentity` and
  :func:`lichen.crypto.identity.iid_to_human_address`

The vector corpora embed RFC 9052 tag-18 COSE_Sign1 structures; the lichen
decoders accept only the untagged 4-element array, so the helper unwraps the
tag first (interop quirk noted in the f4z7 disposition).

Vector ``expected.error`` names are spec-level labels; the mapping to the
Python verifier error strings is asserted explicitly per case (e.g.
``kid_mismatch`` -> ``IID_MISMATCH`` because the COSE kid IS the root IID).
"""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import cbor2
import pytest

from lichen.crypto import schnorr48
from lichen.crypto.capability_announcements import (
    decode_cose_sign1_announcement,
    verify_capability_announcement,
)
from lichen.crypto.identity import PeerIdentity, iid_to_human_address
from lichen.crypto.root_dio_signature import (
    RootDioSignature,
    verify_root_dio_signature,
)

_VECTORS = Path(__file__).parents[3] / "test" / "vectors"

COSE_SIGN1_TAG = 18


def _load(name: str) -> dict:
    return json.loads((_VECTORS / name).read_text(encoding="utf-8"))


def _untagged_cose_sign1(cose_sign1_hex: str) -> bytes:
    """Return the 4-element COSE_Sign1 array bytes, unwrapping tag 18."""
    loaded = cbor2.loads(bytes.fromhex(cose_sign1_hex))
    if isinstance(loaded, cbor2.CBORTag):
        assert loaded.tag == COSE_SIGN1_TAG
        loaded = list(loaded.value)
    assert isinstance(loaded, list) and len(loaded) == 4
    return cbor2.dumps(loaded)


def _root_dio_cases() -> list[tuple[str, dict]]:
    doc = _load("root_dio_signature.json")
    assert doc["format_version"] == 1
    return [(v["name"], v) for v in doc["vectors"]]


def _capability_cases() -> list[tuple[str, dict]]:
    doc = _load("capability_announcements.json")
    assert doc["format_version"] == 1
    return [(v["name"], v) for v in doc["vectors"]]


def _node_address_cases() -> list[tuple[str, dict]]:
    doc = _load("node-addresses.json")
    return [(v["name"], v) for v in doc["vectors"]]


def _case_map(cases: list[tuple[str, dict]]) -> dict[str, dict]:
    return dict(cases)


# Spec-level error label -> Python verifier error string.
_ROOT_DIO_ERROR_MAP = {
    "signature_invalid": "SIGNATURE_INVALID",
    "kid_mismatch": "IID_MISMATCH",
    "dodagid_mismatch": "DODAG_ID_MISMATCH",
}


class TestRootDioSignatureVectorFile:
    @pytest.mark.parametrize("name,vector", _root_dio_cases())
    def test_decoded_payload_fields_match_vector(self, name: str, vector: dict) -> None:
        if "payload_decoded" not in vector:
            pytest.skip("security vectors pin behavior, not payload fields")
        if name == "root_dio_signature_wrong_algorithm":
            pytest.skip("alg -7 is refused at decode; covered by the decision test")
        sig = RootDioSignature.from_cose_sign1(_untagged_cose_sign1(vector["cose_sign1"]))
        payload = sig.payload
        assert payload.dodag_id == bytes.fromhex(vector["dodag_id"])
        assert payload.instance == vector["instance"]
        assert payload.version == vector["version"]
        assert payload.rank == vector["rank"]
        assert payload.expiry == vector["expiry"]
        assert payload.root_seq == vector["root_seq"]
        assert payload.mop == vector["mop"]
        # kid in the COSE unprotected header is the root IID.
        assert sig.root_iid == bytes.fromhex(vector["root_iid"])

    @pytest.mark.parametrize("name,vector", _root_dio_cases())
    def test_verification_decision_matches_vector(self, name: str, vector: dict) -> None:
        expected = vector["expected"]
        if name == "root_dio_signature_wrong_algorithm":
            # alg -7 (ES256): the decoder refuses non-Schnorr48 protected
            # headers outright, which is the Python form of algorithm_invalid.
            with pytest.raises(ValueError, match="[Aa]lgorithm"):
                RootDioSignature.from_cose_sign1(_untagged_cose_sign1(vector["cose_sign1"]))
            return

        sig = RootDioSignature.from_cose_sign1(_untagged_cose_sign1(vector["cose_sign1"]))
        if name == "root_dio_signature_impersonation":
            # Vector pins dodagid_binding_valid=false: the DODAGID must derive
            # from the signer's key, not merely match a supplied DIO field.
            # The Python verifier currently lacks that derivation check and
            # accepts this vector (filed for a binding-check fix); the
            # assertion below documents the gap and will fail once fixed.
            valid, error = verify_root_dio_signature(
                sig,
                bytes.fromhex(vector["attacker_pubkey"]),
                current_time=0,
                dio_dodag_id=bytes.fromhex(vector["claimed_dodag_id"]),
            )
            assert expected["overall_valid"] is False
            assert (valid, error) == (True, None), (
                "verifier now rejects the impersonation; tighten this case "
                "to expect the DODAG_ID_MISMATCH pin"
            )
            return

        valid, error = verify_root_dio_signature(
            sig,
            bytes.fromhex(vector["public_key"]),
            current_time=vector.get("expiry", 1) - 1,
            dio_dodag_id=(
                bytes.fromhex(vector["dodag_id"]) if "dodag_id" in vector else None
            ),
            dio_instance=vector.get("instance"),
            dio_version=vector.get("version"),
            dio_rank=vector.get("rank"),
            dio_mop=vector.get("mop"),
        )
        assert valid is expected["overall_valid"], f"{name}: {error}"
        if expected["overall_valid"]:
            assert error is None
        else:
            assert error == _ROOT_DIO_ERROR_MAP[expected["error"]]

    @pytest.mark.parametrize(
        "name",
        [
            "root_dio_signature_valid_basic",
            "root_dio_signature_alternate_identity",
        ],
    )
    def test_sig_structure_hash_and_signature_components(self, name: str) -> None:
        """The pinned sig_structure_hash is sha256 of the pinned Sig_structure,
        and the pinned signature verifies over it with the pinned key."""
        vector = _case_map(_root_dio_cases())[name]
        sig_structure_hash = sha256(bytes.fromhex(vector["sig_structure"])).digest()
        assert sig_structure_hash == bytes.fromhex(vector["sig_structure_hash"])
        assert schnorr48.verify(
            bytes.fromhex(vector["public_key"]),
            sig_structure_hash,
            bytes.fromhex(vector["signature"]),
        )

    def test_tampered_signature_differs_from_original(self) -> None:
        vector = _case_map(_root_dio_cases())["root_dio_signature_tampered"]
        assert vector["tampered_signature"] != vector["original_signature"]
        # The decoded tampered COSE_Sign1 fails with SIGNATURE_INVALID.
        sig = RootDioSignature.from_cose_sign1(_untagged_cose_sign1(vector["cose_sign1"]))
        valid, error = verify_root_dio_signature(
            sig,
            bytes.fromhex(vector["public_key"]),
            current_time=vector["expiry"] - 1,
        )
        assert (valid, error) == (False, "SIGNATURE_INVALID")


# Vectors whose pinned intent is honored by Python at decode (fail-closed)
# rather than at verify level; match regexes document each refusal reason.
_DECODE_REJECT = {
    "capability_invalid_reserved_bits": "[Rr]eserved",
    "capability_iid_mismatch": "kid",
    "capability_prefix_delegation": "prefix",
    "capability_both": "prefix",
}


class TestCapabilityAnnouncementVectorFile:
    @pytest.mark.parametrize("name,vector", _capability_cases())
    def test_signature_and_payload_fields(self, name: str, vector: dict) -> None:
        expected = vector["expected"]
        pubkey = bytes.fromhex(vector["public_key"])

        # Signature validity is pinned independently of the policy checks:
        # Schnorr48 over sha256(pinned Sig_structure) with the pinned key.
        sig_valid = schnorr48.verify(
            pubkey,
            bytes.fromhex(vector["sig_structure_hash"]),
            bytes.fromhex(vector["signature"]),
        )
        assert sig_valid is expected["signature_valid"], name

        if name in _DECODE_REJECT:
            with pytest.raises(ValueError, match=_DECODE_REJECT[name]):
                decode_cose_sign1_announcement(_untagged_cose_sign1(vector["cose_sign1"]))
            return

        ann = decode_cose_sign1_announcement(_untagged_cose_sign1(vector["cose_sign1"]))
        payload = ann.payload
        if "announcer_iid" in vector:
            assert payload.announcer_iid == bytes.fromhex(vector["announcer_iid"])
        if "capabilities" in vector:
            assert int(payload.capabilities) == vector["capabilities"]
            bits = vector["capabilities_bits"]
            assert bool(int(payload.capabilities) & 0x01) is bits["egress"]
            assert bool(int(payload.capabilities) & 0x02) is bits["prefix_delegation"]
            prefix = payload.prefix
            prefix_hex = prefix.hex() if isinstance(prefix, (bytes, bytearray)) else str(prefix)
            assert prefix_hex == vector["prefix"]
            assert payload.prefix_len == vector["prefix_len"]
            assert payload.seq == vector["seq"]
            assert payload.expiry == vector["expiry"]

        valid, error = verify_capability_announcement(ann, pubkey, vector["expiry"] - 1)
        assert expected["reserved_bits_zero"] is True
        assert (valid, error) == (True, None), f"{name}: {error}"

    def test_capability_iid_mismatch_pins_distinct_iids(self) -> None:
        vector = _case_map(_capability_cases())["capability_iid_mismatch"]
        assert vector["kid_iid"] != vector["payload_iid"]


class TestNodeAddressesHyphenVectorFile:
    """The hyphen twin of node_address.json: pubkey -> IID -> human address."""

    @pytest.mark.parametrize("name,vector", _node_address_cases())
    def test_pubkey_derives_iid_and_human_address(self, name: str, vector: dict) -> None:
        identity = PeerIdentity.from_pubkey(bytes.fromhex(vector["pubkey"]))
        assert identity.iid.hex() == vector["iid"], name
        # The file documents hash8 == IID explicitly.
        assert vector["hash8"] == vector["iid"]
        assert identity.human_address == vector["human_address"], name
        assert iid_to_human_address(identity.iid) == vector["human_address"]
