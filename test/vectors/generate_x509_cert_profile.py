#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate X.509 certificate-profile encoding test vectors (appendix-x509-cert-profile).

Pins the DER encodings of the profile's wire-level building blocks, toward
the chain-validation and cross-signing vectors that
spec/appendix-x509-cert-profile.md section 9 promises for test/vectors/:

* section 2  SubjectPublicKeyInfo: Ed25519 (id-Ed25519 1.3.101.112),
  parameters absent, 32-byte raw key (RFC 8410).
* section 4  subjectAltName: exactly one iPAddress GeneralName ([7]
  primitive, 16 bytes) carrying the node's native address.
* section 5  Mesh role extension: OID 2.25.<UUID-arc> (ITU-T X.667),
  non-critical, extnValue = OCTET STRING wrapping a DER BIT STRING of
  role bits (leaf=0, relay=1, gateway=2).

Oracles (never the code under test; no lichen package imports):

* The native address is the upstream Yggdrasil AddrForKey bytes pinned
  byte-for-byte by test/vectors/yggdrasil_address.json
  (``upstream_addr_for_key``), per the settled upstream-yggdrasil-addressing
  decision. NOTE: the appendix's normative text is pre-migration and still
  specifies the rejected SHA-512 native profile — the section-2
  "SHA-512-derived IID produces the node's addresses" sentence, the
  section-4 MUST-level formula ``addr = [0x02] + SHA-512(pubkey)[0:7] +
  IID``, its worked example, and the section-8-step-4 verifier binding
  recomputation. These vectors intentionally pin the settled AddrForKey
  form; a verifier built from the stale section-8 text would reject them.
* SPKI and SAN DER are cross-checked against pyca/cryptography
  (independent X.509/DER implementation).
* Role-extnValue bytes are cross-checked two ways: the spec section-5
  worked table (authoritative text) vs. this generator's bit-packing rule
  (MSB-first, bit 0 = 0x80); a mismatch fails generation loudly.
* The role OID arc is cross-checked: UUID 5787c1be-467b-5e51-92c4-77bcaeb02a21
  as a 128-bit integer MUST equal the spec's decimal arc
  116347725289407359125616919235271862817.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from atomic_json import atomic_write_json_batch, json_bytes, read_bounded_exact  # noqa: E402

OUTPUT = HERE / "x509_cert_profile.json"

# --- Spec constants (appendix-x509-cert-profile.md) -------------------------

ED25519_OID = "1.3.101.112"  # id-Ed25519, RFC 8410
SAN_OID = "2.5.29.17"  # id-ce-subjectAltName, RFC 5280
MESH_ROLE_OID = "2.25.116347725289407359125616919235271862817"
MESH_ROLE_UUID = "5787c1be-467b-5e51-92c4-77bcaeb02a21"
MESH_ROLE_ARC_DECIMAL = 116347725289407359125616919235271862817

# Section 5 worked extnValue table (authoritative spec text). The generator
# independently derives the same bytes from the bit-packing rule and refuses
# to emit vectors if the two disagree.
SPEC_ROLE_EXTNVALUE = {
    "leaf": "040403020780",
    "relay": "040403020640",
    "gateway": "040403020520",
    "leaf+relay": "0404030206c0",
    "leaf+relay+gateway": "0404030205e0",
}

ROLE_BITS = {"leaf": 0, "relay": 1, "gateway": 2}


# --- Minimal DER writer ------------------------------------------------------


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + der_len(len(content)) + content


def der_sequence(content: bytes) -> bytes:
    return der_tlv(0x30, content)


def der_octet_string(content: bytes) -> bytes:
    return der_tlv(0x04, content)


def der_bit_string(content: bytes, unused_bits: int) -> bytes:
    return der_tlv(0x03, bytes([unused_bits]) + content)


def der_oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    assert len(arcs) >= 2 and arcs[0] in (0, 1, 2) and (arcs[1] < 40 or arcs[0] == 2)
    # X.690: the first subidentifier (40*arc0 + arc1) is itself base-128 encoded.
    first = 40 * arcs[0] + arcs[1]
    groups = [first & 0x7F]
    first >>= 7
    while first:
        groups.append(0x80 | (first & 0x7F))
        first >>= 7
    out = bytearray(reversed(groups))
    for arc in arcs[2:]:
        assert arc >= 0
        groups = [arc & 0x7F]
        arc >>= 7
        while arc:
            groups.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out.extend(reversed(groups))
    return der_tlv(0x06, bytes(out))


# --- Profile encodings -------------------------------------------------------


def spki_der(pubkey: bytes) -> bytes:
    """RFC 8410 SubjectPublicKeyInfo for a raw Ed25519 key."""
    assert len(pubkey) == 32
    alg_id = der_sequence(der_oid(ED25519_OID))  # parameters absent
    return der_sequence(alg_id + der_bit_string(pubkey, 0))


def san_value_der(native_addr: bytes) -> bytes:
    """subjectAltName extension VALUE (extnValue content): one iPAddress.

    GeneralName iPAddress is context tag [7], primitive (0x87), 16 bytes.
    """
    assert len(native_addr) == 16
    return der_sequence(der_tlv(0x87, native_addr))


def role_bit_string(roles: list[str]) -> bytes:
    """Section-5 bit packing: MSB-first named bits (bit 0 = 0x80 = leaf)."""
    byte = 0
    for role in roles:
        byte |= 0x80 >> ROLE_BITS[role]
    if byte == 0:
        return der_bit_string(b"", 0)  # empty BIT STRING == unasserted
    highest = max(ROLE_BITS[r] for r in roles)
    return der_bit_string(bytes([byte]), 7 - highest)


def role_extnvalue_der(roles: list[str]) -> bytes:
    return der_octet_string(role_bit_string(roles))


def role_extension_der(roles: list[str]) -> bytes:
    """Full Extension (extnID + extnValue; critical absent = false)."""
    return der_sequence(der_oid(MESH_ROLE_OID) + role_extnvalue_der(roles))


def san_extension_der(native_addr: bytes, critical: bool) -> bytes:
    """Full Extension for subjectAltName (critical per RFC 5280 rule)."""
    body = der_oid(SAN_OID)
    if critical:
        body += der_tlv(0x01, b"\xff")
    body += der_octet_string(san_value_der(native_addr))
    return der_sequence(body)


# --- Oracle cross-checks ------------------------------------------------------


def pyca_spki_der(pubkey: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return Ed25519PublicKey.from_public_bytes(pubkey).public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )


def pyca_san_value_der(native_addr: bytes) -> bytes:
    import ipaddress

    from cryptography import x509

    san = x509.SubjectAlternativeName(
        [x509.IPAddress(ipaddress.IPv6Address(native_addr))]
    )
    return san.public_bytes()


def load_pinned_native_identity() -> tuple[bytes, bytes]:
    """Pinned upstream AddrForKey oracle pair from yggdrasil_address.json."""
    import json

    with open(HERE / "yggdrasil_address.json", "rb") as fh:
        doc = json.load(fh)
    for v in doc["vectors"]:
        if v["name"] == "upstream_addr_for_key":
            return bytes.fromhex(v["public_key"]), bytes.fromhex(v["address"])
    raise RuntimeError("yggdrasil_address.json: upstream_addr_for_key missing")


def ipv6_text(addr: bytes) -> str:
    import ipaddress

    return str(ipaddress.IPv6Address(addr))


# --- Document -----------------------------------------------------------------


def document() -> dict:
    # Oracle consistency: UUID-as-integer MUST equal the spec's decimal arc.
    uuid_int = int(MESH_ROLE_UUID.replace("-", ""), 16)
    if uuid_int != MESH_ROLE_ARC_DECIMAL:
        raise RuntimeError(
            "spec internal divergence: mesh-role UUID does not equal the "
            f"decimal OID arc ({uuid_int} != {MESH_ROLE_ARC_DECIMAL})"
        )

    pubkey, native_addr = load_pinned_native_identity()

    # SPKI: hand-rolled DER vs pyca (independent implementation).
    spki = spki_der(pubkey)
    if spki != pyca_spki_der(pubkey):
        raise RuntimeError("SPKI DER mismatch vs pyca/cryptography oracle")

    # SAN value: hand-rolled DER vs pyca.
    san = san_value_der(native_addr)
    if san != pyca_san_value_der(native_addr):
        raise RuntimeError("SAN value DER mismatch vs pyca/cryptography oracle")

    # Role table: spec text vs this generator's bit-packing rule.
    role_cases = []
    for name, roles in [
        ("role_extnvalue_leaf", ["leaf"]),
        ("role_extnvalue_relay", ["relay"]),
        ("role_extnvalue_gateway", ["gateway"]),
        ("role_extnvalue_leaf_relay", ["leaf", "relay"]),
        ("role_extnvalue_leaf_relay_gateway", ["leaf", "relay", "gateway"]),
    ]:
        derived = role_extnvalue_der(roles).hex()
        spec_given = SPEC_ROLE_EXTNVALUE["+".join(roles)]
        if derived != spec_given:
            raise RuntimeError(
                f"role extnValue mismatch for {roles}: derived {derived}, "
                f"spec table {spec_given}"
            )
        role_cases.append(
            {
                "name": name,
                "description": (
                    "Section 5 worked extnValue: OCTET STRING wrapping DER BIT "
                    "STRING, roles " + "+".join(roles)
                ),
                "roles": roles,
                "bit_string_content_hex": role_bit_string(roles)[3:].hex(),
                "extn_value_hex": derived,
                "full_extension_hex": role_extension_der(roles).hex(),
            }
        )

    cases = [
        {
            "name": "spki_der_node_a",
            "description": (
                "Section 2 + RFC 8410: SEQUENCE { SEQUENCE { id-Ed25519 }, "
                "BIT STRING <32-byte raw key> }; parameters absent. "
                "Cross-checked against pyca/cryptography."
            ),
            "subject_public_key_hex": pubkey.hex(),
            "spki_der_hex": spki.hex(),
        },
        {
            "name": "san_value_der_node_a",
            "description": (
                "Section 4: subjectAltName extnValue content = SEQUENCE of "
                "exactly one iPAddress GeneralName ([7] primitive, 16 bytes) "
                "carrying the node native address = upstream AddrForKey(SPKI) "
                "in 0200::/8. Cross-checked against pyca/cryptography. The "
                "appendix's normative section-2/section-4/section-8-step-4 "
                "text and worked example are pre-migration (rejected SHA-512 "
                "native profile); this vector intentionally pins the settled "
                "AddrForKey form (see document description)."
            ),
            "native_address_hex": native_addr.hex(),
            "san_value_der_hex": san.hex(),
        },
        {
            "name": "san_extension_critical_der_node_a",
            "description": (
                "Full SAN Extension with critical TRUE (required when the "
                "subject DN is empty, RFC 5280 4.2.1.6): extnID "
                "id-ce-subjectAltName (2.5.29.17), critical BOOLEAN TRUE, "
                "extnValue wrapping the pinned SAN value."
            ),
            "san_extension_der_hex": san_extension_der(native_addr, critical=True).hex(),
        },
        {
            "name": "san_extension_non_critical_der_node_a",
            "description": (
                "Full SAN Extension, non-critical (required when a subject "
                "DN is present): extnID id-ce-subjectAltName, no critical "
                "field, extnValue wrapping the pinned SAN value."
            ),
            "san_extension_der_hex": san_extension_der(native_addr, critical=False).hex(),
        },
        {
            "name": "role_extnvalue_empty_bit_string_unasserted",
            "description": (
                "Section 5: a present-but-empty BIT STRING (no named bits) "
                "MUST be treated as unasserted, exactly as if the extension "
                "were absent; authorization MUST NOT read absence as leaf."
            ),
            "roles": [],
            "bit_string_content_hex": role_bit_string([])[3:].hex(),
            "extn_value_hex": role_extnvalue_der([]).hex(),
            "full_extension_hex": role_extension_der([]).hex(),
            "expect_semantics": "unasserted",
        },
        {
            "name": "role_oid_der",
            "description": (
                "Section 5 extnID: 2.25.<UUID-arc> where the arc is UUID "
                "5787c1be-467b-5e51-92c4-77bcaeb02a21 (UUIDv5, DNS namespace, "
                "x509-mesh-role.lichen.tech) as a 128-bit integer = "
                "116347725289407359125616919235271862817. Registration-free "
                "ITU-T X.667 arc; DER OID content cross-checks the spec's "
                "decimal arc against the UUID."
            ),
            "oid_dotted": MESH_ROLE_OID,
            "oid_der_hex": der_oid(MESH_ROLE_OID).hex(),
        },
    ]
    cases.extend(role_cases)

    return {
        "$schema": "./x509_cert_profile.schema.json",
        "vector_type": "x509_cert_profile",
        "format_version": 1,
        "description": (
            "X.509v3 certificate-profile wire encodings "
            "(spec/appendix-x509-cert-profile.md sections 2/4/5): Ed25519 "
            "SPKI, subjectAltName native-address binding, mesh-role "
            "extension OID and extnValue. Building blocks toward the "
            "chain-validation vectors promised by appendix section 9. "
            "Native addresses use the settled upstream Yggdrasil "
            "AddrForKey profile pinned by yggdrasil_address.json; the "
            "appendix's pre-migration SHA-512-based normative text "
            "(sections 2, 4, 8 step 4) and worked example are the rejected "
            "native profile and are NOT pinned here."
        ),
        "spec": "spec/appendix-x509-cert-profile.md sections 2, 4, 5, 9",
        "oracle": {
            "basis": (
                "RFC 8410 (Ed25519 SPKI), RFC 5280 (SAN extension form), "
                "ITU-T X.667 (2.25 UUID arc), upstream AddrForKey pinned by "
                "test/vectors/yggdrasil_address.json#upstream_addr_for_key, "
                "spec section-5 worked table; DER cross-checked against "
                "pyca/cryptography"
            ),
            "implementation": (
                "hand-rolled DER writer in this generator; no lichen package "
                "imports"
            ),
            "generator_command": "python3 test/vectors/generate_x509_cert_profile.py",
            "freshness_command": "python3 test/vectors/generate_x509_cert_profile.py --check",
        },
        "constants": {
            "ed25519_oid": ED25519_OID,
            "ed25519_oid_der_hex": der_oid(ED25519_OID).hex(),
            "san_oid": SAN_OID,
            "san_oid_der_hex": der_oid(SAN_OID).hex(),
            "mesh_role_oid": MESH_ROLE_OID,
            "mesh_role_uuid": MESH_ROLE_UUID,
            "mesh_role_oid_der_hex": der_oid(MESH_ROLE_OID).hex(),
            "native_address_prefix": "0200::/8",
            "ipaddress_generalname_tag": "87",
            "role_bits": ROLE_BITS,
        },
        "identities": [
            {
                "name": "node_a",
                "public_key_hex": pubkey.hex(),
                "native_address_hex": native_addr.hex(),
                "native_address_ipv6": ipv6_text(native_addr),
                "oracle_source": (
                    "test/vectors/yggdrasil_address.json#upstream_addr_for_key"
                ),
            }
        ],
        "cases": cases,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    generated = document()
    if args.check:
        try:
            current = read_bounded_exact(OUTPUT)
        except (FileNotFoundError, RuntimeError):
            current = None
        if current != json_bytes(generated):
            print(f"out-of-date vector file: {OUTPUT.name}", file=sys.stderr)
            return 1
        return 0
    atomic_write_json_batch([(OUTPUT, generated)])
    print(f"Wrote {len(generated['cases'])} X.509 profile cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
