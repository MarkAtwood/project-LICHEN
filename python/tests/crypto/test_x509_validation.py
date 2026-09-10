# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Independent certificate-chain validation tests."""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

from lichen.crypto import (
    CertificateValidationError,
    validate_certificate_chain,
    validate_leaf_san_binding,
)

NOW = datetime.now(UTC).replace(microsecond=0)


def _certificate(
    subject: str,
    issuer: x509.Name,
    subject_key: rsa.RSAPrivateKey | ed25519.Ed25519PublicKey,
    signer_key: rsa.RSAPrivateKey,
    *,
    is_ca: bool,
    digital_signature: bool,
    san: x509.SubjectAlternativeName | None = None,
    san_critical: bool = False,
) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    subject_public_key = (
        subject_key.public_key() if isinstance(subject_key, rsa.RSAPrivateKey) else subject_key
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(subject_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(minutes=1))
        .not_valid_after(NOW + timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=1 if is_ca else None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature,
                content_commitment=False,
                key_encipherment=not is_ca,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    )
    if san is not None:
        builder = builder.add_extension(san, critical=san_critical)
    certificate = builder.sign(signer_key, hashes.SHA256())
    return certificate.public_bytes(serialization.Encoding.DER)


def _chain(*, leaf_ca: bool = False, leaf_digital_signature: bool = True):
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(
        "bdbacfd82240de3dcd123924cbb55256fb8dab08aa98e305528ab84f419e6efb"
    ))
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "root")])
    intermediate = _certificate(
        "intermediate", root_name, intermediate_key, root_key, is_ca=True, digital_signature=False
    )
    intermediate_cert = x509.load_der_x509_certificate(intermediate)
    leaf = _certificate(
        "leaf",
        intermediate_cert.subject,
        leaf_key,
        intermediate_key,
        is_ca=leaf_ca,
        digital_signature=leaf_digital_signature,
        san=x509.SubjectAlternativeName([x509.IPAddress(IPv6Address("200:848a:604f:bb7e:4384:65db:8db6:6895"))]),
    )
    root = _certificate("root", root_name, root_key, root_key, is_ca=True, digital_signature=False)
    return leaf, intermediate, root


def test_valid_chain_terminates_at_configured_anchor() -> None:
    leaf, intermediate, root = _chain()

    result = validate_certificate_chain(leaf, [intermediate], [root], now=NOW)

    assert result.subject.rfc4514_string() == "CN=leaf"


def test_wrong_anchor_is_rejected_even_when_names_are_similar() -> None:
    leaf, intermediate, _root = _chain()
    _other_leaf, _other_intermediate, other_root = _chain()

    with pytest.raises(CertificateValidationError, match="signature|trust anchor"):
        validate_certificate_chain(leaf, [intermediate], [other_root], now=NOW)


@pytest.mark.parametrize(
    ("leaf_ca", "leaf_digital_signature", "message"),
    [(True, True, "must not be a CA"), (False, False, "digitalSignature")],
)
def test_leaf_constraints_are_required(
    leaf_ca: bool, leaf_digital_signature: bool, message: str
) -> None:
    leaf, intermediate, root = _chain(
        leaf_ca=leaf_ca, leaf_digital_signature=leaf_digital_signature
    )

    with pytest.raises(CertificateValidationError, match=message):
        validate_certificate_chain(leaf, [intermediate], [root], now=NOW)


def test_san_binding_uses_pinned_upstream_address() -> None:
    key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ))
    signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificate = x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(
        x509.Name([])
    ).public_key(key).serial_number(1).not_valid_before(NOW).not_valid_after(
        NOW + timedelta(days=1)
    ).add_extension(
        x509.SubjectAlternativeName([x509.IPAddress(IPv6Address("200:389e:777a:ce07:c7d6:ca08:166e:cd20"))]),
        critical=True,
    ).sign(signer, hashes.SHA256())

    validate_leaf_san_binding(certificate)


@pytest.mark.parametrize(
    "san",
    [
        x509.SubjectAlternativeName([]),
        x509.SubjectAlternativeName([
            x509.IPAddress(IPv6Address("200:389e:777a:ce07:c7d6:ca08:166e:cd20")),
            x509.IPAddress(IPv6Address("200:389e:777a:ce07:c7d6:ca08:166e:cd20")),
        ]),
        x509.SubjectAlternativeName([
            x509.IPAddress(IPv6Address("200:389e:777a:ce07:c7d6:ca08:166e:cd21")),
        ]),
        x509.SubjectAlternativeName([x509.DNSName("node.example")]),
    ],
)
def test_san_binding_rejects_invalid_forms(san: x509.SubjectAlternativeName) -> None:
    key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ))
    signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificate = x509.CertificateBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "node")])
    ).issuer_name(
        x509.Name([])
    ).public_key(key).serial_number(1).not_valid_before(NOW).not_valid_after(
        NOW + timedelta(days=1)
    ).add_extension(san, critical=False).sign(signer, hashes.SHA256())

    with pytest.raises(CertificateValidationError):
        validate_leaf_san_binding(certificate)


def test_san_binding_ignores_non_native_ip_addresses() -> None:
    key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ))
    signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificate = x509.CertificateBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "node")])
    ).issuer_name(
        x509.Name([])
    ).public_key(key).serial_number(1).not_valid_before(NOW).not_valid_after(
        NOW + timedelta(days=1)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.IPAddress(IPv4Address("192.0.2.1")),
            x509.IPAddress(IPv6Address("200:389e:777a:ce07:c7d6:ca08:166e:cd20")),
        ]),
        critical=False,
    ).sign(signer, hashes.SHA256())

    validate_leaf_san_binding(certificate)
