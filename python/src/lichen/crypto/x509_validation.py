# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Small RFC 5280 certificate-chain validator for configured anchors."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa


class CertificateValidationError(ValueError):
    """The certificate chain or its leaf constraints are invalid."""


def validate_certificate_chain(
    leaf_der: bytes,
    intermediates_der: Sequence[bytes],
    trust_anchors_der: Sequence[bytes],
    *,
    now: datetime | None = None,
) -> x509.Certificate:
    """Validate a leaf to one of the exact configured DER trust anchors.

    The path is built by issuer/subject linkage, but authorization requires a
    matching anchor and every child signature is verified with its issuer key.
    """
    if not trust_anchors_der:
        raise CertificateValidationError("at least one trust anchor is required")
    try:
        leaf = _load(leaf_der)
        intermediates = [_load(value) for value in intermediates_der]
        anchors = [_load(value) for value in trust_anchors_der]
    except (TypeError, ValueError) as exc:
        raise CertificateValidationError("invalid DER certificate") from exc

    if now is None:
        now = datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    now_utc = now.astimezone(UTC).replace(tzinfo=None)
    _check_leaf_constraints(leaf)

    remaining = list(intermediates)
    current = leaf
    seen: set[bytes] = set()
    while True:
        current_der = current.public_bytes(serialization.Encoding.DER)
        if current_der in seen:
            raise CertificateValidationError("certificate chain contains a loop")
        seen.add(current_der)
        _check_validity(current, now_utc)

        for anchor_der, _anchor in zip(trust_anchors_der, anchors, strict=True):
            if current_der == anchor_der:
                return leaf

        candidates = [
            certificate
            for certificate in [*remaining, *anchors]
            if certificate.subject == current.issuer
        ]
        if not candidates:
            raise CertificateValidationError("certificate chain does not reach a trust anchor")
        issuer = next(
            (candidate for candidate in candidates if _verifies(current, candidate)), None
        )
        if issuer is None:
            raise CertificateValidationError("certificate signature is invalid")
        if issuer in remaining:
            _check_issuer_constraints(issuer)
            remaining.remove(issuer)
        current = issuer


def _load(value: bytes) -> x509.Certificate:
    if type(value) is not bytes:
        raise TypeError("certificate must be DER bytes")
    return x509.load_der_x509_certificate(value)


def _check_validity(certificate: x509.Certificate, now: datetime) -> None:
    if not certificate.not_valid_before <= now <= certificate.not_valid_after:
        raise CertificateValidationError("certificate is outside its validity period")


def _check_leaf_constraints(certificate: x509.Certificate) -> None:
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CertificateValidationError("leaf constraints are required") from exc
    if constraints.ca:
        raise CertificateValidationError("leaf certificate must not be a CA")
    if not usage.digital_signature:
        raise CertificateValidationError("leaf certificate lacks digitalSignature")


def _check_issuer_constraints(certificate: x509.Certificate) -> None:
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CertificateValidationError("issuer constraints are required") from exc
    if not constraints.ca:
        raise CertificateValidationError("issuer certificate must be a CA")
    if not usage.key_cert_sign:
        raise CertificateValidationError("issuer certificate lacks keyCertSign")


def _verifies(certificate: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        key = issuer.public_key()
        signature = certificate.signature
        parameters = certificate.signature_hash_algorithm
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, certificate.tbs_certificate_bytes, padding.PKCS1v15(), parameters)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, certificate.tbs_certificate_bytes, ec.ECDSA(parameters))
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(signature, certificate.tbs_certificate_bytes)
        else:
            return False
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True
