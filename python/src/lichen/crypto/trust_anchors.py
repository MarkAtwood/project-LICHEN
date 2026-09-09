# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Trust-anchor store for credential verification (spec 06-security.md 8.13).

Verifiers maintain a list of trusted issuer keys ("Trust Anchors"). An
anchor is either a raw Ed25519 issuer key or an X.509 CA certificate
(DER) whose subject public key is the issuer key; several DER certs over
the SAME key are cross-signed representations of one anchor.

Anchors are keyed by the issuer IID (kid in the COSE_Sign1 header), so
credential verification step 3 ("lookup issuer pubkey by kid in trust
store") is a direct dict lookup. Pre-configured (provisioned) anchors are
built in at construction and cannot be removed at runtime; runtime
anchors are added via the trust-anchors CoAP resource and are removable.

In-memory only. NVS persistence of runtime anchors is a follow-up; the
TrustStore persistence protocol in this package is the model.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .identity import _pubkey_to_iid

KIND_RAW_ED25519 = "raw-ed25519"
KIND_X509 = "x509"
_VALID_KINDS = (KIND_RAW_ED25519, KIND_X509)

# Bounds (spec 8.13 sets no numbers; these mirror the 64-entry bound the
# spec uses for other per-peer caches). Every stored cert is re-served to
# unauthenticated GET callers, so accumulation MUST be bounded — in count
# AND in bytes. Ed25519 CA certs are a few hundred bytes; 1 KiB is a
# generous ceiling that also bounds DER parse cost.
MAX_ANCHORS = 64
MAX_CERTS_PER_ANCHOR = 8
MAX_CERT_DER_BYTES = 1024
# Metadata is re-served to unauthenticated GET callers like certs are, so
# it is bounded on the same rationale.
MAX_METADATA_ENTRIES = 8
MAX_METADATA_BYTES = 256


class TrustAnchorError(Exception):
    """Base class for trust-anchor store errors."""


class DuplicateAnchorError(TrustAnchorError):
    """An anchor with this issuer IID already exists."""


class StoreFullError(TrustAnchorError):
    """The bounded anchor store is at capacity."""


class ProvisionedAnchorError(TrustAnchorError):
    """Pre-configured anchors cannot be removed at runtime."""


class UnknownAnchorError(TrustAnchorError):
    """No anchor with this issuer IID."""


def _validate_pubkey(pubkey: object) -> bytes:
    if type(pubkey) is not bytes:
        raise TypeError("pubkey must be bytes")
    if len(pubkey) != 32:
        raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")
    return pubkey


def pubkey_from_der_cert(der: bytes) -> bytes:
    """Extract the Ed25519 subject public key from a DER CA certificate.

    Rejects non-DER input, non-Ed25519 keys, and certs that are not CAs
    (spec 8.13 anchors are issuer roots; a non-CA cert cannot issue).

    The cert's issuer signature and validity window are NOT checked here:
    a cross-signed cert's issuer root may not be in this store, and chain
    validation is the X.509 path's job (viku.6). The trust invariant of
    this store is key-pinning — only the subject key is trusted; cert
    material is chain input for verifiers, nothing more.
    """
    if type(der) is not bytes:
        raise TypeError("cert der must be bytes")
    if not 0 < len(der) <= MAX_CERT_DER_BYTES:
        raise ValueError(f"cert der must be 1..{MAX_CERT_DER_BYTES} bytes")
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError as exc:
        raise ValueError("cert der does not parse") from exc
    try:
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("cert is not a CA (no basicConstraints)") from exc
    if not basic_constraints.ca:
        raise ValueError("cert is not a CA (basicConstraints ca=false)")
    public_key = cert.public_key()
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("cert subject key is not Ed25519")
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


@dataclass(frozen=True)
class TrustAnchor:
    """A trusted credential issuer (spec 8.13 Trust Anchors).

    Attributes:
        pubkey: 32-byte Ed25519 issuer public key.
        kind: KIND_RAW_ED25519 or KIND_X509.
        certs: DER certificates over `pubkey` (empty for raw anchors;
            multiple entries are cross-signed representations).
        provisioned: True if pre-configured (firmware/provisioning);
            provisioned anchors cannot be removed at runtime.
        metadata: Optional application-specific data (str -> str).
    """

    # metadata is a MappingProxyType (unhashable); anchors are identified by
    # issuer_iid, so make hashing explicitly unsupported rather than fail
    # with an accidental TypeError deep in a dict/set operation.
    __hash__ = None  # type: ignore[assignment]

    pubkey: bytes
    kind: str = KIND_RAW_ED25519
    certs: tuple[bytes, ...] = ()
    provisioned: bool = False
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_pubkey(self.pubkey)
        if self.kind not in _VALID_KINDS:
            raise ValueError(f"kind must be one of {_VALID_KINDS}")
        if type(self.provisioned) is not bool:
            raise TypeError("provisioned must be bool")
        if self.kind == KIND_X509 and not self.certs:
            raise ValueError("x509 anchor requires at least one cert")
        if self.kind == KIND_RAW_ED25519 and self.certs:
            raise ValueError("raw anchor must not carry certs")
        for der in self.certs:
            if pubkey_from_der_cert(der) != self.pubkey:
                raise ValueError("cert subject key does not match anchor pubkey")
        if len(self.certs) > MAX_CERTS_PER_ANCHOR:
            raise ValueError(f"at most {MAX_CERTS_PER_ANCHOR} certs per anchor")
        if not isinstance(self.metadata, Mapping):
            raise TypeError("metadata must be a mapping")
        if len(self.metadata) > MAX_METADATA_ENTRIES:
            raise ValueError(f"at most {MAX_METADATA_ENTRIES} metadata entries")
        copied: dict[str, str] = {}
        metadata_bytes = 0
        for key, value in self.metadata.items():
            if type(key) is not str or type(value) is not str:
                raise TypeError("metadata keys and values must be str")
            metadata_bytes += len(key.encode()) + len(value.encode())
            copied[key] = value
        if metadata_bytes > MAX_METADATA_BYTES:
            raise ValueError(f"metadata exceeds {MAX_METADATA_BYTES} bytes")
        object.__setattr__(self, "metadata", MappingProxyType(copied))

    @property
    def issuer_iid(self) -> bytes:
        """8-byte issuer IID (COSE kid) derived from the pubkey."""
        return _pubkey_to_iid(self.pubkey)


class TrustAnchorStore:
    """Trusted issuer anchors keyed by issuer IID (spec 8.13).

    Provisioned anchors are supplied at construction (pre-configured /
    firmware roots). Their trusted KEY set is immutable through the
    runtime API: they cannot be removed, and the runtime add path refuses
    to create provisioned anchors. A provisioned anchor MAY accumulate
    cross-signed certs at runtime — attachment validates the same subject
    key, so the trust decision (the key) never changes, only the cert
    representations a verifier can chain through. Runtime anchors can be
    added and removed freely.
    """

    def __init__(self, provisioned: tuple[TrustAnchor, ...] = ()) -> None:
        self._anchors: dict[bytes, TrustAnchor] = {}
        for anchor in provisioned:
            if type(anchor) is not TrustAnchor:
                raise TypeError("provisioned entries must be TrustAnchor")
            if not anchor.provisioned:
                raise ValueError("provisioned entries must set provisioned=True")
            self._add(anchor)

    def _add(self, anchor: TrustAnchor) -> None:
        iid = anchor.issuer_iid
        if iid in self._anchors:
            raise DuplicateAnchorError(f"anchor {iid.hex()} already exists")
        if len(self._anchors) >= MAX_ANCHORS:
            raise StoreFullError(f"anchor store at capacity ({MAX_ANCHORS})")
        self._anchors[iid] = anchor

    def add(self, anchor: TrustAnchor) -> None:
        """Add a runtime anchor; DuplicateAnchorError if the IID exists.

        Refuses provisioned anchors: pre-configured roots enter only via
        the constructor, so every runtime-added anchor stays removable.
        """
        if type(anchor) is not TrustAnchor:
            raise TypeError("anchor must be TrustAnchor")
        if anchor.provisioned:
            raise ValueError("runtime add refuses provisioned anchors")
        self._add(anchor)

    def add_cross_signed_cert(self, issuer_iid: bytes, der: bytes) -> TrustAnchor:
        """Attach a cross-signed DER cert to an existing anchor.

        The cert's subject key MUST equal the anchor's key (a cross-signed
        root is the same key certified by another root). Allowed on
        provisioned anchors: the trusted key cannot change, only the cert
        representations grow. A raw-ed25519 anchor that gains a cert
        becomes kind=x509 (raw anchors carry no certs by definition); the
        kind flip changes no trust decision — the pinned key is identical.
        """
        anchor = self.get(issuer_iid)
        if anchor is None:
            raise UnknownAnchorError(f"no anchor {issuer_iid.hex()}")
        if pubkey_from_der_cert(der) != anchor.pubkey:
            raise ValueError("cross-signed cert key does not match anchor")
        if der in anchor.certs:
            raise DuplicateAnchorError("cert already attached")
        updated = TrustAnchor(
            pubkey=anchor.pubkey,
            kind=KIND_X509,
            certs=(*anchor.certs, der),
            provisioned=anchor.provisioned,
            metadata=dict(anchor.metadata),
        )
        self._anchors[issuer_iid] = updated
        return updated

    def remove(self, issuer_iid: bytes) -> TrustAnchor:
        """Remove a runtime anchor; provisioned anchors are refused."""
        anchor = self.get(issuer_iid)
        if anchor is None:
            raise UnknownAnchorError(f"no anchor {issuer_iid.hex()}")
        if anchor.provisioned:
            raise ProvisionedAnchorError("provisioned anchors are not removable")
        del self._anchors[issuer_iid]
        return anchor

    def get(self, issuer_iid: bytes) -> TrustAnchor | None:
        return self._anchors.get(issuer_iid)

    def issuer_pubkey(self, issuer_iid: bytes) -> bytes | None:
        """Verification step 3: issuer pubkey lookup by COSE kid."""
        anchor = self.get(issuer_iid)
        return None if anchor is None else anchor.pubkey

    def list(self) -> tuple[TrustAnchor, ...]:
        return tuple(self._anchors.values())

    def __len__(self) -> int:
        return len(self._anchors)

    def __contains__(self, issuer_iid: bytes) -> bool:
        return issuer_iid in self._anchors
