# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Local Facts (gateway-issued) per spec section 8.13.1.

Gateways issue local facts for nodes in their mesh. No PKI is required; trust
is implicit (a node trusts its gateway). A fact is a COSE_Sign1 credential
signed by the issuing gateway's Ed25519 key (Schnorr48-Ed25519, alg -65537),
carrying a set of ``lichen:`` claims about what the gateway will do for the
node (relay to emergency services, relay others' traffic, priority, quota,
...). Facts are mesh-lifetime: gateway restart or root re-election invalidates
cached facts.

This is the Python reference implementation of the credential model: claim
encoding, COSE_Sign1 issuance (gateway side) and verification (node side).
The CoAP resource wiring (POST /.well-known/local-fact) and OSCORE transport
protection are separate concerns layered on top of this model.

COSE Algorithm: Schnorr48-Ed25519 (algorithm ID -65537)
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from hashlib import sha256
from typing import cast

import cbor2

from ..crypto import schnorr48
from ..crypto.delegation_tokens import (
    COSE_ALG_LABEL,
    COSE_KID_LABEL,
    SCHNORR48_ED25519_ALG,
    cose_protected_header,
    cose_sig_structure,
)
from ..crypto.identity import Identity, _pubkey_to_iid

# Local fact claim names (spec 8.13.1 "Local Fact Claims").
CLAIM_EMERGENCY = "lichen:emergency"
CLAIM_EMERGENCY_CALLBACK = "lichen:emergency_callback"
CLAIM_RELAY = "lichen:relay"
CLAIM_PRIORITY = "lichen:priority"
CLAIM_CHANNEL = "lichen:channel"
CLAIM_QUOTA = "lichen:quota"
CLAIM_SPONSORED = "lichen:sponsored"

# Claim name -> expected CBOR/Python type(s). bool is checked before int
# because Python bool is a subclass of int.
_CLAIM_TYPES: dict[str, tuple[type, ...]] = {
    CLAIM_EMERGENCY: (bool,),
    CLAIM_EMERGENCY_CALLBACK: (str,),
    CLAIM_RELAY: (bool,),
    CLAIM_PRIORITY: (int,),
    CLAIM_CHANNEL: (list,),
    CLAIM_QUOTA: (int,),
    CLAIM_SPONSORED: (str,),
}

# Priority is a uint 0=low .. 3=emergency (spec 8.13.1).
_MAX_PRIORITY = 3


class LocalFactError(Exception):
    """Local fact issuance/verification error."""


def _loads_strict(data: bytes, what: str) -> object:
    """Decode one CBOR item, rejecting trailing bytes.

    cbor2.loads silently ignores bytes after the first item; a fail-closed
    decoder must not accept a payload/envelope with trailing garbage (which
    would also be invisible to signature verification).
    """
    buf = io.BytesIO(data)
    try:
        value = cbor2.CBORDecoder(buf).decode()
    except (cbor2.CBORDecodeError, OverflowError) as e:
        raise LocalFactError(f"invalid {what}: {e}") from None
    if buf.tell() != len(data):
        raise LocalFactError(f"trailing bytes after {what}")
    return value


@dataclass(frozen=True)
class LocalFactClaims:
    """The set of ``lichen:`` claims asserted by a local fact.

    All claims are optional; a fact carries whatever subset the gateway's
    policy grants. Attribute values are already validated for type and range
    in :meth:`__post_init__`.
    """

    emergency: bool | None = None
    emergency_callback: str | None = None
    relay: bool | None = None
    priority: int | None = None
    channel: tuple[str, ...] | None = None
    quota: int | None = None
    sponsored: str | None = None

    def __post_init__(self) -> None:
        # bool claims use an exact-type check (bool is a subclass of int).
        if self.emergency is not None and type(self.emergency) is not bool:
            raise LocalFactError(f"{CLAIM_EMERGENCY} must be a bool")
        if self.relay is not None and type(self.relay) is not bool:
            raise LocalFactError(f"{CLAIM_RELAY} must be a bool")
        if self.emergency_callback is not None and type(self.emergency_callback) is not str:
            raise LocalFactError(f"{CLAIM_EMERGENCY_CALLBACK} must be a tstr")
        if self.sponsored is not None and type(self.sponsored) is not str:
            raise LocalFactError(f"{CLAIM_SPONSORED} must be a tstr")
        if self.priority is not None and (
            type(self.priority) is not int or not 0 <= self.priority <= _MAX_PRIORITY
        ):
            raise LocalFactError(f"{CLAIM_PRIORITY} must be a uint 0..{_MAX_PRIORITY}")
        if self.quota is not None and (type(self.quota) is not int or self.quota < 0):
            raise LocalFactError(f"{CLAIM_QUOTA} must be a non-negative uint")
        # Require a real (non-str/bytes) sequence of tstr: a bare str would
        # iterate as characters and pass the element check; a non-iterable
        # would raise TypeError instead of LocalFactError.
        if self.channel is not None and (
            isinstance(self.channel, (str, bytes))
            or not isinstance(self.channel, (tuple, list))
            or not all(type(c) is str for c in self.channel)
        ):
            raise LocalFactError(f"{CLAIM_CHANNEL} must be a list of tstr")
        # Normalize to tuple: from_cbor decodes CBOR arrays to list but
        # normalizes to tuple itself, and to_cbor accepts either. Frozen
        # dataclass equality is by-value, so a list-built claims would never
        # equal its own decode — the wire-bstr consistency check on LocalFact
        # would then falsely reject an otherwise valid fact. Single source of
        # truth here keeps encode/decode symmetric.
        if self.channel is not None and not isinstance(self.channel, tuple):
            object.__setattr__(self, "channel", tuple(self.channel))

    def to_cbor(self) -> bytes:
        """Encode the claims as a CBOR map (payload of the COSE).

        Keys are emitted in a fixed insertion order (deterministic for a given
        construction); this is not the CBOR "canonical" (length-first)
        ordering. Other encoders may legally emit a different order, which is
        why verification runs over the retained wire bstrs, not a re-encode
        (see verify_local_fact).
        """
        claims: dict[str, object] = {}
        if self.emergency is not None:
            claims[CLAIM_EMERGENCY] = self.emergency
        if self.emergency_callback is not None:
            claims[CLAIM_EMERGENCY_CALLBACK] = self.emergency_callback
        if self.relay is not None:
            claims[CLAIM_RELAY] = self.relay
        if self.priority is not None:
            claims[CLAIM_PRIORITY] = self.priority
        if self.channel is not None:
            claims[CLAIM_CHANNEL] = list(self.channel)
        if self.quota is not None:
            claims[CLAIM_QUOTA] = self.quota
        if self.sponsored is not None:
            claims[CLAIM_SPONSORED] = self.sponsored
        return cbor2.dumps(claims)

    @classmethod
    def from_cbor(cls, data: bytes) -> LocalFactClaims:
        """Decode a CBOR claims map, validating claim names and types.

        Unknown claims are rejected: a node must not silently ignore a fact it
        does not understand (fail-closed on policy assertions).
        """
        claims = _loads_strict(data, "claims CBOR")
        if not isinstance(claims, dict):
            raise LocalFactError("local-fact payload must be a map")
        # Validate every claim's type up front (fail-closed on unknown names).
        for key, val in claims.items():
            expected = _CLAIM_TYPES.get(key)
            if expected is None:
                raise LocalFactError(f"unknown local-fact claim: {key!r}")
            # bool claims use an exact-type check (bool is a subclass of int,
            # so a uint 1 must not coerce to True, nor True to a uint claim).
            if expected == (bool,) and type(val) is not bool:
                raise LocalFactError(f"{key} must be a bool")
            if expected == (int,) and type(val) is not int:
                raise LocalFactError(f"{key} must be a uint")
            if expected == (str,) and type(val) is not str:
                raise LocalFactError(f"{key} must be a tstr")
            if expected == (list,) and (
                not isinstance(val, list) or not all(type(c) is str for c in val)
            ):
                raise LocalFactError(f"{key} must be a list of tstr")

        # Types are validated above; the dataclass __post_init__ re-checks the
        # ranges. mypy cannot narrow the heterogeneous map values, so build via
        # a typed view.
        channel = claims.get(CLAIM_CHANNEL)
        return cls(
            emergency=cast("bool | None", claims.get(CLAIM_EMERGENCY)),
            emergency_callback=cast("str | None", claims.get(CLAIM_EMERGENCY_CALLBACK)),
            relay=cast("bool | None", claims.get(CLAIM_RELAY)),
            priority=cast("int | None", claims.get(CLAIM_PRIORITY)),
            channel=tuple(channel) if channel is not None else None,
            quota=cast("int | None", claims.get(CLAIM_QUOTA)),
            sponsored=cast("str | None", claims.get(CLAIM_SPONSORED)),
        )


@dataclass(frozen=True)
class LocalFact:
    """A signed local-fact credential (COSE_Sign1).

    Attributes:
        claims: The asserted ``lichen:`` claims.
        issuer_iid: 8-byte IID of the issuing gateway (COSE kid).
        signature: 48-byte Schnorr48 signature.
        protected_bytes: Received protected-header bstr, retained verbatim.
        payload_bytes: Received payload bstr, retained verbatim.

    The wire bstrs are retained because RFC 9052 section 4.4 signs the
    protected header and payload AS TRANSPORTED: a peer using a different
    (equally valid) CBOR encoding — other map-key order, non-minimal ints —
    produces bytes that re-encoding here would not reproduce, breaking
    Python<->C/Rust interop. Both are populated by :meth:`from_cose_sign1`
    and :func:`issue_local_fact`; they are None only for a fact constructed
    directly from its fields.
    """

    claims: LocalFactClaims
    issuer_iid: bytes
    signature: bytes = field(repr=False)
    protected_bytes: bytes | None = field(default=None, repr=False)
    payload_bytes: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.issuer_iid, bytes) or len(self.issuer_iid) != 8:
            raise LocalFactError("issuer_iid must be an 8-byte gateway IID")
        if not isinstance(self.signature, bytes):
            raise LocalFactError("signature must be bytes")
        if len(self.signature) != 48:
            raise LocalFactError(f"signature must be 48 bytes, got {len(self.signature)}")
        if (self.protected_bytes is None) != (self.payload_bytes is None):
            raise LocalFactError("wire bstrs must be retained as a pair or not at all")
        # Wire bstrs, when present, must actually be bytes (module contract:
        # bad field types raise LocalFactError, never leak a TypeError from
        # the CBOR layer).
        if self.protected_bytes is not None and (
            not isinstance(self.protected_bytes, bytes)
            or not isinstance(self.payload_bytes, bytes)
        ):
            raise LocalFactError("wire bstrs must be bytes")
        # The retained wire bstrs are what the signature is verified over
        # (RFC 9052 section 4.4); they must decode to exactly the claims
        # carried on the object. On a frozen dataclass the idiomatic mutation
        # is dataclasses.replace(fact, claims=...), which keeps the old wire
        # bstrs; without this check a desynced fact would verify over the OLD
        # signed payload while .claims carries unverified fields, silently
        # dropping the tamper-resistance property. Compare decoded
        # (encoding-agnostic) so a peer's valid-but-different CBOR encoding
        # still passes.
        if self.payload_bytes is not None and (
            LocalFactClaims.from_cbor(self.payload_bytes) != self.claims
        ):
            raise LocalFactError(
                "claims do not match the retained payload_bytes: "
                "payload_bytes do not decode to the claims on the fact"
            )

    def to_cose_sign1(self) -> bytes:
        """Encode as a CBOR COSE_Sign1 array [protected, unprotected, payload, sig].

        When wire bstrs were retained (decode or issuance), they are emitted
        verbatim so a forwarded/stored fact stays byte-identical and its
        signature remains valid for downstream verifiers.
        """
        protected = (
            self.protected_bytes if self.protected_bytes is not None else cose_protected_header()
        )
        payload = self.payload_bytes if self.payload_bytes is not None else self.claims.to_cbor()
        unprotected = {COSE_KID_LABEL: self.issuer_iid}
        return cbor2.dumps([protected, unprotected, payload, self.signature])

    @classmethod
    def from_cose_sign1(cls, data: bytes) -> LocalFact:
        """Decode a COSE_Sign1 local fact. Signature verification is the
        caller's job (:func:`verify_local_fact`) with the resolved gateway key."""
        cose_array = _loads_strict(data, "COSE envelope")
        if not isinstance(cose_array, list) or len(cose_array) != 4:
            raise LocalFactError("COSE_Sign1 must be a 4-element array")
        protected_bytes, unprotected, payload_bytes, signature = cose_array
        if not isinstance(protected_bytes, bytes) or not isinstance(payload_bytes, bytes):
            raise LocalFactError("protected header and payload must be bstr")
        protected = _loads_strict(protected_bytes, "protected header")
        alg = protected.get(COSE_ALG_LABEL) if isinstance(protected, dict) else None
        if alg != SCHNORR48_ED25519_ALG:
            raise LocalFactError(
                f"local-fact alg must be Schnorr48-Ed25519 ({SCHNORR48_ED25519_ALG})"
            )
        if not isinstance(unprotected, dict):
            raise LocalFactError("COSE unprotected header must be a map")
        issuer_iid = unprotected.get(COSE_KID_LABEL)
        if not isinstance(issuer_iid, bytes) or len(issuer_iid) != 8:
            raise LocalFactError("kid in unprotected header must be an 8-byte gateway IID")
        if not isinstance(signature, bytes) or len(signature) != 48:
            raise LocalFactError("signature must be 48 bytes")
        claims = LocalFactClaims.from_cbor(payload_bytes)
        return cls(
            claims=claims,
            issuer_iid=issuer_iid,
            signature=signature,
            protected_bytes=protected_bytes,
            payload_bytes=payload_bytes,
        )


def issue_local_fact(identity: Identity, claims: LocalFactClaims) -> LocalFact:
    """Issue (sign) a local fact with the gateway's identity.

    Args:
        identity: The issuing gateway's identity (signing key + IID).
        claims: The claims to assert.

    Returns:
        A signed LocalFact ready for transmission.
    """
    protected = cose_protected_header()
    payload_bytes = claims.to_cbor()
    sig_structure = cose_sig_structure(protected, payload_bytes)
    to_sign = sha256(sig_structure).digest()
    signature = schnorr48.sign(identity.privkey, identity.pubkey, to_sign)
    return LocalFact(
        claims=claims,
        issuer_iid=identity.iid,
        signature=signature,
        protected_bytes=protected,
        payload_bytes=payload_bytes,
    )


def verify_local_fact(fact: LocalFact, gateway_pubkey: bytes) -> bool:
    """Verify a local fact's Schnorr48 signature against the gateway pubkey.

    The Sig_structure is built over the protected-header and payload bstrs
    AS TRANSPORTED (RFC 9052 section 4.4), retained on the fact by
    :meth:`LocalFact.from_cose_sign1` / :func:`issue_local_fact`. For a fact
    constructed directly from fields (no wire bytes), the header and claims
    are re-encoded instead — correct only against an encoder using this
    module's exact encoding, which is all a locally built fact can promise.

    Args:
        fact: The decoded local fact.
        gateway_pubkey: The issuing gateway's 32-byte Ed25519 public key.

    Returns:
        True if the signature verifies and the claimed issuer IID matches the
        verifying key, False otherwise.
    """
    # issuer_iid lives in the unprotected header (not signature-covered), so
    # bind it to the verifying key: a fact claiming gateway A's IID must
    # verify against A's pubkey. Matches verify_delegation_token's
    # DELEGATOR_IID_MISMATCH hygiene; matters if downstream trusts issuer_iid
    # for federation/audit rather than resolving keys strictly by kid.
    if _pubkey_to_iid(gateway_pubkey) != fact.issuer_iid:
        return False
    if fact.protected_bytes is not None and fact.payload_bytes is not None:
        protected = fact.protected_bytes
        payload_bytes = fact.payload_bytes
    else:
        protected = cose_protected_header()
        payload_bytes = fact.claims.to_cbor()
    sig_structure = cose_sig_structure(protected, payload_bytes)
    digest = sha256(sig_structure).digest()
    return schnorr48.verify(gateway_pubkey, digest, fact.signature)
