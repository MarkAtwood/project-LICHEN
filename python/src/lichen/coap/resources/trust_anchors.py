# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""GET/POST/DELETE /.well-known/trust-anchors (spec 06-security.md 8.13).

Verifiers maintain trusted issuer anchors ("Trust Anchors"). This
resource exposes the anchor set over CoAP:

- GET: list anchors (CBOR array; public keys/certs are not secret).
- POST: add a runtime anchor — CBOR map {kind, pubkey | certs, metadata?}.
  Guarded by an injected authorization callback over the OSCORE-bound
  requester identity; fail-closed when no callback is configured.
- DELETE: remove a runtime anchor — CBOR map {id: <8-byte issuer IID>}.
  Provisioned (pre-configured) anchors refuse with 4.03.

Cross-signed roots: POST a second DER cert for an existing anchor's key
with {"cross_signed": true}; the cert attaches to that anchor instead of
creating a duplicate.

Python reference for viku.2; Rust and C ports are follow-ups.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import aiocoap
import cbor2
from aiocoap import Message, resource

from lichen.coap.resources.cbor_validation import _decode_single_cbor
from lichen.coap.resources.deaddrop import _request_context_id
from lichen.crypto.trust_anchors import (
    KIND_RAW_ED25519,
    KIND_X509,
    DuplicateAnchorError,
    ProvisionedAnchorError,
    StoreFullError,
    TrustAnchor,
    TrustAnchorStore,
    UnknownAnchorError,
    pubkey_from_der_cert,
)

CBOR = 60

_KNOWN_POST_FIELDS = {"kind", "pubkey", "certs", "metadata", "cross_signed", "id"}
_NEW_ANCHOR_FIELDS = {"kind", "pubkey", "certs", "metadata"}
_CROSS_SIGNED_FIELDS = {"cross_signed", "id", "certs"}
_KNOWN_DELETE_FIELDS = {"id"}
_MAX_CERTS_PER_POST = 4


def _anchor_to_cbor(anchor: TrustAnchor) -> dict[str, Any]:
    return {
        "id": anchor.issuer_iid,
        "kind": anchor.kind,
        "pubkey": anchor.pubkey,
        "certs": list(anchor.certs),
        "provisioned": anchor.provisioned,
        "metadata": dict(anchor.metadata),
    }


def _error(code: int, detail: str) -> Message:
    msg = Message(code=code)
    msg.opt.content_format = CBOR
    msg.payload = cbor2.dumps({"error": detail})
    return msg


class TrustAnchorsResource(resource.Resource):
    """/.well-known/trust-anchors (spec 8.13).

    `authorize` maps the OSCORE-bound requester identity (context id) to
    an allow/deny decision for mutations. Fail-closed: no identity or no
    callback means no mutation. GET is unauthenticated — anchors are
    public keys, and verifiers must be able to enumerate them.
    """

    rt = "lichen.trust-anchors"

    def __init__(
        self,
        store: TrustAnchorStore,
        authorize: Callable[[str], bool] | None = None,
    ) -> None:
        super().__init__()
        self._store = store
        self._authorize = authorize

    def _authorized(self, request: Message) -> bool:
        context_id = _request_context_id(request)
        if context_id is None or self._authorize is None:
            return False
        return bool(self._authorize(context_id))

    async def render_get(self, request: Message) -> Message:
        msg = Message(code=aiocoap.CONTENT)
        msg.opt.content_format = CBOR
        msg.payload = cbor2.dumps([_anchor_to_cbor(anchor) for anchor in self._store.list()])
        return msg

    async def render_post(self, request: Message) -> Message:
        if not self._authorized(request):
            return _error(aiocoap.FORBIDDEN, "forbidden")
        if not request.payload:
            return _error(aiocoap.BAD_REQUEST, "empty_payload")
        try:
            body: Any = _decode_single_cbor(request.payload)
        except Exception:
            return _error(aiocoap.BAD_REQUEST, "bad_cbor")
        if not isinstance(body, dict) or not set(body) <= _KNOWN_POST_FIELDS:
            return _error(aiocoap.BAD_REQUEST, "bad_fields")

        metadata = body.get("metadata", {})
        if not isinstance(metadata, dict) or not all(
            type(k) is str and type(v) is str for k, v in metadata.items()
        ):
            return _error(aiocoap.BAD_REQUEST, "bad_metadata")

        try:
            if body.get("cross_signed") is True:
                # Strict field set per path: silently dropped fields hide
                # client mistakes (e.g. an "id" on create).
                if not set(body) <= _CROSS_SIGNED_FIELDS:
                    return _error(aiocoap.BAD_REQUEST, "bad_fields")
                return self._post_cross_signed(body)
            if not set(body) <= _NEW_ANCHOR_FIELDS:
                return _error(aiocoap.BAD_REQUEST, "bad_fields")
            return self._post_new_anchor(body, metadata)
        except (TypeError, ValueError) as exc:
            return _error(aiocoap.BAD_REQUEST, str(exc))

    def _post_new_anchor(self, body: dict[str, Any], metadata: dict[str, str]) -> Message:
        kind = body.get("kind")
        pubkey = body.get("pubkey")
        certs = body.get("certs", [])
        if kind == KIND_RAW_ED25519:
            if certs is not None and (not isinstance(certs, list) or certs):
                return _error(aiocoap.BAD_REQUEST, "raw anchor must not carry certs")
            if type(pubkey) is not bytes:
                return _error(aiocoap.BAD_REQUEST, "bad_pubkey")
            anchor = TrustAnchor(pubkey=pubkey, kind=kind, metadata=metadata)
        elif kind == KIND_X509:
            if not isinstance(certs, list) or not certs or len(certs) > _MAX_CERTS_PER_POST:
                return _error(aiocoap.BAD_REQUEST, "bad_certs")
            # Derive the anchor key from the first cert; TrustAnchor
            # validation rejects any additional cert over a different key.
            derived = pubkey_from_der_cert(certs[0])
            # An explicit pubkey is honored but must match the cert: a
            # silent mismatch would pin a different key than the caller
            # intended while reporting success.
            if pubkey is not None and pubkey != derived:
                return _error(aiocoap.BAD_REQUEST, "pubkey_mismatch")
            anchor = TrustAnchor(
                pubkey=derived,
                kind=kind,
                certs=tuple(certs),
                metadata=metadata,
            )
        else:
            return _error(aiocoap.BAD_REQUEST, "bad_kind")
        try:
            self._store.add(anchor)
        except DuplicateAnchorError:
            return _error(aiocoap.CONFLICT, "duplicate")
        except StoreFullError:
            return _error(aiocoap.SERVICE_UNAVAILABLE, "store_full")
        msg = Message(code=aiocoap.CREATED)
        msg.opt.content_format = CBOR
        msg.payload = cbor2.dumps({"id": anchor.issuer_iid})
        return msg

    def _post_cross_signed(self, body: dict[str, Any]) -> Message:
        certs = body.get("certs")
        if not isinstance(certs, list) or len(certs) != 1:
            return _error(aiocoap.BAD_REQUEST, "cross_signed carries exactly one cert")
        anchor_id = body.get("id")
        if type(anchor_id) is not bytes or len(anchor_id) != 8:
            return _error(aiocoap.BAD_REQUEST, "bad_id")
        try:
            self._store.add_cross_signed_cert(anchor_id, certs[0])
        except UnknownAnchorError:
            return _error(aiocoap.NOT_FOUND, "unknown_anchor")
        except DuplicateAnchorError:
            return _error(aiocoap.CONFLICT, "duplicate")
        except (TypeError, ValueError) as exc:
            return _error(aiocoap.BAD_REQUEST, str(exc))
        return Message(code=aiocoap.CHANGED)

    async def render_delete(self, request: Message) -> Message:
        if not self._authorized(request):
            return _error(aiocoap.FORBIDDEN, "forbidden")
        if not request.payload:
            return _error(aiocoap.BAD_REQUEST, "empty_payload")
        try:
            body: Any = _decode_single_cbor(request.payload)
        except Exception:
            return _error(aiocoap.BAD_REQUEST, "bad_cbor")
        if not isinstance(body, dict) or not set(body) <= _KNOWN_DELETE_FIELDS:
            return _error(aiocoap.BAD_REQUEST, "bad_fields")
        anchor_id = body.get("id")
        if type(anchor_id) is not bytes or len(anchor_id) != 8:
            return _error(aiocoap.BAD_REQUEST, "bad_id")
        try:
            self._store.remove(anchor_id)
        except UnknownAnchorError:
            return _error(aiocoap.NOT_FOUND, "unknown_anchor")
        except ProvisionedAnchorError:
            return _error(aiocoap.FORBIDDEN, "provisioned")
        return Message(code=aiocoap.DELETED)
