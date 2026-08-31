# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Base classes and constants for CoAP resources."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

import cbor2
from aiocoap import (
    CONTENT,
    FORBIDDEN,
    METHOD_NOT_ALLOWED,
    NOT_FOUND,
    UNAUTHORIZED,
    Message,
    resource,
)
from aiocoap.numbers import ContentFormat

from lichen.coap.access import AccessLevel, can_access

if TYPE_CHECKING:
    pass

CBOR = ContentFormat.CBOR
SENML_CBOR = ContentFormat(112)  # application/senml+cbor (RFC 8428)

AccessLevelResolver = Callable[[Message], AccessLevel]


def denied_response(
    access_level: AccessLevelResolver | None,
    request: Message,
    method: str,
    resource_path: str,
) -> Message | None:
    """Server-side LCI authorization gate (spec/11-lci.md 17.6.3).

    Resolves the requester's access level through ``access_level`` and
    applies the pinned ``can_access`` rule table. A ``None`` resolver means
    the assembler wired no level source, which fails closed to the
    least-privileged tier (17.5.4 R-11-030: raw diagnostics MUST require
    local administrative authorization).
    """
    level = access_level(request) if access_level is not None else AccessLevel.READ_ONLY
    allowed, code = can_access(level, method, resource_path)
    if allowed:
        return None
    if code is None:
        # can_access never returns (False, None); fail closed regardless.
        return Message(code=FORBIDDEN)
    code_map = {
        "4.01": UNAUTHORIZED,
        "4.03": FORBIDDEN,
        "4.04": NOT_FOUND,
        "4.05": METHOD_NOT_ALLOWED,
    }
    return Message(code=code_map.get(code, FORBIDDEN))


class NodeInfo(Protocol):
    """Data source backing the CoAP resources."""

    def get_status(self) -> dict[str, Any]: ...
    def get_neighbors(self) -> list[dict[str, Any]]: ...
    def get_routes(self) -> dict[str, Any]: ...
    def get_config(self) -> dict[str, Any]: ...
    def set_config(self, updates: dict[str, Any]) -> None: ...
    def get_radio_config(self) -> dict[str, Any]: ...
    def set_radio_config(self, updates: dict[str, Any]) -> None: ...
    def get_identity(self) -> dict[str, Any]: ...


@dataclass
class StaticNodeInfo:
    """A simple in-memory :class:`NodeInfo` for tests and single-node sims."""

    status: dict[str, Any] = field(default_factory=dict)
    neighbors: list[dict[str, Any]] = field(default_factory=list)
    routes: dict[str, Any] = field(default_factory=lambda: {"routes": [], "default_route": None})
    config: dict[str, Any] = field(default_factory=dict)
    radio_config: dict[str, Any] = field(default_factory=dict)
    identity: dict[str, Any] = field(default_factory=dict)

    def get_status(self) -> dict[str, Any]:
        return dict(self.status)

    def get_neighbors(self) -> list[dict[str, Any]]:
        return [dict(n) for n in self.neighbors]

    def get_routes(self) -> dict[str, Any]:
        return {
            "routes": [dict(r) for r in self.routes.get("routes", [])],
            "default_route": self.routes.get("default_route"),
        }

    def get_config(self) -> dict[str, Any]:
        return dict(self.config)

    def set_config(self, updates: dict[str, Any]) -> None:
        unknown = set(updates) - set(self.config)
        if unknown:
            raise ValueError(f"unknown config keys: {sorted(unknown)}")
        candidate = dict(self.config)
        candidate.update(updates)
        self.config = candidate

    def get_radio_config(self) -> dict[str, Any]:
        return dict(self.radio_config)

    def set_radio_config(self, updates: dict[str, Any]) -> None:
        unknown = set(updates) - set(self.radio_config)
        if unknown:
            raise ValueError(f"unknown radio config keys: {sorted(unknown)}")
        candidate = dict(self.radio_config)
        candidate.update(updates)
        self.radio_config = candidate

    def get_identity(self) -> dict[str, Any]:
        return dict(self.identity)


def _cbor_response(value: Any) -> Message:
    msg = Message(code=CONTENT, payload=cbor2.dumps(value))
    msg.opt.content_format = CBOR
    return msg


class _ReadResource(resource.Resource):
    """A read-only CBOR resource advertising a resource type."""

    rt = "lichen"

    def __init__(self, node_info: NodeInfo) -> None:
        super().__init__()
        self.node_info = node_info

    def get_link_description(self) -> dict[str, Any]:
        # Link-format attribute values are strings (RFC 6690).
        return {"rt": self.rt, "ct": str(int(CBOR))}
