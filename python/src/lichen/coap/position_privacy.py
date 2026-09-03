# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Position-sharing privacy modes (spec 12-apps.md section 18.1).

Three modes govern who may read the node's position:

* ``public``  — anyone; beacons also carry position
* ``group``   — group-OSCORE members only
* ``private`` — one specific peer over pairwise OSCORE only

Reject codes pinned by ``test/vectors/position_privacy_auth.json``:
missing authentication is ``4.01 Unauthorized``; authenticated but
not entitled (non-member or wrong peer) is ``4.03 Forbidden``. Mode
changes take effect immediately for subsequent requests, and beacons
include position only in public mode (beacons are public broadcast).
"""

from __future__ import annotations

import enum


class PositionPrivacyMode(enum.Enum):
    """Position visibility mode (spec/12-apps.md 18.2.4)."""

    OFF = "off"
    PUBLIC = "public"
    GROUP = "group"
    PRIVATE = "private"


CODE_OK = "2.05 Content"
CODE_UNAUTHORIZED = "4.01 Unauthorized"
CODE_FORBIDDEN = "4.03 Forbidden"


class PositionPrivacyPolicy:
    """Mode-aware gate for position reads and beacon inclusion."""

    def __init__(
        self,
        mode: PositionPrivacyMode | str = PositionPrivacyMode.PUBLIC,
        *,
        member_groups: set[str] | None = None,
        allowed_peer_iid: str | None = None,
        allowed_peers: set[str] | None = None,
    ) -> None:
        if isinstance(mode, str):
            mode = PositionPrivacyMode(mode)
        self._mode = mode
        self.member_groups = member_groups or set()
        # Spec 18.2.4 private-mode whitelist: peers explicitly allowed to
        # read this node's position over pairwise OSCORE. Generalized from
        # the single-peer form; allowed_peer_iid seeds the set for back-compat.
        self._allowed_peers: set[str] = set(allowed_peers or set())
        if allowed_peer_iid is not None:
            self._allowed_peers.add(allowed_peer_iid)

    @property
    def mode(self) -> PositionPrivacyMode:
        return self._mode

    @mode.setter
    def mode(self, value: PositionPrivacyMode | str) -> None:
        if isinstance(value, str):
            value = PositionPrivacyMode(value)
        self._mode = value

    @property
    def allowed_peers(self) -> frozenset[str]:
        return frozenset(self._allowed_peers)

    def set_allowed_peers(self, peers: set[str] | list[str]) -> None:
        """Replace the private-mode whitelist (PUT /config/privacy/allowed)."""
        self._allowed_peers = set(peers)

    def _peer_allowed(self, requester_iid: str | None) -> bool:
        return requester_iid is not None and requester_iid in self._allowed_peers

    def check_read(
        self,
        *,
        oscore: bool = False,
        oscore_context: str | None = None,
        requester_iid: str | None = None,
    ) -> tuple[bool, str]:
        """Authorize one GET /position against the current mode.

        Returns ``(accept, response_code)``.
        """
        if self._mode is PositionPrivacyMode.OFF:
            # GPS disabled — no position sharing at all (spec 18.2.4).
            return (False, CODE_FORBIDDEN)

        if self._mode is PositionPrivacyMode.PUBLIC:
            return (True, CODE_OK)

        if self._mode is PositionPrivacyMode.GROUP:
            if not oscore:
                return (False, CODE_UNAUTHORIZED)
            if self._peer_allowed(requester_iid):
                return (True, CODE_OK)
            if oscore_context == "group":
                return (True, CODE_OK)
            return (False, CODE_FORBIDDEN)

        # PRIVATE
        if not oscore:
            return (False, CODE_UNAUTHORIZED)
        if self._peer_allowed(requester_iid):
            return (True, CODE_OK)
        return (False, CODE_FORBIDDEN)

    def include_position_in_beacon(self) -> bool:
        """Whether the PUBLIC broadcast beacon carries position.

        Per spec 18.2.4, only public mode beacons to all. OFF mode never
        shares position; GROUP mode shares it via the *encrypted* ff35
        group beacon (see include_encrypted_group_beacon); PRIVATE mode
        never beacons.
        """
        return self._mode is PositionPrivacyMode.PUBLIC

    def include_encrypted_group_beacon(self) -> bool:
        """Whether the encrypted ff35 group beacon is emitted (spec 18.2.4).

        GROUP mode beacons to the group only, sealed with the group OSCORE
        key (spec 18.2.4 table: "Beacon to group only (encrypted)"). The
        sealed emission itself goes through
        :func:`lichen.coap.group_beacon.seal_position_beacon`; this predicate
        gates whether that emitter runs.
        """
        return self._mode is PositionPrivacyMode.GROUP
