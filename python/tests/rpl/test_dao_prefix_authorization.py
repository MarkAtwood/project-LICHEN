# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Table-driven root DAO prefix-authorization matrix (spec 8.7-8.7.2).

Python twin of rust/lichen-rpl/tests/dao_prefix_authorization.rs. The `.44.7`
wire profile rejects non-/128 Target options during origin validation before
authorization; delegation tokens govern foreign /128 host routes. Every denial
must leave route and replay state untouched.

Delegation fixtures are built with create_prefix_delegation_token as
round-trip/wiring tests; the token codec's own oracle tests live in
tests/crypto/.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import IPv6Address

import pytest

from lichen.crypto.delegation_tokens import create_prefix_delegation_token
from lichen.crypto.identity import Identity, yggdrasil_address
from lichen.crypto.schnorr48 import sign
from lichen.rpl.dao_manager import DaoError, DaoManager
from lichen.rpl.dao_origin import (
    DAO_ORIGIN_SIGNATURE_TYPE,
    DaoOriginValidator,
    compute_signature_transcript,
)
from lichen.rpl.dao_persistence import MemoryPersistence
from lichen.rpl.dao_types import RplTarget, TransitInformation
from lichen.rpl.messages import DAO, RplOption, RplOptionType
from lichen.rpl.routing import RouteTarget

ROOT_SEED = bytes([0x11] * 32)
NODE_SEED = bytes([0x55] * 32)
OTHER_SEED = bytes([0x66] * 32)
FOREIGN_SEED = bytes([0x77] * 32)

ROOT_IDENTITY = Identity.from_seed(ROOT_SEED)
ROOT_ADDR = yggdrasil_address(ROOT_IDENTITY.pubkey)
NODE_IDENTITY = Identity.from_seed(NODE_SEED)
NODE_ADDR = yggdrasil_address(NODE_IDENTITY.pubkey)
OTHER_IDENTITY = Identity.from_seed(OTHER_SEED)
FOREIGN_IDENTITY = Identity.from_seed(FOREIGN_SEED)
FOREIGN_ADDR = yggdrasil_address(FOREIGN_IDENTITY.pubkey)
DODAG_ID = ROOT_ADDR

NOW = 1000.0
FAR_EXPIRY = 2000
DELEGATED_PREFIX = IPv6Address("2001:db8:aa::")


class _PinTable:
    """Minimal pinned-key table: IID -> Ed25519 pubkey (spec 8.6)."""

    def __init__(self, pins: dict[bytes, bytes]) -> None:
        self._pins = pins

    def pinned_pubkey_for(self, iid: bytes) -> bytes | None:
        return self._pins.get(iid)


def make_root_manager(
    wall_clock: Callable[[], float] | None = None,
) -> tuple[DaoManager, MemoryPersistence]:
    """Root manager authenticating NODE as the only pinned origin."""
    if wall_clock is None:
        wall_clock = lambda: NOW  # noqa: E731
    persistence = MemoryPersistence()
    pins = _PinTable({NODE_IDENTITY.iid: NODE_IDENTITY.pubkey})
    validator = DaoOriginValidator(pins, persistence)
    manager = DaoManager(
        node_address=ROOT_ADDR,
        is_root=True,
        dodag_id=DODAG_ID,
        origin_validator=validator,
        persistence=persistence,
        origin_identity=ROOT_IDENTITY,
        wall_clock=wall_clock,
    )
    return manager, persistence


def _sign_dao(identity: Identity, origin_sequence: int, options: list[RplOption]) -> DAO:
    unsigned = DAO(rpl_instance_id=0, dao_sequence=1, dodag_id=DODAG_ID, options=options).to_bytes()
    source = yggdrasil_address(identity.pubkey)
    transcript = compute_signature_transcript(source, DODAG_ID, origin_sequence, unsigned)
    signature = sign(identity.privkey, identity.pubkey, transcript)
    sig_option = RplOption(
        DAO_ORIGIN_SIGNATURE_TYPE, struct.pack(">Q", origin_sequence) + signature
    )
    wire = DAO(
        rpl_instance_id=0,
        dao_sequence=1,
        dodag_id=DODAG_ID,
        options=options + [sig_option],
    ).to_bytes()
    return DAO.from_bytes(wire)


def make_signed_dao(
    identity: Identity,
    parent: IPv6Address,
    origin_sequence: int,
    *,
    target: IPv6Address | None = None,
    external: bool = False,
) -> DAO:
    """Build a /128-target DAO with a valid origin signature (spec 8.6)."""
    if target is None:
        target = yggdrasil_address(identity.pubkey)
    options = [
        RplTarget(target).to_option(),
        TransitInformation(
            parent,
            path_sequence=241,
            path_lifetime=255,
            external=external,
        ).to_option(),
    ]
    return _sign_dao(identity, origin_sequence, options)


def make_signed_prefix_target_dao(
    identity: Identity,
    parent: IPv6Address,
    origin_sequence: int,
    prefix_len: int,
    prefix_bytes: bytes,
) -> DAO:
    """Build a DAO whose Target option carries a generalized (len, prefix)."""
    options = [
        RplOption(RplOptionType.RPL_TARGET, bytes([0, prefix_len]) + prefix_bytes),
        TransitInformation(parent, path_sequence=241, path_lifetime=255).to_option(),
    ]
    return _sign_dao(identity, origin_sequence, options)


@dataclass(frozen=True)
class PrefixAuthCase:
    """One matrix row: (name, DAO builder, expected denial reason, allowed)."""

    name: str
    make_dao: Callable[[], DAO]
    expected_reason: str | None
    accepted: bool


CASES = [
    PrefixAuthCase(
        "self_host_route_allowed",
        lambda: make_signed_dao(NODE_IDENTITY, ROOT_ADDR, 1),
        "installed",
        True,
    ),
    PrefixAuthCase(
        "foreign_host_route_rejected",
        lambda: make_signed_dao(NODE_IDENTITY, ROOT_ADDR, 1, target=FOREIGN_ADDR),
        "target_mismatch",
        False,
    ),
    PrefixAuthCase(
        "slash_zero_rejected",
        lambda: make_signed_prefix_target_dao(NODE_IDENTITY, ROOT_ADDR, 1, 0, b""),
        "malformed_option",
        False,
    ),
    PrefixAuthCase(
        "undelegated_broad_prefix_rejected",
        lambda: make_signed_prefix_target_dao(
            NODE_IDENTITY, ROOT_ADDR, 1, 64, DELEGATED_PREFIX.packed[:8]
        ),
        "malformed_option",
        False,
    ),
]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_dao_prefix_authorization_allow_deny_matrix(case: PrefixAuthCase) -> None:
    """Allow/deny rows reject before any route or replay-floor mutation."""
    manager, persistence = make_root_manager()
    routes_before = manager.routing_table.routes()
    dao = case.make_dao()

    if case.accepted:
        manager.validate_and_process_dao(dao, NODE_ADDR)
        assert RouteTarget.host(NODE_ADDR) in manager.routing_table.routes()
        floor = persistence.get_floor(NODE_IDENTITY.pubkey)
        assert floor is not None
        assert floor[0] == 1
    else:
        with pytest.raises(DaoError) as denied:
            manager.validate_and_process_dao(dao, NODE_ADDR)
        assert denied.value.reason == case.expected_reason
        assert manager.routing_table.routes() == routes_before
        assert persistence.get_floor(NODE_IDENTITY.pubkey) is None
        # A denial must not advance the replay floor: identical bytes and
        # origin_sequence reproduce the identical rejection.
        with pytest.raises(DaoError) as retry:
            manager.validate_and_process_dao(dao, NODE_ADDR)
        assert retry.value.reason == case.expected_reason


def test_delegated_foreign_host_route_allowed_after_seeding() -> None:
    """Same denied bytes become routable once the delegation is installed."""
    manager, persistence = make_root_manager()
    manager.validate_and_process_dao(make_signed_dao(NODE_IDENTITY, ROOT_ADDR, 1), NODE_ADDR)
    routes_before = manager.routing_table.routes()
    foreign_dao = make_signed_dao(NODE_IDENTITY, NODE_ADDR, 2, target=FOREIGN_ADDR)

    with pytest.raises(DaoError) as denied:
        manager.validate_and_process_dao(foreign_dao, NODE_ADDR)
    assert denied.value.reason == "target_mismatch"
    assert manager.routing_table.routes() == routes_before
    # The denial did not advance the replay floor past the self-DAO's.
    floor = persistence.get_floor(NODE_IDENTITY.pubkey)
    assert floor is not None
    assert floor[0] == 1

    token = create_prefix_delegation_token(
        ROOT_IDENTITY, NODE_IDENTITY.iid, FOREIGN_ADDR, 128, FAR_EXPIRY, 1
    )
    manager.install_prefix_delegation(token)

    # Identical bytes, identical origin_sequence: accepted once delegated.
    manager.validate_and_process_dao(foreign_dao, NODE_ADDR)
    routes = manager.routing_table.routes()
    assert RouteTarget.host(FOREIGN_ADDR) in routes
    assert RouteTarget.host(NODE_ADDR) in routes
    snapshot = manager.routing_table_snapshot()
    assert snapshot[FOREIGN_ADDR.packed.hex()] == [
        NODE_ADDR.packed.hex(),
        FOREIGN_ADDR.packed.hex(),
    ]
    floor = persistence.get_floor(NODE_IDENTITY.pubkey)
    assert floor is not None
    assert floor[0] == 2


def test_delegation_is_bound_to_the_delegated_origin() -> None:
    """A delegation issued to another origin does not authorize this one."""
    manager, persistence = make_root_manager()
    token = create_prefix_delegation_token(
        ROOT_IDENTITY, OTHER_IDENTITY.iid, FOREIGN_ADDR, 128, FAR_EXPIRY, 1
    )
    manager.install_prefix_delegation(token)
    routes_before = manager.routing_table.routes()

    foreign_dao = make_signed_dao(NODE_IDENTITY, NODE_ADDR, 1, target=FOREIGN_ADDR)
    with pytest.raises(DaoError) as denied:
        manager.validate_and_process_dao(foreign_dao, NODE_ADDR)
    assert denied.value.reason == "delegate_mismatch"
    assert manager.routing_table.routes() == routes_before
    assert persistence.get_floor(NODE_IDENTITY.pubkey) is None


def test_expired_delegation_is_rejected_without_mutation() -> None:
    """A delegation valid at install time is denied once expiry passes."""
    clock = [NOW]
    manager, persistence = make_root_manager(wall_clock=lambda: clock[0])
    token = create_prefix_delegation_token(
        ROOT_IDENTITY, NODE_IDENTITY.iid, FOREIGN_ADDR, 128, FAR_EXPIRY, 1
    )
    manager.install_prefix_delegation(token)

    clock[0] = float(FAR_EXPIRY + 1)
    foreign_dao = make_signed_dao(NODE_IDENTITY, NODE_ADDR, 1, target=FOREIGN_ADDR)
    with pytest.raises(DaoError) as denied:
        manager.validate_and_process_dao(foreign_dao, NODE_ADDR)
    assert denied.value.reason == "delegation_expired"
    assert manager.routing_table.routes() == {}
    assert persistence.get_floor(NODE_IDENTITY.pubkey) is None


def test_external_transit_rejected_without_mutation() -> None:
    """External (E=1) reachability stays rejected by the .44.7 profile."""
    manager, persistence = make_root_manager()
    routes_before = manager.routing_table.routes()

    egress_dao = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, 1, external=True)
    with pytest.raises(DaoError) as denied:
        manager.validate_and_process_dao(egress_dao, NODE_ADDR)
    assert denied.value.reason == "unsupported_transit_e"
    assert manager.routing_table.routes() == routes_before
    assert persistence.get_floor(NODE_IDENTITY.pubkey) is None


def test_delegation_cannot_relax_the_wire_profile() -> None:
    """A seeded /64 delegation does not admit a sub-/128 Target option."""
    manager, _ = make_root_manager()
    manager.install_prefix_delegation(
        create_prefix_delegation_token(
            ROOT_IDENTITY, NODE_IDENTITY.iid, DELEGATED_PREFIX, 64, FAR_EXPIRY, 1
        )
    )

    dao = make_signed_prefix_target_dao(
        NODE_IDENTITY, ROOT_ADDR, 1, 64, DELEGATED_PREFIX.packed[:8]
    )
    with pytest.raises(DaoError) as denied:
        manager.validate_and_process_dao(dao, NODE_ADDR)
    assert denied.value.reason == "malformed_option"


def test_install_prefix_delegation_fails_closed() -> None:
    """::/0 is never delegable and foreign-signed tokens fail verification."""
    manager, _ = make_root_manager()

    with pytest.raises(DaoError) as denied:
        manager.install_prefix_delegation(
            create_prefix_delegation_token(
                ROOT_IDENTITY, NODE_IDENTITY.iid, IPv6Address("::"), 0, FAR_EXPIRY, 1
            )
        )
    assert denied.value.reason == "default_route"

    with pytest.raises(DaoError) as denied:
        manager.install_prefix_delegation(
            create_prefix_delegation_token(
                NODE_IDENTITY, NODE_IDENTITY.iid, FOREIGN_ADDR, 128, FAR_EXPIRY, 1
            )
        )
    assert denied.value.reason == "delegation_invalid"


def test_expired_token_fails_install() -> None:
    """Install-time verification rejects tokens already past expiry."""
    manager, _ = make_root_manager(wall_clock=lambda: FAR_EXPIRY + 1)
    with pytest.raises(DaoError) as denied:
        manager.install_prefix_delegation(
            create_prefix_delegation_token(
                ROOT_IDENTITY, NODE_IDENTITY.iid, FOREIGN_ADDR, 128, FAR_EXPIRY, 1
            )
        )
    assert denied.value.reason == "delegation_expired"


def test_delegation_table_is_bounded_and_sequence_is_monotonic() -> None:
    """The table caps at 64 entries; delegation_seq strictly increases."""
    manager, _ = make_root_manager()
    for index in range(64):
        prefix = IPv6Address(f"2001:db8::{index + 1:x}")
        manager.install_prefix_delegation(
            create_prefix_delegation_token(
                ROOT_IDENTITY, NODE_IDENTITY.iid, prefix, 128, FAR_EXPIRY, 1
            )
        )
    with pytest.raises(DaoError) as denied:
        manager.install_prefix_delegation(
            create_prefix_delegation_token(
                ROOT_IDENTITY,
                NODE_IDENTITY.iid,
                IPv6Address("2001:db8::ff"),
                128,
                FAR_EXPIRY,
                1,
            )
        )
    assert denied.value.reason == "delegation_capacity"

    manager, _ = make_root_manager()
    manager.install_prefix_delegation(
        create_prefix_delegation_token(
            ROOT_IDENTITY, NODE_IDENTITY.iid, FOREIGN_ADDR, 128, FAR_EXPIRY, 2
        )
    )
    with pytest.raises(DaoError) as denied:
        manager.install_prefix_delegation(
            create_prefix_delegation_token(
                ROOT_IDENTITY, NODE_IDENTITY.iid, FOREIGN_ADDR, 128, FAR_EXPIRY, 1
            )
        )
    assert denied.value.reason == "delegation_seq_replay"
    manager.install_prefix_delegation(
        create_prefix_delegation_token(
            ROOT_IDENTITY, NODE_IDENTITY.iid, FOREIGN_ADDR, 128, FAR_EXPIRY, 3
        )
    )
