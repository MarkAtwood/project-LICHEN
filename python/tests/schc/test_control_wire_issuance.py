# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Control-wire authority must only escape authenticated manager transitions."""

from __future__ import annotations

import threading

import pytest

from lichen.crypto.identity import Identity, PeerIdentity
from lichen.ipv6.addr import iid_to_eui64
from lichen.link.replay import ReplayProtector
from lichen.schc.fragment import (
    RETRANSMISSION_TIMEOUT_SECONDS,
    WINDOW_SIZE,
    Ack,
    FragmentError,
    FragmentSender,
    ack_request,
    fragmentation_rule_for_sender,
    receiver_abort,
    sender_abort,
)
from lichen.schc.session_manager import SchcSessionManager, _SessionRecord
from lichen.timing.time_sync import MonotonicClock

LOCAL_NODE = Identity.from_seed(bytes(range(32)))
REMOTE_NODE = Identity.from_seed(bytes(range(32, 64)))
STRANGER_NODE = Identity.from_seed(bytes([0xEE]) * 32)
LOCAL_IDENTITY = LOCAL_NODE.pubkey
REMOTE_IDENTITY = REMOTE_NODE.pubkey
STRANGER_IDENTITY = STRANGER_NODE.pubkey


def _eui64(identity: bytes) -> bytes:
    return iid_to_eui64(PeerIdentity.from_pubkey(identity).iid)


class _Harness:
    def __init__(self) -> None:
        self.generations: dict[bytes, object] = {}
        self.now = 1000.0
        self.token = object()
        self.manager = SchcSessionManager(
            local_identity=LOCAL_IDENTITY,
            replay_protector=ReplayProtector(),
            security_lock=threading.RLock(),
            control_issuer_token=self.token,
            key_generation_lookup=self.generations.get,
            clock=MonotonicClock(lambda: self.now),
        )

    def install_generation(self, identity: bytes) -> object:
        generation = object()
        self.generations[identity] = generation
        return generation

    def start_session(self, identity: bytes = REMOTE_IDENTITY) -> FragmentSender:
        sender = self.manager.create_sender(b"lichen", identity, self.generations[identity])
        self.manager.activate_and_start(sender)
        return sender


def _control_forms(peer: bytes) -> list[tuple[str, bytes, bool]]:
    sender_rule = fragmentation_rule_for_sender(LOCAL_IDENTITY, peer)
    receiver_rule = fragmentation_rule_for_sender(peer, LOCAL_IDENTITY)
    return [
        ("canonical-ack", Ack(receiver_rule, 0, complete=True).to_bytes(), True),
        ("negative-ack", Ack(receiver_rule, 0, (False,) * WINDOW_SIZE).to_bytes(), True),
        ("ack-request", ack_request(sender_rule, 0), False),
        ("sender-abort", sender_abort(sender_rule), False),
        ("receiver-abort", receiver_abort(receiver_rule), True),
    ]


FORGED_FORMS = _control_forms(STRANGER_IDENTITY)
REMOTE_FORMS = _control_forms(REMOTE_IDENTITY)
FORGED_IDS = [form[0] for form in FORGED_FORMS]
REMOTE_IDS = [form[0] for form in REMOTE_FORMS]


def test_public_generic_control_issuer_is_absent() -> None:
    manager = _Harness().manager
    assert not hasattr(manager, "issue_control_wire")
    with pytest.raises(AttributeError):
        manager.issue_control_wire(  # type: ignore[attr-defined]
            sender_abort(0x78), REMOTE_IDENTITY, object(), response=False
        )


@pytest.mark.parametrize(("name", "control", "response"), FORGED_FORMS, ids=FORGED_IDS)
def test_forged_direct_issuance_unknown_peer_is_never_consumable(
    name: str, control: bytes, response: bool
) -> None:
    del name
    harness = _Harness()
    forged = harness.manager._issue_control_wire_unlocked(
        control, STRANGER_IDENTITY, object(), response=response
    )
    assert bytes(forged) == control
    assert not harness.manager.consume_fragment_wire(forged, _eui64(STRANGER_IDENTITY))
    assert not harness.manager.consume_fragment_wire(forged, _eui64(REMOTE_IDENTITY))


@pytest.mark.parametrize(("name", "control", "response"), REMOTE_FORMS, ids=REMOTE_IDS)
def test_forged_direct_issuance_foreign_generation_is_never_consumable(
    name: str, control: bytes, response: bool
) -> None:
    del name
    harness = _Harness()
    harness.install_generation(REMOTE_IDENTITY)
    forged = harness.manager._issue_control_wire_unlocked(
        control, REMOTE_IDENTITY, object(), response=response
    )
    assert not harness.manager.consume_fragment_wire(forged, _eui64(REMOTE_IDENTITY))


@pytest.mark.parametrize(("name", "control", "response"), REMOTE_FORMS, ids=REMOTE_IDS)
def test_wire_minted_before_key_rotation_is_not_consumable_after(
    name: str, control: bytes, response: bool
) -> None:
    del name
    harness = _Harness()
    generation = harness.install_generation(REMOTE_IDENTITY)
    forged = harness.manager._issue_control_wire_unlocked(
        control, REMOTE_IDENTITY, generation, response=response
    )
    harness.manager.invalidate_remote_policy(REMOTE_IDENTITY)
    assert not harness.manager.consume_fragment_wire(forged, _eui64(REMOTE_IDENTITY))


@pytest.mark.parametrize(("name", "control", "response"), FORGED_FORMS, ids=FORGED_IDS)
def test_forged_direct_issuance_missing_generation_fails_closed(
    name: str, control: bytes, response: bool
) -> None:
    del name
    harness = _Harness()
    with pytest.raises(FragmentError, match="current key generation"):
        harness.manager._issue_control_wire_unlocked(
            control, STRANGER_IDENTITY, None, response=response
        )


@pytest.mark.parametrize(("name", "control", "response"), FORGED_FORMS, ids=FORGED_IDS)
def test_token_gated_issuance_rejects_unknown_peer(
    name: str, control: bytes, response: bool
) -> None:
    del name
    harness = _Harness()
    with pytest.raises(FragmentError, match="transition authority"):
        harness.manager._issue_link_transition_control_wire(
            object(), control, STRANGER_IDENTITY, object(), response=response
        )
    with pytest.raises(FragmentError, match="not current"):
        harness.manager._issue_link_transition_control_wire(
            harness.token, control, STRANGER_IDENTITY, object(), response=response
        )


@pytest.mark.parametrize(("name", "control", "response"), REMOTE_FORMS, ids=REMOTE_IDS)
def test_link_transition_path_issues_one_use_consumable_wires(
    name: str, control: bytes, response: bool
) -> None:
    del name
    harness = _Harness()
    generation = harness.install_generation(REMOTE_IDENTITY)
    wire = harness.manager._issue_link_transition_control_wire(
        harness.token, control, REMOTE_IDENTITY, generation, response=response
    )
    assert bytes(wire) == control
    assert harness.manager.consume_fragment_wire(wire, _eui64(REMOTE_IDENTITY))
    assert not harness.manager.consume_fragment_wire(wire, _eui64(REMOTE_IDENTITY))


def test_active_sender_abort_transition_issues_one_use_wire() -> None:
    harness = _Harness()
    harness.install_generation(REMOTE_IDENTITY)
    sender = harness.start_session()
    rule = fragmentation_rule_for_sender(LOCAL_IDENTITY, REMOTE_IDENTITY)
    wire = harness.manager.cancel_with_abort(sender)
    assert wire == sender_abort(rule)
    assert harness.manager.consume_fragment_wire(wire, _eui64(REMOTE_IDENTITY))
    assert not harness.manager.consume_fragment_wire(wire, _eui64(REMOTE_IDENTITY))


def test_active_sender_timeout_transition_issues_one_use_ack_request() -> None:
    harness = _Harness()
    harness.install_generation(REMOTE_IDENTITY)
    sender = harness.start_session()
    assert harness.manager.transition_timeout_if_due(sender) == b""
    harness.now += RETRANSMISSION_TIMEOUT_SECONDS + 1.0
    request = harness.manager.transition_timeout_if_due(sender)
    rule = fragmentation_rule_for_sender(LOCAL_IDENTITY, REMOTE_IDENTITY)
    assert request == ack_request(rule, sender.final_window())
    assert harness.manager.consume_fragment_wire(request, _eui64(REMOTE_IDENTITY))
    assert not harness.manager.consume_fragment_wire(request, _eui64(REMOTE_IDENTITY))


def test_create_sender_rejects_none_key_generation() -> None:
    harness = _Harness()
    with pytest.raises(FragmentError, match="current key generation"):
        harness.manager.create_sender(b"lichen", REMOTE_IDENTITY, None)
    assert harness.manager._prepared == {}
    assert harness.manager._records == {}


def test_keyless_stranger_fragment_wire_is_never_consumable() -> None:
    harness = _Harness()
    sender = FragmentSender(b"lichen")
    record = _SessionRecord(
        sender=sender,
        remote_signer_identity=STRANGER_IDENTITY,
        rule_id=0x78,
        generation=0,
        key_generation=None,
        fragments=tuple(sender._fragments),
        high_water=0,
        idle_expires_at=harness.now + 60.0,
    )
    harness.manager._sender_records[id(sender)] = record
    wire = harness.manager._issue_fragment_wire_unlocked(sender, record, sender._fragments[0])
    assert not harness.manager.consume_fragment_wire(wire, _eui64(STRANGER_IDENTITY))


def test_authenticated_fragment_wire_is_one_use_consumable() -> None:
    harness = _Harness()
    harness.install_generation(REMOTE_IDENTITY)
    sender = harness.manager.create_sender(
        b"lichen", REMOTE_IDENTITY, harness.generations[REMOTE_IDENTITY]
    )
    wires = harness.manager.activate_and_start(sender)
    assert wires
    for wire in wires:
        assert harness.manager.consume_fragment_wire(wire, _eui64(REMOTE_IDENTITY))
        assert not harness.manager.consume_fragment_wire(wire, _eui64(REMOTE_IDENTITY))
