# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Group OSCORE epoch/key manager unit tests (spec 18.8.5).

Oracle: ``test/vectors/group_oscore_key.json`` drives the behaviors its named
vectors pin (``key_epoch_increment``, ``epoch_rollback_reject``,
``epoch_future_reject``). The remaining behaviors (wrap-coherent epoch
semantics, rekey timestamp retention, group_id isolation, secret redaction)
are tested from the operative semantics documented in
:mod:`lichen.crypto.group_oscore`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from lichen.crypto.group_oscore import (
    EPOCH_WRAP,
    GRACE_PERIOD_S,
    GroupKeyManager,
    GroupKeyMaterial,
)

VECTORS = json.loads((Path(__file__).parents[3] / "test/vectors/group_oscore_key.json").read_text())

GROUP_ID = bytes.fromhex("1234567890abcdef")
GROUP_KEY_1 = bytes.fromhex("deadbeefcafebabedeadbeefcafebabe")


def _vec(name: str) -> dict[str, Any]:
    matches = [v for v in VECTORS["vectors"] if v["name"] == name]
    assert len(matches) == 1, f"vector {name!r} not unique in {VECTORS['name']}"
    return matches[0]


class _Clock:
    """Controllable fake clock standing in for the manager's time_func."""

    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def _manager(group_id: bytes = GROUP_ID, time_func: _Clock | None = None) -> GroupKeyManager:
    return GroupKeyManager(group_id, GROUP_KEY_1, time_func=time_func)


class TestEpochIncrement:
    def test_increment_matches_vector(self) -> None:
        """Vector ``key_epoch_increment``: monotonic increment on each rekey."""
        vec = _vec("key_epoch_increment")
        assert vec["initial_epoch"] == 1
        assert vec["expected"]["wraps_at"] == EPOCH_WRAP == 4294967295
        mgr = _manager()
        assert mgr.epoch == vec["initial_epoch"]
        mgr.rekey(b"\x02" * 16)
        assert mgr.epoch == vec["after_rekey_epoch"]
        mgr.rekey(b"\x03" * 16)
        assert mgr.epoch == 3 > vec["after_rekey_epoch"]

    def test_epoch_wraps_after_u32_max(self) -> None:
        """key_epoch wraps back to 1 once it reaches ``wraps_at`` (0xFFFFFFFF).

        Epoch space starts at 1, so the successor of the maximum u32 epoch is
        1, not 0. The current material is seeded directly to the wrap point
        (rekeying 2**32 - 1 times is not an option).
        """
        clock = _Clock()
        mgr = _manager(time_func=clock)
        mgr._current = GroupKeyMaterial(epoch=EPOCH_WRAP, key=GROUP_KEY_1, created_s=clock.t)
        mgr.rekey(b"\x02" * 16)
        assert mgr.epoch == 1
        wrapped_out = mgr.key_for_epoch(EPOCH_WRAP)
        assert wrapped_out is not None
        assert wrapped_out.key == GROUP_KEY_1
        assert wrapped_out.created_s == 1000.0
        assert mgr.key_for_epoch(1).key == b"\x02" * 16


class TestWrapCoherentSemantics:
    """Post-wrap epoch semantics: successor/predecessor, grace, identity.

    Replaces the former ``test_wrap_boundary_validation``, which blessed
    numerically-ordered (wrap-blind) validation.
    """

    @staticmethod
    def _at_wrap(clock: _Clock) -> GroupKeyManager:
        mgr = _manager(time_func=clock)
        mgr._current = GroupKeyMaterial(epoch=EPOCH_WRAP, key=GROUP_KEY_1, created_s=clock.t)
        return mgr

    def test_successor_accepted_across_wrap(self) -> None:
        """Manager still at max accepts the wrapped successor epoch 1.

        The epoch after 0xFFFFFFFF is the successor (a peer rekeyed across
        the wrap), not a rollback; epoch 2 is two steps ahead (unknown).
        """
        mgr = self._at_wrap(_Clock())
        assert mgr.validate_epoch(1) == (True, "ok")
        assert mgr.validate_epoch(2) == (False, "future_epoch_unknown")

    def test_wrapped_manager_accepts_max_within_grace(self) -> None:
        """Manager at post-wrap epoch 1 accepts laggard max-epoch messages.

        The superseded maximum material is held inside its grace window, so
        the laggard side is a grace candidate, not future/unknown; after
        grace it reads as rollback (spec 18.8.2).
        """
        clock = _Clock()
        mgr = self._at_wrap(clock)
        mgr.rekey(b"\x02" * 16)
        assert mgr.epoch == 1
        assert mgr.validate_epoch(EPOCH_WRAP) == (True, "ok")
        clock.t += GRACE_PERIOD_S + 1.0
        assert mgr.validate_epoch(EPOCH_WRAP) == (False, "epoch_rollback")

    def test_predecessor_accepted_on_strict_grace_boundary(self) -> None:
        """Immediate predecessor: accepted up to (incl.) grace, then not."""
        clock = _Clock()
        mgr = _manager(time_func=clock)
        mgr.rekey(b"\x02" * 16)
        assert mgr.validate_epoch(1) == (True, "ok")
        clock.t += GRACE_PERIOD_S
        assert mgr.validate_epoch(1) == (True, "ok")
        clock.t += 1.0
        assert mgr.validate_epoch(1) == (False, "epoch_rollback")

    def test_identity_not_epoch_number_grants_current_status(self) -> None:
        """A same-numbered foreign material is not the current key.

        Epoch numbers recur after a wrap; use-authorization is scoped to
        material the manager actually holds, compared by identity.
        """
        clock = _Clock()
        mgr = self._at_wrap(clock)
        mgr.rekey(b"\x02" * 16)  # wraps to epoch 1, new generation
        foreign = GroupKeyMaterial(epoch=1, key=b"\xaa" * 16, created_s=clock.t)
        assert mgr.epoch == 1
        assert mgr.key_valid_at(foreign, clock.t) is False
        assert mgr.key_valid_at(mgr.key_for_epoch(1), clock.t) is True

    def test_wrap_drops_epoch_colliding_previous_entries(self) -> None:
        """Retained epoch-1 material is dropped when the epoch wraps to 1.

        A colliding entry would shadow the new current in key_for_epoch.
        """
        clock = _Clock()
        mgr = _manager(time_func=clock)
        stale = GroupKeyMaterial(epoch=1, key=b"\xaa" * 16, created_s=clock.t)
        mgr._previous.append(stale)
        mgr._current = GroupKeyMaterial(epoch=EPOCH_WRAP, key=GROUP_KEY_1, created_s=clock.t)
        mgr.rekey(b"\x02" * 16)
        assert all(held is not stale for held in mgr._previous)
        assert mgr.key_for_epoch(1) is not stale
        assert mgr.key_for_epoch(1).key == b"\x02" * 16

    def test_id_context_encoding_stable_and_reuse_refused_across_wrap(self) -> None:
        """id_context stays group_id || epoch; material reuse is refused.

        The encoding is unqualified across wrap generations (vector-pinned);
        safety comes from the enforced never-reuse invariant instead.
        """
        clock = _Clock()
        mgr = self._at_wrap(clock)
        reused = b"\xaa" * 16
        mgr._previous.append(GroupKeyMaterial(epoch=1, key=reused, created_s=clock.t))
        with pytest.raises(RuntimeError, match="reused across wrap"):
            mgr.rekey(reused)
        assert mgr.epoch == EPOCH_WRAP  # refusal left the wrap undone
        mgr.rekey(b"\x02" * 16)
        assert mgr.epoch == 1
        assert mgr.oscore_id_context() == GROUP_ID + (1).to_bytes(4, "big")


class TestEpochValidation:
    def test_rollback_rejected_matches_vector(self) -> None:
        """Vector ``epoch_rollback_reject``: epoch < current is rejected."""
        vec = _vec("epoch_rollback_reject")
        mgr = _manager()
        while mgr.epoch < vec["current_epoch"]:
            mgr.rekey()
        assert mgr.validate_epoch(vec["message_epoch"]) == (
            vec["expected"]["accept"],
            vec["expected"]["reason"],
        )

    def test_future_rejected_matches_vector(self) -> None:
        """Vector ``epoch_future_reject``: epoch > current+1 is rejected."""
        vec = _vec("epoch_future_reject")
        mgr = _manager()
        while mgr.epoch < vec["current_epoch"]:
            mgr.rekey()
        assert mgr.validate_epoch(vec["message_epoch"]) == (
            vec["expected"]["accept"],
            vec["expected"]["reason"],
        )

    def test_window_current_next_and_grace_predecessor(self) -> None:
        """Acceptance window: [current-1 (grace-gated), current, current+1]."""
        clock = _Clock()
        mgr = _manager(time_func=clock)
        mgr.rekey(b"\x02" * 16)
        assert mgr.validate_epoch(2) == (True, "ok")
        assert mgr.validate_epoch(3) == (True, "ok")
        assert mgr.validate_epoch(4) == (False, "future_epoch_unknown")
        assert mgr.validate_epoch(0) == (False, "epoch_rollback")
        # The immediate predecessor is a grace candidate (spec 18.8.2: the
        # old key_epoch is rejected only after the grace period).
        assert mgr.validate_epoch(1) == (True, "ok")
        clock.t += GRACE_PERIOD_S
        assert mgr.validate_epoch(1) == (True, "ok")
        clock.t += 1.0
        assert mgr.validate_epoch(1) == (False, "epoch_rollback")


class TestRekeyTimestampRetention:
    def test_previous_material_keeps_created_s(self) -> None:
        """A rekey retains the previous epoch, key, and rekey timestamp."""
        clock = _Clock()
        mgr = _manager(time_func=clock)
        first = mgr.key_for_epoch(1)
        assert first is not None
        created_s = first.created_s
        clock.t += 60.0
        mgr.rekey(b"\x02" * 16)
        old = mgr.key_for_epoch(1)
        assert old is first
        assert old.created_s == created_s == 1000.0
        assert old.key == GROUP_KEY_1
        assert mgr.key_for_epoch(2).created_s == 1060.0

    def test_retained_timestamp_feeds_validity(self) -> None:
        """The retained created_s (not the rekey call time) governs validity."""
        clock = _Clock()
        mgr = _manager(time_func=clock)
        first = mgr.key_for_epoch(1)
        clock.t += GRACE_PERIOD_S
        mgr.rekey(b"\x02" * 16)
        clock.t += 1.0
        assert mgr.key_valid_at(first, clock.t) is False
        mgr.rekey(b"\x03" * 16)
        second = mgr.key_for_epoch(2)
        clock.t += GRACE_PERIOD_S
        assert mgr.key_valid_at(second, clock.t) is False
        assert mgr.key_valid_at(mgr.key_for_epoch(3), clock.t) is True


class TestGroupIdIsolation:
    def test_id_context_binds_group_id(self) -> None:
        """id_context = group_id || epoch(u32 BE); groups never collide."""
        mgr_a = _manager(group_id=b"\x01" * 8)
        mgr_b = _manager(group_id=b"\x02" * 8)
        assert mgr_a.oscore_id_context() == b"\x01" * 8 + (1).to_bytes(4, "big")
        assert mgr_a.oscore_id_context() != mgr_b.oscore_id_context()
        assert mgr_a.oscore_id_context(7) != mgr_b.oscore_id_context(7)

    def test_epochs_and_validation_are_group_isolated(self) -> None:
        """Rekeying one group leaves another group's epoch state untouched."""
        clock = _Clock()
        mgr_a = _manager(group_id=b"\x01" * 8, time_func=clock)
        mgr_b = _manager(group_id=b"\x02" * 8, time_func=clock)
        mgr_a.rekey(b"\x02" * 16)
        assert mgr_a.epoch == 2
        assert mgr_b.epoch == 1
        assert mgr_a.validate_epoch(1) == (True, "ok")  # predecessor, in grace
        assert mgr_b.validate_epoch(1) == (True, "ok")  # current
        assert mgr_a.key_for_epoch(2) is not None
        assert mgr_b.key_for_epoch(2) is None
        clock.t += GRACE_PERIOD_S + 1.0
        # A's predecessor aged out of grace; B's current epoch is untouched.
        assert mgr_a.validate_epoch(1) == (False, "epoch_rollback")
        assert mgr_b.validate_epoch(1) == (True, "ok")


class TestSecretRedaction:
    def test_material_repr_and_str_redact_key(self) -> None:
        material = GroupKeyMaterial(epoch=1, key=GROUP_KEY_1, created_s=0.0)
        for text in (repr(material), str(material)):
            assert GROUP_KEY_1.hex() not in text
            assert "redacted" in text
            assert "epoch=1" in text

    def test_manager_repr_and_str_redact_key(self) -> None:
        mgr = _manager()
        for text in (repr(mgr), str(mgr)):
            assert GROUP_KEY_1.hex() not in text
            assert "key" not in text
            assert "epoch=1" in text
            assert "members=0" in text
