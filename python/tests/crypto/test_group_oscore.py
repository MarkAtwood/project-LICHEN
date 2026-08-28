# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Group OSCORE epoch/key manager unit tests (spec 18.8.5).

Oracle: ``test/vectors/group_oscore_key.json`` drives the behaviors its named
vectors pin (``key_epoch_increment``, ``epoch_rollback_reject``,
``epoch_future_reject``). The remaining behaviors (u32 wrap, rekey timestamp
retention, group_id isolation, secret redaction) are tested from the operative
semantics documented in :mod:`lichen.crypto.group_oscore`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lichen.crypto.group_oscore import (
    EPOCH_WRAP,
    GRACE_PERIOD_S,
    GroupKeyManager,
    GroupKeyMaterial,
)

VECTORS = json.loads(
    (Path(__file__).parents[3] / "test/vectors/group_oscore_key.json").read_text()
)

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


def _manager(
    group_id: bytes = GROUP_ID, time_func: _Clock | None = None
) -> GroupKeyManager:
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
        mgr._current = GroupKeyMaterial(
            epoch=EPOCH_WRAP, key=GROUP_KEY_1, created_s=clock.t
        )
        mgr.rekey(b"\x02" * 16)
        assert mgr.epoch == 1
        wrapped_out = mgr.key_for_epoch(EPOCH_WRAP)
        assert wrapped_out is not None
        assert wrapped_out.key == GROUP_KEY_1
        assert wrapped_out.created_s == 1000.0
        assert mgr.key_for_epoch(1).key == b"\x02" * 16

    def test_wrap_boundary_validation(self) -> None:
        """Just after wrapping to 1, low epochs are rollback.

        Validation is numeric, so the old maximum epoch reads as an unknown
        future epoch relative to the new epoch 1.
        """
        mgr = _manager()
        mgr._current = GroupKeyMaterial(epoch=EPOCH_WRAP, key=GROUP_KEY_1, created_s=0.0)
        mgr.rekey(b"\x02" * 16)
        assert mgr.validate_epoch(0) == (False, "epoch_rollback")
        assert mgr.validate_epoch(EPOCH_WRAP) == (False, "future_epoch_unknown")
        assert mgr.validate_epoch(1) == (True, "ok")


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

    def test_current_and_next_are_accepted(self) -> None:
        """The acceptance window is exactly [current, current+1]."""
        mgr = _manager()
        mgr.rekey(b"\x02" * 16)
        assert mgr.validate_epoch(2) == (True, "ok")
        assert mgr.validate_epoch(3) == (True, "ok")
        assert mgr.validate_epoch(4) == (False, "future_epoch_unknown")
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
        mgr_a = _manager(group_id=b"\x01" * 8)
        mgr_b = _manager(group_id=b"\x02" * 8)
        mgr_a.rekey(b"\x02" * 16)
        assert mgr_a.epoch == 2
        assert mgr_b.epoch == 1
        assert mgr_a.validate_epoch(1) == (False, "epoch_rollback")
        assert mgr_b.validate_epoch(1) == (True, "ok")
        assert mgr_a.key_for_epoch(2) is not None
        assert mgr_b.key_for_epoch(2) is None


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
