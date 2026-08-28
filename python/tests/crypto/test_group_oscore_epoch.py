# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the group OSCORE epoch manager.

Vector-driven tests use test/vectors/group_oscore_key.json as the oracle.
Additional unit tests pin spec-derived semantics the vectors do not cover
(next-epoch classification, u32 wrap, key lookup, constructor validation).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from lichen.crypto.group_oscore_epoch import (
    GRACE_PERIOD_MS,
    KEY_EPOCH_WRAPS_AT,
    EpochStatus,
    GroupEpochManager,
)

VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "group_oscore_key.json"
with open(VECTORS_PATH) as f:
    VECTORS: dict[str, dict[str, Any]] = {v["name"]: v for v in json.load(f)["vectors"]}

SECRET_A = bytes(range(32))
SECRET_B = bytes(range(32, 64))
SECRET_C = bytes(range(64, 96))


def make_manager(key_epoch: int, **kwargs: Any) -> GroupEpochManager:
    return GroupEpochManager("team-alpha", SECRET_A, key_epoch=key_epoch, **kwargs)


class TestKeyEpochIncrement:
    """Vector key_epoch_increment: monotonic u32 epoch, wraps at 4294967295."""

    def test_increment_on_rekey(self) -> None:
        vec = VECTORS["key_epoch_increment"]
        mgr = make_manager(vec["initial_epoch"])
        mgr.rekey(SECRET_B)
        assert mgr.key_epoch == vec["after_rekey_epoch"]
        assert vec["expected"]["monotonic"] is True
        assert mgr.current_master_secret == SECRET_B
        assert mgr.previous_epoch == vec["initial_epoch"]
        assert mgr.previous_master_secret == SECRET_A
        assert mgr.rekey_time_ms is not None

    def test_wraps_at_u32_max(self) -> None:
        vec = VECTORS["key_epoch_increment"]
        assert vec["expected"]["wraps_at"] == KEY_EPOCH_WRAPS_AT
        mgr = make_manager(KEY_EPOCH_WRAPS_AT)
        mgr.rekey(SECRET_B)
        assert mgr.key_epoch == 0


class TestEpochRollbackReject:
    """Vector epoch_rollback_reject: epoch < current is rejected."""

    def test_rollback_rejected(self) -> None:
        vec = VECTORS["epoch_rollback_reject"]
        mgr = make_manager(vec["current_epoch"])
        status = mgr.validate_epoch(vec["message_epoch"])
        assert status is EpochStatus.ROLLBACK
        assert not status.accepted
        assert status.value == vec["expected"]["reason"]
        assert mgr.master_secret_for_epoch(vec["message_epoch"]) is None


class TestEpochFutureReject:
    """Vector epoch_future_reject: epoch > current+1 is rejected."""

    def test_future_rejected(self) -> None:
        vec = VECTORS["epoch_future_reject"]
        mgr = make_manager(vec["current_epoch"])
        status = mgr.validate_epoch(vec["message_epoch"])
        assert status is EpochStatus.FUTURE
        assert not status.accepted
        assert status.value == vec["expected"]["reason"]
        assert mgr.master_secret_for_epoch(vec["message_epoch"]) is None


class TestGracePeriod:
    """Vectors grace_period_1hr and grace_period_expired: old key validity."""

    @pytest.mark.parametrize("name", ["grace_period_1hr", "grace_period_expired"])
    def test_old_key_validity_within_and_after_grace(self, name: str) -> None:
        vec = VECTORS[name]
        expected = vec["expected"]
        mgr = make_manager(vec["old_epoch"])
        mgr.rekey(SECRET_B, rekey_time_ms=vec["rekey_time_ms"])
        assert mgr.key_epoch == vec["new_epoch"]
        assert mgr.rekey_time_ms == vec["rekey_time_ms"]

        old_status = mgr.validate_epoch(vec["old_epoch"], now_ms=vec["test_time_ms"])
        new_status = mgr.validate_epoch(vec["new_epoch"], now_ms=vec["test_time_ms"])

        assert old_status.accepted is expected["old_key_valid"]
        assert new_status.accepted is expected["new_key_valid"]
        assert new_status is EpochStatus.CURRENT
        if expected["old_key_valid"]:
            assert old_status is EpochStatus.PREVIOUS
            assert mgr.master_secret_for_epoch(vec["old_epoch"], now_ms=vec["test_time_ms"]) == SECRET_A
        else:
            assert old_status is EpochStatus.GRACE_EXPIRED
            assert old_status.value == expected["reason"]
            assert mgr.master_secret_for_epoch(vec["old_epoch"], now_ms=vec["test_time_ms"]) is None


class TestEpochSemantics:
    """Spec-derived semantics the vectors do not pin directly."""

    def test_next_epoch_is_not_rollback_or_unknown_future(self) -> None:
        mgr = make_manager(5)
        status = mgr.validate_epoch(6)
        assert status is EpochStatus.NEXT
        assert not status.accepted
        assert mgr.master_secret_for_epoch(6) is None

    def test_key_lookup_current_previous_and_grace_boundary(self) -> None:
        mgr = make_manager(1)
        mgr.rekey(SECRET_B, rekey_time_ms=0)
        assert mgr.master_secret_for_epoch(2, now_ms=0) == SECRET_B
        assert mgr.master_secret_for_epoch(1, now_ms=0) == SECRET_A
        assert mgr.master_secret_for_epoch(1, now_ms=GRACE_PERIOD_MS) == SECRET_A
        assert mgr.master_secret_for_epoch(1, now_ms=GRACE_PERIOD_MS + 1) is None

    def test_second_rekey_drops_first_previous(self) -> None:
        mgr = make_manager(1)
        mgr.rekey(SECRET_B, rekey_time_ms=0)
        mgr.rekey(SECRET_C, rekey_time_ms=0)
        assert mgr.key_epoch == 3
        assert mgr.previous_epoch == 2
        assert mgr.previous_master_secret == SECRET_B
        assert mgr.validate_epoch(1) is EpochStatus.ROLLBACK

    def test_classification_across_wrap(self) -> None:
        mgr = make_manager(KEY_EPOCH_WRAPS_AT)
        mgr.rekey(SECRET_B, rekey_time_ms=0)
        assert mgr.key_epoch == 0
        assert mgr.validate_epoch(KEY_EPOCH_WRAPS_AT, now_ms=0) is EpochStatus.PREVIOUS
        assert mgr.validate_epoch(KEY_EPOCH_WRAPS_AT - 1) is EpochStatus.ROLLBACK
        assert mgr.validate_epoch(1) is EpochStatus.NEXT
        assert mgr.validate_epoch(2) is EpochStatus.FUTURE

    def test_out_of_range_epoch_rejected(self) -> None:
        mgr = make_manager(5)
        assert mgr.validate_epoch(-1) is EpochStatus.FUTURE
        assert mgr.validate_epoch(2**32) is EpochStatus.FUTURE

    def test_rekey_uses_injected_clock_by_default(self) -> None:
        class Clock:
            def __init__(self) -> None:
                self.now_ms = 0

            def __call__(self) -> int:
                return self.now_ms

        clock = Clock()
        mgr = GroupEpochManager("team-alpha", SECRET_A, key_epoch=1, time_ms_func=clock)
        clock.now_ms = 5000
        mgr.rekey(SECRET_B)
        assert mgr.rekey_time_ms == 5000
        assert mgr.validate_epoch(1) is EpochStatus.PREVIOUS
        clock.now_ms = 5000 + GRACE_PERIOD_MS
        assert mgr.validate_epoch(1) is EpochStatus.PREVIOUS
        clock.now_ms = 5000 + GRACE_PERIOD_MS + 1
        assert mgr.validate_epoch(1) is EpochStatus.GRACE_EXPIRED

    def test_invalid_constructor_arguments(self) -> None:
        with pytest.raises(ValueError):
            GroupEpochManager("team-alpha", b"")
        with pytest.raises(ValueError):
            GroupEpochManager("team-alpha", SECRET_A, key_epoch=-1)
        with pytest.raises(ValueError):
            GroupEpochManager("team-alpha", SECRET_A, key_epoch=2**32)

    def test_rekey_rejects_empty_secret(self) -> None:
        mgr = make_manager(1)
        with pytest.raises(ValueError):
            mgr.rekey(b"")
