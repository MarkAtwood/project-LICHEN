# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Admission recovery when GradientTable.update() fails after the durable commit.

AnnounceProcessor.process() commits the replay floor and key pin to a real
AnnounceStatePersistence before updating the gradient table. If the gradient
update raises, in-memory pin/seen/route state stays empty while the stored
floor advanced. These tests prove the idempotent equal-sequence reconciliation
path reconstructs the admission on in-process retry and after a full restart,
using the exact pinned key and sequence (spec section 9.3).
"""

from __future__ import annotations

from collections import OrderedDict
from ipaddress import IPv6Address

import pytest

from lichen.announce.messages import AnnounceMessage
from lichen.announce.persistence import AnnounceStatePersistence
from lichen.announce.processor import AnnounceProcessor, AnnounceRejectReason
from lichen.crypto.identity import Identity
from lichen.crypto.schnorr48 import sign
from lichen.gradient import GradientSource, GradientTable

_LOCAL = Identity.from_seed(bytes(range(32)))
_REMOTE = Identity.from_seed(bytes(range(32, 64)))

_ADDRESS_PREFIX = bytes.fromhex("0200000000000000")
_NEIGHBOR = IPv6Address("fe80::1")


class MemoryAnchor:
    def __init__(self) -> None:
        self.revisions: dict[bytes, int] = {}

    def read(self, key: bytes) -> int | None:
        return self.revisions.get(key)

    def advance(self, key: bytes, expected: int | None, revision: int) -> None:
        if self.revisions.get(key) != expected or revision != (expected or 0) + 1:
            raise RuntimeError("compare-and-advance failed")
        self.revisions[key] = revision


def _signed_announce(identity: Identity, seq_num: int) -> AnnounceMessage:
    msg = AnnounceMessage(
        originator_iid=identity.iid,
        pubkey=identity.pubkey,
        seq_num=seq_num,
    )
    signature = sign(identity.privkey, identity.pubkey, msg.signed_data())
    return AnnounceMessage(
        originator_iid=msg.originator_iid,
        pubkey=msg.pubkey,
        seq_num=msg.seq_num,
        signature=signature,
        app_data=msg.app_data,
    )


def _build_processor(
    persistence: AnnounceStatePersistence,
    gradient_table: GradientTable | None = None,
) -> AnnounceProcessor:
    """Construct a processor exactly as node.py restores it from persistence."""

    def build_address(iid: bytes) -> IPv6Address:
        return IPv6Address(_ADDRESS_PREFIX + iid)

    return AnnounceProcessor(
        gradient_table=gradient_table if gradient_table is not None else GradientTable(),
        address_builder=build_address,
        _seen=persistence.floors,
        _pinned_keys=persistence.pins,
        _pending_reconciliation=set(persistence.floors),
        state_committer=persistence.commit,
    )


def _fail_gradient_update(processor: AnnounceProcessor, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_update(*_args: object, **_kwargs: object) -> bool:
        raise RuntimeError("gradient unavailable")

    monkeypatch.setattr(processor.gradient_table, "update", fail_update)


def _restore_gradient_update(processor: AnnounceProcessor, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        processor.gradient_table,
        "update",
        lambda entry, now=None: GradientTable.update(processor.gradient_table, entry, now),
    )


@pytest.fixture
def anchor() -> MemoryAnchor:
    return MemoryAnchor()


@pytest.fixture
def state_path(tmp_path) -> object:
    return tmp_path / "node-state"


class TestPostCommitGradientFailure:
    def test_failure_after_commit_keeps_memory_empty_and_floor_advanced(
        self,
        anchor: MemoryAnchor,
        state_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        persistence = AnnounceStatePersistence(state_path, _LOCAL, anchor, allow_bootstrap=True)
        processor = _build_processor(persistence)
        announce = _signed_announce(_REMOTE, 7)

        _fail_gradient_update(processor, monkeypatch)
        with pytest.raises(RuntimeError, match="gradient unavailable"):
            processor.process(announce, _NEIGHBOR, now_ms=0)

        assert processor.known_originators() == []
        assert processor.pinned_pubkey_for(_REMOTE.iid) is None
        assert len(processor.gradient_table) == 0
        assert _REMOTE.iid in processor._pending_reconciliation
        assert persistence.floors == {_REMOTE.iid: 7}
        assert persistence.pins == {_REMOTE.iid: _REMOTE.pubkey}

    def test_retry_reconstructs_admission_with_floor_unchanged(
        self,
        anchor: MemoryAnchor,
        state_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        persistence = AnnounceStatePersistence(state_path, _LOCAL, anchor, allow_bootstrap=True)
        processor = _build_processor(persistence)
        announce = _signed_announce(_REMOTE, 7)

        _fail_gradient_update(processor, monkeypatch)
        with pytest.raises(RuntimeError, match="gradient unavailable"):
            processor.process(announce, _NEIGHBOR, now_ms=0)

        _restore_gradient_update(processor, monkeypatch)
        result = processor.process(announce, _NEIGHBOR, now_ms=1)

        assert result.accepted is True
        assert result.reject_reason is None
        assert processor.known_originators() == [_REMOTE.iid]
        assert processor.pinned_pubkey_for(_REMOTE.iid) == _REMOTE.pubkey
        assert _REMOTE.iid not in processor._pending_reconciliation
        destination = IPv6Address(_ADDRESS_PREFIX + _REMOTE.iid)
        route = processor.gradient_table.lookup(destination, now=1)
        assert route is not None
        assert route.next_hop == _NEIGHBOR
        assert route.seq_num == 7
        assert route.source == GradientSource.ANNOUNCE

        restored = AnnounceStatePersistence(state_path, _LOCAL, anchor, allow_bootstrap=False)
        assert restored.floors == {_REMOTE.iid: 7}
        assert restored.pins == {_REMOTE.iid: _REMOTE.pubkey}

    def test_repeated_failures_stay_recoverable(
        self,
        anchor: MemoryAnchor,
        state_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        persistence = AnnounceStatePersistence(state_path, _LOCAL, anchor, allow_bootstrap=True)
        processor = _build_processor(persistence)
        announce = _signed_announce(_REMOTE, 7)

        _fail_gradient_update(processor, monkeypatch)
        with pytest.raises(RuntimeError, match="gradient unavailable"):
            processor.process(announce, _NEIGHBOR, now_ms=0)
        with pytest.raises(RuntimeError, match="gradient unavailable"):
            processor.process(announce, _NEIGHBOR, now_ms=1)

        restored = AnnounceStatePersistence(state_path, _LOCAL, anchor, allow_bootstrap=False)
        restarted = _build_processor(restored)
        result = restarted.process(announce, _NEIGHBOR, now_ms=2)

        assert result.accepted is True
        destination = IPv6Address(_ADDRESS_PREFIX + _REMOTE.iid)
        assert restarted.gradient_table.lookup(destination, now=2) is not None
        assert restored.floors == {_REMOTE.iid: 7}


class TestRestartReconciliation:
    def test_reconstructs_admission_from_durable_state_after_restart(
        self,
        anchor: MemoryAnchor,
        state_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        persistence = AnnounceStatePersistence(state_path, _LOCAL, anchor, allow_bootstrap=True)
        processor = _build_processor(persistence)
        announce = _signed_announce(_REMOTE, 7)

        _fail_gradient_update(processor, monkeypatch)
        with pytest.raises(RuntimeError, match="gradient unavailable"):
            processor.process(announce, _NEIGHBOR, now_ms=0)

        restored = AnnounceStatePersistence(state_path, _LOCAL, anchor, allow_bootstrap=False)
        assert restored.floors == {_REMOTE.iid: 7}
        restarted = _build_processor(restored)
        result = restarted.process(announce, _NEIGHBOR, now_ms=1)

        assert result.accepted is True
        assert restarted.known_originators() == [_REMOTE.iid]
        assert restarted.pinned_pubkey_for(_REMOTE.iid) == _REMOTE.pubkey
        assert _REMOTE.iid not in restarted._pending_reconciliation
        destination = IPv6Address(_ADDRESS_PREFIX + _REMOTE.iid)
        route = restarted.gradient_table.lookup(destination, now=1)
        assert route is not None
        assert route.next_hop == _NEIGHBOR
        assert route.seq_num == 7

    def test_reconciliation_permit_is_one_shot(
        self,
        anchor: MemoryAnchor,
        state_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        persistence = AnnounceStatePersistence(state_path, _LOCAL, anchor, allow_bootstrap=True)
        processor = _build_processor(persistence)
        announce = _signed_announce(_REMOTE, 7)

        _fail_gradient_update(processor, monkeypatch)
        with pytest.raises(RuntimeError, match="gradient unavailable"):
            processor.process(announce, _NEIGHBOR, now_ms=0)

        restored = AnnounceStatePersistence(state_path, _LOCAL, anchor, allow_bootstrap=False)
        restarted = _build_processor(restored)
        assert restarted.process(announce, _NEIGHBOR, now_ms=1).accepted is True

        replay = restarted.process(announce, _NEIGHBOR, now_ms=2)
        assert replay.accepted is False
        assert replay.reject_reason == AnnounceRejectReason.STALE_SEQNUM

    def test_newer_sequence_supersedes_unreconciled_floor(
        self,
        anchor: MemoryAnchor,
        state_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        persistence = AnnounceStatePersistence(state_path, _LOCAL, anchor, allow_bootstrap=True)
        processor = _build_processor(persistence)
        stale_announce = _signed_announce(_REMOTE, 7)

        _fail_gradient_update(processor, monkeypatch)
        with pytest.raises(RuntimeError, match="gradient unavailable"):
            processor.process(stale_announce, _NEIGHBOR, now_ms=0)

        _restore_gradient_update(processor, monkeypatch)
        newer = _signed_announce(_REMOTE, 8)
        result = processor.process(newer, _NEIGHBOR, now_ms=1)
        assert result.accepted is True

        replay = processor.process(stale_announce, _NEIGHBOR, now_ms=2)
        assert replay.accepted is False
        assert replay.reject_reason == AnnounceRejectReason.STALE_SEQNUM

        restored = AnnounceStatePersistence(state_path, _LOCAL, anchor, allow_bootstrap=False)
        assert restored.floors == {_REMOTE.iid: 8}
        restarted = _build_processor(restored)
        after_restart = restarted.process(stale_announce, _NEIGHBOR, now_ms=3)
        assert after_restart.accepted is False
        assert after_restart.reject_reason == AnnounceRejectReason.STALE_SEQNUM


class TestRestoreReconciliationPermit:
    def test_rejects_mismatched_key_or_sequence(self) -> None:
        processor = AnnounceProcessor(
            gradient_table=GradientTable(),
            address_builder=lambda iid: IPv6Address(_ADDRESS_PREFIX + iid),
            _seen=OrderedDict([(_REMOTE.iid, 7)]),
            _pinned_keys=OrderedDict([(_REMOTE.iid, _REMOTE.pubkey)]),
        )

        with pytest.raises(RuntimeError, match="does not match durable admission"):
            processor._restore_reconciliation_permit(_REMOTE.iid, _REMOTE.pubkey, 8)
        with pytest.raises(RuntimeError, match="does not match durable admission"):
            processor._restore_reconciliation_permit(_REMOTE.iid, bytes(32), 7)
        assert _REMOTE.iid not in processor._pending_reconciliation

        processor._restore_reconciliation_permit(_REMOTE.iid, _REMOTE.pubkey, 7)
        assert _REMOTE.iid in processor._pending_reconciliation

    def test_permit_reconstructs_admission_after_peer_admission_failure(
        self,
        anchor: MemoryAnchor,
        state_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        persistence = AnnounceStatePersistence(state_path, _LOCAL, anchor, allow_bootstrap=True)
        processor = _build_processor(persistence)
        announce = _signed_announce(_REMOTE, 7)
        destination = IPv6Address(_ADDRESS_PREFIX + _REMOTE.iid)

        assert processor.process(announce, _NEIGHBOR, now_ms=0).accepted is True

        processor.gradient_table.remove(destination)
        processor._restore_reconciliation_permit(_REMOTE.iid, _REMOTE.pubkey, 7)

        result = processor.process(announce, _NEIGHBOR, now_ms=1)
        assert result.accepted is True
        route = processor.gradient_table.lookup(destination, now=1)
        assert route is not None
        assert route.next_hop == _NEIGHBOR
        assert _REMOTE.iid not in processor._pending_reconciliation
        assert persistence.floors == {_REMOTE.iid: 7}
