# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Group OSCORE key epoch manager (spec/12-apps.md sections 18.8 and 18.8.5, RFC 9203).

Holds the group key state for one encrypted group:

- ``group_id``
- ``key_epoch``: monotonic u32 counter, wraps 4294967295 -> 0 on rekey
- current master secret
- previous epoch + master secret, retained with the rekey timestamp for the
  1 hour grace window

Incoming message epoch classification (``validate_epoch``):

- epoch == current epoch: CURRENT (accepted, current key)
- epoch == previous epoch, within the 1 hour grace window of the rekey:
  PREVIOUS (accepted, previous key)
- epoch == previous epoch, past the grace window: GRACE_EXPIRED (rejected)
- epoch == current epoch + 1: NEXT (not rollback and not unknown future, but
  no local key exists yet -- the sender has rekeyed ahead of us; fetch the
  new key rather than treating the message as an attack)
- epoch < current epoch (older than the retained previous): ROLLBACK
  (rejected)
- epoch > current epoch + 1: FUTURE (rejected, unknown key)
- epoch outside the u32 range: FUTURE (rejected, unknown epoch)

All comparisons are wrap-safe: epochs are u32 and classified by modular
forward distance, so ordering stays correct across the 4294967295 -> 0 wrap.

Drives the key_epoch_increment, epoch_rollback_reject, epoch_future_reject,
grace_period_1hr, and grace_period_expired vectors in
test/vectors/group_oscore_key.json.
"""

from __future__ import annotations

import enum
import time
from collections.abc import Callable

KEY_EPOCH_WRAPS_AT = 0xFFFFFFFF
"""Largest key_epoch value; incrementing from here wraps to 0."""

GRACE_PERIOD_MS = 3_600_000
"""Old-epoch acceptance window after a rekey (1 hour, spec/12-apps.md 18.8)."""

_HALF_U32 = 0x80000000


def _wall_time_ms() -> int:
    return int(time.time() * 1000)


class EpochStatus(enum.Enum):
    """Verdict for a message epoch against the local group key state."""

    CURRENT = "current"
    PREVIOUS = "previous_in_grace"
    NEXT = "next_epoch_unknown_key"
    ROLLBACK = "epoch_rollback"
    GRACE_EXPIRED = "grace_period_expired"
    FUTURE = "future_epoch_unknown"

    @property
    def accepted(self) -> bool:
        """Whether a message with this epoch can be processed with a local key."""
        return self in (EpochStatus.CURRENT, EpochStatus.PREVIOUS)


class GroupEpochManager:
    """Key epoch state for one group (id, u32 epoch counter, current + previous keys).

    ``rekey()`` is the single mutation point: it retains the current epoch and
    master secret as the previous epoch/key with the rekey timestamp, installs
    the new master secret, and increments the epoch with u32 wrap.

    Args:
        group_id: Group identifier (spec uses names like ``team-alpha``).
        master_secret: Current group master secret (non-empty bytes-like).
        key_epoch: Starting epoch, u32 range.
        time_ms_func: Millisecond clock used to stamp rekeys and to evaluate
            the grace window when no explicit timestamp is passed. Injectable
            for deterministic tests and for monotonic-clock deployments.

    Raises:
        ValueError: If ``master_secret`` is empty or ``key_epoch`` is outside
            the u32 range.
    """

    def __init__(
        self,
        group_id: str,
        master_secret: bytes,
        *,
        key_epoch: int = 0,
        time_ms_func: Callable[[], int] | None = None,
    ) -> None:
        secret = bytes(master_secret)
        if not secret:
            raise ValueError("master_secret must not be empty")
        if not 0 <= key_epoch <= KEY_EPOCH_WRAPS_AT:
            raise ValueError(f"key_epoch must be a u32 (0..{KEY_EPOCH_WRAPS_AT})")
        self._group_id = group_id
        self._master_secret = secret
        self._key_epoch = key_epoch
        self._previous: tuple[int, bytes, int] | None = None
        self._time_ms_func: Callable[[], int] = time_ms_func or _wall_time_ms

    @property
    def group_id(self) -> str:
        return self._group_id

    @property
    def key_epoch(self) -> int:
        return self._key_epoch

    @property
    def current_master_secret(self) -> bytes:
        return self._master_secret

    @property
    def previous_epoch(self) -> int | None:
        return self._previous[0] if self._previous is not None else None

    @property
    def previous_master_secret(self) -> bytes | None:
        return self._previous[1] if self._previous is not None else None

    @property
    def rekey_time_ms(self) -> int | None:
        """Millisecond timestamp of the most recent rekey (start of the grace window)."""
        return self._previous[2] if self._previous is not None else None

    def rekey(self, new_master_secret: bytes, *, rekey_time_ms: int | None = None) -> None:
        """Install a new master secret and increment the epoch (wraps at u32 max).

        The current epoch/key move to the previous slot stamped with the rekey
        timestamp; the grace window for the old key starts here.

        Args:
            new_master_secret: Replacement group master secret (non-empty).
            rekey_time_ms: Explicit rekey timestamp in milliseconds; defaults
                to the injected clock.
        """
        secret = bytes(new_master_secret)
        if not secret:
            raise ValueError("new_master_secret must not be empty")
        timestamp = rekey_time_ms if rekey_time_ms is not None else self._time_ms_func()
        self._previous = (self._key_epoch, self._master_secret, timestamp)
        self._master_secret = secret
        self._key_epoch = (self._key_epoch + 1) & KEY_EPOCH_WRAPS_AT

    def validate_epoch(self, message_epoch: int, *, now_ms: int | None = None) -> EpochStatus:
        """Classify a message epoch against the local key state.

        Args:
            message_epoch: Epoch carried by the incoming message, u32 range.
            now_ms: Explicit current time in milliseconds for the grace check;
                defaults to the injected clock.

        Returns:
            An :class:`EpochStatus` verdict; use ``.accepted`` for the plain
            accept/reject view and ``.value`` for the vector reason string.
        """
        if not 0 <= message_epoch <= KEY_EPOCH_WRAPS_AT:
            return EpochStatus.FUTURE
        if message_epoch == self._key_epoch:
            return EpochStatus.CURRENT
        if self._previous is not None and message_epoch == self._previous[0]:
            now = now_ms if now_ms is not None else self._time_ms_func()
            if now - self._previous[2] <= GRACE_PERIOD_MS:
                return EpochStatus.PREVIOUS
            return EpochStatus.GRACE_EXPIRED
        forward = (message_epoch - self._key_epoch) & KEY_EPOCH_WRAPS_AT
        if forward == 1:
            return EpochStatus.NEXT
        if forward < _HALF_U32:
            return EpochStatus.FUTURE
        return EpochStatus.ROLLBACK

    def master_secret_for_epoch(self, message_epoch: int, *, now_ms: int | None = None) -> bytes | None:
        """Return the master secret to process a message with, or None.

        Resolves the current key for CURRENT and the previous key for
        PREVIOUS (grace-window aware). Every other verdict has no usable
        local key, including NEXT.
        """
        status = self.validate_epoch(message_epoch, now_ms=now_ms)
        if status is EpochStatus.CURRENT:
            return self._master_secret
        if status is EpochStatus.PREVIOUS:
            return self._previous[1]
        return None
