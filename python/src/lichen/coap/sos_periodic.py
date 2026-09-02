# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SOS periodic behavior (spec/12-apps.md 18.4, bead l1qw.37).

- Beacon boost: an active SOS re-notifies observers every
  :data:`BEACON_BOOST_INTERVAL_S` (30 s) via ``SosResource.retrigger()``.
- Auto-timeout: an SOS active longer than :data:`SOS_AUTO_TIMEOUT_S`
  (4 hours) is cancelled automatically.

The driver is clock-injected and executor-neutral: the owner calls
:meth:`SosPeriodicDriver.tick` from its scheduling loop (aiocoap server
loop, Zephyr work queue, or tests with a fake clock).
"""

from __future__ import annotations

from collections.abc import Callable

BEACON_BOOST_INTERVAL_S = 30
SOS_AUTO_TIMEOUT_S = 4 * 3600


class SosPeriodicDriver:
    """Compose with a SosResource-like object to add spec 18.4 periodic
    behavior. ``now`` is an injected monotonic-seconds callable.

    One tick() per superframe/scheduling pulse:
    - re-triggers the beacon pulse on the 30 s boundary
    - auto-cancels at 4 h after activation
    """

    def __init__(
        self,
        resource: object,
        *,
        now: Callable[[], float],
        boost_interval_s: int = BEACON_BOOST_INTERVAL_S,
        auto_timeout_s: int = SOS_AUTO_TIMEOUT_S,
    ) -> None:
        self._resource = resource
        self._now = now
        self._boost_interval_s = boost_interval_s
        self._auto_timeout_s = auto_timeout_s
        self._last_boost: float | None = None
        self._activated_at: float | None = None
        self._was_active = False

    def tick(self) -> None:
        active = bool(getattr(self._resource, "_active", False))
        now = self._now()
        # Auto-cancel first: an SOS past the 4h timeout is cancelled here,
        # which also clears the edge state so a manual re-activate before
        # the next tick is detected as a fresh activation.
        if (
            self._was_active
            and self._activated_at is not None
            and now - self._activated_at >= self._auto_timeout_s
        ):
            cancel = getattr(self._resource, "cancel", None)
            if cancel is not None:
                cancel()
            self._was_active = False
            self._activated_at = None
            self._last_boost = None
            active = False
        # Edge detection: activation starts both timers; cancellation
        # resets them. Re-activation after auto-cancel is a fresh edge
        # because _activated_at was cleared above.
        if active and self._activated_at is None:
            self._activated_at = now
            self._last_boost = now
        elif not active and self._activated_at is not None:
            self._activated_at = None
            self._last_boost = None
        self._was_active = active
        if not active:
            return
        if (
            self._last_boost is None
            or now - self._last_boost >= self._boost_interval_s
        ):
            retrigger = getattr(self._resource, "retrigger", None)
            if retrigger is not None:
                retrigger()
            self._last_boost = now
