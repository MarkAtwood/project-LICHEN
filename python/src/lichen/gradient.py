# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Unified gradient (routing) table (spec section 11).

A single table holds next-hop gradients toward destinations, populated by every
routing method: Announce (section 9), LOADng RREP (section 10), RPL, and passive
learning from forwarded data (section 11.2). Entries carry a source priority so
explicitly-advertised routes win over opportunistic ones.

Replacement order for the same destination (best first): higher source priority,
then higher sequence number (fresher), then lower hop count. Timestamps are
caller-supplied integers (milliseconds); the table never reads a wall clock, so
it is deterministic and usable under the simulator. Capacity is bounded with LRU
eviction.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from functools import total_ordering
from ipaddress import IPv6Address

from lichen.ipv6 import routing_key

MAX_ENTRIES = 64
GRADIENT_TIMEOUT_MS = 600_000  # announce/rrep gradients (spec section 9)
DATA_GRADIENT_TIMEOUT_MS = 60_000  # passive-learning gradients (spec 11.2)

# Adaptive SF thresholds (CCP-16, spec 02a-coordinated-capacity.md 2a.8).
# Mirrors lichen/subsys/lichen/routing/gradient.h LICHEN_SNR_* and the
# lichen_gradient_sf_update/sf_select implementation (zrh2.2); the sf_* tests
# (zrh2.8) use these names, so keep them in sync with the C defines.
SNR_UPGRADE_THRESHOLD = 8  # EWMA SNR above this may upgrade (decrease SF)
SNR_DOWNGRADE_THRESHOLD = 0  # EWMA SNR below this forces downgrade (increase SF)
UPGRADE_COUNT_THRESHOLD = 3  # consecutive good samples before upgrade
DOWNGRADE_COUNT_THRESHOLD = 2  # consecutive bad samples before downgrade
DENSITY_UPGRADE_MAX = 5  # density must be below this for the SF -1 upgrade
DEFAULT_SF = 10  # LICHEN_DEFAULT_SF (Kconfig default): SF absent at step 2
SF_MIN = 7
SF_MAX = 12
# Q16.16 fixed-point thresholds matching the C constants
EMA_LOSS_THRESHOLD_FP = 16384  # 0.25 loss
LOAD_FACTOR_THRESHOLD_FP = 52429  # strictly greater than 0.8

# Sequence number constants for RFC 1982 comparison
SEQ_BITS = 16
SEQ_HALF = 1 << (SEQ_BITS - 1)  # 32768


@total_ordering
class SeqNum:
    """Wrapper for 16-bit sequence numbers with RFC 1982 comparison.

    Why: Naive integer comparison fails when sequence numbers wrap from
    65535 to 0. RFC 1982 defines "greater than" for serial numbers.
    """

    __slots__ = ("_value",)

    def __init__(self, value: int) -> None:
        self._value = value & 0xFFFF

    @property
    def value(self) -> int:
        return self._value

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SeqNum):
            return self._value == other._value
        if isinstance(other, int):
            return self._value == (other & 0xFFFF)
        return NotImplemented

    def __lt__(self, other: SeqNum | int) -> bool:
        if isinstance(other, int):
            other = SeqNum(other)
        if not isinstance(other, SeqNum):
            return NotImplemented
        # RFC 1982: a < b iff b > a iff (b - a) mod 2^N < 2^(N-1)
        diff = (other._value - self._value) & 0xFFFF
        return self._value != other._value and diff < SEQ_HALF

    def __hash__(self) -> int:
        return hash(self._value)

    def __repr__(self) -> str:
        return f"SeqNum({self._value})"


class GradientSource(Enum):
    """How a gradient entry was learned (spec 11.1/11.3)."""

    ANNOUNCE = "announce"
    RREP = "rrep"
    RPL = "rpl"
    DATA = "data"

    @property
    def priority(self) -> int:
        """Higher wins. Explicitly-advertised routes outrank opportunistic data."""
        return 0 if self is GradientSource.DATA else 1


@dataclass
class GradientEntry:
    """A next-hop gradient toward ``destination`` (spec 11.1)."""

    destination: IPv6Address
    next_hop: IPv6Address
    hop_count: int
    seq_num: int
    source: GradientSource
    expires: int
    coords: tuple[float, float] | None = None  # (lat, lon) from app_data (spec 9.7)
    # Per-neighbor adaptive SF tracking (CCP-16, spec 02a 2a.8, zrh2.2):
    # None current_sf means "SF absent" (sf_select applies the default).
    current_sf: int | None = None
    snr_ewma: int = 0
    upgrade_count: int = 0
    downgrade_count: int = 0

    def __post_init__(self) -> None:
        self.destination = routing_key(self.destination)
        self.next_hop = routing_key(self.next_hop)

    def _rank(self) -> tuple[int, SeqNum, int]:
        # Larger is better: priority, then freshness (RFC 1982), then fewer hops.
        return (self.source.priority, SeqNum(self.seq_num), -self.hop_count)


class GradientTable:
    """Bounded, LRU-evicting table of gradient entries."""

    def __init__(self, max_entries: int = MAX_ENTRIES) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self.max_entries = max_entries
        self._entries: OrderedDict[IPv6Address, GradientEntry] = OrderedDict()

    def lookup(
        self, destination: IPv6Address | str, now: int | None = None
    ) -> GradientEntry | None:
        """Return the gradient for ``destination`` (None if absent or expired)."""
        dest = routing_key(destination)
        entry = self._entries.get(dest)
        if entry is None:
            return None
        if now is not None and entry.expires <= now:
            return None
        self._entries.move_to_end(dest)  # mark recently used
        return entry

    def update(self, entry: GradientEntry, now: int | None = None) -> bool:
        """Insert or replace the gradient for ``entry.destination``.

        Replaces the existing entry if it is missing, expired (when ``now`` is
        given), or strictly worse-or-equal in rank than ``entry``. Returns True
        if the table was changed.
        """
        dest = entry.destination
        existing = self._entries.get(dest)
        expired = now is not None and existing is not None and existing.expires <= now

        # Wrap-detection heuristic: if existing seq is high (>49152), new seq is
        # low (<16384), and entry has aged at least 50% of its TTL, assume wrap.
        # RFC 1982 comparison fails when gap exceeds 32768.
        wrap_detected = False
        if existing is not None and now is not None and not expired:
            age = now - (existing.expires - GRADIENT_TIMEOUT_MS)
            if (
                age > GRADIENT_TIMEOUT_MS // 2
                and existing.seq_num > SEQ_HALF + SEQ_HALF // 2  # >49152
                and entry.seq_num < SEQ_HALF // 2  # <16384
            ):
                wrap_detected = True

        if existing is None or expired or wrap_detected or entry._rank() >= existing._rank():
            # Preserve per-neighbor SF tracking state across routing updates
            # (mirrors the C save/restore in lichen_gradient_update,
            # gradient.c:158-181): the SF fields are maintained by the RX
            # path via sf_update() and must not reset when the routing layer
            # refreshes hop_count/seq_num/source.
            if existing is not None:
                entry.current_sf = existing.current_sf
                entry.snr_ewma = existing.snr_ewma
                entry.upgrade_count = existing.upgrade_count
                entry.downgrade_count = existing.downgrade_count
            self._entries[dest] = entry
            self._entries.move_to_end(dest)
            self._evict_if_needed()
            return True
        return False

    def remove(self, destination: IPv6Address | str) -> None:
        """Remove the gradient for ``destination`` if present."""
        self._entries.pop(routing_key(destination), None)

    def remove_via(self, next_hop: IPv6Address | str) -> list[IPv6Address]:
        """Remove every gradient routing through ``next_hop``; return their dsts."""
        nh = routing_key(next_hop)
        dests = [d for d, e in self._entries.items() if e.next_hop == nh]
        for dest in dests:
            del self._entries[dest]
        return dests

    def expire_old(self, now: int) -> int:
        """Drop entries whose ``expires`` is at or before ``now``; return count."""
        stale = [d for d, e in self._entries.items() if e.expires <= now]
        for dest in stale:
            del self._entries[dest]
        return len(stale)

    def sf_update(self, neighbor: IPv6Address | str, snr: int, now: int | None = None) -> None:
        """Update per-neighbor SF tracking from an RX sample (CCP-16).

        Mirrors ``lichen_gradient_sf_update`` (gradient.c:261): advances the
        SNR EWMA (``avg = avg + (sample - avg) >> 2``, alpha = 1/4) and the
        upgrade/downgrade consecutive-sample counters. Silent no-op when the
        neighbor has no gradient entry (same as the C NULL-lookup return).
        """
        entry = self.lookup(neighbor, now)
        if entry is None:
            return
        delta = (snr - entry.snr_ewma) >> 2
        entry.snr_ewma = entry.snr_ewma + delta
        # ponytail: clamp to the C int8_t storage range; unreachable for
        # realistic LoRa SNR, and the C two-slot upgrade path is fixed-point.
        entry.snr_ewma = max(-128, min(127, entry.snr_ewma))
        if entry.snr_ewma > SNR_UPGRADE_THRESHOLD:
            entry.upgrade_count += 1
            entry.downgrade_count = 0
        elif entry.snr_ewma < SNR_DOWNGRADE_THRESHOLD:
            entry.downgrade_count += 1
            entry.upgrade_count = 0
        else:
            entry.upgrade_count = 0
            entry.downgrade_count = 0

    def sf_select(
        self,
        neighbor: IPv6Address | str,
        density: int,
        utilization: int,
        ema_loss_fp: int,
        load_factor_fp: int,
        now: int | None = None,
    ) -> tuple[int, bool] | None:
        """Select the TX spreading factor for ``neighbor`` (CCP-16 2a.8).

        Mirrors ``lichen_gradient_sf_select`` (gradient.c:298) step for step,
        including the post-step-6 minimum-SF floors. Returns None when the
        neighbor has no gradient entry (C: -ENOENT). Persists the selected SF
        on the entry (C: ``entry->sf.current_sf = sf``).
        """
        entry = self.lookup(neighbor, now)
        if entry is None:
            return None

        # Step 1-2: assigned SF, or the default when absent/out of range.
        sf = entry.current_sf
        if sf is None or sf < SF_MIN or sf > SF_MAX:
            sf = DEFAULT_SF

        # Step 3: high density or high utilization triggers SF +2.
        if density > 10 or utilization > 150:
            sf = min(SF_MAX, sf + 2)

        # Step 4: good SNR and low density allows the SF -1 upgrade.
        if (
            entry.snr_ewma > SNR_UPGRADE_THRESHOLD
            and density < DENSITY_UPGRADE_MAX
            and entry.upgrade_count >= UPGRADE_COUNT_THRESHOLD
            and sf > SF_MIN
        ):
            sf = max(SF_MIN, sf - 1)

        # Step 5: high loss / very high utilization / load factor > 0.8.
        tx_allowed = True
        if (
            ema_loss_fp > EMA_LOSS_THRESHOLD_FP
            or load_factor_fp >= LOAD_FACTOR_THRESHOLD_FP
            or utilization > 200
        ):
            sf = min(SF_MAX, sf + 1)
            if utilization > 200:
                # Spec: utilization > 200 forces SF=12 and blocks tx.
                sf = SF_MAX
                tx_allowed = False

        # Post-step-6 minimum-SF floors, applied in order a-d (spec 2a.8
        # Downgrade MUST column); floor (a) subsumes (b).
        if entry.snr_ewma < -5:
            sf = SF_MAX
        elif entry.snr_ewma < 0:
            sf = max(11, sf)
        if density > 10:
            sf = max(11, sf)
        if load_factor_fp >= LOAD_FACTOR_THRESHOLD_FP:
            sf = max(11, sf)

        entry.current_sf = sf
        return (sf, tx_allowed)

    def _evict_if_needed(self) -> None:
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)  # evict least-recently-used

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, destination: IPv6Address | str) -> bool:
        return routing_key(destination) in self._entries

    def entries(self) -> list[GradientEntry]:
        """Return a list of all gradient entries (public iteration API)."""
        return list(self._entries.values())
