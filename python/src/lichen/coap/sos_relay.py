# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SOS re-broadcast with TTL-limited deduplication (spec section 18.4.3).

This module provides relay logic for SOS messages:
- TTL (hop count) limits flooding propagation
- Deduplication ensures each SOS is relayed once per node
- Monotonic origin-sequence enforcement rejects stale-but-unseen sequences
  (with u64 wraparound handling)
- Time-based expiry prevents unbounded memory growth

Per spec 18.4.3: "Nodes receiving SOS: ... Re-broadcast once (controlled
flooding, TTL-limited)"

Per spec 18.4.6: "Relay duty: All nodes relay SOS (once per SOS ID)"

SOS ID is defined as (originating node, sequence number). A node that has
already relayed a given SOS ID silently drops subsequent copies.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Default maximum TTL for SOS messages (limits flood propagation)
# Why 7: typical mesh networks have diameter < 10 hops; 7 balances coverage
# with flood control per spec appendix on network diameter.
DEFAULT_MAX_TTL: int = 7

# Default TTL for originating SOS messages
DEFAULT_INITIAL_TTL: int = 7

# How long to remember seen SOS IDs (seconds)
# Why 4 hours: matches spec 18.4.6 "SOS remains active until cancelled or
# 4-hour timeout"
SEEN_EXPIRY_S: int = 4 * 3600

# Maximum number of seen SOS IDs before LRU eviction
# Why 256: 256 unique (node, seq) pairs is plenty for typical scenarios
SEEN_MAX_SIZE: int = 256

# Maximum number of per-origin sequence high-water marks before LRU eviction
MAX_TRACKED_ORIGINS: int = 1024

# u64 serial-number arithmetic bounds (origin_sequence is a 64-bit counter)
_U64_MODULUS = 1 << 64
_U64_HALF = 1 << 63


def _seq_is_stale(seq: int, max_seen: int) -> bool:
    """True if *seq* is older than *max_seen* in u64 serial-number order.

    Wraparound-safe (RFC 1982 style): a sequence is stale when it lies in
    the past half-window below the high-water mark. Equal or future values
    (including a legitimate ``2**64 - 1`` to ``0`` rollover) are not stale.
    """
    return 0 < (max_seen - seq) % _U64_MODULUS < _U64_HALF


@dataclass(frozen=True)
class SosId:
    """Unique identifier for an SOS message.

    Attributes:
        node: Originating node identifier (16-char hex EUI-64).
        seq: Sequence number for updates from the same node.
    """

    node: str
    seq: int

    def __post_init__(self) -> None:
        if not isinstance(self.node, str) or len(self.node) != 16:
            raise ValueError(f"node must be 16-char hex string, got {self.node!r}")
        if not isinstance(self.seq, int) or self.seq < 0:
            raise ValueError(f"seq must be non-negative int, got {self.seq!r}")


@dataclass
class SosRelayResult:
    """Result of checking whether to relay an SOS message.

    Attributes:
        should_relay: True if the node should re-broadcast this SOS.
        reason: Human-readable reason for the decision.
        new_ttl: TTL value for the relayed message (None if not relaying).
    """

    should_relay: bool
    reason: str
    new_ttl: int | None = None


@dataclass
class SosRelay:
    """SOS relay handler with TTL-limited deduplication.

    Tracks which SOS IDs have been seen to prevent duplicate relays.
    Enforces TTL limits to bound flood propagation.

    Attributes:
        max_ttl: Maximum allowed TTL value.
        time_func: Callable returning current time (for testing).
    """

    max_ttl: int = DEFAULT_MAX_TTL
    time_func: Callable[[], float] = field(default_factory=lambda: time.time)

    # Maps SosId -> timestamp when first seen (OrderedDict for LRU eviction)
    _seen: OrderedDict[SosId, float] = field(
        default_factory=OrderedDict, init=False, repr=False
    )

    # Per-origin high-water origin_sequence for stale-sequence rejection
    _max_seq: OrderedDict[str, int] = field(
        default_factory=OrderedDict, init=False, repr=False
    )

    def check_relay(
        self,
        node: str,
        seq: int,
        ttl: int,
    ) -> SosRelayResult:
        """Check whether to relay an incoming SOS message.

        Args:
            node: Originating node identifier (16-char hex).
            seq: Sequence number for this SOS.
            ttl: Current TTL value from the incoming message.

        Returns:
            SosRelayResult indicating whether to relay and why.
        """
        # Validate node format
        if not isinstance(node, str) or len(node) != 16:
            return SosRelayResult(
                should_relay=False,
                reason=f"invalid node format: {node!r}",
            )

        # Validate seq
        if not isinstance(seq, int) or seq < 0:
            return SosRelayResult(
                should_relay=False,
                reason=f"invalid seq: {seq!r}",
            )

        # TTL exhausted
        if ttl <= 0:
            return SosRelayResult(
                should_relay=False,
                reason="TTL exhausted",
            )

        # TTL exceeds maximum (possible attack or misconfiguration)
        if ttl > self.max_ttl:
            logger.warning("SOS TTL %d exceeds max %d, clamping", ttl, self.max_ttl)
            ttl = self.max_ttl

        # Monotonic origin-sequence gate: a stale-but-unseen sequence is
        # relay-dropped (spec 18.4.1; vector origin_sequence_rollback).
        # Wraparound-fresh sequences and equal-to-high-water sequences pass.
        max_seen = self._max_seq.get(node)
        if max_seen is not None and _seq_is_stale(seq, max_seen):
            return SosRelayResult(
                should_relay=False,
                reason=(
                    f"stale origin sequence {seq} from {node} "
                    f"(max seen {max_seen})"
                ),
            )

        # Prune expired entries before checking
        self._prune_expired()

        # Check if already seen
        sos_id = SosId(node=node, seq=seq)
        if sos_id in self._seen:
            return SosRelayResult(
                should_relay=False,
                reason=f"already relayed SOS from {node} seq={seq}",
            )

        # Record this SOS as seen
        self._record_seen(sos_id)

        # Relay with decremented TTL
        new_ttl = ttl - 1
        return SosRelayResult(
            should_relay=True,
            reason=f"relaying SOS from {node} seq={seq} with TTL={new_ttl}",
            new_ttl=new_ttl,
        )

    def mark_seen(self, node: str, seq: int) -> None:
        """Mark an SOS ID as seen (e.g., for messages we originate).

        Call this when the local node originates an SOS to prevent
        relaying our own message back to ourselves.

        Args:
            node: Originating node identifier.
            seq: Sequence number.
        """
        sos_id = SosId(node=node, seq=seq)
        self._record_seen(sos_id)

    def is_seen(self, node: str, seq: int) -> bool:
        """Check if an SOS ID has been seen.

        Args:
            node: Originating node identifier.
            seq: Sequence number.

        Returns:
            True if this SOS ID has been seen and not expired.
        """
        self._prune_expired()
        try:
            sos_id = SosId(node=node, seq=seq)
        except ValueError:
            return False
        return sos_id in self._seen

    def clear(self) -> int:
        """Clear all seen SOS IDs.

        Returns:
            Number of entries cleared.
        """
        count = len(self._seen)
        self._seen.clear()
        self._max_seq.clear()
        return count

    def _record_seen(self, sos_id: SosId) -> None:
        """Record an SOS ID as seen with current timestamp."""
        now = self.time_func()
        self._seen[sos_id] = now
        # Move to end for LRU ordering
        self._seen.move_to_end(sos_id)
        # Enforce capacity limit
        if len(self._seen) > SEEN_MAX_SIZE:
            # Evict oldest half to amortize eviction cost
            for _ in range(SEEN_MAX_SIZE // 2):
                self._seen.popitem(last=False)
        # Track the per-origin sequence high-water mark
        max_seen = self._max_seq.get(sos_id.node)
        if max_seen is None or not _seq_is_stale(sos_id.seq, max_seen):
            self._max_seq[sos_id.node] = sos_id.seq
        self._max_seq.move_to_end(sos_id.node)
        if len(self._max_seq) > MAX_TRACKED_ORIGINS:
            self._max_seq.popitem(last=False)

    def _prune_expired(self) -> None:
        """Remove SOS IDs older than SEEN_EXPIRY_S."""
        now = self.time_func()
        cutoff = now - SEEN_EXPIRY_S
        # Iterate over a copy of keys since we're modifying during iteration
        expired = [
            sos_id for sos_id, timestamp in self._seen.items() if timestamp < cutoff
        ]
        for sos_id in expired:
            del self._seen[sos_id]
        if expired:
            logger.debug("pruned %d expired SOS IDs", len(expired))

    def __len__(self) -> int:
        """Return number of seen SOS IDs (for diagnostics)."""
        return len(self._seen)


def add_ttl_to_sos_payload(payload: dict, ttl: int = DEFAULT_INITIAL_TTL) -> dict:
    """Add TTL field to an SOS payload dict.

    Args:
        payload: SOS payload dict (modified in place).
        ttl: TTL value to add (default: 7).

    Returns:
        The modified payload dict (same object).
    """
    payload["ttl"] = ttl
    return payload


def get_sos_id_from_payload(payload: dict) -> tuple[str, int] | None:
    """Extract SOS ID (node, seq) from a payload dict.

    Args:
        payload: SOS payload dict with "node" and "seq" fields.

    Returns:
        (node, seq) tuple, or None if fields are missing/invalid.
    """
    node = payload.get("node")
    seq = payload.get("seq")
    if not isinstance(node, str) or len(node) != 16:
        return None
    if not isinstance(seq, int) or seq < 0:
        return None
    return (node, seq)


def get_ttl_from_payload(payload: dict, default: int = DEFAULT_INITIAL_TTL) -> int:
    """Extract TTL from a payload dict.

    Args:
        payload: SOS payload dict.
        default: TTL to return if not present.

    Returns:
        TTL value (clamped to non-negative).
    """
    ttl = payload.get("ttl", default)
    if not isinstance(ttl, int):
        return default
    return max(0, ttl)


__all__ = [
    "DEFAULT_INITIAL_TTL",
    "DEFAULT_MAX_TTL",
    "SEEN_EXPIRY_S",
    "SEEN_MAX_SIZE",
    "SosId",
    "SosRelay",
    "SosRelayResult",
    "add_ttl_to_sos_payload",
    "get_sos_id_from_payload",
    "get_ttl_from_payload",
]
