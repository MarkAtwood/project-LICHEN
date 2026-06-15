"""LOADng route cache (spec section 9.6, appendix B2.2).

Holds discovered forward routes (destination -> next hop) with their metric and
freshness, separate from the unified gradient table: this cache is LOADng's own
working set during and after discovery. Timestamps are caller-supplied integers
(milliseconds) so the cache is deterministic; capacity is bounded with LRU
eviction.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from ipaddress import IPv6Address

ROUTE_CACHE_SIZE = 32
ROUTE_TIMEOUT_MS = 300_000  # 300 s route validity with no traffic
ROUTE_REFRESH_MS = 60_000  # refresh if used within 60 s of activity


def _addr(value: IPv6Address | str) -> IPv6Address:
    return value if isinstance(value, IPv6Address) else IPv6Address(value)


@dataclass
class RouteEntry:
    """A cached LOADng forward route (spec 9.6)."""

    destination: IPv6Address
    next_hop: IPv6Address
    hop_count: int
    metric: int
    seq_num: int
    valid_until: int

    def __post_init__(self) -> None:
        self.destination = _addr(self.destination)
        self.next_hop = _addr(self.next_hop)


class RouteCache:
    """Bounded, LRU-evicting cache of LOADng routes."""

    def __init__(
        self,
        max_entries: int = ROUTE_CACHE_SIZE,
        route_timeout_ms: int = ROUTE_TIMEOUT_MS,
    ) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self.max_entries = max_entries
        self.route_timeout_ms = route_timeout_ms
        self._entries: OrderedDict[IPv6Address, RouteEntry] = OrderedDict()

    def add(self, entry: RouteEntry) -> None:
        """Insert or replace the route to ``entry.destination`` (LRU on insert)."""
        self._entries[entry.destination] = entry
        self._entries.move_to_end(entry.destination)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)  # evict least-recently-used

    def lookup(
        self, destination: IPv6Address | str, now: int | None = None
    ) -> RouteEntry | None:
        """Return the route (None if absent or expired); marks it recently used."""
        dest = _addr(destination)
        entry = self._entries.get(dest)
        if entry is None:
            return None
        if now is not None and entry.valid_until <= now:
            return None
        self._entries.move_to_end(dest)
        return entry

    def remove(self, destination: IPv6Address | str) -> None:
        """Remove the route to ``destination`` if present."""
        self._entries.pop(_addr(destination), None)

    def refresh(self, destination: IPv6Address | str, now: int) -> bool:
        """Extend a route's validity to ``now + route_timeout``; True if found."""
        dest = _addr(destination)
        entry = self._entries.get(dest)
        if entry is None:
            return False
        entry.valid_until = now + self.route_timeout_ms
        self._entries.move_to_end(dest)
        return True

    def expire_old(self, now: int) -> int:
        """Drop routes whose validity is at or before ``now``; return count."""
        stale = [d for d, e in self._entries.items() if e.valid_until <= now]
        for dest in stale:
            del self._entries[dest]
        return len(stale)

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, destination: IPv6Address | str) -> bool:
        return _addr(destination) in self._entries
