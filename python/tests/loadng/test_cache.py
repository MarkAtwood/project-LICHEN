# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the LOADng route cache (spec 9.6, B2.2)."""

from __future__ import annotations

from ipaddress import IPv6Address

import pytest

from lichen.loadng.cache import RouteCache, RouteEntry

DEST = IPv6Address("fd00::100")
HOP = IPv6Address("fe80::a")


def _entry(dest=DEST, next_hop=HOP, hop_count=2, metric=200, seq_num=1, valid_until=1000):
    return RouteEntry(dest, next_hop, hop_count, metric, seq_num, valid_until)


def test_add_and_lookup() -> None:
    cache = RouteCache()
    entry = _entry()
    cache.add(entry)
    assert cache.lookup(DEST) is entry
    assert DEST in cache
    assert len(cache) == 1


def test_lookup_missing() -> None:
    assert RouteCache().lookup("fd00::dead") is None


def test_add_replaces_existing() -> None:
    cache = RouteCache()
    cache.add(_entry(metric=200))
    cache.add(_entry(metric=50, next_hop=IPv6Address("fe80::b")))
    assert cache.lookup(DEST).metric == 50
    assert len(cache) == 1


def test_expiry_via_lookup_and_expire_old() -> None:
    cache = RouteCache()
    cache.add(_entry(valid_until=1000))
    assert cache.lookup(DEST, now=999) is not None
    assert cache.lookup(DEST, now=1000) is None  # inclusive expiry
    assert cache.expire_old(now=1000) == 1
    assert len(cache) == 0


def test_refresh_extends_validity() -> None:
    cache = RouteCache(route_timeout_ms=300_000)
    cache.add(_entry(valid_until=1000))
    assert cache.refresh(DEST, now=5000) is True
    assert cache.lookup(DEST).valid_until == 5000 + 300_000
    assert cache.lookup(DEST, now=100_000) is not None


def test_refresh_missing_returns_false() -> None:
    assert RouteCache().refresh("fd00::dead", now=0) is False


def test_lru_eviction() -> None:
    cache = RouteCache(max_entries=2)
    d1, d2, d3 = IPv6Address("fd00::1"), IPv6Address("fd00::2"), IPv6Address("fd00::3")
    cache.add(_entry(dest=d1))
    cache.add(_entry(dest=d2))
    cache.lookup(d1)  # touch d1 -> d2 is now LRU
    cache.add(_entry(dest=d3))
    assert d1 in cache
    assert d3 in cache
    assert d2 not in cache
    assert len(cache) == 2


def test_remove() -> None:
    cache = RouteCache()
    cache.add(_entry())
    cache.remove(DEST)
    assert DEST not in cache


def test_invalid_capacity() -> None:
    with pytest.raises(ValueError):
        RouteCache(max_entries=0)
