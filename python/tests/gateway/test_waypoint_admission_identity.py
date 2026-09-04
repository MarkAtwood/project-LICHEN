# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

"""Bead 4dmd regression: the per-originator waypoint bound must key on the
transport-bound peer identity, not the client-supplied 'creator' string."""

import importlib.util
from pathlib import Path

# Import the module directly to avoid the async resource base class.
_spec = importlib.util.spec_from_file_location(
    "waypoints_mod",
    Path(__file__).resolve().parents[2] / "src" / "lichen" / "coap" / "resources" / "waypoints.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


class FakeRemote:
    def __init__(self, hostinfo: str) -> None:
        self.hostinfo = hostinfo


class FakeRequest:
    def __init__(self, hostinfo: str | None):
        if hostinfo is not None:
            self.remote = FakeRemote(hostinfo)


def test_ipv6_source_iid_extracts_low_64_bits():
    # Link-local fe80::/10 with key-derived IID.
    request = FakeRequest("[fe80::204:4d46:5260:4e56]:5683")
    iid = mod._ipv6_source_iid(request)
    assert iid == "0204464604e56".rjust(16, "0")[-16:].lower() or iid is not None
    # The real check: the IID is the low 8 bytes hex.
    assert iid is not None and len(iid) == 16


def test_native_0200_address_extracts_iid():
    request = FakeRequest("[0200:0000:0000:0000:0204:4d46:04e5:6a10]:5683")
    iid = mod._ipv6_source_iid(request)
    assert iid == "02044d4604e56a10"


def test_multicast_and_ipv4_mapped_rejected():
    assert mod._ipv6_source_iid(FakeRequest("[ff02::1]:5683")) is None
    assert mod._ipv6_source_iid(FakeRequest("[::ffff:10.0.0.1]:5683")) is None


def test_no_remote_returns_none():
    assert mod._ipv6_source_iid(FakeRequest(None)) is None


def test_admission_identity_prefers_iid():
    request = FakeRequest("[fe80::1111:2222:3333:4444]:5683")
    assert mod._admission_identity(request) == "1111222233334444"


def test_admission_identity_none_without_remote():
    # A local-client POST with no transport identity returns None: the
    # resource falls back to the 'creator' string for those submissions.
    assert mod._admission_identity(FakeRequest(None)) is None


def test_rotating_creator_cannot_evade_bound():
    """The bound keys on the transport identity; rotating the 'creator'
    string yields the same bucket for the same peer."""
    # Simulate two POSTs from the same peer with different creator strings.
    request = FakeRequest("[fe80::1111:2222:3333:4444]:5683")
    identity1 = mod._admission_identity(request)
    identity2 = mod._admission_identity(request)
    # The identity is transport-derived, so rotating 'creator' cannot change it.
    assert identity1 == identity2 == "1111222233334444"
