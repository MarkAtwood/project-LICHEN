# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Per-datagram evidence: published RFC ciphertexts and real resource dispatch."""

from __future__ import annotations

import asyncio
import json
from dataclasses import FrozenInstanceError, fields
from pathlib import Path

import cbor2
import pytest
import pytest_asyncio
from aiocoap import CREATED, EMPTY, GET, POST, UNAUTHORIZED, Message, resource
from aiocoap.blockwise import Block1Spool, ContinueException, IncompleteException
from aiocoap.numbers.types import ACK, NON

from lichen.coap.resources.messaging import MessagesResource, _request_is_oscore_protected
from lichen.coap.secure import ReplayWindowConflictError, SecureDatagramChannel
from lichen.coap.secure.channel import _EdhocChannel
from lichen.coap.transport import InMemoryNetwork, create_lichen_context
from lichen.crypto.identity import Identity
from lichen.crypto.oscore import MemorySecurityContext

from .conftest import RecordingChannel, make_context

VECTORS = Path(__file__).resolve().parents[3] / "test" / "vectors"
OSCORE = json.loads((VECTORS / "oscore.json").read_text())["vectors"]
ADDRESS = json.loads((VECTORS / "yggdrasil_address.json").read_text())["vectors"]
PEER_A = ADDRESS[0]
PEER_B = next(v for v in ADDRESS if v["name"] == "lichen_rfc8032_test1_key")
C4 = next(v for v in OSCORE if v["name"] == "rfc8613_c4_request_protection")
C5 = next(v for v in OSCORE if v["name"] == "rfc8613_c5_request_protection_no_salt")


def rfc_context(vector=C4):
    return MemorySecurityContext(
        master_secret=bytes.fromhex(vector["master_secret"]),
        master_salt=bytes.fromhex(vector["master_salt"] or ""),
        sender_id=bytes.fromhex(vector["recipient_id"]),
        recipient_id=bytes.fromhex(vector["sender_id"]),
    )


def provision(channel, source="relay-a", vector=C4, peer=PEER_A):
    """Provision independent RFC material with a separately pinned peer key."""
    context = rfc_context(vector)
    channel.add_context_sync(source, context, bytes.fromhex(peer["public_key"]))
    return context


def wire(vector=C4, mid=1):
    """Use published ciphertext, never this implementation's protect output."""
    message = Message(code=POST, _mtype=NON, _mid=mid, _token=b"rfc")
    message.opt.oscore = bytes.fromhex(vector["expected"]["oscore_option"])
    message.payload = bytes.fromhex(vector["expected"]["ciphertext"])
    return message.encode()


@pytest_asyncio.fixture
async def receiving(monkeypatch):
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate(), require_oscore=False)
    provision(channel)
    context = await create_lichen_context(channel, "server")
    transport = context.request_interfaces[0].token_interface.message_interface
    received = []
    monkeypatch.setattr(transport._mm, "dispatch_message", received.append)
    try:
        yield channel, transport, received
    finally:
        await context.shutdown()


@pytest.mark.asyncio
async def test_rfc_ciphertext_binds_copied_peer_not_source(receiving):
    channel, transport, received = receiving
    await channel._process_incoming(wire(), "relay-a")
    assert len(received) == 1
    request = received[0]
    assert request.code == GET
    assert request.opt.uri_path == ("tv1",)
    assert request.payload == b""
    assert request.opt.oscore is None
    assert _request_is_oscore_protected(request)
    remote = request.remote
    assert remote.hostinfo == "relay-a"
    assert remote.oscore_context_id == PEER_A["ipv6"]
    assert request.oscore_context_id == PEER_A["ipv6"]
    evidence = remote._evidence
    assert evidence.peer_pubkey == bytes.fromhex(PEER_A["public_key"])
    assert evidence.generation == 1
    assert isinstance(evidence.context_id, bytes) and evidence.context_id
    assert {field.name for field in fields(evidence)} == {
        "peer_pubkey",
        "context_id",
        "generation",
    }
    assert not hasattr(remote, "oscore_context")
    with pytest.raises(FrozenInstanceError):
        evidence.generation = 9
    with pytest.raises(AttributeError):
        remote.oscore_context_id = "forged"
    # Context replacement/removal cannot change an already delivered identity.
    await channel.remove_context("relay-a")
    assert remote.oscore_context_id == PEER_A["ipv6"]
    assert remote._evidence is evidence
    fresh = await transport.determine_remote(Message(code=GET, uri="coap://relay-a/tv1"))
    assert fresh.oscore_context_id is None
    # Evidence is not part of exchange identity (ACK matching must still work).
    assert fresh == remote and hash(fresh) == hash(remote)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure", ["auth", "wrong-peer", "unknown", "persist", "conflict", "replay"]
)
async def test_failures_never_dispatch_evidence(receiving, monkeypatch, failure):
    channel, _transport, received = receiving
    packet = wire()
    source = "relay-a"
    persist = channel._context_store.compare_and_set_replay_window
    if failure == "auth":
        packet = packet[:-1] + bytes([packet[-1] ^ 1])
    elif failure == "wrong-peer":
        provision(channel, "relay-b", C5, PEER_B)
        source = "relay-b"
    elif failure == "unknown":
        source = "unknown"
    elif failure in ("persist", "conflict"):

        async def fail(*args):
            if failure == "conflict":
                raise ReplayWindowConflictError(0, 0)
            raise OSError("injected replay commit failure")

        monkeypatch.setattr(channel._context_store, "compare_and_set_replay_window", fail)
    elif failure == "replay":
        await channel._process_incoming(packet, source)
        assert len(received) == 1
        received.clear()
    await channel._process_incoming(packet, source)
    assert received == []
    if failure in ("auth", "persist", "conflict"):
        # Rejection did not consume the packet or leave stale delivery metadata.
        monkeypatch.setattr(channel._context_store, "compare_and_set_replay_window", persist)
        await channel._process_incoming(wire(), source)
        assert len(received) == 1


@pytest.mark.asyncio
async def test_concurrent_peers_and_plaintext_keep_datagram_metadata_isolated(
    receiving, monkeypatch
):
    channel, transport, received = receiving
    provision(channel, "relay-b", C5, PEER_B)
    entered = asyncio.Event()
    release = asyncio.Event()
    persist = channel._context_store.compare_and_set_replay_window

    async def delayed(source, *args):
        if source == "relay-a":
            entered.set()
            await release.wait()
        await persist(source, *args)

    monkeypatch.setattr(channel._context_store, "compare_and_set_replay_window", delayed)
    first = asyncio.create_task(channel._process_incoming(wire(), "relay-a"))
    try:
        await asyncio.wait_for(entered.wait(), 1)
        assert received == []  # unprotect alone is insufficient
        await channel._process_incoming(wire(C5, mid=2), "relay-b")
        assert received[0].remote.oscore_context_id == PEER_B["ipv6"]
        plaintext = Message(code=GET, _mtype=NON, _mid=3).encode()
        await channel._process_incoming(plaintext, "relay-a")
        assert received[1].remote.oscore_context_id is None
        assert getattr(received[1], "oscore_context_id", None) is None
    finally:
        release.set()
        await first
    assert received[2].remote.oscore_context_id == PEER_A["ipv6"]
    await channel._process_incoming(plaintext, "relay-a")
    await channel._process_incoming(Message(code=EMPTY, _mtype=ACK, _mid=4).encode(), "relay-a")
    assert all(m.remote._evidence is None for m in received[3:])
    assert all(getattr(m, "oscore_context_id", None) is None for m in received[3:])
    assert received[0].remote.oscore_context_id == PEER_B["ipv6"]
    # Even option 9 on a raw transport does not create evidence.
    transport._on_datagram(wire(), "relay-a")
    assert not _request_is_oscore_protected(received[-1])


@pytest.mark.asyncio
async def test_edhoc_dispatch_has_no_evidence(receiving, monkeypatch):
    channel, _transport, received = receiving
    channel._edhoc_channel = _EdhocChannel(channel._inner)
    edhoc_context = await create_lichen_context(channel._edhoc_channel, "server")
    edhoc_transport = edhoc_context.request_interfaces[0].token_interface.message_interface
    edhoc_received = []
    monkeypatch.setattr(edhoc_transport._mm, "dispatch_message", edhoc_received.append)
    try:
        channel._edhoc_active_peers.add("relay-a")
        await channel._process_incoming(Message(code=POST, _mtype=NON, _mid=5).encode(), "relay-a")
        assert received == []
        assert len(edhoc_received) == 1
        assert edhoc_received[0].remote._evidence is None
        assert getattr(edhoc_received[0], "oscore_context_id", None) is None
    finally:
        await edhoc_context.shutdown()


@pytest.mark.asyncio
async def test_blockwise_cannot_inherit_another_datagrams_evidence(receiving):
    channel, transport, received = receiving
    await channel._process_incoming(wire(), "relay-a")
    authenticated = received[-1].remote
    transport._on_datagram(Message(code=POST, _mtype=NON, _mid=2).encode(), "relay-a")
    plaintext = received[-1].remote
    # A different context generation must not share the old assembly either.
    # Obtain fresh evidence from the independent C.5 ciphertext.
    await channel.add_context("relay-a", rfc_context(C5), bytes.fromhex(PEER_A["public_key"]))
    await channel._process_incoming(wire(C5, mid=3), "relay-a")
    rekeyed = received[-1].remote
    assert rekeyed._evidence is not None
    for next_remote in (plaintext, rekeyed):
        spool = Block1Spool()
        first = Message(code=POST, payload=b"a" * 16, block1=(0, True, 0))
        first.remote = authenticated
        last = Message(code=POST, payload=b"b", block1=(1, False, 0))
        last.remote = next_remote
        with pytest.raises(ContinueException):
            spool.feed_and_take(first)
        with pytest.raises(IncompleteException):
            spool.feed_and_take(last)
        last.remote = authenticated
        assert spool.feed_and_take(last).payload == b"a" * 16 + b"b"


@pytest.mark.asyncio
async def test_raw_two_argument_callback_and_registration_cleanup():
    channel = SecureDatagramChannel(RecordingChannel(), Identity.generate())
    provision(channel)
    verified = []
    registration = channel._set_verified_receiver(lambda *args: verified.append(args))
    assert not channel.clear_receiver(lambda *_: None)
    assert channel.clear_receiver(registration)
    raw = []
    channel.set_receiver(lambda data, source: raw.append((data, source)))
    try:
        await channel._process_incoming(wire(), "relay-a")
        assert verified == []
        assert len(raw) == 1 and raw[0][1] == "relay-a"
        assert Message.decode(raw[0][0]).code == GET
    finally:
        await channel.shutdown()
    assert channel._verified_receiver is None


@pytest.mark.asyncio
async def test_verified_callback_failure_is_not_retried_as_raw():
    channel = SecureDatagramChannel(RecordingChannel(), Identity.generate())
    provision(channel)
    calls = []

    def fail(data, source, evidence):
        calls.append((data, source, evidence))
        raise TypeError("receiver failure, not an arity mismatch")

    channel._set_verified_receiver(fail)
    try:
        await channel._process_incoming(wire(), "relay-a")
        assert len(calls) == 1
        assert calls[0][2].peer_pubkey == bytes.fromhex(PEER_A["public_key"])
        assert channel._active_peer_contexts["relay-a"].inbound_requests == {}
        # Authentication was already committed even though delivery failed.
        await channel._process_incoming(wire(), "relay-a")
        assert len(calls) == 1
    finally:
        await channel.shutdown()


@pytest.mark.asyncio
async def test_cancelled_persistence_does_not_publish_evidence(receiving, monkeypatch):
    channel, _transport, received = receiving
    persist = channel._context_store.compare_and_set_replay_window
    entered = asyncio.Event()

    async def interrupted(*args):
        entered.set()
        await asyncio.Future()

    monkeypatch.setattr(channel._context_store, "compare_and_set_replay_window", interrupted)
    pending = asyncio.create_task(channel._process_incoming(wire(), "relay-a"))
    try:
        await asyncio.wait_for(entered.wait(), 1)
    finally:
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
    assert received == []
    monkeypatch.setattr(channel._context_store, "compare_and_set_replay_window", persist)
    await channel._process_incoming(wire(), "relay-a")
    assert len(received) == 1
    assert received[0].remote.oscore_context_id == PEER_A["ipv6"]


@pytest.mark.asyncio
async def test_placeholder_peer_binding_cannot_authorize(receiving):
    channel, _transport, received = receiving
    provision(channel, "placeholder", C5, {"public_key": b"legacy-key".hex()})
    await channel._process_incoming(wire(C5), "placeholder")
    assert len(received) == 1
    assert received[0].remote._evidence is None
    assert not _request_is_oscore_protected(received[0])


@pytest.mark.asyncio
async def test_protected_request_reaches_actual_inbox_resource_gate():
    network = InMemoryNetwork()
    client_host = PEER_A["ipv6"]
    server_host = PEER_B["ipv6"]
    client = SecureDatagramChannel(network.channel(client_host), Identity.generate())
    server = SecureDatagramChannel(
        network.channel(server_host), Identity.generate(), require_oscore=False
    )
    client.add_context_sync(server_host, make_context(), bytes.fromhex(PEER_B["public_key"]))
    server.add_context_sync(
        client_host, make_context(b"\x02", b"\x01"), bytes.fromhex(PEER_A["public_key"])
    )
    seen = []
    rendered = asyncio.Queue()

    class Inbox(MessagesResource):
        async def render_post(self, request):
            seen.append(request)
            result = await super().render_post(request)
            rendered.put_nowait(result)
            return result

    site = resource.Site()
    inbox = Inbox()
    site.add_resource(("msg", "inbox"), inbox)
    server_context = await create_lichen_context(server, server_host, site=site)
    client_context = await create_lichen_context(client, client_host)
    try:

        def request():
            return Message(
                code=POST,
                uri=f"coap://[{server_host}]/msg/inbox",
                payload=cbor2.dumps({"body": "hello", "to": "all"}),
            )

        response = await asyncio.wait_for(client_context.request(request()).response, 2)
        assert response.code == CREATED
        assert (await asyncio.wait_for(rendered.get(), 2)).code == CREATED
        assert seen[0].remote.oscore_context_id == PEER_A["ipv6"]
        assert response.remote.oscore_context_id == PEER_B["ipv6"]
        assert inbox.inbox()[0]["body"] == "hello"
        # The same provisioned source's later plaintext must fail the real gate.
        plaintext = request()
        plaintext.mtype = NON
        plaintext.mid = 123
        plaintext.token = b"plain"
        await server._process_incoming(plaintext.encode(), client_host)
        result = await asyncio.wait_for(rendered.get(), 2)
        assert result.code == UNAUTHORIZED
        assert seen[1].remote.oscore_context_id is None
        assert len(inbox.inbox()) == 1
    finally:
        await client_context.shutdown()
        await server_context.shutdown()
