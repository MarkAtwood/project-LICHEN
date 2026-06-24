"""Tests for LICHEN Native Node handler."""

import pytest

from lichen.crypto.identity import Identity
from lichen.interface.handler import NodeHandler, bind_native
from lichen.interface.messages import (
    ConfigGet,
    ConfigKey,
    ConfigResult,
    ConfigSet,
    Hello,
    MessageType,
    ResultCode,
)
from lichen.interface.tcp import connect
from lichen.node import Node, NodeConfig
from lichen.radio.base import Radio


class MockRadio(Radio):
    """Minimal radio for testing."""

    async def transmit(self, data: bytes) -> None:
        pass

    async def receive(self, timeout_ms: int) -> bytes | None:
        return None

    def get_rssi(self) -> int:
        return -100


@pytest.fixture
def node():
    """Create a test node."""
    identity = Identity.generate()
    radio = MockRadio()
    return Node(identity=identity, radio=radio, config=NodeConfig())


@pytest.fixture
async def handler(node):
    """Create handler with server."""
    h = NodeHandler(node=node)
    await h.serve("127.0.0.1", 0)
    yield h
    await h.close()


class TestHello:
    @pytest.mark.asyncio
    async def test_hello_response(self, handler: NodeHandler):
        addr = handler._server.address
        assert addr is not None

        conn = await connect(addr[0], addr[1])
        try:
            # Send hello
            await conn.send(Hello(version=1, firmware="test-client"))

            # Get response
            response = await conn.recv()
            assert isinstance(response, Hello)
            assert response.version == 1
            assert response.firmware == "sim-0.1.0"
            assert response.iid is not None
            assert len(response.iid) == 8
            assert MessageType.CONFIG_GET in response.supported
        finally:
            await conn.close()


class TestConfig:
    @pytest.mark.asyncio
    async def test_config_get_all(self, handler: NodeHandler):
        addr = handler._server.address
        assert addr is not None

        conn = await connect(addr[0], addr[1])
        try:
            await conn.send(ConfigGet())
            response = await conn.recv()

            assert isinstance(response, ConfigResult)
            assert response.result == ResultCode.OK
            assert response.values is not None
            assert ConfigKey.RECEIVE_TIMEOUT in response.values
            assert ConfigKey.ANNOUNCE_INTERVAL in response.values
        finally:
            await conn.close()

    @pytest.mark.asyncio
    async def test_config_get_specific(self, handler: NodeHandler):
        addr = handler._server.address
        assert addr is not None

        conn = await connect(addr[0], addr[1])
        try:
            await conn.send(ConfigGet(keys=[ConfigKey.RECEIVE_TIMEOUT]))
            response = await conn.recv()

            assert isinstance(response, ConfigResult)
            assert response.result == ResultCode.OK
            assert ConfigKey.RECEIVE_TIMEOUT in response.values
            assert ConfigKey.ANNOUNCE_INTERVAL not in response.values
        finally:
            await conn.close()

    @pytest.mark.asyncio
    async def test_config_set(self, handler: NodeHandler, node: Node):
        addr = handler._server.address
        assert addr is not None

        conn = await connect(addr[0], addr[1])
        try:
            # Set new value
            await conn.send(
                ConfigSet(values={ConfigKey.RECEIVE_TIMEOUT: 2000})
            )
            response = await conn.recv()

            assert isinstance(response, ConfigResult)
            assert response.result == ResultCode.OK

            # Verify it changed
            assert node.config.receive_timeout_ms == 2000
        finally:
            await conn.close()


class TestMeshState:
    @pytest.mark.asyncio
    async def test_get_mesh_state(self, handler: NodeHandler):
        state = handler.get_mesh_state()
        assert state is not None
        assert state.gradients is not None
        assert state.neighbors is not None


class TestNodeInfo:
    @pytest.mark.asyncio
    async def test_get_node_info(self, handler: NodeHandler, node: Node):
        info = handler.get_node_info()
        assert info is not None
        assert info.iid == node.identity.iid
        assert info.hardware == "python-sim"


class TestBindNative:
    @pytest.mark.asyncio
    async def test_bind_native(self, node: Node):
        handler = await bind_native(node, port=0)
        try:
            assert handler._server is not None
            addr = handler._server.address
            assert addr is not None

            # Connect and verify
            conn = await connect(addr[0], addr[1])
            try:
                await conn.send(Hello())
                response = await conn.recv()
                assert isinstance(response, Hello)
            finally:
                await conn.close()
        finally:
            await handler.close()
