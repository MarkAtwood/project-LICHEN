"""Shared pytest fixtures for LICHEN tests."""

import pytest


@pytest.fixture
def anyio_backend() -> str:
    """Use asyncio as the async backend."""
    return "asyncio"
