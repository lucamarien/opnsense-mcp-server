"""Shared test fixtures — mock OPNsense API responses."""

from __future__ import annotations

from collections.abc import Generator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.api_client import OPNsenseAPI, SavepointManager
from opnsense_mcp.config import OPNsenseConfig
from opnsense_mcp.config_cache import ConfigCache


@pytest.fixture
def env_vars() -> Generator[dict[str, str]]:
    """Set standard test environment variables."""
    test_env = {
        "OPNSENSE_URL": "https://10.0.0.1/api",
        "OPNSENSE_API_KEY": "test-key-abc123",
        "OPNSENSE_API_SECRET": "test-secret-xyz789",
        "OPNSENSE_VERIFY_SSL": "false",
        "OPNSENSE_ALLOW_WRITES": "false",
    }
    with patch.dict("os.environ", test_env, clear=False):
        yield test_env


@pytest.fixture
def mock_config() -> OPNsenseConfig:
    """Create a test configuration object."""
    return OPNsenseConfig(
        url="https://10.0.0.1/api",
        api_key="test-key-abc123",
        api_secret="test-secret-xyz789",
        verify_ssl=False,
        allow_writes=False,
    )


@pytest.fixture
def mock_config_writes() -> OPNsenseConfig:
    """Create a test configuration with writes enabled."""
    return OPNsenseConfig(
        url="https://10.0.0.1/api",
        api_key="test-key-abc123",
        api_secret="test-secret-xyz789",
        verify_ssl=False,
        allow_writes=True,
    )


def _make_response(
    status_code: int = 200,
    json_data: dict[str, Any] | None = None,
) -> MagicMock:
    """Create a mock httpx.Response."""
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = json_data if json_data is not None else {}
    return response


@pytest.fixture
def mock_httpx_client() -> AsyncMock:
    """Create a mock httpx.AsyncClient with a default 200 response."""
    client = AsyncMock()
    client.get.return_value = _make_response()
    client.post.return_value = _make_response()
    client.aclose = AsyncMock()
    return client


@pytest.fixture
def firmware_status_pre25_7() -> dict[str, Any]:
    """Mock firmware/status response for OPNsense pre-25.7."""
    return {
        "product_version": "25.1.2",
        "product_name": "OPNsense",
        "product_id": "opnsense",
    }


@pytest.fixture
def firmware_status_25_7() -> dict[str, Any]:
    """Mock firmware/status response for OPNsense 25.7+."""
    return {
        "product_version": "25.7.1",
        "product_name": "OPNsense",
        "product_id": "opnsense",
    }


@pytest.fixture
def firmware_status_26_x() -> dict[str, Any]:
    """Mock firmware/status response for OPNsense 26.x+ (nested product)."""
    return {
        "product": {
            "product_version": "26.1.3",
            "product_name": "OPNsense",
            "product_id": "opnsense",
            "product_abi": "26.1",
            "product_nickname": "Witty Woodpecker",
        },
        "status_msg": "",
        "status": "update",
    }


@pytest.fixture
def mock_api(mock_config: OPNsenseConfig) -> OPNsenseAPI:
    """Create an OPNsenseAPI with a mocked httpx client and pre-detected version."""
    api = OPNsenseAPI(mock_config)
    api._client = AsyncMock()
    api._detected_version = (25, 1)
    api._use_snake_case = False
    return api


@pytest.fixture
def mock_config_cache() -> ConfigCache:
    """Create a fresh ConfigCache for testing."""
    return ConfigCache()


@pytest.fixture
def mock_ctx(mock_api: OPNsenseAPI, mock_config_cache: ConfigCache) -> MagicMock:
    """Create a mock FastMCP Context with the API client in lifespan_context."""
    ctx = MagicMock()
    ctx.lifespan_context = {"api": mock_api, "config_cache": mock_config_cache}
    return ctx


@pytest.fixture
def mock_savepoint_mgr_no_writes(mock_api: OPNsenseAPI) -> SavepointManager:
    """Create a SavepointManager with a write-disabled mocked API."""
    return SavepointManager(mock_api)


@pytest.fixture
def mock_ctx_no_writes(
    mock_api: OPNsenseAPI,
    mock_savepoint_mgr_no_writes: SavepointManager,
    mock_config_cache: ConfigCache,
) -> MagicMock:
    """Create a mock Context with savepoint manager but writes DISABLED."""
    ctx = MagicMock()
    ctx.lifespan_context = {
        "api": mock_api,
        "savepoint_mgr": mock_savepoint_mgr_no_writes,
        "config_cache": mock_config_cache,
    }
    return ctx


@pytest.fixture
def mock_api_writes(mock_config_writes: OPNsenseConfig) -> OPNsenseAPI:
    """Create an OPNsenseAPI with writes enabled and mocked httpx client."""
    api = OPNsenseAPI(mock_config_writes)
    api._client = AsyncMock()
    api._detected_version = (25, 1)
    api._use_snake_case = False
    return api


@pytest.fixture
def mock_savepoint_mgr(mock_api_writes: OPNsenseAPI) -> SavepointManager:
    """Create a SavepointManager with a write-enabled mocked API."""
    return SavepointManager(mock_api_writes)


@pytest.fixture
def mock_ctx_writes(
    mock_api_writes: OPNsenseAPI,
    mock_savepoint_mgr: SavepointManager,
    mock_config_cache: ConfigCache,
) -> MagicMock:
    """Create a mock Context with both API and savepoint manager (writes enabled)."""
    ctx = MagicMock()
    ctx.lifespan_context = {
        "api": mock_api_writes,
        "savepoint_mgr": mock_savepoint_mgr,
        "config_cache": mock_config_cache,
    }
    return ctx
