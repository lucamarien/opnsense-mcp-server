"""Tests for HAProxy tools."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.api_client import WriteDisabledError
from opnsense_mcp.tools.haproxy import (
    opn_haproxy_add,
    opn_haproxy_configtest,
    opn_haproxy_delete,
    opn_haproxy_get,
    opn_haproxy_search,
    opn_haproxy_status,
    opn_haproxy_update,
    opn_reconfigure_haproxy,
)


class TestOpnHaproxyStatus:
    """Tests for opn_haproxy_status."""

    async def test_calls_haproxy_status(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"status": "running"})
        result = await opn_haproxy_status(mock_ctx)
        mock_api.get.assert_called_once_with("haproxy.service.status")
        assert result == {"status": "running"}


class TestOpnReconfigureHaproxy:
    """Tests for opn_reconfigure_haproxy."""

    async def test_calls_reconfigure_endpoint(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        result = await opn_reconfigure_haproxy(mock_ctx_writes)
        mock_api_writes.post.assert_called_once_with("haproxy.service.reconfigure")
        assert result["status"] == "ok"
        assert result["service"] == "haproxy"

    async def test_requires_writes_enabled(self, mock_api, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_reconfigure_haproxy(mock_ctx)

    async def test_returns_unknown_on_missing_status(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={})
        result = await opn_reconfigure_haproxy(mock_ctx_writes)
        assert result["status"] == "unknown"


class TestOpnHaproxySearch:
    """Tests for opn_haproxy_search."""

    async def test_search_frontends(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_haproxy_search(mock_ctx, resource_type="frontends")
        mock_api.post.assert_called_once_with(
            "haproxy.settings.search_frontends",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_search_backends(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_haproxy_search(mock_ctx, resource_type="backends")
        mock_api.post.assert_called_once_with(
            "haproxy.settings.search_backends",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )

    async def test_search_servers(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_haproxy_search(mock_ctx, resource_type="servers")
        mock_api.post.assert_called_once_with(
            "haproxy.settings.search_servers",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )

    async def test_search_acls(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_haproxy_search(mock_ctx, resource_type="acls")
        mock_api.post.assert_called_once_with(
            "haproxy.settings.search_acls",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )

    async def test_search_healthchecks(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_haproxy_search(mock_ctx, resource_type="healthchecks")
        mock_api.post.assert_called_once_with(
            "haproxy.settings.search_healthchecks",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )

    async def test_passes_search_and_limit(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_haproxy_search(mock_ctx, resource_type="frontends", search="web", limit=20)
        mock_api.post.assert_called_once_with(
            "haproxy.settings.search_frontends",
            {"current": 1, "rowCount": 20, "searchPhrase": "web"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_haproxy_search(mock_ctx, resource_type="frontends", limit=800)
        call_args = mock_api.post.call_args[0][1]
        assert call_args["rowCount"] == 500

    async def test_invalid_resource_type(self, mock_api, mock_ctx):
        result = await opn_haproxy_search(mock_ctx, resource_type="invalid")
        assert "error" in result
        assert "Invalid resource_type" in result["error"]


class TestOpnHaproxyGet:
    """Tests for opn_haproxy_get."""

    async def test_get_frontend(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"frontend": {"name": "web-https"}})
        result = await opn_haproxy_get(mock_ctx, resource_type="frontends", uuid="abc-123")
        mock_api.get.assert_called_once_with("haproxy.settings.get_frontend", path_suffix="abc-123")
        assert result == {"frontend": {"name": "web-https"}}

    async def test_get_backend(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"backend": {"name": "pool1"}})
        result = await opn_haproxy_get(mock_ctx, resource_type="backends", uuid="def-456")
        mock_api.get.assert_called_once_with("haproxy.settings.get_backend", path_suffix="def-456")
        assert result == {"backend": {"name": "pool1"}}

    async def test_invalid_resource_type(self, mock_api, mock_ctx):
        result = await opn_haproxy_get(mock_ctx, resource_type="unknown", uuid="abc-123")
        assert "error" in result


class TestOpnHaproxyAdd:
    """Tests for opn_haproxy_add."""

    async def test_add_frontend(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "new-uuid-123"})
        config = {"name": "web-v6", "bind": "[::]:443", "mode": "http"}
        result = await opn_haproxy_add(mock_ctx_writes, resource_type="frontends", config=config)
        mock_api_writes.post.assert_called_once_with("haproxy.settings.add_frontend", {"frontend": config})
        assert result["uuid"] == "new-uuid-123"

    async def test_add_server(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "srv-uuid"})
        config = {"name": "srv1", "address": "2001:db8::1", "port": "8080"}
        result = await opn_haproxy_add(mock_ctx_writes, resource_type="servers", config=config)
        mock_api_writes.post.assert_called_once_with("haproxy.settings.add_server", {"server": config})
        assert result["uuid"] == "srv-uuid"

    async def test_requires_writes_enabled(self, mock_api, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_haproxy_add(
                mock_ctx,
                resource_type="frontends",
                config={"name": "test"},
            )

    async def test_empty_config_rejected(self, mock_api_writes, mock_ctx_writes):
        result = await opn_haproxy_add(mock_ctx_writes, resource_type="frontends", config={})
        assert "error" in result
        assert "empty" in result["error"]

    async def test_invalid_resource_type(self, mock_api_writes, mock_ctx_writes):
        result = await opn_haproxy_add(mock_ctx_writes, resource_type="invalid", config={"name": "test"})
        assert "error" in result


class TestOpnHaproxyUpdate:
    """Tests for opn_haproxy_update."""

    async def test_update_frontend(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        config = {"bind": "[::]:443,0.0.0.0:443"}
        result = await opn_haproxy_update(
            mock_ctx_writes,
            resource_type="frontends",
            uuid="abc-123",
            config=config,
        )
        mock_api_writes.post.assert_called_once_with(
            "haproxy.settings.set_frontend",
            {"frontend": config},
            path_suffix="abc-123",
        )
        assert result["result"] == "saved"

    async def test_toggle_via_update(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        await opn_haproxy_update(
            mock_ctx_writes,
            resource_type="backends",
            uuid="def-456",
            config={"enabled": "0"},
        )
        mock_api_writes.post.assert_called_once_with(
            "haproxy.settings.set_backend",
            {"backend": {"enabled": "0"}},
            path_suffix="def-456",
        )

    async def test_requires_writes_enabled(self, mock_api, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_haproxy_update(
                mock_ctx,
                resource_type="frontends",
                uuid="abc-123",
                config={"enabled": "1"},
            )

    async def test_empty_config_rejected(self, mock_api_writes, mock_ctx_writes):
        result = await opn_haproxy_update(
            mock_ctx_writes,
            resource_type="frontends",
            uuid="abc-123",
            config={},
        )
        assert "error" in result


class TestOpnHaproxyDelete:
    """Tests for opn_haproxy_delete."""

    async def test_delete_server(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "deleted"})
        result = await opn_haproxy_delete(mock_ctx_writes, resource_type="servers", uuid="srv-uuid")
        mock_api_writes.post.assert_called_once_with("haproxy.settings.del_server", path_suffix="srv-uuid")
        assert result["result"] == "deleted"

    async def test_requires_writes_enabled(self, mock_api, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_haproxy_delete(mock_ctx, resource_type="frontends", uuid="abc-123")

    async def test_invalid_resource_type(self, mock_api_writes, mock_ctx_writes):
        result = await opn_haproxy_delete(mock_ctx_writes, resource_type="invalid", uuid="abc-123")
        assert "error" in result


class TestOpnHaproxyConfigtest:
    """Tests for opn_haproxy_configtest."""

    async def test_calls_configtest(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"result": "Configuration file is valid"})
        result = await opn_haproxy_configtest(mock_ctx)
        mock_api.get.assert_called_once_with("haproxy.service.configtest")
        assert "result" in result
