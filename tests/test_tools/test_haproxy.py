"""Tests for HAProxy tools (v0.5: enforced configtest, import-time endpoints)."""

from __future__ import annotations

from unittest.mock import AsyncMock

from opnsense_mcp.api_client import ENDPOINT_REGISTRY, OPNsenseAPIError
from opnsense_mcp.tools.haproxy import (
    _HAPROXY_RESOURCES,
    opn_haproxy_add,
    opn_haproxy_configtest,
    opn_haproxy_delete,
    opn_haproxy_get,
    opn_haproxy_search,
    opn_haproxy_status,
    opn_haproxy_update,
    opn_reconfigure_haproxy,
)


class TestEndpointRegistration:
    def test_all_crud_endpoints_registered_at_import(self):
        for singular in _HAPROXY_RESOURCES.values():
            for verb in ("get", "add", "set", "del"):
                logical = f"haproxy.settings.{verb}_{singular}"
                assert logical in ENDPOINT_REGISTRY, f"missing {logical}"
                camel, snake = ENDPOINT_REGISTRY[logical]
                assert camel == f"haproxy/settings/{verb}{singular.capitalize()}"
                assert snake == f"haproxy/settings/{verb}_{singular}"


class TestHaproxyStatus:
    async def test_calls_status(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"status": "running"})
        result = await opn_haproxy_status(mock_ctx)
        mock_api.get.assert_called_once_with("haproxy.service.status")
        assert result == {"status": "running"}

    async def test_plugin_missing_envelope(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(side_effect=OPNsenseAPIError("no haproxy", status_code=400))
        result = await opn_haproxy_status(mock_ctx)
        assert result["error_type"] == "api"
        assert "plugin" in result["hint"]


class TestHaproxySearch:
    async def test_search_frontends(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": []})
        await opn_haproxy_search(mock_ctx, resource_type="frontends", search="web", limit=10)
        mock_api.post.assert_called_once_with(
            "haproxy.settings.search_frontends",
            {"current": 1, "rowCount": 10, "searchPhrase": "web"},
        )

    async def test_search_all_types(self, mock_api, mock_ctx):
        for rt in _HAPROXY_RESOURCES:
            mock_api.post = AsyncMock(return_value={"rows": []})
            await opn_haproxy_search(mock_ctx, resource_type=rt)
            assert mock_api.post.call_args[0][0] == f"haproxy.settings.search_{rt}"


class TestHaproxyGet:
    async def test_get_backend(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"backend": {"name": "pool1"}})
        result = await opn_haproxy_get(mock_ctx, resource_type="backends", uuid="be-1")
        mock_api.get.assert_called_once_with("haproxy.settings.get_backend", path_suffix="be-1")
        assert result["backend"]["name"] == "pool1"


class TestHaproxyAdd:
    async def test_add_requires_config(self, mock_api_writes, mock_ctx_writes):
        result = await opn_haproxy_add(mock_ctx_writes, resource_type="servers", config={})
        assert result["error_type"] == "validation"

    async def test_add_server(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "srv-1"})
        config = {"name": "srv1", "address": "10.0.0.5", "port": "8080"}
        result = await opn_haproxy_add(mock_ctx_writes, resource_type="servers", config=config)
        mock_api_writes.post.assert_called_once_with("haproxy.settings.add_server", {"server": config})
        assert result["uuid"] == "srv-1"

    async def test_writes_disabled(self, mock_ctx_no_writes):
        result = await opn_haproxy_add(mock_ctx_no_writes, resource_type="servers", config={"name": "x"})
        assert result["error_type"] == "writes_disabled"


class TestHaproxyUpdate:
    async def test_update_sends_partial_config(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        await opn_haproxy_update(mock_ctx_writes, resource_type="backends", uuid="be-1", config={"enabled": "0"})
        mock_api_writes.post.assert_called_once_with(
            "haproxy.settings.set_backend",
            {"backend": {"enabled": "0"}},
            path_suffix="be-1",
        )

    async def test_update_requires_config(self, mock_ctx_writes):
        result = await opn_haproxy_update(mock_ctx_writes, resource_type="backends", uuid="be-1", config={})
        assert result["error_type"] == "validation"


class TestHaproxyDelete:
    async def test_delete(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "deleted"})
        result = await opn_haproxy_delete(mock_ctx_writes, resource_type="acls", uuid="acl-1")
        mock_api_writes.post.assert_called_once_with("haproxy.settings.del_acl", path_suffix="acl-1")
        assert result["result"] == "deleted"


class TestHaproxyConfigtest:
    async def test_calls_configtest(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"result": "Configuration file is valid"})
        result = await opn_haproxy_configtest(mock_ctx)
        mock_api.get.assert_called_once_with("haproxy.service.configtest")
        assert "valid" in result["result"]


class TestReconfigureHaproxy:
    async def test_validates_before_reconfiguring(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value={"result": "Configuration file is valid"})
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        result = await opn_reconfigure_haproxy(mock_ctx_writes)
        mock_api_writes.get.assert_called_once_with("haproxy.service.configtest")
        mock_api_writes.post.assert_called_once_with("haproxy.service.reconfigure")
        assert result["status"] == "ok"
        assert "configtest" in result

    async def test_refuses_on_failed_configtest(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value={"result": "[ALERT] parsing error in section 'frontend web'"})
        mock_api_writes.post = AsyncMock()
        result = await opn_reconfigure_haproxy(mock_ctx_writes)
        assert result["error_type"] == "configtest"
        mock_api_writes.post.assert_not_called()  # reconfigure never reached

    async def test_refuses_on_fatal_marker(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value={"result": "fatal errors found in configuration"})
        mock_api_writes.post = AsyncMock()
        result = await opn_reconfigure_haproxy(mock_ctx_writes)
        assert result["error_type"] == "configtest"

    async def test_writes_disabled(self, mock_ctx_no_writes):
        result = await opn_reconfigure_haproxy(mock_ctx_no_writes)
        assert result["error_type"] == "writes_disabled"
