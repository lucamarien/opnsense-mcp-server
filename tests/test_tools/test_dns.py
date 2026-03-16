"""Tests for DNS tools."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.api_client import WriteDisabledError
from opnsense_mcp.tools.dns import (
    opn_add_dns_override,
    opn_dns_stats,
    opn_list_dns_forwards,
    opn_list_dns_overrides,
    opn_reconfigure_unbound,
)


class TestOpnListDnsOverrides:
    """Tests for opn_list_dns_overrides."""

    async def test_calls_search_override(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_list_dns_overrides(mock_ctx)
        mock_api.post.assert_called_once_with(
            "unbound.search_override",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_phrase(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_dns_overrides(mock_ctx, search="myhost")
        mock_api.post.assert_called_once_with(
            "unbound.search_override",
            {"current": 1, "rowCount": 50, "searchPhrase": "myhost"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_dns_overrides(mock_ctx, limit=999)
        mock_api.post.assert_called_once_with(
            "unbound.search_override",
            {"current": 1, "rowCount": 500, "searchPhrase": ""},
        )


class TestOpnListDnsForwards:
    """Tests for opn_list_dns_forwards."""

    async def test_calls_search_forward(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_list_dns_forwards(mock_ctx)
        mock_api.post.assert_called_once_with(
            "unbound.search_forward",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_and_limit(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_dns_forwards(mock_ctx, search="cloudflare", limit=10)
        mock_api.post.assert_called_once_with(
            "unbound.search_forward",
            {"current": 1, "rowCount": 10, "searchPhrase": "cloudflare"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_dns_forwards(mock_ctx, limit=501)
        mock_api.post.assert_called_once_with(
            "unbound.search_forward",
            {"current": 1, "rowCount": 500, "searchPhrase": ""},
        )


class TestOpnDnsStats:
    """Tests for opn_dns_stats."""

    async def test_calls_unbound_stats(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"stats": {}})
        result = await opn_dns_stats(mock_ctx)
        mock_api.get.assert_called_once_with("unbound.stats")
        assert result == {"stats": {}}


class TestOpnReconfigureUnbound:
    """Tests for opn_reconfigure_unbound."""

    async def test_calls_reconfigure_endpoint(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        result = await opn_reconfigure_unbound(mock_ctx_writes)
        mock_api_writes.post.assert_called_once_with("unbound.service.reconfigure")
        assert result["status"] == "ok"
        assert result["service"] == "unbound"

    async def test_requires_writes_enabled(self, mock_api, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_reconfigure_unbound(mock_ctx)

    async def test_returns_unknown_on_missing_status(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={})
        result = await opn_reconfigure_unbound(mock_ctx_writes)
        assert result["status"] == "unknown"


class TestOpnAddDnsOverride:
    """Tests for opn_add_dns_override."""

    async def test_creates_override_and_reconfigures(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved", "uuid": "dns-uuid-1"},
                {"status": "ok"},
            ]
        )
        result = await opn_add_dns_override(
            mock_ctx_writes,
            hostname="myserver",
            domain="local.lan",
            server="192.168.1.50",
        )
        assert mock_api_writes.post.call_count == 2
        assert result["uuid"] == "dns-uuid-1"
        assert result["hostname"] == "myserver.local.lan"
        assert result["applied"] == "ok"

    async def test_passes_correct_payload(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved", "uuid": "dns-uuid-2"},
                {"status": "ok"},
            ]
        )
        await opn_add_dns_override(
            mock_ctx_writes,
            hostname="web",
            domain="example.com",
            server="10.0.0.1",
            description="Web server",
        )
        call_args = mock_api_writes.post.call_args_list[0]
        assert call_args[0][0] == "unbound.add_host_override"
        host = call_args[0][1]["host"]
        assert host["hostname"] == "web"
        assert host["domain"] == "example.com"
        assert host["server"] == "10.0.0.1"
        assert host["description"] == "Web server"
        assert host["enabled"] == "1"

    async def test_requires_writes_enabled(self, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_add_dns_override(
                mock_ctx,
                hostname="test",
                domain="local.lan",
                server="192.168.1.1",
            )

    async def test_validates_hostname(self, mock_ctx_writes):
        result = await opn_add_dns_override(
            mock_ctx_writes,
            hostname="invalid host!",
            domain="local.lan",
            server="192.168.1.1",
        )
        assert "error" in result

    async def test_validates_domain(self, mock_ctx_writes):
        result = await opn_add_dns_override(
            mock_ctx_writes,
            hostname="test",
            domain="",
            server="192.168.1.1",
        )
        assert "error" in result

    async def test_validates_server_ip(self, mock_ctx_writes):
        result = await opn_add_dns_override(
            mock_ctx_writes,
            hostname="test",
            domain="local.lan",
            server="not-an-ip",
        )
        assert "error" in result

    async def test_accepts_ipv6_server(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved", "uuid": "dns-v6"},
                {"status": "ok"},
            ]
        )
        result = await opn_add_dns_override(
            mock_ctx_writes,
            hostname="v6host",
            domain="local.lan",
            server="fd00::1",
        )
        assert result["server"] == "fd00::1"

    async def test_invalidates_cache(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved", "uuid": "dns-cache"},
                {"status": "ok"},
            ]
        )
        await opn_add_dns_override(
            mock_ctx_writes,
            hostname="test",
            domain="local.lan",
            server="192.168.1.1",
        )
        cache = mock_ctx_writes.lifespan_context["config_cache"]
        assert cache.is_stale
