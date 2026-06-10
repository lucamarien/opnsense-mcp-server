"""Tests for DHCP tools (backend-aware leases + manage range, v0.5)."""

from __future__ import annotations

from unittest.mock import AsyncMock

from opnsense_mcp.tools.dhcp import (
    opn_list_dhcp_leases,
    opn_list_dnsmasq_ranges,
    opn_manage_dnsmasq_range,
    opn_reconfigure_dnsmasq,
)


class TestListDhcpLeasesExplicitBackend:
    async def test_dnsmasq_backend(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [{"hostname": "pc"}], "rowCount": 1})
        result = await opn_list_dhcp_leases(mock_ctx, backend="dnsmasq", search="pc", limit=10)
        mock_api.post.assert_called_once_with(
            "dnsmasq.leases.search",
            {"current": 1, "rowCount": 10, "searchPhrase": "pc"},
        )
        assert result["backend"] == "dnsmasq"
        assert result["rowCount"] == 1

    async def test_kea_backend(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": []})
        result = await opn_list_dhcp_leases(mock_ctx, backend="kea")
        mock_api.post.assert_called_once_with(
            "kea.leases4.search",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result["backend"] == "kea"

    async def test_isc_backend_uses_get(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"rows": [{"address": "10.0.0.5"}]})
        result = await opn_list_dhcp_leases(mock_ctx, backend="isc")
        mock_api.get.assert_called_once_with("dhcpv4.leases.search")
        assert result["backend"] == "isc"
        assert result["rows"] == [{"address": "10.0.0.5"}]


class TestListDhcpLeasesAutoDetection:
    async def test_auto_uses_cached_inventory(self, mock_api, mock_ctx, mock_config_cache):
        mock_config_cache._loaded_at = 1.0
        mock_config_cache._stale = False
        mock_config_cache._inventory = {"dhcp": {"active": "kea"}}
        mock_api.post = AsyncMock(return_value={"rows": []})
        result = await opn_list_dhcp_leases(mock_ctx)
        assert result["backend"] == "kea"
        assert mock_api.post.call_args[0][0] == "kea.leases4.search"

    async def test_auto_detects_when_cache_unloaded(self, mock_api, mock_ctx):
        # dnsmasq running -> chosen; detection calls get() for statuses/leases
        mock_api.get = AsyncMock(
            side_effect=[
                {"status": "running"},  # dnsmasq.service.status
                {"rows": []},  # dnsmasq.leases.search (count)
                {"status": "disabled"},  # kea.service.status
                {"rows": []},  # dhcpv4.leases.search (isc probe)
            ]
        )
        mock_api.post = AsyncMock(return_value={"rows": [{"hostname": "x"}]})
        result = await opn_list_dhcp_leases(mock_ctx)
        assert result["backend"] == "dnsmasq"
        mock_api.post.assert_called_once()

    async def test_auto_no_backend_returns_error(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(
            side_effect=[
                {"status": "stopped"},  # dnsmasq not running
                {"status": "disabled"},  # kea disabled
                {},  # isc probe -> dict but no running backend
            ]
        )
        result = await opn_list_dhcp_leases(mock_ctx)
        assert result["error_type"] == "not_found"
        assert "dnsmasq" in result["error"]


class TestListDnsmasqRanges:
    async def test_calls_search_range(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": []})
        await opn_list_dnsmasq_ranges(mock_ctx, search="lan", limit=20)
        mock_api.post.assert_called_once_with(
            "dnsmasq.settings.search_range",
            {"current": 1, "rowCount": 20, "searchPhrase": "lan"},
        )


class TestManageDnsmasqRange:
    async def test_add_requires_fields(self, mock_api_writes, mock_ctx_writes):
        result = await opn_manage_dnsmasq_range(mock_ctx_writes, action="add", interface="lan")
        assert result["error_type"] == "validation"
        assert "start_addr" in result["error"]

    async def test_add_creates_and_reconfigures(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved", "uuid": "range-1"},
                {"status": "ok"},
            ]
        )
        result = await opn_manage_dnsmasq_range(
            mock_ctx_writes,
            action="add",
            interface="lan",
            start_addr="192.168.1.100",
            end_addr="192.168.1.200",
        )
        endpoints = [c[0][0] for c in mock_api_writes.post.call_args_list]
        assert endpoints == ["dnsmasq.settings.add_range", "dnsmasq.service.reconfigure"]
        config = mock_api_writes.post.call_args_list[0][0][1]["range"]
        assert config["lease_time"] == "24h"  # default
        assert config["enabled"] == "1"
        assert result["uuid"] == "range-1"
        assert result["reconfigure_status"] == "ok"

    async def test_add_ipv6_range(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(side_effect=[{"uuid": "r6"}, {"status": "ok"}])
        await opn_manage_dnsmasq_range(
            mock_ctx_writes,
            action="add",
            interface="lan",
            start_addr="::100",
            end_addr="::200",
            prefix_len="64",
            ra_mode="slaac",
        )
        config = mock_api_writes.post.call_args_list[0][0][1]["range"]
        assert config["prefix_len"] == "64"
        assert config["ra_mode"] == "slaac"

    async def test_update_requires_uuid(self, mock_ctx_writes):
        result = await opn_manage_dnsmasq_range(mock_ctx_writes, action="update", lease_time="1h")
        assert result["error_type"] == "validation"

    async def test_update_sends_only_provided(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "ok"}])
        await opn_manage_dnsmasq_range(mock_ctx_writes, action="update", uuid="range-1", lease_time="12h")
        call = mock_api_writes.post.call_args_list[0]
        assert call[0][0] == "dnsmasq.settings.set_range"
        assert call[0][1] == {"range": {"lease_time": "12h"}}
        assert call[1]["path_suffix"] == "range-1"

    async def test_delete_reconfigures(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "deleted"}, {"status": "ok"}])
        result = await opn_manage_dnsmasq_range(mock_ctx_writes, action="delete", uuid="range-1")
        endpoints = [c[0][0] for c in mock_api_writes.post.call_args_list]
        assert endpoints == ["dnsmasq.settings.del_range", "dnsmasq.service.reconfigure"]
        assert result["uuid"] == "range-1"

    async def test_writes_disabled(self, mock_ctx_no_writes):
        result = await opn_manage_dnsmasq_range(
            mock_ctx_no_writes, action="add", interface="lan", start_addr="a", end_addr="b"
        )
        assert result["error_type"] == "writes_disabled"


class TestReconfigureDnsmasq:
    async def test_reconfigures(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        result = await opn_reconfigure_dnsmasq(mock_ctx_writes)
        mock_api_writes.post.assert_called_once_with("dnsmasq.service.reconfigure")
        assert result == {"status": "ok", "service": "dnsmasq"}

    async def test_writes_disabled(self, mock_ctx_no_writes):
        result = await opn_reconfigure_dnsmasq(mock_ctx_no_writes)
        assert result["error_type"] == "writes_disabled"
