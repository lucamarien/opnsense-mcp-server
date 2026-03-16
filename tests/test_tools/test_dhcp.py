"""Tests for DHCP tools."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.api_client import WriteDisabledError
from opnsense_mcp.tools.dhcp import (
    opn_add_dnsmasq_range,
    opn_list_dhcp_leases,
    opn_list_dnsmasq_leases,
    opn_list_dnsmasq_ranges,
    opn_list_kea_leases,
    opn_reconfigure_dnsmasq,
)


class TestOpnListDhcpLeases:
    """Tests for opn_list_dhcp_leases (ISC DHCP)."""

    async def test_calls_dhcpv4_leases_search(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"leases": []})
        result = await opn_list_dhcp_leases(mock_ctx)
        mock_api.get.assert_called_once_with("dhcpv4.leases.search")
        assert result == {"leases": []}


class TestOpnListKeaLeases:
    """Tests for opn_list_kea_leases."""

    async def test_calls_kea_leases_search(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_list_kea_leases(mock_ctx)
        mock_api.post.assert_called_once_with(
            "kea.leases4.search",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_and_limit(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_kea_leases(mock_ctx, search="192.168", limit=20)
        mock_api.post.assert_called_once_with(
            "kea.leases4.search",
            {"current": 1, "rowCount": 20, "searchPhrase": "192.168"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_kea_leases(mock_ctx, limit=999)
        call_args = mock_api.post.call_args[0][1]
        assert call_args["rowCount"] == 500


class TestOpnListDnsmasqLeases:
    """Tests for opn_list_dnsmasq_leases."""

    async def test_calls_dnsmasq_leases_search(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_list_dnsmasq_leases(mock_ctx)
        mock_api.post.assert_called_once_with(
            "dnsmasq.leases.search",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_and_limit(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_dnsmasq_leases(mock_ctx, search="server", limit=100)
        mock_api.post.assert_called_once_with(
            "dnsmasq.leases.search",
            {"current": 1, "rowCount": 100, "searchPhrase": "server"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_dnsmasq_leases(mock_ctx, limit=800)
        call_args = mock_api.post.call_args[0][1]
        assert call_args["rowCount"] == 500


class TestOpnListDnsmasqRanges:
    """Tests for opn_list_dnsmasq_ranges."""

    async def test_calls_search_range(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_list_dnsmasq_ranges(mock_ctx)
        mock_api.post.assert_called_once_with(
            "dnsmasq.settings.search_range",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_and_limit(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_dnsmasq_ranges(mock_ctx, search="lan", limit=20)
        mock_api.post.assert_called_once_with(
            "dnsmasq.settings.search_range",
            {"current": 1, "rowCount": 20, "searchPhrase": "lan"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_dnsmasq_ranges(mock_ctx, limit=999)
        call_args = mock_api.post.call_args[0][1]
        assert call_args["rowCount"] == 500


class TestOpnAddDnsmasqRange:
    """Tests for opn_add_dnsmasq_range."""

    async def test_creates_ipv4_range_and_reconfigures(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved", "uuid": "range-uuid-v4"},
                {"status": "ok"},
            ]
        )
        result = await opn_add_dnsmasq_range(
            mock_ctx_writes,
            interface="lan",
            start_addr="192.168.1.100",
            end_addr="192.168.1.200",
        )
        # First call: add range
        add_call = mock_api_writes.post.call_args_list[0]
        assert add_call[0][0] == "dnsmasq.settings.add_range"
        range_cfg = add_call[0][1]["range"]
        assert range_cfg["interface"] == "lan"
        assert range_cfg["start_addr"] == "192.168.1.100"
        assert range_cfg["end_addr"] == "192.168.1.200"
        assert range_cfg["enabled"] == "1"
        assert "prefix_len" not in range_cfg
        assert "ra_mode" not in range_cfg
        # Second call: reconfigure
        reconf_call = mock_api_writes.post.call_args_list[1]
        assert reconf_call[0][0] == "dnsmasq.service.reconfigure"
        # Result
        assert result["uuid"] == "range-uuid-v4"
        assert result["reconfigure_status"] == "ok"

    async def test_creates_ipv6_range_with_ra(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved", "uuid": "range-uuid-v6"},
                {"status": "ok"},
            ]
        )
        result = await opn_add_dnsmasq_range(
            mock_ctx_writes,
            interface="lan",
            start_addr="::100",
            end_addr="::200",
            prefix_len="64",
            ra_mode="ra-stateless",
        )
        add_call = mock_api_writes.post.call_args_list[0]
        range_cfg = add_call[0][1]["range"]
        assert range_cfg["prefix_len"] == "64"
        assert range_cfg["ra_mode"] == "ra-stateless"
        assert result["uuid"] == "range-uuid-v6"

    async def test_includes_description_and_lease_time(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved", "uuid": "range-uuid"},
                {"status": "ok"},
            ]
        )
        await opn_add_dnsmasq_range(
            mock_ctx_writes,
            interface="lan",
            start_addr="192.168.1.100",
            end_addr="192.168.1.200",
            lease_time="1h",
            description="Short-lease pool",
        )
        add_call = mock_api_writes.post.call_args_list[0]
        range_cfg = add_call[0][1]["range"]
        assert range_cfg["lease_time"] == "1h"
        assert range_cfg["description"] == "Short-lease pool"

    async def test_requires_writes_enabled(self, mock_api, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_add_dnsmasq_range(
                mock_ctx,
                interface="lan",
                start_addr="192.168.1.100",
                end_addr="192.168.1.200",
            )

    async def test_rejects_empty_interface(self, mock_api_writes, mock_ctx_writes):
        result = await opn_add_dnsmasq_range(
            mock_ctx_writes,
            interface="",
            start_addr="192.168.1.100",
            end_addr="192.168.1.200",
        )
        assert "error" in result
        assert "interface" in result["error"]

    async def test_rejects_empty_start_addr(self, mock_api_writes, mock_ctx_writes):
        result = await opn_add_dnsmasq_range(
            mock_ctx_writes,
            interface="lan",
            start_addr="",
            end_addr="192.168.1.200",
        )
        assert "error" in result
        assert "start_addr" in result["error"]

    async def test_rejects_empty_end_addr(self, mock_api_writes, mock_ctx_writes):
        result = await opn_add_dnsmasq_range(
            mock_ctx_writes,
            interface="lan",
            start_addr="192.168.1.100",
            end_addr="",
        )
        assert "error" in result
        assert "end_addr" in result["error"]


class TestOpnReconfigureDnsmasq:
    """Tests for opn_reconfigure_dnsmasq."""

    async def test_calls_reconfigure_endpoint(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        result = await opn_reconfigure_dnsmasq(mock_ctx_writes)
        mock_api_writes.post.assert_called_once_with("dnsmasq.service.reconfigure")
        assert result["status"] == "ok"
        assert result["service"] == "dnsmasq"

    async def test_requires_writes_enabled(self, mock_api, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_reconfigure_dnsmasq(mock_ctx)

    async def test_returns_unknown_on_missing_status(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={})
        result = await opn_reconfigure_dnsmasq(mock_ctx_writes)
        assert result["status"] == "unknown"
