"""Tests for network tools."""

from __future__ import annotations

from unittest.mock import AsyncMock

from opnsense_mcp.tools.network import (
    opn_arp_table,
    opn_interface_stats,
    opn_ipv6_status,
    opn_list_static_routes,
    opn_ndp_table,
)


class TestOpnInterfaceStats:
    """Tests for opn_interface_stats."""

    async def test_calls_interface_statistics(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"statistics": {}})
        result = await opn_interface_stats(mock_ctx)
        mock_api.get.assert_called_once_with("interface.statistics")
        assert result == {"statistics": {}}


class TestOpnArpTable:
    """Tests for opn_arp_table."""

    async def test_calls_interface_arp(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"arp": []})
        result = await opn_arp_table(mock_ctx)
        mock_api.get.assert_called_once_with("interface.arp")
        assert result == {"arp": []}


class TestOpnNdpTable:
    """Tests for opn_ndp_table."""

    async def test_calls_interface_ndp(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(
            return_value=[
                {"ip": "fe80::1", "mac": "aa:bb:cc:dd:ee:ff", "intf": "em0"},
            ]
        )
        result = await opn_ndp_table(mock_ctx)
        mock_api.get.assert_called_once_with("interface.ndp")
        assert isinstance(result, list)
        assert result[0]["ip"] == "fe80::1"

    async def test_returns_empty_ndp_table(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value=[])
        result = await opn_ndp_table(mock_ctx)
        mock_api.get.assert_called_once_with("interface.ndp")
        assert result == []


class TestOpnIpv6Status:
    """Tests for opn_ipv6_status."""

    def _setup_cache(self, mock_ctx, interfaces_data):
        """Set up ConfigCache with pre-loaded interface data."""
        cache = mock_ctx.lifespan_context["config_cache"]
        # Simulate a loaded cache with interface sections
        cache._loaded_at = 1.0
        cache._stale = False
        cache._sections = {"interfaces": interfaces_data}
        cache._section_sizes = {"interfaces": 100}
        return cache

    async def test_returns_interface_ipv6_info(self, mock_api, mock_ctx):
        self._setup_cache(
            mock_ctx,
            {
                "lan": {
                    "descr": "LAN",
                    "ipaddr": "192.168.1.1",
                    "ipaddrv6": "track6",
                    "track6-interface": "wan",
                    "track6-prefix-id": "0",
                },
                "wan": {
                    "descr": "WAN",
                    "ipaddr": "dhcp",
                    "ipaddrv6": "dhcp6",
                },
            },
        )
        mock_api.get = AsyncMock(return_value={})
        result = await opn_ipv6_status(mock_ctx)
        assert result["summary"]["ipv6_configured"] == 2
        assert result["interfaces"][0]["ipv6_method"] == "track6"
        assert result["interfaces"][0]["track6_interface"] == "wan"
        assert result["interfaces"][1]["ipv6_method"] == "dhcpv6-pd"

    async def test_returns_no_ipv6_configured(self, mock_api, mock_ctx):
        self._setup_cache(
            mock_ctx,
            {
                "lan": {
                    "descr": "LAN",
                    "ipaddr": "192.168.1.1",
                    "ipaddrv6": "",
                },
            },
        )
        mock_api.get = AsyncMock(return_value={})
        result = await opn_ipv6_status(mock_ctx)
        assert result["summary"]["ipv6_configured"] == 0
        assert result["summary"]["ipv4_only"] == 1
        assert result["interfaces"][0]["ipv6_configured"] is False

    async def test_static_ipv6_address(self, mock_api, mock_ctx):
        self._setup_cache(
            mock_ctx,
            {
                "dmz": {
                    "descr": "DMZ",
                    "ipaddr": "10.0.0.1",
                    "ipaddrv6": "2001:db8::1",
                    "subnetv6": "64",
                },
            },
        )
        mock_api.get = AsyncMock(return_value={})
        result = await opn_ipv6_status(mock_ctx)
        assert result["interfaces"][0]["ipv6_method"] == "static"
        assert result["interfaces"][0]["ipv6_address"] == "2001:db8::1/64"

    async def test_error_on_missing_config(self, mock_api, mock_ctx):
        cache = mock_ctx.lifespan_context["config_cache"]
        cache._loaded_at = 1.0
        cache._stale = False
        cache._sections = {}
        result = await opn_ipv6_status(mock_ctx)
        assert "error" in result


class TestOpnListStaticRoutes:
    """Tests for opn_list_static_routes."""

    async def test_calls_routes_search(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_list_static_routes(mock_ctx)
        mock_api.post.assert_called_once_with(
            "routes.search",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_phrase(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_static_routes(mock_ctx, search="10.0.0")
        mock_api.post.assert_called_once_with(
            "routes.search",
            {"current": 1, "rowCount": 50, "searchPhrase": "10.0.0"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_static_routes(mock_ctx, limit=999)
        mock_api.post.assert_called_once_with(
            "routes.search",
            {"current": 1, "rowCount": 500, "searchPhrase": ""},
        )

    async def test_returns_route_rows(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(
            return_value={
                "rows": [{"network": "10.0.0.0/24", "gateway": "192.168.1.1"}],
                "rowCount": 1,
            }
        )
        result = await opn_list_static_routes(mock_ctx)
        assert len(result["rows"]) == 1
