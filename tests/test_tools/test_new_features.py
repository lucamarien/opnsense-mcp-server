"""Tests for v0.5 feature tools: find_host, system_health, traffic_top."""

from __future__ import annotations

from unittest.mock import AsyncMock

from opnsense_mcp.api_client import OPNsenseAPIError
from opnsense_mcp.tools.network import opn_find_host, opn_traffic_top
from opnsense_mcp.tools.system import opn_system_health


def _inventory_cache(cache, backend: str = "dnsmasq") -> None:
    cache._loaded_at = 1.0
    cache._stale = False
    cache._inventory = {"dhcp": {"active": backend}}


class TestFindHost:
    async def test_query_too_short(self, mock_ctx):
        result = await opn_find_host(mock_ctx, query="x")
        assert result["error_type"] == "validation"

    async def test_finds_across_sources(self, mock_api, mock_ctx, mock_config_cache):
        _inventory_cache(mock_config_cache)
        mock_api.get = AsyncMock(
            side_effect=[
                # ARP
                {"rows": [{"ip": "192.168.1.77", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "laptop", "intf": "igb1"}]},
                # NDP
                {"rows": [{"ip": "fe80::1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "intf": "igb1"}]},
            ]
        )
        mock_api.post = AsyncMock(
            side_effect=[
                # dnsmasq leases
                {"rows": [{"address": "192.168.1.77", "hwaddr": "aa:bb:cc:dd:ee:ff", "hostname": "laptop"}]},
                # DNS overrides
                {"rows": [{"hostname": "laptop", "domain": "local.lan", "server": "192.168.1.77"}]},
            ]
        )
        result = await opn_find_host(mock_ctx, query="aa:bb:cc:dd:ee:ff")
        sources = {m["source"] for m in result["matches"]}
        assert "arp" in sources
        assert "ndp" in sources
        assert "dhcp_lease(dnsmasq)" in sources
        # MAC didn't match DNS override (matched by name/ip only)
        assert result["total"] == 3
        assert result["sources_failed"] == []

    async def test_matches_dns_override_by_hostname(self, mock_api, mock_ctx, mock_config_cache):
        _inventory_cache(mock_config_cache)
        mock_api.get = AsyncMock(side_effect=[{"rows": []}, {"rows": []}])
        mock_api.post = AsyncMock(
            side_effect=[
                {"rows": []},  # leases
                {"rows": [{"hostname": "nas", "domain": "local.lan", "server": "10.0.0.9"}]},
            ]
        )
        result = await opn_find_host(mock_ctx, query="nas")
        assert result["total"] == 1
        assert result["matches"][0]["source"] == "dns_override"
        assert result["matches"][0]["hostname"] == "nas.local.lan"

    async def test_failed_sources_reported(self, mock_api, mock_ctx, mock_config_cache):
        _inventory_cache(mock_config_cache)
        mock_api.get = AsyncMock(side_effect=OPNsenseAPIError("down"))
        mock_api.post = AsyncMock(side_effect=OPNsenseAPIError("down"))
        result = await opn_find_host(mock_ctx, query="laptop")
        assert result["total"] == 0
        assert set(result["sources_failed"]) == {"arp", "ndp", "dhcp_leases", "dns_overrides"}

    async def test_no_backend_skips_leases(self, mock_api, mock_ctx, mock_config_cache):
        _inventory_cache(mock_config_cache, backend="none")
        mock_api.get = AsyncMock(side_effect=[{"rows": []}, {"rows": []}])
        mock_api.post = AsyncMock(return_value={"rows": []})
        await opn_find_host(mock_ctx, query="laptop")
        # only the DNS override search posts
        assert mock_api.post.call_count == 1


class TestSystemHealth:
    async def test_collects_all_sections(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(
            side_effect=[
                {"memory": {"total": "8192M", "used": "2048M"}},
                {"devices": [{"device": "/dev/ada0", "used_pct": "42%"}]},
                {"uptime": "12 days", "loadavg": "0.5, 0.4, 0.3"},
                [{"device": "cpu0", "temperature": "45"}],
            ]
        )
        result = await opn_system_health(mock_ctx)
        endpoints = [c[0][0] for c in mock_api.get.call_args_list]
        assert endpoints == [
            "diagnostics.system.resources",
            "diagnostics.system.disk",
            "diagnostics.system.time",
            "diagnostics.system.temperature",
        ]
        assert result["memory"]["memory"]["total"] == "8192M"
        assert result["sections_unavailable"] == []

    async def test_partial_failure_degrades(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(
            side_effect=[
                {"memory": {}},
                OPNsenseAPIError("disk probe failed"),
                {"uptime": "1 day"},
                OPNsenseAPIError("no sensors"),
            ]
        )
        result = await opn_system_health(mock_ctx)
        assert result["sections_unavailable"] == ["disk", "temperature"]
        assert "unavailable" in result["disk"]
        assert result["system"]["uptime"] == "1 day"


class TestTrafficTop:
    async def test_calls_top_with_interfaces(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"lan": [{"address": "192.168.1.5", "rate": "10Mb"}]})
        result = await opn_traffic_top(mock_ctx, interfaces="lan,wan")
        mock_api.get.assert_called_once_with("diagnostics.traffic.top", path_suffix="lan,wan")
        assert "lan" in result

    async def test_empty_interfaces_rejected(self, mock_ctx):
        result = await opn_traffic_top(mock_ctx, interfaces="  ")
        assert result["error_type"] == "validation"
