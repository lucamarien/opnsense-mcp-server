"""Tests for VPN tools."""

from __future__ import annotations

from unittest.mock import AsyncMock

from opnsense_mcp.tools.vpn import opn_ipsec_status, opn_openvpn_status, opn_wireguard_status

_SEARCH_PARAMS = {"current": 1, "rowCount": 500, "searchPhrase": ""}


class TestOpnWireguardStatus:
    """Tests for opn_wireguard_status."""

    async def test_calls_wireguard_show(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"tunnels": []})
        result = await opn_wireguard_status(mock_ctx)
        mock_api.get.assert_called_once_with("wireguard.service.show")
        assert result == {"tunnels": []}


class TestOpnIpsecStatus:
    """Tests for opn_ipsec_status."""

    async def test_calls_all_three_endpoints(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"status": "running"})
        mock_api.post = AsyncMock(
            side_effect=[
                {"rows": [{"id": "ph1-1"}]},
                {"rows": [{"id": "ph2-1"}]},
            ]
        )
        result = await opn_ipsec_status(mock_ctx)
        mock_api.get.assert_called_once_with("ipsec.service.status")
        assert mock_api.post.call_count == 2
        mock_api.post.assert_any_call("ipsec.sessions.phase1", _SEARCH_PARAMS)
        mock_api.post.assert_any_call("ipsec.sessions.phase2", _SEARCH_PARAMS)
        assert result["service_status"] == "running"

    async def test_returns_structured_result(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"status": "running"})
        mock_api.post = AsyncMock(
            side_effect=[
                {"rows": [{"id": "ph1-1"}]},
                {"rows": [{"id": "ph2-1"}, {"id": "ph2-2"}]},
            ]
        )
        result = await opn_ipsec_status(mock_ctx)
        assert len(result["phase1"]) == 1
        assert len(result["phase2"]) == 2

    async def test_handles_empty_responses(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={})
        mock_api.post = AsyncMock(side_effect=[{}, {}])
        result = await opn_ipsec_status(mock_ctx)
        assert result["service_status"] == "unknown"
        assert result["phase1"] == []
        assert result["phase2"] == []


class TestOpnOpenvpnStatus:
    """Tests for opn_openvpn_status."""

    async def test_calls_all_three_endpoints(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(
            side_effect=[
                {"rows": [{"name": "server1"}]},
                {"rows": [{"common_name": "client1"}]},
                {"rows": [{"network": "10.0.0.0/24"}]},
            ]
        )
        await opn_openvpn_status(mock_ctx)
        assert mock_api.post.call_count == 3
        mock_api.post.assert_any_call("openvpn.instances", _SEARCH_PARAMS)
        mock_api.post.assert_any_call("openvpn.sessions", _SEARCH_PARAMS)
        mock_api.post.assert_any_call("openvpn.routes", _SEARCH_PARAMS)

    async def test_returns_structured_result(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(
            side_effect=[
                {"rows": [{"name": "server1"}]},
                {"rows": [{"common_name": "client1"}, {"common_name": "client2"}]},
                {"rows": [{"network": "10.0.0.0/24"}]},
            ]
        )
        result = await opn_openvpn_status(mock_ctx)
        assert len(result["instances"]) == 1
        assert len(result["sessions"]) == 2
        assert len(result["routes"]) == 1

    async def test_handles_empty_responses(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(side_effect=[{}, {}, {}])
        result = await opn_openvpn_status(mock_ctx)
        assert result["instances"] == []
        assert result["sessions"] == []
        assert result["routes"] == []
