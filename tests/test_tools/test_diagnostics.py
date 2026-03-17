"""Tests for diagnostics tools."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from opnsense_mcp.tools.diagnostics import (
    opn_dns_lookup,
    opn_pf_states,
    opn_ping,
    opn_traceroute,
)


class TestOpnPing:
    """Tests for opn_ping."""

    async def test_successful_ping(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(
            side_effect=[
                # set → returns uuid
                {"result": "ok", "uuid": "ping-job-1"},
                # start
                {"status": "ok"},
                # remove (cleanup)
                {"status": "ok"},
            ],
        )
        mock_api.get = AsyncMock(
            return_value={
                "rows": [
                    {
                        "uuid": "ping-job-1",
                        "status": "done",
                        "loss": "0%",
                        "min": "1.2",
                        "avg": "2.5",
                        "max": "5.1",
                    },
                ],
                "rowCount": 1,
            },
        )

        with patch("opnsense_mcp.tools.diagnostics.asyncio.sleep", new_callable=AsyncMock):
            result = await opn_ping(mock_ctx, host="8.8.8.8")

        assert result["host"] == "8.8.8.8"
        assert result["count"] == 3
        assert result["loss"] == "0%"
        assert result["status"] == "done"

        # Verify set was called with correct config
        set_call = mock_api.post.call_args_list[0]
        assert set_call[0][0] == "diagnostics.ping.set"
        assert set_call[0][1]["ping"]["settings"]["hostname"] == "8.8.8.8"
        assert set_call[0][1]["ping"]["settings"]["count"] == "3"

        # Verify start was called with uuid suffix
        start_call = mock_api.post.call_args_list[1]
        assert start_call[0][0] == "diagnostics.ping.start"
        assert start_call[1]["path_suffix"] == "ping-job-1"

    async def test_ping_count_capped_at_10(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(
            side_effect=[
                {"result": "ok", "uuid": "ping-cap"},
                {"status": "ok"},
                {"status": "ok"},
            ],
        )
        mock_api.get = AsyncMock(
            return_value={
                "rows": [{"uuid": "ping-cap", "status": "done", "send": 10}],
                "rowCount": 1,
            },
        )

        with patch("opnsense_mcp.tools.diagnostics.asyncio.sleep", new_callable=AsyncMock):
            await opn_ping(mock_ctx, host="1.1.1.1", count=999)

        set_call = mock_api.post.call_args_list[0]
        assert set_call[0][1]["ping"]["settings"]["count"] == "10"

    async def test_ping_count_minimum_1(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(
            side_effect=[
                {"result": "ok", "uuid": "ping-min"},
                {"status": "ok"},
                {"status": "ok"},
            ],
        )
        mock_api.get = AsyncMock(
            return_value={
                "rows": [{"uuid": "ping-min", "status": "done", "send": 1}],
                "rowCount": 1,
            },
        )

        with patch("opnsense_mcp.tools.diagnostics.asyncio.sleep", new_callable=AsyncMock):
            await opn_ping(mock_ctx, host="1.1.1.1", count=0)

        set_call = mock_api.post.call_args_list[0]
        assert set_call[0][1]["ping"]["settings"]["count"] == "1"

    async def test_ping_returns_error_on_missing_uuid(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"result": "failed"})

        result = await opn_ping(mock_ctx, host="bad-host")

        assert "error" in result

    async def test_ping_timeout_cleans_up_job(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(
            side_effect=[
                {"result": "ok", "uuid": "ping-timeout"},
                {"status": "ok"},
                # remove call at cleanup
                {"status": "ok"},
            ],
        )
        # Job never finishes
        mock_api.get = AsyncMock(
            return_value={
                "rows": [{"uuid": "ping-timeout", "status": "running"}],
                "rowCount": 1,
            },
        )

        with (
            patch(
                "opnsense_mcp.tools.diagnostics.asyncio.sleep",
                new_callable=AsyncMock,
            ),
            patch(
                "opnsense_mcp.tools.diagnostics._MAX_PING_POLLS",
                2,
            ),
        ):
            result = await opn_ping(mock_ctx, host="10.0.0.1")

        assert "error" in result
        assert "timed out" in result["error"]
        # Verify remove was called for cleanup
        remove_call = mock_api.post.call_args_list[-1]
        assert remove_call[0][0] == "diagnostics.ping.remove"
        assert remove_call[1]["path_suffix"] == "ping-timeout"

    async def test_ping_cleans_up_on_exception(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(
            side_effect=[
                {"result": "ok", "uuid": "ping-exc"},
                {"status": "ok"},
                # remove cleanup
                {"status": "ok"},
            ],
        )
        mock_api.get = AsyncMock(side_effect=RuntimeError("API connection lost"))

        with (
            patch(
                "opnsense_mcp.tools.diagnostics.asyncio.sleep",
                new_callable=AsyncMock,
            ),
            pytest.raises(RuntimeError, match="API connection lost"),
        ):
            await opn_ping(mock_ctx, host="8.8.8.8")

        remove_call = mock_api.post.call_args_list[-1]
        assert remove_call[0][0] == "diagnostics.ping.remove"
        assert remove_call[1]["path_suffix"] == "ping-exc"

    async def test_ping_rejects_invalid_hostname(self, mock_api, mock_ctx):
        result = await opn_ping(mock_ctx, host="8.8.8.8; rm -rf /")
        assert "error" in result
        assert "invalid" in result["error"].lower()

    async def test_ping_rejects_shell_metacharacters(self, mock_api, mock_ctx):
        for bad_char in ("(", ")", "{", "}", "<", ">", "'", '"', "\\", " "):
            result = await opn_ping(mock_ctx, host=f"host{bad_char}bad")
            assert "error" in result, f"Should reject hostname with '{bad_char}'"

    async def test_ping_rejects_empty_hostname(self, mock_api, mock_ctx):
        result = await opn_ping(mock_ctx, host="")
        assert "error" in result


class TestOpnTraceroute:
    """Tests for opn_traceroute."""

    async def test_runs_traceroute(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(
            return_value={
                "result": "ok",
                "response": [
                    {"hop": 1, "address": "10.0.0.1", "rtt": "1.2ms"},
                    {"hop": 2, "address": "192.168.1.1", "rtt": "5.3ms"},
                ],
            },
        )

        result = await opn_traceroute(mock_ctx, host="8.8.8.8")

        assert result["host"] == "8.8.8.8"
        assert result["result"] == "ok"
        assert len(result["response"]) == 2

        call_args = mock_api.post.call_args
        assert call_args[0][0] == "diagnostics.traceroute.set"
        payload = call_args[0][1]["traceroute"]
        assert payload["hostname"] == "8.8.8.8"
        assert payload["protocol"] == "ICMP"
        assert payload["ipproto"] == "4"

    async def test_custom_protocol_and_ip_version(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"result": "ok", "response": []})

        await opn_traceroute(mock_ctx, host="::1", protocol="UDP", ip_version="6")

        payload = mock_api.post.call_args[0][1]["traceroute"]
        assert payload["protocol"] == "UDP"
        assert payload["ipproto"] == "6"

    async def test_rejects_invalid_protocol(self, mock_api, mock_ctx):
        result = await opn_traceroute(mock_ctx, host="8.8.8.8", protocol="INVALID")
        assert "error" in result
        assert "protocol" in result["error"].lower()

    async def test_rejects_invalid_ip_version(self, mock_api, mock_ctx):
        result = await opn_traceroute(mock_ctx, host="8.8.8.8", ip_version="5")
        assert "error" in result
        assert "ip_version" in result["error"].lower()

    async def test_rejects_invalid_hostname(self, mock_api, mock_ctx):
        result = await opn_traceroute(mock_ctx, host="host | cat /etc/passwd")
        assert "error" in result


class TestOpnDnsLookup:
    """Tests for opn_dns_lookup."""

    async def test_performs_dns_lookup(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(
            return_value={
                "result": "ok",
                "response": [{"address": "93.184.216.34", "type": "A"}],
            },
        )

        result = await opn_dns_lookup(mock_ctx, hostname="example.com")

        assert result["hostname"] == "example.com"
        assert result["result"] == "ok"

        call_args = mock_api.post.call_args
        assert call_args[0][0] == "diagnostics.dns_diagnostics.set"
        payload = call_args[0][1]["dns"]["settings"]
        assert payload["hostname"] == "example.com"
        assert payload["server"] == ""

    async def test_custom_dns_server(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"result": "ok", "response": []})

        await opn_dns_lookup(mock_ctx, hostname="example.com", server="1.1.1.1")

        payload = mock_api.post.call_args[0][1]["dns"]["settings"]
        assert payload["server"] == "1.1.1.1"

    async def test_rejects_invalid_hostname(self, mock_api, mock_ctx):
        result = await opn_dns_lookup(mock_ctx, hostname="example.com`whoami`")
        assert "error" in result

    async def test_rejects_invalid_server(self, mock_api, mock_ctx):
        result = await opn_dns_lookup(mock_ctx, hostname="example.com", server="8.8.8.8; rm -rf /")
        assert "error" in result
        assert "DNS server" in result["error"]

    async def test_accepts_valid_server(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"result": "ok", "response": []})
        result = await opn_dns_lookup(mock_ctx, hostname="example.com", server="dns.google")
        assert "error" not in result


class TestOpnPfStates:
    """Tests for opn_pf_states."""

    async def test_queries_state_table(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(
            return_value={
                "rows": [
                    {
                        "id": "1",
                        "iface": "em0",
                        "proto": "tcp",
                        "src": "192.168.1.10:54321",
                        "dst": "93.184.216.34:443",
                        "state": "ESTABLISHED",
                    },
                ],
                "rowCount": 1,
            },
        )

        result = await opn_pf_states(mock_ctx)

        mock_api.post.assert_called_once_with(
            "diagnostics.firewall.query_states",
            {"current": 1, "rowCount": 200, "searchPhrase": ""},
        )
        assert len(result["rows"]) == 1
        assert result["rows"][0]["proto"] == "tcp"

    async def test_passes_search_phrase(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})

        await opn_pf_states(mock_ctx, search="192.168.1.10")

        call_args = mock_api.post.call_args[0][1]
        assert call_args["searchPhrase"] == "192.168.1.10"

    async def test_limit_capped_at_1000(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})

        await opn_pf_states(mock_ctx, limit=9999)

        call_args = mock_api.post.call_args[0][1]
        assert call_args["rowCount"] == 1000
