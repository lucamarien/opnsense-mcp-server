"""Tests for service tools."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.api_client import WriteDisabledError
from opnsense_mcp.tools.services import (
    opn_add_ddns_account,
    opn_configure_mdns_repeater,
    opn_crowdsec_alerts,
    opn_crowdsec_status,
    opn_list_acme_certs,
    opn_list_cron_jobs,
    opn_list_ddns_accounts,
    opn_mdns_repeater_status,
    opn_reconfigure_ddclient,
)


class TestOpnListAcmeCerts:
    """Tests for opn_list_acme_certs."""

    async def test_calls_acme_search(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_list_acme_certs(mock_ctx)
        mock_api.post.assert_called_once_with(
            "acmeclient.certs.search",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_phrase(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_acme_certs(mock_ctx, search="example.com")
        mock_api.post.assert_called_once_with(
            "acmeclient.certs.search",
            {"current": 1, "rowCount": 50, "searchPhrase": "example.com"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_acme_certs(mock_ctx, limit=800)
        mock_api.post.assert_called_once_with(
            "acmeclient.certs.search",
            {"current": 1, "rowCount": 500, "searchPhrase": ""},
        )


class TestOpnListCronJobs:
    """Tests for opn_list_cron_jobs."""

    async def test_calls_cron_search(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_list_cron_jobs(mock_ctx)
        mock_api.post.assert_called_once_with(
            "cron.search_jobs",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_and_limit(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_cron_jobs(mock_ctx, search="backup", limit=20)
        mock_api.post.assert_called_once_with(
            "cron.search_jobs",
            {"current": 1, "rowCount": 20, "searchPhrase": "backup"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_cron_jobs(mock_ctx, limit=501)
        mock_api.post.assert_called_once_with(
            "cron.search_jobs",
            {"current": 1, "rowCount": 500, "searchPhrase": ""},
        )


class TestOpnCrowdsecStatus:
    """Tests for opn_crowdsec_status."""

    _SEARCH_PARAMS = {"current": 1, "rowCount": 500, "searchPhrase": ""}

    async def test_returns_status_and_counts(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"status": "running"})
        mock_api.post = AsyncMock(
            side_effect=[
                {"rows": [{"id": "1", "type": "ban"}], "rowCount": 1},
                {"rows": [{"id": "a1"}], "rowCount": 1},
            ],
        )
        result = await opn_crowdsec_status(mock_ctx)
        mock_api.get.assert_called_once_with("crowdsec.service.status")
        mock_api.post.assert_any_call("crowdsec.decisions.search", self._SEARCH_PARAMS)
        mock_api.post.assert_any_call("crowdsec.alerts.search", self._SEARCH_PARAMS)
        assert result["service_status"] == "running"
        assert result["decisions_count"] == 1
        assert result["alerts_count"] == 1

    async def test_empty_decisions_and_alerts(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"status": "running"})
        mock_api.post = AsyncMock(
            side_effect=[
                {"rows": [], "rowCount": 0},
                {"rows": [], "rowCount": 0},
            ],
        )
        result = await opn_crowdsec_status(mock_ctx)
        assert result["decisions_count"] == 0
        assert result["alerts_count"] == 0

    async def test_limits_decisions_to_20(self, mock_api, mock_ctx):
        many_decisions = [{"id": str(i)} for i in range(30)]
        mock_api.get = AsyncMock(return_value={"status": "running"})
        mock_api.post = AsyncMock(
            side_effect=[
                {"rows": many_decisions, "rowCount": 30},
                {"rows": [], "rowCount": 0},
            ],
        )
        result = await opn_crowdsec_status(mock_ctx)
        assert len(result["decisions"]) == 20
        assert result["decisions_count"] == 30


class TestOpnCrowdsecAlerts:
    """Tests for opn_crowdsec_alerts."""

    async def test_calls_alerts_search(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_crowdsec_alerts(mock_ctx)
        mock_api.post.assert_called_once_with(
            "crowdsec.alerts.search",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_and_limit(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_crowdsec_alerts(mock_ctx, search="ssh", limit=20)
        mock_api.post.assert_called_once_with(
            "crowdsec.alerts.search",
            {"current": 1, "rowCount": 20, "searchPhrase": "ssh"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_crowdsec_alerts(mock_ctx, limit=999)
        call_args = mock_api.post.call_args[0][1]
        assert call_args["rowCount"] == 500


class TestOpnListDdnsAccounts:
    """Tests for opn_list_ddns_accounts."""

    async def test_calls_dyndns_search(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_list_ddns_accounts(mock_ctx)
        mock_api.post.assert_called_once_with(
            "dyndns.accounts.search",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_and_limit(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_ddns_accounts(mock_ctx, search="example.com", limit=20)
        mock_api.post.assert_called_once_with(
            "dyndns.accounts.search",
            {"current": 1, "rowCount": 20, "searchPhrase": "example.com"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_ddns_accounts(mock_ctx, limit=800)
        call_args = mock_api.post.call_args[0][1]
        assert call_args["rowCount"] == 500

    async def test_sanitizes_passwords(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(
            return_value={
                "rows": [
                    {
                        "hostname": "fw.example.com",
                        "password": "super-secret-api-token",
                        "%password": "masked",
                        "service": "cloudflare",
                    },
                ],
                "rowCount": 1,
            }
        )
        result = await opn_list_ddns_accounts(mock_ctx)
        row = result["rows"][0]
        assert row["password"] == "***"
        assert row["%password"] == "***"
        assert row["hostname"] == "fw.example.com"
        assert row["service"] == "cloudflare"


class TestOpnAddDdnsAccount:
    """Tests for opn_add_ddns_account."""

    async def test_creates_account_and_reconfigures(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved", "uuid": "ddns-uuid-123"},
                {"status": "ok"},
            ]
        )
        result = await opn_add_ddns_account(
            mock_ctx_writes,
            service="cloudflare",
            hostname="fw.example.com",
            username="user@example.com",
            password="api-token-123",
        )
        # First call: add account
        add_call = mock_api_writes.post.call_args_list[0]
        assert add_call[0][0] == "dyndns.accounts.add"
        account = add_call[0][1]["account"]
        assert account["service"] == "cloudflare"
        assert account["hostname"] == "fw.example.com"
        assert account["username"] == "user@example.com"
        assert account["password"] == "api-token-123"
        assert account["enabled"] == "1"
        # Second call: reconfigure
        reconf_call = mock_api_writes.post.call_args_list[1]
        assert reconf_call[0][0] == "dyndns.service.reconfigure"
        # Result
        assert result["uuid"] == "ddns-uuid-123"
        assert result["reconfigure_status"] == "ok"

    async def test_optional_fields_omitted_when_empty(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved", "uuid": "ddns-uuid"},
                {"status": "ok"},
            ]
        )
        await opn_add_ddns_account(mock_ctx_writes, service="he", hostname="fw.example.com")
        add_call = mock_api_writes.post.call_args_list[0]
        account = add_call[0][1]["account"]
        assert "username" not in account
        assert "password" not in account
        assert "interface" not in account
        assert "description" not in account

    async def test_includes_interface_and_description(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved", "uuid": "ddns-uuid"},
                {"status": "ok"},
            ]
        )
        await opn_add_ddns_account(
            mock_ctx_writes,
            service="cloudflare",
            hostname="fw.example.com",
            interface="wan",
            description="Primary WAN IPv6",
        )
        add_call = mock_api_writes.post.call_args_list[0]
        account = add_call[0][1]["account"]
        assert account["interface"] == "wan"
        assert account["description"] == "Primary WAN IPv6"

    async def test_requires_writes_enabled(self, mock_api, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_add_ddns_account(mock_ctx, service="cloudflare", hostname="fw.example.com")

    async def test_rejects_empty_service(self, mock_api_writes, mock_ctx_writes):
        result = await opn_add_ddns_account(mock_ctx_writes, service="", hostname="fw.example.com")
        assert "error" in result
        assert "service" in result["error"]

    async def test_rejects_empty_hostname(self, mock_api_writes, mock_ctx_writes):
        result = await opn_add_ddns_account(mock_ctx_writes, service="cloudflare", hostname="")
        assert "error" in result
        assert "hostname" in result["error"]

    async def test_ipv6_checkip_method(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved", "uuid": "v6-uuid"},
                {"status": "ok"},
            ]
        )
        await opn_add_ddns_account(
            mock_ctx_writes,
            service="cloudflare",
            hostname="v6.example.com",
            checkip="web_dyndns6",
        )
        add_call = mock_api_writes.post.call_args_list[0]
        account = add_call[0][1]["account"]
        assert account["checkip"] == "web_dyndns6"


class TestOpnReconfigureDdclient:
    """Tests for opn_reconfigure_ddclient."""

    async def test_calls_reconfigure_endpoint(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        result = await opn_reconfigure_ddclient(mock_ctx_writes)
        mock_api_writes.post.assert_called_once_with("dyndns.service.reconfigure")
        assert result["status"] == "ok"
        assert result["service"] == "ddclient"

    async def test_requires_writes_enabled(self, mock_api, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_reconfigure_ddclient(mock_ctx)

    async def test_returns_unknown_on_missing_status(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={})
        result = await opn_reconfigure_ddclient(mock_ctx_writes)
        assert result["status"] == "unknown"


class TestOpnMdnsRepeaterStatus:
    """Tests for opn_mdns_repeater_status."""

    async def test_returns_status_and_config(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(
            side_effect=[
                {
                    "mdnsrepeater": {
                        "enabled": "1",
                        "interfaces": "lan,opt1",
                        "blocklist": "",
                        "enablecarp": "0",
                    },
                },
                {"status": "running"},
            ],
        )
        result = await opn_mdns_repeater_status(mock_ctx)
        assert result["service_running"] == "running"
        assert result["enabled"] == "1"
        assert result["interfaces"] == "lan,opt1"
        assert result["blocklist"] == ""
        assert result["enable_carp"] == "0"

    async def test_disabled_service(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(
            side_effect=[
                {
                    "mdnsrepeater": {
                        "enabled": "0",
                        "interfaces": "",
                        "blocklist": "",
                        "enablecarp": "0",
                    },
                },
                {"status": "stopped"},
            ],
        )
        result = await opn_mdns_repeater_status(mock_ctx)
        assert result["service_running"] == "stopped"
        assert result["enabled"] == "0"

    async def test_calls_correct_endpoints(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(
            side_effect=[
                {"mdnsrepeater": {"enabled": "0", "interfaces": ""}},
                {"status": "stopped"},
            ],
        )
        await opn_mdns_repeater_status(mock_ctx)
        calls = [c[0][0] for c in mock_api.get.call_args_list]
        assert calls == ["mdnsrepeater.settings.get", "mdnsrepeater.service.status"]


class TestOpnConfigureMdnsRepeater:
    """Tests for opn_configure_mdns_repeater."""

    async def test_requires_writes_enabled(self, mock_api, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_configure_mdns_repeater(mock_ctx, interfaces="lan,opt1")

    async def test_configures_and_reconfigures(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved"},
                {"status": "ok"},
            ],
        )
        result = await opn_configure_mdns_repeater(mock_ctx_writes, enabled=True, interfaces="lan,opt1")
        # First call: set settings
        set_call = mock_api_writes.post.call_args_list[0]
        assert set_call[0][0] == "mdnsrepeater.settings.set"
        payload = set_call[0][1]
        assert payload["mdnsrepeater"]["enabled"] == "1"
        assert payload["mdnsrepeater"]["interfaces"] == "lan,opt1"
        # Second call: reconfigure
        reconf_call = mock_api_writes.post.call_args_list[1]
        assert reconf_call[0][0] == "mdnsrepeater.service.reconfigure"
        # Result
        assert result["result"] == "saved"
        assert result["reconfigure_status"] == "ok"
        assert result["interfaces"] == "lan,opt1"

    async def test_disable_mdns_repeater(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved"},
                {"status": "ok"},
            ],
        )
        result = await opn_configure_mdns_repeater(mock_ctx_writes, enabled=False, interfaces="lan")
        set_call = mock_api_writes.post.call_args_list[0]
        payload = set_call[0][1]
        assert payload["mdnsrepeater"]["enabled"] == "0"
        assert result["enabled"] == "0"
