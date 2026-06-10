"""Tests for service tools (DDNS manage, merged CrowdSec, mDNS, v0.5)."""

from __future__ import annotations

from unittest.mock import AsyncMock

from opnsense_mcp.api_client import OPNsenseAPIError
from opnsense_mcp.tools.services import (
    opn_configure_mdns_repeater,
    opn_crowdsec_status,
    opn_list_acme_certs,
    opn_list_cron_jobs,
    opn_list_ddns_accounts,
    opn_manage_ddns_account,
    opn_mdns_repeater_status,
    opn_reconfigure_ddclient,
)


class TestListDdnsAccounts:
    async def test_calls_search_and_masks_credentials(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(
            return_value={
                "rows": [
                    {"hostname": "fw.example.com", "password": "supersecret", "%password": "supersecret"},
                ],
                "rowCount": 1,
            }
        )
        result = await opn_list_ddns_accounts(mock_ctx)
        mock_api.post.assert_called_once_with(
            "dyndns.accounts.search",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result["rows"][0]["password"] == "***"
        assert result["rows"][0]["%password"] == "***"

    async def test_plugin_missing_envelope(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(side_effect=OPNsenseAPIError("not found", status_code=404))
        result = await opn_list_ddns_accounts(mock_ctx)
        assert result["error_type"] == "api"
        assert "plugin" in result["hint"]


class TestManageDdnsAccount:
    async def test_add_requires_service_and_hostname(self, mock_api_writes, mock_ctx_writes):
        result = await opn_manage_ddns_account(mock_ctx_writes, action="add", service="cloudflare")
        assert result["error_type"] == "validation"
        assert "hostname" in result["error"]

    async def test_add_creates_and_reconfigures(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved", "uuid": "ddns-1"},
                {"status": "ok"},
            ]
        )
        result = await opn_manage_ddns_account(
            mock_ctx_writes,
            action="add",
            service="cloudflare",
            hostname="fw.example.com",
            password="token123",
        )
        endpoints = [c[0][0] for c in mock_api_writes.post.call_args_list]
        assert endpoints == ["dyndns.accounts.add", "dyndns.service.reconfigure"]
        account = mock_api_writes.post.call_args_list[0][0][1]["account"]
        assert account["checkip"] == "web_dyndns"  # default
        assert account["enabled"] == "1"
        assert result["uuid"] == "ddns-1"

    async def test_update_sends_only_provided(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "ok"}])
        await opn_manage_ddns_account(mock_ctx_writes, action="update", uuid="ddns-1", hostname="new.example.com")
        call = mock_api_writes.post.call_args_list[0]
        assert call[0][0] == "dyndns.accounts.set"
        assert call[0][1] == {"account": {"hostname": "new.example.com"}}
        assert call[1]["path_suffix"] == "ddns-1"

    async def test_update_requires_uuid(self, mock_ctx_writes):
        result = await opn_manage_ddns_account(mock_ctx_writes, action="update", hostname="x")
        assert result["error_type"] == "validation"

    async def test_delete_reconfigures(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "deleted"}, {"status": "ok"}])
        result = await opn_manage_ddns_account(mock_ctx_writes, action="delete", uuid="ddns-1")
        endpoints = [c[0][0] for c in mock_api_writes.post.call_args_list]
        assert endpoints == ["dyndns.accounts.del", "dyndns.service.reconfigure"]
        assert result["uuid"] == "ddns-1"

    async def test_writes_disabled(self, mock_ctx_no_writes):
        result = await opn_manage_ddns_account(
            mock_ctx_no_writes, action="add", service="cloudflare", hostname="x.example.com"
        )
        assert result["error_type"] == "writes_disabled"


class TestReconfigureDdclient:
    async def test_reconfigures(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        result = await opn_reconfigure_ddclient(mock_ctx_writes)
        mock_api_writes.post.assert_called_once_with("dyndns.service.reconfigure")
        assert result == {"status": "ok", "service": "ddclient"}


class TestListAcmeAndCron:
    async def test_acme(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": []})
        await opn_list_acme_certs(mock_ctx, limit=10)
        mock_api.post.assert_called_once_with(
            "acmeclient.certs.search",
            {"current": 1, "rowCount": 10, "searchPhrase": ""},
        )

    async def test_cron(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": []})
        await opn_list_cron_jobs(mock_ctx)
        mock_api.post.assert_called_once_with(
            "cron.search_jobs",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )


class TestCrowdsecStatus:
    async def test_counts_use_totals_not_page_length(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"status": "running"})
        mock_api.post = AsyncMock(
            side_effect=[
                {"rows": [{"id": 1}, {"id": 2}], "total": 1234},
                {"rows": [{"id": 3}], "total": 567},
            ]
        )
        result = await opn_crowdsec_status(mock_ctx)
        assert result["service_status"] == "running"
        assert result["decisions_count"] == 1234
        assert result["alerts_count"] == 567
        assert len(result["decisions"]) == 2
        assert len(result["alerts"]) == 1

    async def test_count_falls_back_to_rows(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"status": "running"})
        mock_api.post = AsyncMock(side_effect=[{"rows": [{"id": 1}]}, {"rows": []}])
        result = await opn_crowdsec_status(mock_ctx)
        assert result["decisions_count"] == 1
        assert result["alerts_count"] == 0

    async def test_search_and_limit_forwarded(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"status": "running"})
        mock_api.post = AsyncMock(side_effect=[{"rows": []}, {"rows": []}])
        await opn_crowdsec_status(mock_ctx, search="ssh", limit=5)
        for call in mock_api.post.call_args_list:
            assert call[0][1] == {"current": 1, "rowCount": 5, "searchPhrase": "ssh"}

    async def test_plugin_missing_envelope(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(side_effect=OPNsenseAPIError("nope", status_code=400))
        result = await opn_crowdsec_status(mock_ctx)
        assert result["error_type"] == "api"


class TestMdnsRepeater:
    async def test_status(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(
            side_effect=[
                {"mdnsrepeater": {"enabled": "1", "interfaces": "lan,opt1", "blocklist": "", "enablecarp": "0"}},
                {"status": "running"},
            ]
        )
        result = await opn_mdns_repeater_status(mock_ctx)
        assert result["service_running"] == "running"
        assert result["interfaces"] == "lan,opt1"

    async def test_configure_preserves_existing_string_fields(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(
            return_value={
                "mdnsrepeater": {
                    "enabled": "0",
                    "interfaces": "lan",
                    "blocklist": "opt3",
                    "enablecarp": "1",
                }
            }
        )
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "ok"}])
        result = await opn_configure_mdns_repeater(mock_ctx_writes, enabled=True, interfaces="lan,opt1")
        payload = mock_api_writes.post.call_args_list[0][0][1]["mdnsrepeater"]
        assert payload["enabled"] == "1"
        assert payload["interfaces"] == "lan,opt1"
        assert payload["blocklist"] == "opt3"  # preserved
        assert payload["enablecarp"] == "1"  # preserved
        assert result["reconfigure_status"] == "ok"

    async def test_configure_skips_non_string_fields(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(
            return_value={"mdnsrepeater": {"blocklist": {"opt3": {"selected": 1}}, "enablecarp": ""}}
        )
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "ok"}])
        await opn_configure_mdns_repeater(mock_ctx_writes, enabled=True, interfaces="lan,opt1")
        payload = mock_api_writes.post.call_args_list[0][0][1]["mdnsrepeater"]
        assert "blocklist" not in payload  # option-dict shape not carried over
        assert "enablecarp" not in payload  # empty string not carried over

    async def test_configure_survives_get_failure(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(side_effect=OPNsenseAPIError("boom"))
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "ok"}])
        result = await opn_configure_mdns_repeater(mock_ctx_writes, enabled=False, interfaces="lan")
        payload = mock_api_writes.post.call_args_list[0][0][1]["mdnsrepeater"]
        assert payload == {"enabled": "0", "interfaces": "lan"}
        assert result["result"] == "saved"

    async def test_configure_writes_disabled(self, mock_ctx_no_writes):
        result = await opn_configure_mdns_repeater(mock_ctx_no_writes)
        assert result["error_type"] == "writes_disabled"
