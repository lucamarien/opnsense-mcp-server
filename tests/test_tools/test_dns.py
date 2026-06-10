"""Tests for DNS tools (manage/edit surface, v0.5)."""

from __future__ import annotations

from unittest.mock import AsyncMock

from opnsense_mcp.api_client import OPNsenseAPIError
from opnsense_mcp.tools.dns import (
    _extract_dnsbl_values,
    opn_apply_dnsbl,
    opn_dns_stats,
    opn_edit_dnsbl_allowlist,
    opn_get_dnsbl,
    opn_list_dns_forwards,
    opn_list_dns_overrides,
    opn_list_dnsbl,
    opn_manage_dns_override,
    opn_reconfigure_unbound,
    opn_set_dnsbl,
)

_DNSBL_FORM = {
    "blocklist": {
        "enabled": "1",
        "type": {
            "ag": {"value": "AdGuard List", "selected": 1},
            "hgz002": {"value": "[hagezi] Multi NORMAL", "selected": 1},
            "hgz011": {"value": "[hagezi] TI Feeds", "selected": 0},
        },
        "lists": {"": {"value": "", "selected": 1}},
        "allowlists": {
            "existing.example.com": {"value": "existing.example.com", "selected": 1},
            "": {"value": "", "selected": 1},
        },
        "blocklists": {"": {"value": "", "selected": 1}},
        "wildcards": {"": {"value": "", "selected": 1}},
        "source_nets": {"": {"value": "", "selected": 1}},
        "address": "",
        "nxdomain": "0",
        "cache_ttl": "72000",
        "description": "Test blocklist",
    }
}

_UUID = "7aafe899-6392-4a05-8205-565919b17f02"


# ---------------------------------------------------------------------------
# Read tools
# ---------------------------------------------------------------------------


class TestListTools:
    async def test_list_overrides(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": []})
        await opn_list_dns_overrides(mock_ctx, search="srv", limit=10)
        mock_api.post.assert_called_once_with(
            "unbound.search_override",
            {"current": 1, "rowCount": 10, "searchPhrase": "srv"},
        )

    async def test_list_forwards(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": []})
        await opn_list_dns_forwards(mock_ctx)
        mock_api.post.assert_called_once_with(
            "unbound.search_forward",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )

    async def test_list_limit_clamped(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": []})
        await opn_list_dns_overrides(mock_ctx, limit=99999)
        assert mock_api.post.call_args[0][1]["rowCount"] == 500

    async def test_dns_stats(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"total.num.queries": "100"})
        result = await opn_dns_stats(mock_ctx)
        mock_api.get.assert_called_once_with("unbound.stats")
        assert result == {"total.num.queries": "100"}

    async def test_api_error_envelope(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(side_effect=OPNsenseAPIError("down", status_code=503))
        result = await opn_dns_stats(mock_ctx)
        assert result["error_type"] == "api"


class TestReconfigureUnbound:
    async def test_reconfigures(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        result = await opn_reconfigure_unbound(mock_ctx_writes)
        mock_api_writes.post.assert_called_once_with("unbound.service.reconfigure")
        assert result == {"status": "ok", "service": "unbound"}

    async def test_writes_disabled(self, mock_ctx_no_writes):
        result = await opn_reconfigure_unbound(mock_ctx_no_writes)
        assert result["error_type"] == "writes_disabled"


# ---------------------------------------------------------------------------
# opn_manage_dns_override
# ---------------------------------------------------------------------------


class TestManageDnsOverride:
    async def test_add_requires_fields(self, mock_api_writes, mock_ctx_writes):
        result = await opn_manage_dns_override(mock_ctx_writes, action="add", hostname="srv")
        assert result["error_type"] == "validation"
        assert "domain" in result["error"]
        assert "server" in result["error"]

    async def test_add_validates_hostname(self, mock_ctx_writes):
        result = await opn_manage_dns_override(
            mock_ctx_writes, action="add", hostname="bad host", domain="lan", server="10.0.0.1"
        )
        assert result["error_type"] == "validation"

    async def test_add_validates_ip(self, mock_ctx_writes):
        result = await opn_manage_dns_override(
            mock_ctx_writes, action="add", hostname="srv", domain="local.lan", server="not-an-ip"
        )
        assert result["error_type"] == "validation"

    async def test_add_creates_and_applies(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved", "uuid": "ov-1"},
                {"status": "ok"},
            ]
        )
        result = await opn_manage_dns_override(
            mock_ctx_writes, action="add", hostname="srv", domain="local.lan", server="10.0.0.5"
        )
        endpoints = [c[0][0] for c in mock_api_writes.post.call_args_list]
        assert endpoints == ["unbound.add_host_override", "unbound.service.reconfigure"]
        host = mock_api_writes.post.call_args_list[0][0][1]["host"]
        assert host["hostname"] == "srv"
        assert host["enabled"] == "1"
        assert result["uuid"] == "ov-1"
        assert result["hostname"] == "srv.local.lan"
        assert result["applied"] == "ok"

    async def test_add_accepts_ipv6(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(side_effect=[{"uuid": "ov-1"}, {"status": "ok"}])
        result = await opn_manage_dns_override(
            mock_ctx_writes, action="add", hostname="srv", domain="local.lan", server="2001:db8::1"
        )
        assert "error" not in result

    async def test_update_requires_uuid(self, mock_ctx_writes):
        result = await opn_manage_dns_override(mock_ctx_writes, action="update", server="10.0.0.9")
        assert result["error_type"] == "validation"

    async def test_update_sends_only_provided(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "ok"}])
        await opn_manage_dns_override(mock_ctx_writes, action="update", uuid="ov-1", server="10.0.0.9")
        call = mock_api_writes.post.call_args_list[0]
        assert call[0][0] == "unbound.set_host_override"
        assert call[0][1] == {"host": {"server": "10.0.0.9"}}
        assert call[1]["path_suffix"] == "ov-1"

    async def test_delete_applies(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "deleted"}, {"status": "ok"}])
        result = await opn_manage_dns_override(mock_ctx_writes, action="delete", uuid="ov-1")
        endpoints = [c[0][0] for c in mock_api_writes.post.call_args_list]
        assert endpoints == ["unbound.del_host_override", "unbound.service.reconfigure"]
        assert result["applied"] == "ok"

    async def test_writes_disabled(self, mock_ctx_no_writes):
        result = await opn_manage_dns_override(
            mock_ctx_no_writes, action="add", hostname="h", domain="d.lan", server="10.0.0.1"
        )
        assert result["error_type"] == "writes_disabled"


# ---------------------------------------------------------------------------
# DNSBL helpers and tools
# ---------------------------------------------------------------------------


class TestExtractDnsblValues:
    def test_extracts_selected_providers(self):
        result = _extract_dnsbl_values(_DNSBL_FORM["blocklist"])
        codes = result["type"].split(",")
        assert "ag" in codes
        assert "hgz002" in codes
        assert "hgz011" not in codes

    def test_extracts_text_fields(self):
        result = _extract_dnsbl_values(_DNSBL_FORM["blocklist"])
        assert result["allowlists"] == "existing.example.com"

    def test_passes_simple_fields(self):
        result = _extract_dnsbl_values(_DNSBL_FORM["blocklist"])
        assert result["enabled"] == "1"
        assert result["cache_ttl"] == "72000"


class TestGetDnsbl:
    async def test_parses_form(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value=_DNSBL_FORM)
        result = await opn_get_dnsbl(mock_ctx, uuid=_UUID)
        assert result["enabled"] is True
        assert "ag" in result["selected_providers"]
        assert "hgz011" in result["available_providers"]
        assert result["allowlists"] == ["existing.example.com"]
        assert result["description"] == "Test blocklist"

    async def test_list_dnsbl(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": []})
        await opn_list_dnsbl(mock_ctx)
        mock_api.post.assert_called_once_with(
            "unbound.search_dnsbl",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )


def _dnsbl_write_mock(api) -> None:
    """Mock GET (form) + POSTs (set, dnsbl regen, reconfigure)."""
    api.get = AsyncMock(return_value=_DNSBL_FORM)
    api.post = AsyncMock(
        side_effect=[
            {"result": "saved"},
            {"status": "OK\n"},
            {"status": "ok"},
        ]
    )


class TestSetDnsbl:
    async def test_read_modify_write_preserves(self, mock_api_writes, mock_ctx_writes):
        _dnsbl_write_mock(mock_api_writes)
        result = await opn_set_dnsbl(mock_ctx_writes, uuid=_UUID, nxdomain=True)
        sent = mock_api_writes.post.call_args_list[0][0][1]["blocklist"]
        assert sent["nxdomain"] == "1"  # changed
        assert sent["allowlists"] == "existing.example.com"  # preserved
        assert "ag" in sent["type"]  # preserved providers
        assert result["dnsbl_status"] == "OK"
        assert result["service_status"] == "ok"

    async def test_set_providers(self, mock_api_writes, mock_ctx_writes):
        _dnsbl_write_mock(mock_api_writes)
        await opn_set_dnsbl(mock_ctx_writes, uuid=_UUID, providers="hgz011")
        sent = mock_api_writes.post.call_args_list[0][0][1]["blocklist"]
        assert sent["type"] == "hgz011"

    async def test_applies_dnsbl_and_reconfigure(self, mock_api_writes, mock_ctx_writes):
        _dnsbl_write_mock(mock_api_writes)
        await opn_set_dnsbl(mock_ctx_writes, uuid=_UUID, enabled=True)
        endpoints = [c[0][0] for c in mock_api_writes.post.call_args_list]
        assert endpoints == ["unbound.set_dnsbl", "unbound.service.dnsbl", "unbound.service.reconfigure"]

    async def test_writes_disabled(self, mock_ctx_no_writes):
        result = await opn_set_dnsbl(mock_ctx_no_writes, uuid=_UUID, enabled=True)
        assert result["error_type"] == "writes_disabled"


class TestEditDnsblAllowlist:
    async def test_requires_input(self, mock_ctx_writes):
        result = await opn_edit_dnsbl_allowlist(mock_ctx_writes, uuid=_UUID)
        assert result["error_type"] == "validation"

    async def test_add_merges_without_overwriting(self, mock_api_writes, mock_ctx_writes):
        _dnsbl_write_mock(mock_api_writes)
        result = await opn_edit_dnsbl_allowlist(mock_ctx_writes, uuid=_UUID, add_domains="new.example.com")
        assert result["added"] == ["new.example.com"]
        sent = mock_api_writes.post.call_args_list[0][0][1]["blocklist"]
        assert "existing.example.com" in sent["allowlists"]
        assert "new.example.com" in sent["allowlists"]

    async def test_add_reports_already_present(self, mock_api_writes, mock_ctx_writes):
        _dnsbl_write_mock(mock_api_writes)
        result = await opn_edit_dnsbl_allowlist(mock_ctx_writes, uuid=_UUID, add_domains="existing.example.com")
        assert result["added"] == []
        assert result["already_present"] == ["existing.example.com"]

    async def test_remove_existing(self, mock_api_writes, mock_ctx_writes):
        _dnsbl_write_mock(mock_api_writes)
        result = await opn_edit_dnsbl_allowlist(mock_ctx_writes, uuid=_UUID, remove_domains="existing.example.com")
        assert result["removed"] == ["existing.example.com"]
        sent = mock_api_writes.post.call_args_list[0][0][1]["blocklist"]
        assert "existing.example.com" not in sent["allowlists"]

    async def test_remove_missing_reported(self, mock_api_writes, mock_ctx_writes):
        _dnsbl_write_mock(mock_api_writes)
        result = await opn_edit_dnsbl_allowlist(mock_ctx_writes, uuid=_UUID, remove_domains="nope.example.com")
        assert result["not_found"] == ["nope.example.com"]

    async def test_add_and_remove_in_one_call(self, mock_api_writes, mock_ctx_writes):
        _dnsbl_write_mock(mock_api_writes)
        result = await opn_edit_dnsbl_allowlist(
            mock_ctx_writes,
            uuid=_UUID,
            add_domains="new.example.com",
            remove_domains="existing.example.com",
        )
        assert result["added"] == ["new.example.com"]
        assert result["removed"] == ["existing.example.com"]
        sent = mock_api_writes.post.call_args_list[0][0][1]["blocklist"]
        assert sent["allowlists"] == "new.example.com"

    async def test_comma_separated_input(self, mock_api_writes, mock_ctx_writes):
        _dnsbl_write_mock(mock_api_writes)
        result = await opn_edit_dnsbl_allowlist(mock_ctx_writes, uuid=_UUID, add_domains="a.com, b.com")
        assert sorted(result["added"]) == ["a.com", "b.com"]


class TestApplyDnsbl:
    async def test_regenerates_and_restarts(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(side_effect=[{"status": "OK\n"}, {"status": "ok"}])
        result = await opn_apply_dnsbl(mock_ctx_writes)
        endpoints = [c[0][0] for c in mock_api_writes.post.call_args_list]
        assert endpoints == ["unbound.service.dnsbl", "unbound.service.reconfigure"]
        assert result == {"dnsbl_status": "OK", "service_status": "ok"}

    async def test_writes_disabled(self, mock_ctx_no_writes):
        result = await opn_apply_dnsbl(mock_ctx_no_writes)
        assert result["error_type"] == "writes_disabled"
