"""Tests for DNS tools."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.api_client import OPNsenseAPIError, WriteDisabledError
from opnsense_mcp.tools.dns import (
    _extract_dnsbl_values,
    opn_add_dns_override,
    opn_add_dnsbl_allowlist,
    opn_delete_dns_override,
    opn_dns_stats,
    opn_get_dnsbl,
    opn_list_dns_forwards,
    opn_list_dns_overrides,
    opn_list_dnsbl,
    opn_reconfigure_unbound,
    opn_remove_dnsbl_allowlist,
    opn_set_dnsbl,
    opn_update_dns_override,
    opn_update_dnsbl,
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


# ---------------------------------------------------------------------------
# DNSBL tests
# ---------------------------------------------------------------------------

# Reusable fixtures for DNSBL tests
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


class TestExtractDnsblValues:
    """Tests for _extract_dnsbl_values helper."""

    def test_extracts_selected_providers(self):
        form = _DNSBL_FORM["blocklist"]
        result = _extract_dnsbl_values(form)
        codes = result["type"].split(",")
        assert "ag" in codes
        assert "hgz002" in codes
        assert "hgz011" not in codes

    def test_extracts_text_fields(self):
        form = _DNSBL_FORM["blocklist"]
        result = _extract_dnsbl_values(form)
        assert result["allowlists"] == "existing.example.com"
        assert result["blocklists"] == ""
        assert result["wildcards"] == ""

    def test_extracts_simple_fields(self):
        form = _DNSBL_FORM["blocklist"]
        result = _extract_dnsbl_values(form)
        assert result["enabled"] == "1"
        assert result["nxdomain"] == "0"
        assert result["cache_ttl"] == "72000"
        assert result["description"] == "Test blocklist"

    def test_handles_empty_form(self):
        result = _extract_dnsbl_values({})
        assert result.get("type", "") == ""
        assert result.get("allowlists", "") == ""


class TestOpnListDnsbl:
    """Tests for opn_list_dnsbl."""

    async def test_calls_search_dnsbl(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_list_dnsbl(mock_ctx)
        mock_api.post.assert_called_once_with(
            "unbound.search_dnsbl",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_and_limit(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_dnsbl(mock_ctx, search="hagezi", limit=10)
        mock_api.post.assert_called_once_with(
            "unbound.search_dnsbl",
            {"current": 1, "rowCount": 10, "searchPhrase": "hagezi"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_dnsbl(mock_ctx, limit=999)
        mock_api.post.assert_called_once_with(
            "unbound.search_dnsbl",
            {"current": 1, "rowCount": 500, "searchPhrase": ""},
        )


class TestOpnGetDnsbl:
    """Tests for opn_get_dnsbl."""

    async def test_calls_get_dnsbl_with_uuid(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value=_DNSBL_FORM)
        await opn_get_dnsbl(mock_ctx, uuid=_UUID)
        mock_api.get.assert_called_once_with("unbound.get_dnsbl", path_suffix=_UUID)

    async def test_parses_selected_providers(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value=_DNSBL_FORM)
        result = await opn_get_dnsbl(mock_ctx, uuid=_UUID)
        assert "ag" in result["selected_providers"]
        assert "hgz002" in result["selected_providers"]
        assert "hgz011" not in result["selected_providers"]

    async def test_parses_available_providers(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value=_DNSBL_FORM)
        result = await opn_get_dnsbl(mock_ctx, uuid=_UUID)
        assert result["available_providers"]["ag"] == "AdGuard List"
        assert "hgz011" in result["available_providers"]

    async def test_parses_allowlist_entries(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value=_DNSBL_FORM)
        result = await opn_get_dnsbl(mock_ctx, uuid=_UUID)
        assert "existing.example.com" in result["allowlists"]

    async def test_returns_config_fields(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value=_DNSBL_FORM)
        result = await opn_get_dnsbl(mock_ctx, uuid=_UUID)
        assert result["enabled"] is True
        assert result["nxdomain"] is False
        assert result["cache_ttl"] == "72000"
        assert result["description"] == "Test blocklist"


class TestOpnSetDnsbl:
    """Tests for opn_set_dnsbl."""

    async def test_requires_writes_enabled(self, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_set_dnsbl(mock_ctx, uuid=_UUID, enabled=False)

    async def test_read_modify_write_calls(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value=_DNSBL_FORM)
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "OK\n\n"}, {"status": "ok"}])
        result = await opn_set_dnsbl(mock_ctx_writes, uuid=_UUID, enabled=False)
        # Verify read
        mock_api_writes.get.assert_called_once_with("unbound.get_dnsbl", path_suffix=_UUID)
        # Verify write + apply (3 POST calls: set_dnsbl + service.dnsbl + service.reconfigure)
        assert mock_api_writes.post.call_count == 3
        set_call = mock_api_writes.post.call_args_list[0]
        assert set_call[0][0] == "unbound.set_dnsbl"
        assert set_call[1]["path_suffix"] == _UUID
        assert mock_api_writes.post.call_args_list[1][0][0] == "unbound.service.dnsbl"
        assert mock_api_writes.post.call_args_list[2][0][0] == "unbound.service.reconfigure"
        assert result["result"] == "saved"
        assert result["dnsbl_status"] == "OK"
        assert result["service_status"] == "ok"

    async def test_only_changes_provided_fields(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value=_DNSBL_FORM)
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "OK"}, {"status": "ok"}])
        await opn_set_dnsbl(mock_ctx_writes, uuid=_UUID, description="New desc")
        payload = mock_api_writes.post.call_args_list[0][0][1]["blocklist"]
        # Description changed
        assert payload["description"] == "New desc"
        # Other fields preserved
        assert "ag" in payload["type"]
        assert payload["enabled"] == "1"
        assert payload["cache_ttl"] == "72000"

    async def test_updates_providers(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value=_DNSBL_FORM)
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "OK"}, {"status": "ok"}])
        await opn_set_dnsbl(mock_ctx_writes, uuid=_UUID, providers="hgz003,sb")
        payload = mock_api_writes.post.call_args_list[0][0][1]["blocklist"]
        assert payload["type"] == "hgz003,sb"

    async def test_invalidates_cache(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value=_DNSBL_FORM)
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "OK"}, {"status": "ok"}])
        await opn_set_dnsbl(mock_ctx_writes, uuid=_UUID, enabled=True)
        cache = mock_ctx_writes.lifespan_context["config_cache"]
        assert cache.is_stale

    async def test_raises_on_api_error(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(side_effect=OPNsenseAPIError("Not found"))
        with pytest.raises(OPNsenseAPIError, match="Not found"):
            await opn_set_dnsbl(mock_ctx_writes, uuid=_UUID, enabled=True)


class TestOpnAddDnsblAllowlist:
    """Tests for opn_add_dnsbl_allowlist."""

    async def test_requires_writes_enabled(self, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_add_dnsbl_allowlist(mock_ctx, uuid=_UUID, domains="example.com")

    async def test_appends_to_existing_allowlist(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value=_DNSBL_FORM)
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "OK"}, {"status": "ok"}])
        result = await opn_add_dnsbl_allowlist(mock_ctx_writes, uuid=_UUID, domains="new.example.com")
        payload = mock_api_writes.post.call_args_list[0][0][1]["blocklist"]
        assert "new.example.com" in payload["allowlists"]
        assert "existing.example.com" in payload["allowlists"]
        assert "new.example.com" in result["added"]

    async def test_deduplicates_domains(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value=_DNSBL_FORM)
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "OK"}, {"status": "ok"}])
        result = await opn_add_dnsbl_allowlist(mock_ctx_writes, uuid=_UUID, domains="existing.example.com")
        assert result["already_present"] == ["existing.example.com"]
        assert result["added"] == []

    async def test_accepts_comma_separated(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value=_DNSBL_FORM)
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "OK"}, {"status": "ok"}])
        result = await opn_add_dnsbl_allowlist(mock_ctx_writes, uuid=_UUID, domains="a.com,b.com")
        assert sorted(result["added"]) == ["a.com", "b.com"]

    async def test_applies_and_invalidates_cache(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value=_DNSBL_FORM)
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "OK"}, {"status": "ok"}])
        await opn_add_dnsbl_allowlist(mock_ctx_writes, uuid=_UUID, domains="test.com")
        assert mock_api_writes.post.call_count == 3
        assert mock_api_writes.post.call_args_list[1][0][0] == "unbound.service.dnsbl"
        assert mock_api_writes.post.call_args_list[2][0][0] == "unbound.service.reconfigure"
        cache = mock_ctx_writes.lifespan_context["config_cache"]
        assert cache.is_stale

    async def test_accepts_newline_separated(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value=_DNSBL_FORM)
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "OK"}, {"status": "ok"}])
        result = await opn_add_dnsbl_allowlist(mock_ctx_writes, uuid=_UUID, domains="a.com\nb.com")
        assert sorted(result["added"]) == ["a.com", "b.com"]

    async def test_handles_whitespace(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value=_DNSBL_FORM)
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "OK"}, {"status": "ok"}])
        result = await opn_add_dnsbl_allowlist(mock_ctx_writes, uuid=_UUID, domains="  a.com  ,  b.com  ")
        assert sorted(result["added"]) == ["a.com", "b.com"]

    async def test_raises_on_api_error(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(side_effect=OPNsenseAPIError("Not found"))
        with pytest.raises(OPNsenseAPIError, match="Not found"):
            await opn_add_dnsbl_allowlist(mock_ctx_writes, uuid=_UUID, domains="test.com")

    async def test_empty_domains_returns_error(self, mock_ctx_writes):
        result = await opn_add_dnsbl_allowlist(mock_ctx_writes, uuid=_UUID, domains="")
        assert "error" in result


class TestOpnRemoveDnsblAllowlist:
    """Tests for opn_remove_dnsbl_allowlist."""

    async def test_requires_writes_enabled(self, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_remove_dnsbl_allowlist(mock_ctx, uuid=_UUID, domains="example.com")

    async def test_removes_domains(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value=_DNSBL_FORM)
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "OK"}, {"status": "ok"}])
        result = await opn_remove_dnsbl_allowlist(mock_ctx_writes, uuid=_UUID, domains="existing.example.com")
        payload = mock_api_writes.post.call_args_list[0][0][1]["blocklist"]
        assert "existing.example.com" not in payload["allowlists"]
        assert result["removed"] == ["existing.example.com"]
        assert result["not_found"] == []

    async def test_reports_not_found(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value=_DNSBL_FORM)
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "OK"}, {"status": "ok"}])
        result = await opn_remove_dnsbl_allowlist(mock_ctx_writes, uuid=_UUID, domains="nonexistent.com")
        assert result["not_found"] == ["nonexistent.com"]
        assert result["removed"] == []

    async def test_applies_and_invalidates_cache(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value=_DNSBL_FORM)
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "OK"}, {"status": "ok"}])
        await opn_remove_dnsbl_allowlist(mock_ctx_writes, uuid=_UUID, domains="existing.example.com")
        assert mock_api_writes.post.call_count == 3
        assert mock_api_writes.post.call_args_list[1][0][0] == "unbound.service.dnsbl"
        assert mock_api_writes.post.call_args_list[2][0][0] == "unbound.service.reconfigure"
        cache = mock_ctx_writes.lifespan_context["config_cache"]
        assert cache.is_stale

    async def test_accepts_newline_separated(self, mock_api_writes, mock_ctx_writes):
        # Add a second allowlist entry to the form for this test
        form = {
            "blocklist": {
                **_DNSBL_FORM["blocklist"],
                "allowlists": {
                    "existing.example.com": {"value": "existing.example.com", "selected": 1},
                    "other.example.com": {"value": "other.example.com", "selected": 1},
                    "": {"value": "", "selected": 1},
                },
            },
        }
        mock_api_writes.get = AsyncMock(return_value=form)
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "OK"}, {"status": "ok"}])
        result = await opn_remove_dnsbl_allowlist(
            mock_ctx_writes, uuid=_UUID, domains="existing.example.com\nother.example.com"
        )
        assert sorted(result["removed"]) == ["existing.example.com", "other.example.com"]
        assert result["not_found"] == []

    async def test_empty_domains_returns_error(self, mock_ctx_writes):
        result = await opn_remove_dnsbl_allowlist(mock_ctx_writes, uuid=_UUID, domains="")
        assert "error" in result


class TestOpnUpdateDnsbl:
    """Tests for opn_update_dnsbl."""

    async def test_requires_writes_enabled(self, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_update_dnsbl(mock_ctx)

    async def test_calls_dnsbl_and_reconfigure(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(side_effect=[{"status": "OK\n\n"}, {"status": "ok"}])
        result = await opn_update_dnsbl(mock_ctx_writes)
        assert mock_api_writes.post.call_count == 2
        assert mock_api_writes.post.call_args_list[0][0][0] == "unbound.service.dnsbl"
        assert mock_api_writes.post.call_args_list[1][0][0] == "unbound.service.reconfigure"
        assert result["dnsbl_status"] == "OK"
        assert result["service_status"] == "ok"

    async def test_invalidates_cache(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(side_effect=[{"status": "OK"}, {"status": "ok"}])
        await opn_update_dnsbl(mock_ctx_writes)
        cache = mock_ctx_writes.lifespan_context["config_cache"]
        assert cache.is_stale

    async def test_handles_missing_status(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(side_effect=[{}, {}])
        result = await opn_update_dnsbl(mock_ctx_writes)
        assert result["dnsbl_status"] == "unknown"
        assert result["service_status"] == "unknown"


class TestOpnUpdateDnsOverride:
    """Tests for opn_update_dns_override."""

    async def test_updates_with_partial_fields(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[{"result": "saved"}, {"status": "ok"}],
        )
        result = await opn_update_dns_override(
            mock_ctx_writes,
            uuid="dns-uuid-1",
            server="10.0.0.5",
        )
        set_call = mock_api_writes.post.call_args_list[0]
        assert set_call[0][0] == "unbound.set_host_override"
        assert set_call[0][1] == {"host": {"server": "10.0.0.5"}}
        assert set_call[1]["path_suffix"] == "dns-uuid-1"
        assert result["result"] == "saved"
        assert result["uuid"] == "dns-uuid-1"
        assert result["applied"] == "ok"

    async def test_updates_multiple_fields(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[{"result": "saved"}, {"status": "ok"}],
        )
        await opn_update_dns_override(
            mock_ctx_writes,
            uuid="dns-uuid-1",
            hostname="newhost",
            domain="example.com",
            server="10.0.0.1",
            description="Updated",
            enabled=False,
        )
        host = mock_api_writes.post.call_args_list[0][0][1]["host"]
        assert host["hostname"] == "newhost"
        assert host["domain"] == "example.com"
        assert host["server"] == "10.0.0.1"
        assert host["description"] == "Updated"
        assert host["enabled"] == "0"

    async def test_validates_hostname(self, mock_ctx_writes):
        result = await opn_update_dns_override(mock_ctx_writes, uuid="dns-uuid-1", hostname="invalid host!")
        assert "error" in result
        assert "hostname" in result["error"]

    async def test_validates_domain(self, mock_ctx_writes):
        result = await opn_update_dns_override(mock_ctx_writes, uuid="dns-uuid-1", domain="not valid!")
        assert "error" in result
        assert "domain" in result["error"]

    async def test_validates_server_ip(self, mock_ctx_writes):
        result = await opn_update_dns_override(mock_ctx_writes, uuid="dns-uuid-1", server="not-an-ip")
        assert "error" in result
        assert "server" in result["error"]

    async def test_requires_writes_enabled(self, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_update_dns_override(mock_ctx, uuid="dns-uuid-1", server="10.0.0.1")

    async def test_reconfigures_unbound_after_update(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[{"result": "saved"}, {"status": "ok"}],
        )
        await opn_update_dns_override(mock_ctx_writes, uuid="dns-uuid-1", server="10.0.0.1")
        assert mock_api_writes.post.call_args_list[1][0][0] == "unbound.service.reconfigure"

    async def test_invalidates_config_cache(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[{"result": "saved"}, {"status": "ok"}],
        )
        cache = mock_ctx_writes.lifespan_context["config_cache"]
        cache._stale = False
        await opn_update_dns_override(mock_ctx_writes, uuid="dns-uuid-1", server="10.0.0.1")
        assert cache._stale


class TestOpnDeleteDnsOverride:
    """Tests for opn_delete_dns_override."""

    async def test_deletes_and_reconfigures(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[{"result": "deleted"}, {"status": "ok"}],
        )
        result = await opn_delete_dns_override(mock_ctx_writes, uuid="dns-to-delete")
        mock_api_writes.post.assert_any_call("unbound.del_host_override", path_suffix="dns-to-delete")
        assert result["result"] == "deleted"
        assert result["uuid"] == "dns-to-delete"
        assert result["applied"] == "ok"

    async def test_requires_writes_enabled(self, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_delete_dns_override(mock_ctx, uuid="dns-uuid-1")

    async def test_reconfigures_unbound(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[{"result": "deleted"}, {"status": "ok"}],
        )
        await opn_delete_dns_override(mock_ctx_writes, uuid="dns-uuid-1")
        assert mock_api_writes.post.call_args_list[1][0][0] == "unbound.service.reconfigure"

    async def test_invalidates_config_cache(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[{"result": "deleted"}, {"status": "ok"}],
        )
        cache = mock_ctx_writes.lifespan_context["config_cache"]
        cache._stale = False
        await opn_delete_dns_override(mock_ctx_writes, uuid="dns-uuid-1")
        assert cache._stale
