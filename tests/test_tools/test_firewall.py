"""Tests for firewall tools."""

from __future__ import annotations

import copy
from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.api_client import OPNsenseAPIError, WriteDisabledError
from opnsense_mcp.tools.firewall import (
    opn_add_alias,
    opn_add_firewall_category,
    opn_add_firewall_rule,
    opn_add_icmpv6_rules,
    opn_add_nat_rule,
    opn_confirm_changes,
    opn_delete_alias,
    opn_delete_firewall_category,
    opn_delete_firewall_rule,
    opn_delete_nat_rule,
    opn_firewall_log,
    opn_list_firewall_aliases,
    opn_list_firewall_categories,
    opn_list_firewall_rules,
    opn_list_nat_rules,
    opn_set_rule_categories,
    opn_toggle_alias,
    opn_toggle_firewall_rule,
    opn_update_alias,
    opn_update_firewall_rule,
    opn_update_nat_rule,
)


class TestOpnListFirewallRules:
    """Tests for opn_list_firewall_rules."""

    async def test_calls_search_rule(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_list_firewall_rules(mock_ctx)
        mock_api.post.assert_called_once_with(
            "firewall.search_rule",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_phrase(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_firewall_rules(mock_ctx, search="LAN")
        mock_api.post.assert_called_once_with(
            "firewall.search_rule",
            {"current": 1, "rowCount": 50, "searchPhrase": "LAN"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_firewall_rules(mock_ctx, limit=1000)
        mock_api.post.assert_called_once_with(
            "firewall.search_rule",
            {"current": 1, "rowCount": 500, "searchPhrase": ""},
        )


class TestOpnListFirewallAliases:
    """Tests for opn_list_firewall_aliases."""

    async def test_calls_alias_search(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_list_firewall_aliases(mock_ctx)
        mock_api.post.assert_called_once_with(
            "firewall.alias.search",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_and_limit(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_firewall_aliases(mock_ctx, search="blocklist", limit=25)
        mock_api.post.assert_called_once_with(
            "firewall.alias.search",
            {"current": 1, "rowCount": 25, "searchPhrase": "blocklist"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_firewall_aliases(mock_ctx, limit=600)
        mock_api.post.assert_called_once_with(
            "firewall.alias.search",
            {"current": 1, "rowCount": 500, "searchPhrase": ""},
        )


class TestOpnFirewallLog:
    """Tests for opn_firewall_log."""

    _SAMPLE_ENTRIES = [
        {"src": "10.55.6.201", "dst": "43.157.31.62", "action": "block", "interface": "opt1"},
        {"src": "192.168.1.10", "dst": "8.8.8.8", "action": "pass", "interface": "lan"},
        {"src": "10.55.6.201", "dst": "120.53.71.194", "action": "pass", "interface": "opt1"},
        {"src": "192.168.1.20", "dst": "1.1.1.1", "action": "block", "interface": "lan"},
    ]

    async def test_calls_firewall_log(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value=self._SAMPLE_ENTRIES)
        result = await opn_firewall_log(mock_ctx)
        mock_api.get.assert_called_once_with("firewall.log")
        assert result["total"] == 4
        assert len(result["entries"]) == 4

    async def test_filter_by_source_ip(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value=self._SAMPLE_ENTRIES)
        result = await opn_firewall_log(mock_ctx, source_ip="10.55.6.201")
        assert result["total"] == 2
        assert all("10.55.6.201" in e["src"] for e in result["entries"])

    async def test_filter_by_destination_ip(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value=self._SAMPLE_ENTRIES)
        result = await opn_firewall_log(mock_ctx, destination_ip="8.8.8.8")
        assert result["total"] == 1
        assert result["entries"][0]["dst"] == "8.8.8.8"

    async def test_filter_by_action(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value=self._SAMPLE_ENTRIES)
        result = await opn_firewall_log(mock_ctx, action="block")
        assert result["total"] == 2
        assert all(e["action"] == "block" for e in result["entries"])

    async def test_filter_by_interface(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value=self._SAMPLE_ENTRIES)
        result = await opn_firewall_log(mock_ctx, interface="opt1")
        assert result["total"] == 2

    async def test_combined_filters(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value=self._SAMPLE_ENTRIES)
        result = await opn_firewall_log(mock_ctx, source_ip="10.55.6.201", action="block")
        assert result["total"] == 1
        assert result["entries"][0]["dst"] == "43.157.31.62"

    async def test_limit_caps_results(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value=self._SAMPLE_ENTRIES)
        result = await opn_firewall_log(mock_ctx, limit=2)
        assert result["total"] == 4
        assert len(result["entries"]) == 2

    async def test_no_filter_returns_all(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"rows": self._SAMPLE_ENTRIES})
        result = await opn_firewall_log(mock_ctx)
        assert result["total"] == 4

    async def test_no_matches_returns_empty(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value=self._SAMPLE_ENTRIES)
        result = await opn_firewall_log(mock_ctx, source_ip="99.99.99.99")
        assert result["total"] == 0
        assert result["entries"] == []


class TestOpnConfirmChanges:
    """Tests for opn_confirm_changes."""

    async def test_calls_savepoint_confirm(self, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.confirm = AsyncMock(return_value={"status": "ok"})
        result = await opn_confirm_changes(mock_ctx_writes, revision="rev-abc-123")
        mock_savepoint_mgr.confirm.assert_called_once_with("rev-abc-123")
        assert result == {"status": "ok"}

    async def test_passes_revision_correctly(self, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.confirm = AsyncMock(return_value={"status": "ok"})
        await opn_confirm_changes(mock_ctx_writes, revision="rev-xyz-789")
        mock_savepoint_mgr.confirm.assert_called_once_with("rev-xyz-789")

    async def test_returns_confirmation_result(self, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.confirm = AsyncMock(return_value={"status": "confirmed", "revision": "rev-123"})
        result = await opn_confirm_changes(mock_ctx_writes, revision="rev-123")
        assert result == {"status": "confirmed", "revision": "rev-123"}


class TestOpnToggleFirewallRule:
    """Tests for opn_toggle_firewall_rule."""

    async def test_creates_savepoint_toggles_and_applies(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-toggle-1")
        mock_api_writes.post = AsyncMock(return_value={"changed": True})
        mock_savepoint_mgr.apply = AsyncMock(return_value={"status": "ok"})
        result = await opn_toggle_firewall_rule(mock_ctx_writes, uuid="rule-uuid-1")
        mock_savepoint_mgr.create.assert_called_once()
        mock_api_writes.post.assert_called_once_with("firewall.toggle_rule", path_suffix="rule-uuid-1")
        mock_savepoint_mgr.apply.assert_called_once_with("rev-toggle-1")
        assert result["revision"] == "rev-toggle-1"
        assert result["uuid"] == "rule-uuid-1"

    async def test_returns_revision_for_confirmation(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-toggle-2")
        mock_api_writes.post = AsyncMock(return_value={})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        result = await opn_toggle_firewall_rule(mock_ctx_writes, uuid="rule-uuid-2")
        assert "revision" in result
        assert "message" in result

    async def test_fails_when_writes_disabled(self, mock_ctx_no_writes):
        with pytest.raises(WriteDisabledError):
            await opn_toggle_firewall_rule(mock_ctx_no_writes, uuid="rule-uuid-1")

    async def test_returns_error_on_api_failure(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-toggle-err")
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Toggle failed"))
        result = await opn_toggle_firewall_rule(mock_ctx_writes, uuid="rule-uuid-1")
        assert "error" in result
        assert result["revision"] == "rev-toggle-err"


class TestOpnAddFirewallRule:
    """Tests for opn_add_firewall_rule."""

    async def test_creates_rule_with_defaults(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-add-1")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "new-rule-uuid"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        result = await opn_add_firewall_rule(mock_ctx_writes)
        call_args = mock_api_writes.post.call_args
        assert call_args[0][0] == "firewall.add_rule"
        rule = call_args[0][1]["rule"]
        assert rule["action"] == "pass"
        assert rule["direction"] == "in"
        assert rule["quick"] == "1"
        assert rule["enabled"] == "1"
        assert rule["source_not"] == "0"
        assert rule["destination_not"] == "0"
        assert rule["log"] == "0"
        assert rule["sequence"] == "1"
        assert result["uuid"] == "new-rule-uuid"
        assert result["revision"] == "rev-add-1"

    async def test_quick_defaults_to_1(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-add-q")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "uuid-q"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_add_firewall_rule(mock_ctx_writes, action="block", direction="out")
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert rule["quick"] == "1"

    async def test_quick_false(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-add-qf")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "uuid-qf"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_add_firewall_rule(mock_ctx_writes, quick=False)
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert rule["quick"] == "0"

    async def test_accepts_inet46(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-add-46")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "uuid-46"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        result = await opn_add_firewall_rule(mock_ctx_writes, ip_protocol="inet46")
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert rule["ipprotocol"] == "inet46"
        assert result["uuid"] == "uuid-46"

    async def test_validates_action(self, mock_ctx_writes):
        result = await opn_add_firewall_rule(mock_ctx_writes, action="allow")
        assert "error" in result
        assert "action" in result["error"]

    async def test_validates_direction(self, mock_ctx_writes):
        result = await opn_add_firewall_rule(mock_ctx_writes, direction="forward")
        assert "error" in result
        assert "direction" in result["error"]

    async def test_passes_custom_parameters(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-add-c")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "uuid-c"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_add_firewall_rule(
            mock_ctx_writes,
            action="block",
            direction="out",
            interface="wan",
            ip_protocol="inet6",
            protocol="TCP",
            source_net="192.168.1.0/24",
            source_not=True,
            source_port="1024-65535",
            destination_net="10.0.0.0/8",
            destination_not=True,
            destination_port="443",
            gateway="WAN_GW",
            log=True,
            quick=False,
            sequence=50,
            categories="cat-uuid-1,cat-uuid-2",
            description="Block outbound HTTPS",
        )
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert rule["action"] == "block"
        assert rule["direction"] == "out"
        assert rule["interface"] == "wan"
        assert rule["ipprotocol"] == "inet6"
        assert rule["protocol"] == "TCP"
        assert rule["source_net"] == "192.168.1.0/24"
        assert rule["source_not"] == "1"
        assert rule["source_port"] == "1024-65535"
        assert rule["destination_net"] == "10.0.0.0/8"
        assert rule["destination_not"] == "1"
        assert rule["destination_port"] == "443"
        assert rule["gateway"] == "WAN_GW"
        assert rule["log"] == "1"
        assert rule["quick"] == "0"
        assert rule["sequence"] == "50"
        assert rule["categories"] == "cat-uuid-1,cat-uuid-2"
        assert rule["description"] == "Block outbound HTTPS"

    async def test_destination_not(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-add-dn")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "uuid-dn"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_add_firewall_rule(mock_ctx_writes, destination_net="Private_Networks", destination_not=True)
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert rule["destination_not"] == "1"
        assert rule["destination_net"] == "Private_Networks"

    async def test_source_not(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-add-sn")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "uuid-sn"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_add_firewall_rule(mock_ctx_writes, source_not=True)
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert rule["source_not"] == "1"

    async def test_sequence(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-add-seq")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "uuid-seq"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_add_firewall_rule(mock_ctx_writes, sequence=2121)
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert rule["sequence"] == "2121"

    async def test_log_enabled(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-add-log")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "uuid-log"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_add_firewall_rule(mock_ctx_writes, log=True)
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert rule["log"] == "1"

    async def test_gateway(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-add-gw")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "uuid-gw"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_add_firewall_rule(mock_ctx_writes, gateway="WAN_DHCP")
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert rule["gateway"] == "WAN_DHCP"

    async def test_categories(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-add-cat")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "uuid-cat"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_add_firewall_rule(mock_ctx_writes, categories="uuid-a,uuid-b")
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert rule["categories"] == "uuid-a,uuid-b"

    async def test_source_port(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-add-sp")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "uuid-sp"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_add_firewall_rule(mock_ctx_writes, source_port="1024-65535")
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert rule["source_port"] == "1024-65535"

    async def test_omits_empty_optional_strings(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-add-p")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "uuid-p"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_add_firewall_rule(mock_ctx_writes)
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert "destination_port" not in rule
        assert "source_port" not in rule
        assert "gateway" not in rule
        assert "categories" not in rule

    async def test_fails_when_writes_disabled(self, mock_ctx_no_writes):
        with pytest.raises(WriteDisabledError):
            await opn_add_firewall_rule(mock_ctx_no_writes)

    async def test_returns_error_on_api_failure(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-add-err")
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Validation error"))
        result = await opn_add_firewall_rule(mock_ctx_writes)
        assert "error" in result
        assert result["revision"] == "rev-add-err"


class TestOpnDeleteFirewallRule:
    """Tests for opn_delete_firewall_rule."""

    async def test_creates_savepoint_deletes_and_applies(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-del-1")
        mock_api_writes.post = AsyncMock(return_value={"result": "deleted"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        result = await opn_delete_firewall_rule(mock_ctx_writes, uuid="rule-to-delete")
        mock_api_writes.post.assert_called_once_with("firewall.del_rule", path_suffix="rule-to-delete")
        mock_savepoint_mgr.apply.assert_called_once_with("rev-del-1")
        assert result["revision"] == "rev-del-1"
        assert result["result"] == "deleted"

    async def test_returns_revision_for_confirmation(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-del-2")
        mock_api_writes.post = AsyncMock(return_value={"result": "deleted"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        result = await opn_delete_firewall_rule(mock_ctx_writes, uuid="rule-uuid-2")
        assert result["revision"] == "rev-del-2"
        assert result["uuid"] == "rule-uuid-2"

    async def test_fails_when_writes_disabled(self, mock_ctx_no_writes):
        with pytest.raises(WriteDisabledError):
            await opn_delete_firewall_rule(mock_ctx_no_writes, uuid="rule-uuid-1")

    async def test_returns_error_on_api_failure(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-del-err")
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Rule not found"))
        result = await opn_delete_firewall_rule(mock_ctx_writes, uuid="bad-uuid")
        assert "error" in result
        assert result["revision"] == "rev-del-err"


class TestOpnAddAlias:
    """Tests for opn_add_alias."""

    async def test_creates_alias_with_correct_payload(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "alias-uuid-1"})
        result = await opn_add_alias(
            mock_ctx_writes,
            name="my_hosts",
            content="192.168.1.1\n192.168.1.2",
        )
        call_args = mock_api_writes.post.call_args
        assert call_args[0][0] == "firewall.alias.add"
        alias = call_args[0][1]["alias"]
        assert alias["name"] == "my_hosts"
        assert alias["type"] == "host"
        assert alias["content"] == "192.168.1.1\n192.168.1.2"
        assert alias["enabled"] == "1"
        assert result["uuid"] == "alias-uuid-1"
        assert result["name"] == "my_hosts"

    async def test_requires_writes_enabled(self, mock_api, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_add_alias(mock_ctx, name="test_alias")

    async def test_validates_alias_type(self, mock_ctx_writes):
        result = await opn_add_alias(mock_ctx_writes, name="test", alias_type="invalid")
        assert "error" in result
        assert "alias_type" in result["error"]

    async def test_validates_name_no_spaces(self, mock_ctx_writes):
        result = await opn_add_alias(mock_ctx_writes, name="my hosts")
        assert "error" in result
        assert "name" in result["error"]

    async def test_validates_name_no_special_chars(self, mock_ctx_writes):
        result = await opn_add_alias(mock_ctx_writes, name="my-hosts!")
        assert "error" in result

    async def test_passes_geoip_type(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "geo-uuid"})
        await opn_add_alias(
            mock_ctx_writes,
            name="eu_countries",
            alias_type="geoip",
            content="DE\nFR\nNL",
        )
        alias = mock_api_writes.post.call_args[0][1]["alias"]
        assert alias["type"] == "geoip"
        assert alias["content"] == "DE\nFR\nNL"


class TestOpnListNatRules:
    """Tests for opn_list_nat_rules."""

    async def test_calls_nat_search_rule(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_list_nat_rules(mock_ctx)
        mock_api.post.assert_called_once_with(
            "nat.dnat.search_rule",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_phrase(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_nat_rules(mock_ctx, search="web")
        mock_api.post.assert_called_once_with(
            "nat.dnat.search_rule",
            {"current": 1, "rowCount": 50, "searchPhrase": "web"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_nat_rules(mock_ctx, limit=1000)
        mock_api.post.assert_called_once_with(
            "nat.dnat.search_rule",
            {"current": 1, "rowCount": 500, "searchPhrase": ""},
        )

    async def test_passes_custom_limit(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_nat_rules(mock_ctx, limit=25)
        call_args = mock_api.post.call_args
        assert call_args[0][1]["rowCount"] == 25


class TestOpnAddNatRule:
    """Tests for opn_add_nat_rule."""

    async def test_creates_nat_rule_with_savepoint(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-nat-1")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "nat-uuid-1"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        result = await opn_add_nat_rule(
            mock_ctx_writes,
            destination_port="8080",
            target_ip="192.168.1.100",
            target_port="80",
        )
        mock_savepoint_mgr.create.assert_called_once()
        mock_savepoint_mgr.apply.assert_called_once_with("rev-nat-1")
        assert result["revision"] == "rev-nat-1"
        assert result["uuid"] == "nat-uuid-1"

    async def test_defaults_target_port_to_destination_port(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-nat-2")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "nat-uuid-2"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_add_nat_rule(
            mock_ctx_writes,
            destination_port="443",
            target_ip="192.168.1.100",
        )
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert rule["target_port"] == "443"

    async def test_requires_destination_port(self, mock_ctx_writes):
        result = await opn_add_nat_rule(mock_ctx_writes, target_ip="192.168.1.1")
        assert "error" in result
        assert "destination_port" in result["error"]

    async def test_requires_target_ip(self, mock_ctx_writes):
        result = await opn_add_nat_rule(mock_ctx_writes, destination_port="80")
        assert "error" in result
        assert "target_ip" in result["error"]

    async def test_validates_protocol(self, mock_ctx_writes):
        result = await opn_add_nat_rule(
            mock_ctx_writes,
            destination_port="80",
            target_ip="192.168.1.1",
            protocol="ICMP",
        )
        assert "error" in result
        assert "protocol" in result["error"]

    async def test_fails_when_writes_disabled(self, mock_ctx_no_writes):
        with pytest.raises(WriteDisabledError):
            await opn_add_nat_rule(
                mock_ctx_no_writes,
                destination_port="80",
                target_ip="192.168.1.1",
            )

    async def test_returns_error_on_api_failure(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-nat-err")
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Validation failed"))
        result = await opn_add_nat_rule(
            mock_ctx_writes,
            destination_port="80",
            target_ip="192.168.1.1",
        )
        assert "error" in result
        assert result["revision"] == "rev-nat-err"

    async def test_passes_all_parameters(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-nat-all")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "nat-all"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_add_nat_rule(
            mock_ctx_writes,
            interface="opt1",
            protocol="UDP",
            destination_port="51820",
            target_ip="10.0.0.5",
            target_port="51820",
            description="WireGuard forward",
        )
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert rule["interface"] == "opt1"
        assert rule["protocol"] == "UDP"
        assert rule["destination_port"] == "51820"
        assert rule["target_ip"] == "10.0.0.5"
        assert rule["description"] == "WireGuard forward"


class TestOpnListFirewallCategories:
    """Tests for opn_list_firewall_categories."""

    async def test_calls_category_search(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_list_firewall_categories(mock_ctx)
        mock_api.post.assert_called_once_with(
            "firewall.category.search",
            {"current": 1, "rowCount": 100, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_phrase(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_firewall_categories(mock_ctx, search="web")
        mock_api.post.assert_called_once_with(
            "firewall.category.search",
            {"current": 1, "rowCount": 100, "searchPhrase": "web"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_firewall_categories(mock_ctx, limit=1000)
        mock_api.post.assert_called_once_with(
            "firewall.category.search",
            {"current": 1, "rowCount": 500, "searchPhrase": ""},
        )


class TestOpnAddFirewallCategory:
    """Tests for opn_add_firewall_category."""

    async def test_creates_category(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "cat-uuid-1"})
        result = await opn_add_firewall_category(mock_ctx_writes, name="Web Services", color="0000ff")
        call_args = mock_api_writes.post.call_args
        assert call_args[0][0] == "firewall.category.add"
        cat = call_args[0][1]["category"]
        assert cat["name"] == "Web Services"
        assert cat["color"] == "0000ff"
        assert cat["auto"] == "0"
        assert result["uuid"] == "cat-uuid-1"
        assert result["name"] == "Web Services"

    async def test_rejects_empty_name(self, mock_ctx_writes):
        result = await opn_add_firewall_category(mock_ctx_writes, name="")
        assert "error" in result

    async def test_rejects_name_with_comma(self, mock_ctx_writes):
        result = await opn_add_firewall_category(mock_ctx_writes, name="web,dns")
        assert "error" in result
        assert "comma" in result["error"].lower()

    async def test_rejects_invalid_hex_color(self, mock_ctx_writes):
        result = await opn_add_firewall_category(mock_ctx_writes, name="test", color="ZZZZZZ")
        assert "error" in result
        assert "color" in result["error"].lower()

    async def test_rejects_short_hex_color(self, mock_ctx_writes):
        result = await opn_add_firewall_category(mock_ctx_writes, name="test", color="FFF")
        assert "error" in result

    async def test_requires_writes_enabled(self, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_add_firewall_category(mock_ctx, name="test")


class TestOpnDeleteFirewallCategory:
    """Tests for opn_delete_firewall_category."""

    async def test_deletes_with_savepoint(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-cat-del-1")
        mock_api_writes.post = AsyncMock(return_value={"result": "deleted"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        result = await opn_delete_firewall_category(mock_ctx_writes, uuid="cat-to-delete")
        mock_savepoint_mgr.create.assert_called_once()
        mock_api_writes.post.assert_called_once_with("firewall.category.del", path_suffix="cat-to-delete")
        mock_savepoint_mgr.apply.assert_called_once_with("rev-cat-del-1")
        assert result["revision"] == "rev-cat-del-1"
        assert result["result"] == "deleted"

    async def test_fails_when_writes_disabled(self, mock_ctx_no_writes):
        with pytest.raises(WriteDisabledError):
            await opn_delete_firewall_category(mock_ctx_no_writes, uuid="cat-uuid-1")

    async def test_returns_error_on_api_failure(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-cat-del-err")
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Category not found"))
        result = await opn_delete_firewall_category(mock_ctx_writes, uuid="bad-uuid")
        assert "error" in result
        assert result["revision"] == "rev-cat-del-err"


class TestOpnSetRuleCategories:
    """Tests for opn_set_rule_categories."""

    async def test_assigns_categories_with_savepoint(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-setcat-1")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        result = await opn_set_rule_categories(mock_ctx_writes, uuid="rule-uuid-1", categories="cat-a,cat-b")
        mock_savepoint_mgr.create.assert_called_once()
        mock_api_writes.post.assert_called_once_with(
            "firewall.set_rule",
            {"rule": {"categories": "cat-a,cat-b"}},
            path_suffix="rule-uuid-1",
        )
        mock_savepoint_mgr.apply.assert_called_once_with("rev-setcat-1")
        assert result["revision"] == "rev-setcat-1"
        assert result["uuid"] == "rule-uuid-1"

    async def test_clears_categories_with_empty_string(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-setcat-clear")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        result = await opn_set_rule_categories(mock_ctx_writes, uuid="rule-uuid-2", categories="")
        call_args = mock_api_writes.post.call_args
        assert call_args[0][1]["rule"]["categories"] == ""
        assert result["revision"] == "rev-setcat-clear"

    async def test_returns_error_on_api_failure(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-setcat-err")
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Rule not found"))
        result = await opn_set_rule_categories(mock_ctx_writes, uuid="bad-rule", categories="cat-a")
        assert "error" in result
        assert result["revision"] == "rev-setcat-err"

    async def test_fails_when_writes_disabled(self, mock_ctx_no_writes):
        with pytest.raises(WriteDisabledError):
            await opn_set_rule_categories(mock_ctx_no_writes, uuid="rule-uuid-1", categories="cat-a")

    async def test_invalidates_config_cache(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-setcat-cache")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        cache = mock_ctx_writes.lifespan_context["config_cache"]
        cache._stale = False
        await opn_set_rule_categories(mock_ctx_writes, uuid="rule-uuid-3", categories="cat-c")
        assert cache._stale


class TestOpnAddIcmpv6Rules:
    """Tests for opn_add_icmpv6_rules."""

    async def test_creates_5_icmpv6_rules(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-icmpv6-1")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "icmpv6-uuid"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        result = await opn_add_icmpv6_rules(mock_ctx_writes, interface="lan")
        assert result["rules_created"] == 5
        assert len(result["uuids"]) == 5
        assert result["revision"] == "rev-icmpv6-1"
        assert result["interface"] == "lan"

    async def test_all_rules_are_inet6(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-icmpv6-2")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "uuid"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_add_icmpv6_rules(mock_ctx_writes, interface="opt1")
        for call in mock_api_writes.post.call_args_list:
            if call[0][0] == "firewall.add_rule":
                rule = call[0][1]["rule"]
                assert rule["ipprotocol"] == "inet6"
                assert rule["protocol"] == "ICMPv6"
                assert rule["action"] == "pass"
                assert rule["interface"] == "opt1"

    async def test_handles_partial_api_failure(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-icmpv6-partial")
        call_count = 0

        async def alternating_result(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 3:
                raise OPNsenseAPIError("API error on rule 3")
            return {"result": "saved", "uuid": f"uuid-{call_count}"}

        mock_api_writes.post = AsyncMock(side_effect=alternating_result)
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        result = await opn_add_icmpv6_rules(mock_ctx_writes, interface="lan")
        assert result["rules_created"] == 4
        assert len(result["errors"]) == 1
        assert "rule 3" in result["errors"][0]

    async def test_fails_when_writes_disabled(self, mock_ctx_no_writes):
        with pytest.raises(WriteDisabledError):
            await opn_add_icmpv6_rules(mock_ctx_no_writes, interface="lan")


class TestOpnUpdateAlias:
    """Tests for opn_update_alias."""

    _CURRENT_ALIAS = {
        "alias": {
            "name": "my_hosts",
            "type": "host",
            "content": "192.168.1.1\n192.168.1.2",
            "description": "My hosts",
            "enabled": "1",
            "proto": "",
        },
    }

    async def test_updates_name_only(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(side_effect=lambda *a, **kw: copy.deepcopy(self._CURRENT_ALIAS))
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        result = await opn_update_alias(mock_ctx_writes, uuid="alias-uuid-1", name="renamed_hosts")
        alias = mock_api_writes.post.call_args[0][1]["alias"]
        assert alias["name"] == "renamed_hosts"
        assert alias["type"] == "host"
        assert alias["content"] == "192.168.1.1\n192.168.1.2"
        assert result["result"] == "saved"
        assert result["uuid"] == "alias-uuid-1"

    async def test_updates_content_only(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(side_effect=lambda *a, **kw: copy.deepcopy(self._CURRENT_ALIAS))
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        await opn_update_alias(mock_ctx_writes, uuid="alias-uuid-1", content="10.0.0.1\n10.0.0.2")
        alias = mock_api_writes.post.call_args[0][1]["alias"]
        assert alias["content"] == "10.0.0.1\n10.0.0.2"
        assert alias["name"] == "my_hosts"

    async def test_updates_multiple_fields(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(side_effect=lambda *a, **kw: copy.deepcopy(self._CURRENT_ALIAS))
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        await opn_update_alias(
            mock_ctx_writes,
            uuid="alias-uuid-1",
            name="new_name",
            content="10.0.0.0/24",
            alias_type="network",
            description="Updated",
            enabled=False,
        )
        alias = mock_api_writes.post.call_args[0][1]["alias"]
        assert alias["name"] == "new_name"
        assert alias["content"] == "10.0.0.0/24"
        assert alias["type"] == "network"
        assert alias["description"] == "Updated"
        assert alias["enabled"] == "0"

    async def test_validates_name_regex(self, mock_ctx_writes):
        result = await opn_update_alias(mock_ctx_writes, uuid="alias-uuid-1", name="invalid name!")
        assert "error" in result
        assert "name" in result["error"]

    async def test_validates_alias_type(self, mock_ctx_writes):
        result = await opn_update_alias(mock_ctx_writes, uuid="alias-uuid-1", alias_type="bogus")
        assert "error" in result
        assert "alias_type" in result["error"]

    async def test_requires_writes_enabled(self, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_update_alias(mock_ctx, uuid="alias-uuid-1", name="new")

    async def test_invalidates_config_cache(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(side_effect=lambda *a, **kw: copy.deepcopy(self._CURRENT_ALIAS))
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        cache = mock_ctx_writes.lifespan_context["config_cache"]
        cache._stale = False
        await opn_update_alias(mock_ctx_writes, uuid="alias-uuid-1", name="new")
        assert cache._stale

    async def test_calls_get_then_set(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(side_effect=lambda *a, **kw: copy.deepcopy(self._CURRENT_ALIAS))
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        await opn_update_alias(mock_ctx_writes, uuid="alias-uuid-1", name="new")
        mock_api_writes.get.assert_called_once_with("firewall.alias.get", path_suffix="alias-uuid-1")
        mock_api_writes.post.assert_called_once()
        assert mock_api_writes.post.call_args[0][0] == "firewall.alias.set"
        assert mock_api_writes.post.call_args[1]["path_suffix"] == "alias-uuid-1"


class TestOpnDeleteAlias:
    """Tests for opn_delete_alias."""

    async def test_deletes_by_uuid(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "deleted"})
        result = await opn_delete_alias(mock_ctx_writes, uuid="alias-to-delete")
        mock_api_writes.post.assert_called_once_with("firewall.alias.del", path_suffix="alias-to-delete")
        assert result["result"] == "deleted"
        assert result["uuid"] == "alias-to-delete"

    async def test_requires_writes_enabled(self, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_delete_alias(mock_ctx, uuid="alias-uuid-1")

    async def test_invalidates_config_cache(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "deleted"})
        cache = mock_ctx_writes.lifespan_context["config_cache"]
        cache._stale = False
        await opn_delete_alias(mock_ctx_writes, uuid="alias-uuid-1")
        assert cache._stale

    async def test_returns_result(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "deleted"})
        result = await opn_delete_alias(mock_ctx_writes, uuid="alias-uuid-1")
        assert "result" in result
        assert "uuid" in result


class TestOpnToggleAlias:
    """Tests for opn_toggle_alias."""

    async def test_toggles_by_uuid(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "toggled"})
        result = await opn_toggle_alias(mock_ctx_writes, uuid="alias-toggle-1")
        mock_api_writes.post.assert_called_once_with("firewall.alias.toggle", path_suffix="alias-toggle-1")
        assert result["result"] == "toggled"
        assert result["uuid"] == "alias-toggle-1"

    async def test_requires_writes_enabled(self, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_toggle_alias(mock_ctx, uuid="alias-uuid-1")

    async def test_invalidates_config_cache(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "toggled"})
        cache = mock_ctx_writes.lifespan_context["config_cache"]
        cache._stale = False
        await opn_toggle_alias(mock_ctx_writes, uuid="alias-uuid-1")
        assert cache._stale

    async def test_returns_result(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "toggled"})
        result = await opn_toggle_alias(mock_ctx_writes, uuid="alias-uuid-1")
        assert "result" in result
        assert "uuid" in result


class TestOpnUpdateFirewallRule:
    """Tests for opn_update_firewall_rule."""

    async def test_updates_with_savepoint(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-upd-1")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        result = await opn_update_firewall_rule(
            mock_ctx_writes,
            uuid="rule-uuid-1",
            action="block",
            description="Updated rule",
        )
        mock_savepoint_mgr.create.assert_called_once()
        mock_api_writes.post.assert_called_once_with(
            "firewall.set_rule",
            {"rule": {"action": "block", "description": "Updated rule"}},
            path_suffix="rule-uuid-1",
        )
        mock_savepoint_mgr.apply.assert_called_once_with("rev-upd-1")
        assert result["revision"] == "rev-upd-1"
        assert result["uuid"] == "rule-uuid-1"

    async def test_sends_only_provided_fields(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-upd-partial")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_update_firewall_rule(mock_ctx_writes, uuid="rule-uuid-1", destination_port="443")
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert rule == {"destination_port": "443"}

    async def test_converts_bool_fields(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-upd-bool")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_update_firewall_rule(
            mock_ctx_writes,
            uuid="rule-uuid-1",
            log=True,
            quick=False,
            source_not=True,
            destination_not=False,
            enabled=False,
        )
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert rule["log"] == "1"
        assert rule["quick"] == "0"
        assert rule["source_not"] == "1"
        assert rule["destination_not"] == "0"
        assert rule["enabled"] == "0"

    async def test_converts_sequence_to_string(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-upd-seq")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_update_firewall_rule(mock_ctx_writes, uuid="rule-uuid-1", sequence=42)
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert rule["sequence"] == "42"

    async def test_validates_action_if_provided(self, mock_ctx_writes):
        result = await opn_update_firewall_rule(mock_ctx_writes, uuid="rule-uuid-1", action="allow")
        assert "error" in result
        assert "action" in result["error"]

    async def test_validates_direction_if_provided(self, mock_ctx_writes):
        result = await opn_update_firewall_rule(mock_ctx_writes, uuid="rule-uuid-1", direction="forward")
        assert "error" in result
        assert "direction" in result["error"]

    async def test_validates_ip_protocol_if_provided(self, mock_ctx_writes):
        result = await opn_update_firewall_rule(mock_ctx_writes, uuid="rule-uuid-1", ip_protocol="ipv4")
        assert "error" in result
        assert "ip_protocol" in result["error"]

    async def test_fails_when_writes_disabled(self, mock_ctx_no_writes):
        with pytest.raises(WriteDisabledError):
            await opn_update_firewall_rule(mock_ctx_no_writes, uuid="rule-uuid-1", action="block")

    async def test_returns_error_on_api_failure(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-upd-err")
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Validation error"))
        result = await opn_update_firewall_rule(mock_ctx_writes, uuid="rule-uuid-1", action="block")
        assert "error" in result
        assert result["revision"] == "rev-upd-err"

    async def test_invalidates_config_cache(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-upd-cache")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        cache = mock_ctx_writes.lifespan_context["config_cache"]
        cache._stale = False
        await opn_update_firewall_rule(mock_ctx_writes, uuid="rule-uuid-1", action="pass")
        assert cache._stale


class TestOpnUpdateNatRule:
    """Tests for opn_update_nat_rule."""

    async def test_updates_with_savepoint(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-nat-upd-1")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        result = await opn_update_nat_rule(
            mock_ctx_writes,
            uuid="nat-uuid-1",
            target_ip="10.0.0.5",
        )
        mock_savepoint_mgr.create.assert_called_once()
        mock_api_writes.post.assert_called_once_with(
            "nat.dnat.set_rule",
            {"rule": {"target_ip": "10.0.0.5"}},
            path_suffix="nat-uuid-1",
        )
        mock_savepoint_mgr.apply.assert_called_once_with("rev-nat-upd-1")
        assert result["revision"] == "rev-nat-upd-1"
        assert result["uuid"] == "nat-uuid-1"

    async def test_sends_only_provided_fields(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-nat-upd-partial")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_update_nat_rule(
            mock_ctx_writes,
            uuid="nat-uuid-1",
            target_port="8080",
            description="Updated",
        )
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert rule == {"target_port": "8080", "description": "Updated"}

    async def test_validates_protocol_if_provided(self, mock_ctx_writes):
        result = await opn_update_nat_rule(mock_ctx_writes, uuid="nat-uuid-1", protocol="ICMP")
        assert "error" in result
        assert "protocol" in result["error"]

    async def test_converts_enabled_bool(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-nat-upd-en")
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        await opn_update_nat_rule(mock_ctx_writes, uuid="nat-uuid-1", enabled=False)
        rule = mock_api_writes.post.call_args[0][1]["rule"]
        assert rule["enabled"] == "0"

    async def test_fails_when_writes_disabled(self, mock_ctx_no_writes):
        with pytest.raises(WriteDisabledError):
            await opn_update_nat_rule(mock_ctx_no_writes, uuid="nat-uuid-1", target_ip="10.0.0.1")

    async def test_returns_error_on_api_failure(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-nat-upd-err")
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("NAT error"))
        result = await opn_update_nat_rule(mock_ctx_writes, uuid="nat-uuid-1", target_ip="10.0.0.1")
        assert "error" in result
        assert result["revision"] == "rev-nat-upd-err"


class TestOpnDeleteNatRule:
    """Tests for opn_delete_nat_rule."""

    async def test_deletes_with_savepoint(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-nat-del-1")
        mock_api_writes.post = AsyncMock(return_value={"result": "deleted"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        result = await opn_delete_nat_rule(mock_ctx_writes, uuid="nat-to-delete")
        mock_api_writes.post.assert_called_once_with("nat.dnat.del_rule", path_suffix="nat-to-delete")
        mock_savepoint_mgr.apply.assert_called_once_with("rev-nat-del-1")
        assert result["revision"] == "rev-nat-del-1"
        assert result["result"] == "deleted"

    async def test_returns_revision_for_confirmation(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-nat-del-2")
        mock_api_writes.post = AsyncMock(return_value={"result": "deleted"})
        mock_savepoint_mgr.apply = AsyncMock(return_value={})
        result = await opn_delete_nat_rule(mock_ctx_writes, uuid="nat-uuid-2")
        assert result["revision"] == "rev-nat-del-2"
        assert result["uuid"] == "nat-uuid-2"

    async def test_fails_when_writes_disabled(self, mock_ctx_no_writes):
        with pytest.raises(WriteDisabledError):
            await opn_delete_nat_rule(mock_ctx_no_writes, uuid="nat-uuid-1")

    async def test_returns_error_on_api_failure(self, mock_api_writes, mock_savepoint_mgr, mock_ctx_writes):
        mock_savepoint_mgr.create = AsyncMock(return_value="rev-nat-del-err")
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("NAT rule not found"))
        result = await opn_delete_nat_rule(mock_ctx_writes, uuid="bad-nat-uuid")
        assert "error" in result
        assert result["revision"] == "rev-nat-del-err"
