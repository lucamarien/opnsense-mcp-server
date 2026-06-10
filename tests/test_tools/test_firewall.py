"""Tests for firewall tools (manage_X surface, v0.5)."""

from __future__ import annotations

from unittest.mock import AsyncMock

from opnsense_mcp.api_client import OPNsenseAPIError
from opnsense_mcp.tools.firewall import (
    opn_add_icmpv6_rules,
    opn_confirm_changes,
    opn_firewall_log,
    opn_list_firewall_aliases,
    opn_list_firewall_categories,
    opn_list_firewall_rules,
    opn_list_nat_rules,
    opn_manage_alias,
    opn_manage_firewall_category,
    opn_manage_firewall_rule,
    opn_manage_nat_rule,
)

# ---------------------------------------------------------------------------
# Read tools
# ---------------------------------------------------------------------------


class TestOpnListFirewallRules:
    async def test_calls_search_rule(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_list_firewall_rules(mock_ctx)
        mock_api.post.assert_called_once_with(
            "firewall.search_rule",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_phrase(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": []})
        await opn_list_firewall_rules(mock_ctx, search="ssh", limit=10)
        mock_api.post.assert_called_once_with(
            "firewall.search_rule",
            {"current": 1, "rowCount": 10, "searchPhrase": "ssh"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": []})
        await opn_list_firewall_rules(mock_ctx, limit=9999)
        assert mock_api.post.call_args[0][1]["rowCount"] == 500

    async def test_limit_clamped_below(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": []})
        await opn_list_firewall_rules(mock_ctx, limit=-1)
        assert mock_api.post.call_args[0][1]["rowCount"] == 1

    async def test_api_error_returns_envelope(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(side_effect=OPNsenseAPIError("boom", status_code=500))
        result = await opn_list_firewall_rules(mock_ctx)
        assert result["error_type"] == "api"
        assert result["status_code"] == 500


class TestOpnListFirewallAliases:
    async def test_calls_alias_search(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": []})
        await opn_list_firewall_aliases(mock_ctx, search="block", limit=25)
        mock_api.post.assert_called_once_with(
            "firewall.alias.search",
            {"current": 1, "rowCount": 25, "searchPhrase": "block"},
        )


class TestOpnListNatRules:
    async def test_calls_dnat_search(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": []})
        await opn_list_nat_rules(mock_ctx)
        mock_api.post.assert_called_once_with(
            "nat.dnat.search_rule",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )


class TestOpnListFirewallCategories:
    async def test_calls_category_search(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": []})
        await opn_list_firewall_categories(mock_ctx)
        mock_api.post.assert_called_once_with(
            "firewall.category.search",
            {"current": 1, "rowCount": 100, "searchPhrase": ""},
        )


class TestOpnFirewallLog:
    async def test_returns_entries_and_total(self, mock_api, mock_ctx):
        rows = [{"src": "1.2.3.4", "dst": "5.6.7.8", "action": "block", "interface": "wan"}]
        mock_api.get = AsyncMock(return_value=rows)
        result = await opn_firewall_log(mock_ctx)
        assert result["entries"] == rows
        assert result["total"] == 1

    async def test_filters_by_source_ip(self, mock_api, mock_ctx):
        rows = [
            {"src": "10.0.0.1", "dst": "x", "action": "pass", "interface": "lan"},
            {"src": "10.0.0.2", "dst": "x", "action": "pass", "interface": "lan"},
        ]
        mock_api.get = AsyncMock(return_value=rows)
        result = await opn_firewall_log(mock_ctx, source_ip="10.0.0.1")
        assert result["total"] == 1
        assert result["entries"][0]["src"] == "10.0.0.1"

    async def test_filters_by_action_case_insensitive(self, mock_api, mock_ctx):
        rows = [
            {"src": "a", "dst": "b", "action": "Block", "interface": "wan"},
            {"src": "a", "dst": "b", "action": "pass", "interface": "wan"},
        ]
        mock_api.get = AsyncMock(return_value=rows)
        result = await opn_firewall_log(mock_ctx, action="block")
        assert result["total"] == 1

    async def test_limit_applied_after_filter(self, mock_api, mock_ctx):
        rows = [{"src": f"10.0.0.{i}", "action": "pass"} for i in range(100)]
        mock_api.get = AsyncMock(return_value=rows)
        result = await opn_firewall_log(mock_ctx, limit=10)
        assert len(result["entries"]) == 10
        assert result["total"] == 100

    async def test_handles_dict_response(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"rows": [{"src": "x"}]})
        result = await opn_firewall_log(mock_ctx)
        assert result["total"] == 1


# ---------------------------------------------------------------------------
# Savepoint confirmation
# ---------------------------------------------------------------------------


class TestOpnConfirmChanges:
    async def test_confirms_via_manager(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        result = await opn_confirm_changes(mock_ctx_writes, revision="rev-1")
        mock_api_writes.post.assert_called_once_with("firewall.cancel_rollback", path_suffix="rev-1")
        assert result == {"status": "ok"}

    async def test_writes_disabled_envelope(self, mock_ctx_no_writes):
        result = await opn_confirm_changes(mock_ctx_no_writes, revision="rev-1")
        assert result["error_type"] == "writes_disabled"


# ---------------------------------------------------------------------------
# opn_manage_firewall_rule
# ---------------------------------------------------------------------------


def _savepoint_flow_mock(write_result: dict | None = None) -> AsyncMock:
    """Mock api.post for savepoint → write → apply sequences."""
    return AsyncMock(
        side_effect=[
            {"revision": "rev-sp"},
            write_result if write_result is not None else {"result": "saved", "uuid": "new-uuid"},
            {"status": "ok"},  # apply
        ]
    )


class TestManageFirewallRuleAdd:
    async def test_add_applies_defaults(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = _savepoint_flow_mock()
        result = await opn_manage_firewall_rule(mock_ctx_writes, action="add")
        assert result["revision"] == "rev-sp"
        assert result["uuid"] == "new-uuid"
        rule = mock_api_writes.post.call_args_list[1][0][1]["rule"]
        assert rule["action"] == "pass"
        assert rule["direction"] == "in"
        assert rule["interface"] == "lan"
        assert rule["ipprotocol"] == "inet"
        assert rule["quick"] == "1"
        assert rule["enabled"] == "1"

    async def test_add_overrides_defaults(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = _savepoint_flow_mock()
        await opn_manage_firewall_rule(
            mock_ctx_writes,
            action="add",
            rule_action="block",
            direction="out",
            interface="wan",
            ip_protocol="inet6",
            destination_port="443",
            log=True,
            description="test rule",
        )
        rule = mock_api_writes.post.call_args_list[1][0][1]["rule"]
        assert rule["action"] == "block"
        assert rule["direction"] == "out"
        assert rule["interface"] == "wan"
        assert rule["ipprotocol"] == "inet6"
        assert rule["destination_port"] == "443"
        assert rule["log"] == "1"
        assert rule["description"] == "test rule"

    async def test_add_savepoint_then_write_then_apply(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = _savepoint_flow_mock()
        await opn_manage_firewall_rule(mock_ctx_writes, action="add")
        endpoints = [c[0][0] for c in mock_api_writes.post.call_args_list]
        assert endpoints == ["firewall.savepoint", "firewall.add_rule", "firewall.apply"]

    async def test_add_write_failure_returns_revision(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"revision": "rev-sp"},
                OPNsenseAPIError("validation failed"),
            ]
        )
        result = await opn_manage_firewall_rule(mock_ctx_writes, action="add")
        assert result["error"] == "validation failed"
        assert result["revision"] == "rev-sp"
        assert "auto-revert" in result["message"]

    async def test_writes_disabled_envelope(self, mock_ctx_no_writes):
        result = await opn_manage_firewall_rule(mock_ctx_no_writes, action="add")
        assert result["error_type"] == "writes_disabled"

    async def test_invalidates_config_cache(self, mock_api_writes, mock_ctx_writes, mock_config_cache):
        mock_config_cache._loaded_at = 123.0
        mock_api_writes.post = _savepoint_flow_mock()
        await opn_manage_firewall_rule(mock_ctx_writes, action="add")
        assert mock_config_cache.is_stale


class TestManageFirewallRuleUpdate:
    async def test_update_requires_uuid(self, mock_ctx_writes):
        result = await opn_manage_firewall_rule(mock_ctx_writes, action="update")
        assert result["error_type"] == "validation"
        assert "uuid" in result["error"]

    async def test_update_sends_only_provided_fields(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = _savepoint_flow_mock({"result": "saved"})
        result = await opn_manage_firewall_rule(
            mock_ctx_writes,
            action="update",
            uuid="rule-1",
            description="renamed",
            enabled=False,
        )
        assert result["revision"] == "rev-sp"
        call = mock_api_writes.post.call_args_list[1]
        assert call[0][0] == "firewall.set_rule"
        assert call[0][1] == {"rule": {"description": "renamed", "enabled": "0"}}
        assert call[1]["path_suffix"] == "rule-1"

    async def test_update_categories_only(self, mock_api_writes, mock_ctx_writes):
        # Replaces the removed opn_set_rule_categories tool
        mock_api_writes.post = _savepoint_flow_mock({"result": "saved"})
        await opn_manage_firewall_rule(mock_ctx_writes, action="update", uuid="rule-1", categories="cat-1,cat-2")
        call = mock_api_writes.post.call_args_list[1]
        assert call[0][1] == {"rule": {"categories": "cat-1,cat-2"}}


class TestManageFirewallRuleDeleteToggle:
    async def test_delete_requires_uuid(self, mock_ctx_writes):
        result = await opn_manage_firewall_rule(mock_ctx_writes, action="delete")
        assert result["error_type"] == "validation"

    async def test_delete_flow(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = _savepoint_flow_mock({"result": "deleted"})
        result = await opn_manage_firewall_rule(mock_ctx_writes, action="delete", uuid="rule-1")
        call = mock_api_writes.post.call_args_list[1]
        assert call[0][0] == "firewall.del_rule"
        assert call[1]["path_suffix"] == "rule-1"
        assert result["revision"] == "rev-sp"
        assert result["result"] == "deleted"

    async def test_toggle_flow(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = _savepoint_flow_mock({"changed": True})
        result = await opn_manage_firewall_rule(mock_ctx_writes, action="toggle", uuid="rule-1")
        call = mock_api_writes.post.call_args_list[1]
        assert call[0][0] == "firewall.toggle_rule"
        assert result["uuid"] == "rule-1"
        assert "revision" in result

    async def test_toggle_failure_returns_envelope(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"revision": "rev-sp"},
                OPNsenseAPIError("not found", status_code=404),
            ]
        )
        result = await opn_manage_firewall_rule(mock_ctx_writes, action="toggle", uuid="missing")
        assert result["revision"] == "rev-sp"
        assert "error" in result


# ---------------------------------------------------------------------------
# opn_manage_alias
# ---------------------------------------------------------------------------


class TestManageAlias:
    async def test_add_requires_name(self, mock_api_writes, mock_ctx_writes):
        result = await opn_manage_alias(mock_ctx_writes, action="add")
        assert result["error_type"] == "validation"

    async def test_add_invalid_name(self, mock_api_writes, mock_ctx_writes):
        result = await opn_manage_alias(mock_ctx_writes, action="add", name="bad name!")
        assert result["error_type"] == "validation"

    async def test_add_creates_alias_no_savepoint(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "alias-1"})
        result = await opn_manage_alias(
            mock_ctx_writes,
            action="add",
            name="Blocked_Hosts",
            alias_type="host",
            content="192.168.1.10\n192.168.1.11",
        )
        assert result["uuid"] == "alias-1"
        # Single post — no savepoint/apply around alias writes
        assert mock_api_writes.post.call_count == 1
        payload = mock_api_writes.post.call_args[0][1]["alias"]
        assert payload["name"] == "Blocked_Hosts"
        assert payload["type"] == "host"
        assert payload["enabled"] == "1"

    async def test_update_is_read_modify_write(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(
            return_value={
                "alias": {
                    "name": "Old_Name",
                    "type": "host",
                    "content": "1.1.1.1",
                    "description": "old",
                    "enabled": "1",
                }
            }
        )
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        result = await opn_manage_alias(mock_ctx_writes, action="update", uuid="alias-1", content="2.2.2.2")
        assert result["uuid"] == "alias-1"
        sent = mock_api_writes.post.call_args[0][1]["alias"]
        assert sent["content"] == "2.2.2.2"
        assert sent["name"] == "Old_Name"  # preserved
        assert sent["description"] == "old"  # preserved

    async def test_update_requires_uuid(self, mock_ctx_writes):
        result = await opn_manage_alias(mock_ctx_writes, action="update")
        assert result["error_type"] == "validation"

    async def test_delete(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "deleted"})
        result = await opn_manage_alias(mock_ctx_writes, action="delete", uuid="alias-1")
        mock_api_writes.post.assert_called_once_with("firewall.alias.del", path_suffix="alias-1")
        assert result["result"] == "deleted"

    async def test_toggle(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "ok"})
        await opn_manage_alias(mock_ctx_writes, action="toggle", uuid="alias-1")
        mock_api_writes.post.assert_called_once_with("firewall.alias.toggle", path_suffix="alias-1")

    async def test_writes_disabled(self, mock_ctx_no_writes):
        result = await opn_manage_alias(mock_ctx_no_writes, action="delete", uuid="alias-1")
        assert result["error_type"] == "writes_disabled"


# ---------------------------------------------------------------------------
# opn_manage_nat_rule (apply-only — no savepoint coverage for d_nat)
# ---------------------------------------------------------------------------


class TestManageNatRule:
    async def test_add_requires_destination_port(self, mock_api_writes, mock_ctx_writes):
        result = await opn_manage_nat_rule(mock_ctx_writes, action="add", target_ip="10.0.0.5")
        assert result["error_type"] == "validation"

    async def test_add_requires_target_ip(self, mock_api_writes, mock_ctx_writes):
        result = await opn_manage_nat_rule(mock_ctx_writes, action="add", destination_port="8080")
        assert result["error_type"] == "validation"

    async def test_add_writes_then_applies_no_savepoint(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved", "uuid": "nat-1"},
                {"status": "OK"},
            ]
        )
        result = await opn_manage_nat_rule(
            mock_ctx_writes,
            action="add",
            destination_port="8080",
            target_ip="192.168.1.100",
        )
        endpoints = [c[0][0] for c in mock_api_writes.post.call_args_list]
        assert endpoints == ["nat.dnat.add_rule", "nat.dnat.apply"]
        assert result["uuid"] == "nat-1"
        assert result["applied"] == "OK"
        assert "revision" not in result  # NAT has no savepoint protection

    async def test_add_defaults(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(side_effect=[{"uuid": "nat-1"}, {"status": "OK"}])
        await opn_manage_nat_rule(
            mock_ctx_writes,
            action="add",
            destination_port="8080",
            target_ip="192.168.1.100",
        )
        rule = mock_api_writes.post.call_args_list[0][0][1]["rule"]
        assert rule["interface"] == "wan"
        assert rule["protocol"] == "TCP"
        assert rule["target_port"] == "8080"
        assert rule["enabled"] == "1"

    async def test_update_sends_only_provided(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "OK"}])
        await opn_manage_nat_rule(mock_ctx_writes, action="update", uuid="nat-1", target_ip="10.0.0.9")
        call = mock_api_writes.post.call_args_list[0]
        assert call[0][0] == "nat.dnat.set_rule"
        assert call[0][1] == {"rule": {"target_ip": "10.0.0.9"}}
        assert call[1]["path_suffix"] == "nat-1"

    async def test_delete_applies(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "deleted"}, {"status": "OK"}])
        result = await opn_manage_nat_rule(mock_ctx_writes, action="delete", uuid="nat-1")
        endpoints = [c[0][0] for c in mock_api_writes.post.call_args_list]
        assert endpoints == ["nat.dnat.del_rule", "nat.dnat.apply"]
        assert result["applied"] == "OK"

    async def test_update_requires_uuid(self, mock_ctx_writes):
        result = await opn_manage_nat_rule(mock_ctx_writes, action="update")
        assert result["error_type"] == "validation"

    async def test_writes_disabled(self, mock_ctx_no_writes):
        result = await opn_manage_nat_rule(
            mock_ctx_no_writes, action="add", destination_port="80", target_ip="10.0.0.1"
        )
        assert result["error_type"] == "writes_disabled"


# ---------------------------------------------------------------------------
# opn_manage_firewall_category
# ---------------------------------------------------------------------------


class TestManageFirewallCategory:
    async def test_add_validates_name(self, mock_ctx_writes):
        result = await opn_manage_firewall_category(mock_ctx_writes, action="add", name="bad,name")
        assert result["error_type"] == "validation"

    async def test_add_validates_color(self, mock_ctx_writes):
        result = await opn_manage_firewall_category(mock_ctx_writes, action="add", name="ok", color="red")
        assert result["error_type"] == "validation"

    async def test_add_creates_category(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "cat-1"})
        result = await opn_manage_firewall_category(mock_ctx_writes, action="add", name="Servers", color="ff0000")
        assert result["uuid"] == "cat-1"
        payload = mock_api_writes.post.call_args[0][1]["category"]
        assert payload == {"name": "Servers", "color": "ff0000", "auto": "0"}

    async def test_delete_requires_uuid(self, mock_ctx_writes):
        result = await opn_manage_firewall_category(mock_ctx_writes, action="delete")
        assert result["error_type"] == "validation"

    async def test_delete_savepoint_flow(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = _savepoint_flow_mock({"result": "deleted"})
        result = await opn_manage_firewall_category(mock_ctx_writes, action="delete", uuid="cat-1")
        endpoints = [c[0][0] for c in mock_api_writes.post.call_args_list]
        assert endpoints == ["firewall.savepoint", "firewall.category.del", "firewall.apply"]
        assert result["revision"] == "rev-sp"


# ---------------------------------------------------------------------------
# opn_add_icmpv6_rules
# ---------------------------------------------------------------------------


class TestAddIcmpv6Rules:
    async def test_creates_five_rules_one_savepoint(self, mock_api_writes, mock_ctx_writes):
        responses: list[dict] = [{"revision": "rev-sp"}]
        responses += [{"uuid": f"rule-{i}", "result": "saved"} for i in range(5)]
        responses.append({"status": "ok"})  # apply
        mock_api_writes.post = AsyncMock(side_effect=responses)
        result = await opn_add_icmpv6_rules(mock_ctx_writes, interface="opt1")
        assert result["rules_created"] == 5
        assert result["revision"] == "rev-sp"
        assert len(result["uuids"]) == 5
        endpoints = [c[0][0] for c in mock_api_writes.post.call_args_list]
        assert endpoints[0] == "firewall.savepoint"
        assert endpoints[-1] == "firewall.apply"
        assert endpoints[1:-1] == ["firewall.add_rule"] * 5
        # All rules created on requested interface, IPv6
        for call in mock_api_writes.post.call_args_list[1:-1]:
            rule = call[0][1]["rule"]
            assert rule["interface"] == "opt1"
            assert rule["ipprotocol"] == "inet6"

    async def test_partial_failure_reported(self, mock_api_writes, mock_ctx_writes):
        responses = [
            {"revision": "rev-sp"},
            {"uuid": "rule-0", "result": "saved"},
            OPNsenseAPIError("failed"),
            {"uuid": "rule-2", "result": "saved"},
            {"uuid": "rule-3", "result": "saved"},
            {"uuid": "rule-4", "result": "saved"},
            {"status": "ok"},
        ]
        mock_api_writes.post = AsyncMock(side_effect=responses)
        result = await opn_add_icmpv6_rules(mock_ctx_writes)
        assert result["rules_created"] == 4
        assert len(result["errors"]) == 1

    async def test_writes_disabled(self, mock_ctx_no_writes):
        result = await opn_add_icmpv6_rules(mock_ctx_no_writes)
        assert result["error_type"] == "writes_disabled"
