"""Tests for MCP prompts and resources registration/behavior."""

from __future__ import annotations

from opnsense_mcp.resources import config_section, inventory
from opnsense_mcp.server import mcp


class TestRegistration:
    async def test_prompts_registered(self):
        prompts = {p.name for p in await mcp.list_prompts()}
        assert {"ipv6_migration", "expose_service", "remediate_audit"} <= prompts

    async def test_resource_template_registered(self):
        templates = {t.uri_template for t in await mcp.list_resource_templates()}
        assert "opnsense://config/{section}" in templates

    async def test_inventory_resource_registered(self):
        resources = {str(r.uri) for r in await mcp.list_resources()}
        assert "opnsense://inventory" in resources


class TestPromptContent:
    async def test_prompts_reference_current_tool_names(self):
        # Prompts must not reference removed v0.4 tool names.
        prompts = await mcp.list_prompts()
        stale = ("opn_add_firewall_rule", "opn_add_nat_rule", "opn_add_dns_override", "opn_update_dnsbl")
        for p in prompts:
            rendered = await mcp.get_prompt(p.name)
            text = "".join(str(m.content) for m in (await rendered.render({})).messages)
            for name in stale:
                assert name not in text, f"prompt {p.name} references removed tool {name}"


class TestResources:
    async def test_inventory_loads_cache(self, mock_api, mock_ctx, mock_config_cache):
        mock_config_cache._loaded_at = 1.0
        mock_config_cache._stale = False
        mock_config_cache._inventory = {"firmware": {"version": "26.1"}}
        result = await inventory(mock_ctx)
        assert result["firmware"]["version"] == "26.1"

    async def test_config_section_returns_redacted(self, mock_api, mock_ctx, mock_config_cache):
        mock_config_cache._loaded_at = 1.0
        mock_config_cache._stale = False
        mock_config_cache._sections = {"system": {"hostname": "fw", "password": "secret"}}
        result = await config_section("system", mock_ctx)
        assert result["data"]["hostname"] == "fw"
        assert result["data"]["password"] == "[REDACTED]"

    async def test_config_section_missing(self, mock_api, mock_ctx, mock_config_cache):
        mock_config_cache._loaded_at = 1.0
        mock_config_cache._stale = False
        mock_config_cache._sections = {"system": {}}
        result = await config_section("nope", mock_ctx)
        assert "error" in result
        assert result["available_sections"] == ["system"]
