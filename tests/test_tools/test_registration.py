"""Tests for tool registration on the MCP server."""

from __future__ import annotations


class TestToolRegistration:
    """Verify all tools are registered correctly."""

    async def test_all_expected_tools_registered(self):
        from opnsense_mcp.server import mcp

        tools = await mcp.list_tools()
        tool_names = {t.name for t in tools}
        expected = {
            # System
            "opn_system_status",
            "opn_list_services",
            "opn_gateway_status",
            "opn_download_config",
            "opn_scan_config",
            "opn_get_config_section",
            "opn_mcp_info",
            "opn_system_health",
            # Network
            "opn_interface_stats",
            "opn_arp_table",
            "opn_ndp_table",
            "opn_ipv6_status",
            "opn_list_static_routes",
            "opn_find_host",
            "opn_traffic_top",
            # Firewall
            "opn_list_firewall_rules",
            "opn_list_firewall_aliases",
            "opn_list_nat_rules",
            "opn_list_firewall_categories",
            "opn_firewall_log",
            "opn_confirm_changes",
            "opn_manage_firewall_rule",
            "opn_manage_alias",
            "opn_manage_nat_rule",
            "opn_manage_firewall_category",
            "opn_add_icmpv6_rules",
            # DNS
            "opn_list_dns_overrides",
            "opn_list_dns_forwards",
            "opn_dns_stats",
            "opn_reconfigure_unbound",
            "opn_manage_dns_override",
            # DNSBL
            "opn_list_dnsbl",
            "opn_get_dnsbl",
            "opn_set_dnsbl",
            "opn_edit_dnsbl_allowlist",
            "opn_apply_dnsbl",
            # DHCP
            "opn_list_dhcp_leases",
            "opn_list_dnsmasq_ranges",
            "opn_manage_dnsmasq_range",
            "opn_list_dnsmasq_hosts",
            "opn_manage_dnsmasq_host",
            "opn_reconfigure_dnsmasq",
            # VPN
            "opn_wireguard_status",
            "opn_ipsec_status",
            "opn_openvpn_status",
            # HAProxy
            "opn_haproxy_status",
            "opn_reconfigure_haproxy",
            "opn_haproxy_search",
            "opn_haproxy_get",
            "opn_haproxy_add",
            "opn_haproxy_update",
            "opn_haproxy_delete",
            "opn_haproxy_configtest",
            # Services
            "opn_list_acme_certs",
            "opn_list_cron_jobs",
            "opn_crowdsec_status",
            "opn_list_ddns_accounts",
            "opn_manage_ddns_account",
            "opn_reconfigure_ddclient",
            "opn_mdns_repeater_status",
            "opn_configure_mdns_repeater",
            # Security
            "opn_security_audit",
            # Diagnostics
            "opn_ping",
            "opn_traceroute",
            "opn_dns_lookup",
            "opn_pf_states",
        }
        assert expected.issubset(tool_names), f"Missing tools: {expected - tool_names}"

    async def test_tool_count_matches_expected(self):
        from opnsense_mcp.server import mcp

        tools = await mcp.list_tools()
        assert len(tools) == 66, f"Expected 66 tools, got {len(tools)}"

    async def test_tool_count_under_ceiling(self):
        """The project's self-imposed tool budget: stay under 67 tools."""
        from opnsense_mcp.server import mcp

        tools = await mcp.list_tools()
        assert len(tools) < 67, f"Tool budget exceeded: {len(tools)} >= 67. Consolidate before adding."
