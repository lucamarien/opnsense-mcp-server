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
            # Network
            "opn_interface_stats",
            "opn_arp_table",
            "opn_ndp_table",
            "opn_ipv6_status",
            "opn_list_static_routes",
            # Firewall
            "opn_list_firewall_rules",
            "opn_list_firewall_aliases",
            "opn_firewall_log",
            "opn_confirm_changes",
            "opn_toggle_firewall_rule",
            "opn_add_firewall_rule",
            "opn_delete_firewall_rule",
            "opn_add_alias",
            "opn_list_nat_rules",
            "opn_add_nat_rule",
            "opn_list_firewall_categories",
            "opn_add_firewall_category",
            "opn_delete_firewall_category",
            "opn_set_rule_categories",
            "opn_add_icmpv6_rules",
            # DNS
            "opn_list_dns_overrides",
            "opn_list_dns_forwards",
            "opn_dns_stats",
            "opn_reconfigure_unbound",
            "opn_add_dns_override",
            # DNSBL
            "opn_list_dnsbl",
            "opn_get_dnsbl",
            "opn_set_dnsbl",
            "opn_add_dnsbl_allowlist",
            "opn_remove_dnsbl_allowlist",
            "opn_update_dnsbl",
            # DHCP
            "opn_list_dhcp_leases",
            "opn_list_kea_leases",
            "opn_list_dnsmasq_leases",
            "opn_list_dnsmasq_ranges",
            "opn_add_dnsmasq_range",
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
            "opn_crowdsec_alerts",
            "opn_list_ddns_accounts",
            "opn_add_ddns_account",
            "opn_reconfigure_ddclient",
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
        assert len(tools) == 69, f"Expected 69 tools, got {len(tools)}"
