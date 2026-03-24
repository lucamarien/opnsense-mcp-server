"""Live integration tests for read-only tools against a real OPNsense instance.

Usage:
    # With .env file in project root:
    set -a && source .env && set +a && python -m tests.integration.test_live_readonly

    # Or with explicit env vars:
    OPNSENSE_URL=https://192.168.1.1:10443/api \
    OPNSENSE_API_KEY=... \
    OPNSENSE_API_SECRET=... \
    OPNSENSE_VERIFY_SSL=false \
    python -m tests.integration.test_live_readonly

Requires a running OPNsense instance. NEVER runs write operations.
"""

from __future__ import annotations

import asyncio
import sys
import traceback
from typing import Any
from unittest.mock import MagicMock

from opnsense_mcp.api_client import (
    OPNsenseAPI,
    OPNsenseAPIError,
    SavepointManager,
    WriteDisabledError,
)
from opnsense_mcp.config import load_config
from opnsense_mcp.config_cache import ConfigCache
from opnsense_mcp.tools.dhcp import (
    opn_list_dhcp_leases,
    opn_list_dnsmasq_leases,
    opn_list_dnsmasq_ranges,
    opn_list_kea_leases,
)
from opnsense_mcp.tools.diagnostics import (
    opn_dns_lookup,
    opn_pf_states,
    opn_ping,
    opn_traceroute,
)
from opnsense_mcp.tools.dns import (
    opn_add_dns_override,
    opn_add_dnsbl_allowlist,
    opn_dns_stats,
    opn_get_dnsbl,
    opn_list_dns_forwards,
    opn_list_dns_overrides,
    opn_list_dnsbl,
    opn_reconfigure_unbound,
    opn_remove_dnsbl_allowlist,
    opn_set_dnsbl,
)
from opnsense_mcp.tools.firewall import (
    opn_add_alias,
    opn_add_firewall_category,
    opn_add_firewall_rule,
    opn_add_icmpv6_rules,
    opn_add_nat_rule,
    opn_confirm_changes,
    opn_delete_firewall_category,
    opn_delete_firewall_rule,
    opn_firewall_log,
    opn_list_firewall_aliases,
    opn_list_firewall_categories,
    opn_list_firewall_rules,
    opn_list_nat_rules,
    opn_set_rule_categories,
    opn_toggle_firewall_rule,
)
from opnsense_mcp.tools.haproxy import opn_haproxy_status, opn_reconfigure_haproxy
from opnsense_mcp.tools.network import (
    opn_arp_table,
    opn_interface_stats,
    opn_ipv6_status,
    opn_list_static_routes,
    opn_ndp_table,
)
from opnsense_mcp.tools.security import opn_security_audit
from opnsense_mcp.tools.services import (
    opn_crowdsec_alerts,
    opn_crowdsec_status,
    opn_list_acme_certs,
    opn_list_cron_jobs,
    opn_list_ddns_accounts,
)
from opnsense_mcp.tools.system import (
    opn_download_config,
    opn_gateway_status,
    opn_get_config_section,
    opn_list_services,
    opn_scan_config,
    opn_system_status,
)
from opnsense_mcp.tools.vpn import opn_ipsec_status, opn_openvpn_status, opn_wireguard_status

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
SKIP = "\033[93mSKIP\033[0m"


def _make_ctx(api: OPNsenseAPI, mgr: SavepointManager) -> MagicMock:
    """Create a mock FastMCP Context wrapping a real API client."""
    ctx = MagicMock()
    config_cache = ConfigCache()
    ctx.lifespan_context = {"api": api, "savepoint_mgr": mgr, "config_cache": config_cache}
    return ctx


def _summarize(result: Any, max_chars: int = 120) -> str:
    """Create a short summary string from a tool result."""
    if isinstance(result, list):
        return f"{len(result)} items (list)"
    if not isinstance(result, dict):
        return str(result)[:max_chars]
    if "error" in result:
        return f"error: {result['error']}"
    parts: list[str] = []
    for key in (
        "product_version",
        "product_name",
        "rowCount",
        "total_rules",
        "total_services",
        "running",
        "host",
        "hostname",
        "size_bytes",
        "service_status",
        "decisions_count",
        "alerts_count",
        "selected_providers",
    ):
        if key in result:
            parts.append(f"{key}={result[key]}")
    if "rows" in result:
        parts.append(f"{len(result['rows'])} rows")
    if "summary" in result and isinstance(result["summary"], dict):
        parts.append(f"findings={result['summary'].get('total_findings', '?')}")
    text = ", ".join(parts) if parts else str(list(result.keys()))
    return text[:max_chars]


async def _run_tool(name: str, coro: Any, *, plugin_dependent: bool = False) -> tuple[str, str, Any]:
    """Run a single tool and return (status, summary, result)."""
    try:
        result = await coro
        if isinstance(result, dict) and "error" in result:
            return FAIL, _summarize(result), result
        return PASS, _summarize(result), result
    except OPNsenseAPIError as exc:
        err_str = str(exc)
        if plugin_dependent and ("404" in err_str or "not found" in err_str.lower()):
            return SKIP, f"plugin not installed ({err_str[:80]})", None
        return FAIL, err_str[:120], None
    except Exception as exc:
        return FAIL, f"{type(exc).__name__}: {exc}"[:120], None


async def _test_write_guard(name: str, coro: Any) -> tuple[str, str]:
    """Verify a write tool correctly refuses when writes are disabled."""
    try:
        result = await coro
        if isinstance(result, dict) and "error" in result:
            err = result.get("error", "")
            if "write" in err.lower() or "disabled" in err.lower():
                return PASS, f"correctly refused: {err[:80]}"
        return FAIL, f"write tool did NOT refuse! Got: {str(result)[:80]}"
    except WriteDisabledError:
        return PASS, "correctly raised WriteDisabledError"
    except Exception as exc:
        return FAIL, f"unexpected error: {type(exc).__name__}: {exc}"[:120]


async def main() -> int:
    """Run all integration tests."""
    config = load_config()
    api = OPNsenseAPI(config)
    mgr = SavepointManager(api)
    ctx = _make_ctx(api, mgr)

    passed = 0
    failed = 0
    skipped = 0
    security_audit_result: dict[str, Any] | None = None

    print("=" * 70)
    print("  OPNsense MCP Server — Live Integration Test")
    print("=" * 70)
    print(f"  URL:    {config.url}")
    print(f"  SSL:    verify={'yes' if config.verify_ssl else 'no (self-signed)'}")
    print(f"  Writes: {'ENABLED' if config.allow_writes else 'disabled (read-only)'}")
    print("=" * 70)

    # --- Tier 1: Core tools ---
    print("\n--- Tier 1: Core (must pass) ---")
    tier1 = [
        ("opn_system_status", opn_system_status(ctx)),
        ("opn_list_services", opn_list_services(ctx)),
        ("opn_gateway_status", opn_gateway_status(ctx)),
        ("opn_interface_stats", opn_interface_stats(ctx)),
        ("opn_arp_table", opn_arp_table(ctx)),
    ]
    for name, coro in tier1:
        status, summary, result = await _run_tool(name, coro)
        print(f"  [{status}] {name:30s} -- {summary}")
        if status == PASS:
            passed += 1
            # Capture version info from first call
            if name == "opn_system_status" and result:
                ver = result.get("product_version", "?")
                prod = result.get("product_name", "?")
                print(f"         -> Detected: {prod} {ver}")
                if api._detected_version:
                    snake = "snake_case" if api._use_snake_case else "camelCase"
                    print(f"         -> API style: {snake} (version tuple: {api._detected_version})")
        elif status == FAIL:
            failed += 1
        else:
            skipped += 1

    # --- Tier 2: Domain tools ---
    print("\n--- Tier 2: Domain (should pass) ---")
    tier2 = [
        ("opn_list_firewall_rules", opn_list_firewall_rules(ctx)),
        ("opn_list_firewall_aliases", opn_list_firewall_aliases(ctx)),
        ("opn_firewall_log", opn_firewall_log(ctx)),
        ("opn_list_dns_overrides", opn_list_dns_overrides(ctx)),
        ("opn_list_dns_forwards", opn_list_dns_forwards(ctx)),
        ("opn_dns_stats", opn_dns_stats(ctx)),
        ("opn_list_dnsbl", opn_list_dnsbl(ctx)),
        ("opn_get_dnsbl", opn_get_dnsbl(ctx, uuid="7aafe899-6392-4a05-8205-565919b17f02")),
        ("opn_list_cron_jobs", opn_list_cron_jobs(ctx)),
        ("opn_list_dnsmasq_leases", opn_list_dnsmasq_leases(ctx)),
        ("opn_list_dnsmasq_ranges", opn_list_dnsmasq_ranges(ctx)),
        ("opn_pf_states", opn_pf_states(ctx, limit=20)),
        ("opn_list_nat_rules", opn_list_nat_rules(ctx)),
        ("opn_list_static_routes", opn_list_static_routes(ctx)),
        ("opn_list_firewall_categories", opn_list_firewall_categories(ctx)),
        ("opn_ndp_table", opn_ndp_table(ctx)),
        ("opn_ipv6_status", opn_ipv6_status(ctx)),
    ]
    for name, coro in tier2:
        status, summary, _ = await _run_tool(name, coro)
        print(f"  [{status}] {name:30s} -- {summary}")
        if status == PASS:
            passed += 1
        elif status == FAIL:
            failed += 1
        else:
            skipped += 1

    # --- Tier 3: Plugin-dependent tools ---
    print("\n--- Tier 3: Plugin-dependent (may skip) ---")
    tier3 = [
        ("opn_wireguard_status", opn_wireguard_status(ctx)),
        ("opn_haproxy_status", opn_haproxy_status(ctx)),
        ("opn_list_acme_certs", opn_list_acme_certs(ctx)),
        ("opn_crowdsec_status", opn_crowdsec_status(ctx)),
        ("opn_crowdsec_alerts", opn_crowdsec_alerts(ctx)),
        ("opn_list_dhcp_leases", opn_list_dhcp_leases(ctx)),
        ("opn_list_kea_leases", opn_list_kea_leases(ctx)),
        ("opn_ipsec_status", opn_ipsec_status(ctx)),
        ("opn_openvpn_status", opn_openvpn_status(ctx)),
        ("opn_list_ddns_accounts", opn_list_ddns_accounts(ctx)),
    ]
    for name, coro in tier3:
        status, summary, _ = await _run_tool(name, coro, plugin_dependent=True)
        print(f"  [{status}] {name:30s} -- {summary}")
        if status == PASS:
            passed += 1
        elif status == FAIL:
            failed += 1
        else:
            skipped += 1

    # --- Tier 4: Active diagnostics ---
    print("\n--- Tier 4: Active diagnostics ---")
    tier4 = [
        ("opn_ping", opn_ping(ctx, host="8.8.8.8", count=1)),
        ("opn_traceroute", opn_traceroute(ctx, host="8.8.8.8")),
        ("opn_traceroute (IPv6)", opn_traceroute(ctx, host="2001:4860:4860::8888", ip_version="6")),
        ("opn_dns_lookup", opn_dns_lookup(ctx, hostname="example.com")),
        ("opn_dns_lookup (AAAA)", opn_dns_lookup(ctx, hostname="ipv6.google.com")),
    ]
    for name, coro in tier4:
        status, summary, _ = await _run_tool(name, coro)
        print(f"  [{status}] {name:30s} -- {summary}")
        if status == PASS:
            passed += 1
        elif status == FAIL:
            failed += 1
        else:
            skipped += 1

    # --- Tier 5: Composite tools ---
    print("\n--- Tier 5: Composite ---")
    tier5_security = await _run_tool("opn_security_audit", opn_security_audit(ctx))
    status, summary, security_audit_result = tier5_security
    print(f"  [{status}] {'opn_security_audit':30s} -- {summary}")
    if status == PASS:
        passed += 1
    elif status == FAIL:
        failed += 1
    else:
        skipped += 1

    scan_status, scan_summary, scan_result = await _run_tool("opn_scan_config", opn_scan_config(ctx))
    print(f"  [{scan_status}] {'opn_scan_config':30s} -- {scan_summary}")
    if scan_status == PASS:
        passed += 1
        if scan_result:
            fw = scan_result.get("firmware", {})
            print(f"         -> {fw.get('product', '?')} {fw.get('version', '?')}")
            plugins = scan_result.get("plugins", [])
            print(f"         -> {len(plugins)} plugins installed")
            dhcp = scan_result.get("dhcp", {})
            print(f"         -> DHCP backend: {dhcp.get('active', 'none')}")
            sections = scan_result.get("config_sections", [])
            section_names = [s["name"] for s in sections]
            print(f"         -> {len(sections)} config sections: {', '.join(section_names[:10])}")
    elif scan_status == FAIL:
        failed += 1
    else:
        skipped += 1

    # Test individual section retrieval
    for section_name in ("system", "filter", "interfaces"):
        sec_status, sec_summary, sec_result = await _run_tool(
            f"opn_get_config_section({section_name})",
            opn_get_config_section(ctx, section=section_name),
        )
        print(f"  [{sec_status}] {'  -> ' + section_name:30s} -- {sec_summary}")
        if sec_status == PASS:
            passed += 1
        elif sec_status == FAIL:
            failed += 1
        else:
            skipped += 1

    status, summary, config_result = await _run_tool(
        "opn_download_config", opn_download_config(ctx, include_sensitive=False)
    )
    print(f"  [{status}] {'opn_download_config':30s} -- {summary}")
    if status == PASS:
        passed += 1
    elif status == FAIL:
        failed += 1
    else:
        skipped += 1

    # --- Write guard tests ---
    print("\n--- Write Guard Tests (must refuse) ---")
    write_tests = [
        ("opn_toggle_firewall_rule", opn_toggle_firewall_rule(ctx, uuid="00000000-0000-0000-0000-000000000000")),
        ("opn_add_firewall_rule", opn_add_firewall_rule(ctx, description="integration-test")),
        ("opn_delete_firewall_rule", opn_delete_firewall_rule(ctx, uuid="00000000-0000-0000-0000-000000000000")),
        ("opn_confirm_changes", opn_confirm_changes(ctx, revision="fake-revision")),
        ("opn_add_alias", opn_add_alias(ctx, name="integration_test")),
        ("opn_reconfigure_unbound", opn_reconfigure_unbound(ctx)),
        ("opn_reconfigure_haproxy", opn_reconfigure_haproxy(ctx)),
        ("opn_add_nat_rule", opn_add_nat_rule(ctx, destination_port="9999", target_ip="192.168.1.1")),
        ("opn_add_dns_override", opn_add_dns_override(ctx, hostname="test", domain="test.lan", server="192.168.1.1")),
        ("opn_add_firewall_category", opn_add_firewall_category(ctx, name="integration_test")),
        (
            "opn_delete_firewall_category",
            opn_delete_firewall_category(ctx, uuid="00000000-0000-0000-0000-000000000000"),
        ),
        (
            "opn_set_rule_categories",
            opn_set_rule_categories(ctx, uuid="00000000-0000-0000-0000-000000000000", categories=""),
        ),
        ("opn_add_icmpv6_rules", opn_add_icmpv6_rules(ctx, interface="lan")),
        (
            "opn_set_dnsbl",
            opn_set_dnsbl(ctx, uuid="7aafe899-6392-4a05-8205-565919b17f02", enabled=True),
        ),
        (
            "opn_add_dnsbl_allowlist",
            opn_add_dnsbl_allowlist(ctx, uuid="7aafe899-6392-4a05-8205-565919b17f02", domains="test.example.com"),
        ),
        (
            "opn_remove_dnsbl_allowlist",
            opn_remove_dnsbl_allowlist(ctx, uuid="7aafe899-6392-4a05-8205-565919b17f02", domains="test.example.com"),
        ),
    ]
    for name, coro in write_tests:
        status, summary = await _test_write_guard(name, coro)
        print(f"  [{status}] {name:30s} -- {summary}")
        if status == PASS:
            passed += 1
        else:
            failed += 1

    # --- Security Audit Details ---
    if security_audit_result:
        print("\n" + "=" * 70)
        print("  SECURITY AUDIT DETAILS")
        print("=" * 70)
        audit_sections = (
            "firmware",
            "firewall_rules",
            "nat_rules",
            "dns_security",
            "system_hardening",
            "services",
            "certificates",
            "vpn_security",
            "haproxy",
            "gateways",
        )
        for section_name in audit_sections:
            section = security_audit_result.get(section_name, {})
            if not section:
                print(f"\n  [{section_name}] (not present)")
                continue
            status = section.get("status", "unknown")
            findings = section.get("findings", [])
            print(f"\n  [{section_name}] status={status}, findings={len(findings)}")
            if section.get("reason"):
                print(f"    reason: {section['reason']}")
            # Show extra info fields (rule counts, gateway counts, etc.)
            for key, val in section.items():
                if key not in ("status", "findings", "reason"):
                    print(f"    {key}: {val}")
            for f in findings:
                sev = f.get("severity", "?").upper()
                msg = f.get("message", "")
                check = f.get("check", "")
                compliance = f.get("compliance", [])
                color = "\033[91m" if sev == "CRITICAL" else "\033[93m" if sev == "WARNING" else "\033[94m"
                tags = f" [{', '.join(compliance)}]" if compliance else ""
                print(f"    {color}{sev:8s}\033[0m [{check}] {msg}{tags}")

        # Compliance frameworks
        frameworks = security_audit_result.get("compliance_frameworks", {})
        if frameworks:
            print(f"\n  Compliance frameworks: {len(frameworks.get('frameworks', []))}")
            for fw in frameworks.get("frameworks", []):
                print(f"    - {fw.get('id', '?')}: {fw.get('name', '?')}")
            manual = frameworks.get("manual_review_needed", [])
            if manual:
                print(f"  Manual review items: {len(manual)}")

        summary_data = security_audit_result.get("summary", {})
        print(
            f"\n  Summary: {summary_data.get('critical', 0)} critical, "
            f"{summary_data.get('warning', 0)} warning, "
            f"{summary_data.get('info', 0)} info, "
            f"{summary_data.get('sections_checked', 0)} sections checked, "
            f"{summary_data.get('sections_skipped', 0)} skipped"
        )

    # --- Final Summary ---
    print("\n" + "=" * 70)
    total = passed + failed + skipped
    print(f"  RESULT: {passed}/{total} passed, {failed} failed, {skipped} skipped")
    if failed > 0:
        print(f"  \033[91m** {failed} test(s) FAILED **\033[0m")
    else:
        print("  \033[92mAll tests passed!\033[0m")
    print("=" * 70)

    await api.close()
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
    except Exception:
        traceback.print_exc()
        exit_code = 2
    sys.exit(exit_code)
