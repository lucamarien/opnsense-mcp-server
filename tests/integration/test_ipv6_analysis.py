"""IPv6 Analysis — comprehensive IPv6 configuration analysis against a live OPNsense.

Usage:
    set -a && source .env && set +a && python -m tests.integration.test_ipv6_analysis

Requires a running OPNsense instance. NEVER runs write operations.
"""

from __future__ import annotations

import asyncio
import json
import sys
import traceback
from typing import Any
from unittest.mock import MagicMock

from opnsense_mcp.api_client import OPNsenseAPI, OPNsenseAPIError, SavepointManager
from opnsense_mcp.config import load_config
from opnsense_mcp.config_cache import ConfigCache
from opnsense_mcp.tools.dhcp import opn_list_dnsmasq_leases, opn_list_dnsmasq_ranges
from opnsense_mcp.tools.diagnostics import opn_dns_lookup, opn_ping, opn_traceroute
from opnsense_mcp.tools.dns import opn_list_dns_overrides
from opnsense_mcp.tools.firewall import opn_list_firewall_rules
from opnsense_mcp.tools.haproxy import opn_haproxy_status
from opnsense_mcp.tools.network import opn_list_static_routes
from opnsense_mcp.tools.security import opn_security_audit
from opnsense_mcp.tools.services import opn_list_ddns_accounts
from opnsense_mcp.tools.system import (
    opn_gateway_status,
    opn_get_config_section,
    opn_system_status,
)

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
SKIP = "\033[93mSKIP\033[0m"
INFO = "\033[94mINFO\033[0m"
WARN = "\033[93mWARN\033[0m"
CRIT = "\033[91mCRIT\033[0m"
NONE = "\033[90mNONE\033[0m"
OK = "\033[92mOK\033[0m"

SECTION_SEP = "=" * 70
SUBSECTION_SEP = "-" * 70


def _make_ctx(api: OPNsenseAPI, mgr: SavepointManager) -> MagicMock:
    ctx = MagicMock()
    config_cache = ConfigCache()
    ctx.lifespan_context = {"api": api, "savepoint_mgr": mgr, "config_cache": config_cache}
    return ctx


async def _safe_call(name: str, coro: Any, *, optional: bool = False) -> tuple[str, Any]:
    """Run a tool safely, returning (status, result)."""
    try:
        result = await coro
        if isinstance(result, dict) and "error" in result:
            if optional:
                return "skip", result
            return "fail", result
        return "ok", result
    except OPNsenseAPIError as exc:
        err = str(exc)
        if optional and ("404" in err or "not found" in err.lower()):
            return "skip", {"error": f"not available: {err[:80]}"}
        return "fail", {"error": err[:120]}
    except Exception as exc:
        return "fail", {"error": f"{type(exc).__name__}: {exc}"[:120]}


def _is_ipv6(addr: str) -> bool:
    return ":" in addr


def _print_header(title: str) -> None:
    print(f"\n{SECTION_SEP}")
    print(f"  {title}")
    print(SECTION_SEP)


def _print_sub(title: str) -> None:
    print(f"\n  {SUBSECTION_SEP}")
    print(f"  {title}")
    print(f"  {SUBSECTION_SEP}")


async def main() -> int:
    config = load_config()
    api = OPNsenseAPI(config)
    mgr = SavepointManager(api)
    ctx = _make_ctx(api, mgr)

    readiness: dict[str, str] = {}
    recommendations: list[str] = []

    _print_header("OPNsense IPv6 Analysis")
    print(f"  URL:    {config.url}")
    print(f"  SSL:    verify={'yes' if config.verify_ssl else 'no (self-signed)'}")
    print("  Mode:   read-only analysis")

    # ============================================================
    # 1. System Info
    # ============================================================
    _print_header("1. System Information")

    status, sys_result = await _safe_call("system_status", opn_system_status(ctx))
    if status == "ok":
        ver = sys_result.get("product_version", "?")
        print(f"  Version:   {ver}")
        print(f"  API style: {'snake_case' if api._use_snake_case else 'camelCase'}")
    else:
        print(f"  [{FAIL}] Could not get system status: {sys_result}")
        await api.close()
        return 1

    # ============================================================
    # 2. Gateways — look for IPv6 gateways
    # ============================================================
    _print_header("2. Gateway Analysis")

    status, gw_result = await _safe_call("gateways", opn_gateway_status(ctx))
    if status == "ok":
        items = gw_result.get("items", [])
        v4_gw = [g for g in items if not _is_ipv6(g.get("address", "")) and g.get("address")]
        v6_gw = [g for g in items if _is_ipv6(g.get("address", ""))]
        print(f"  Total gateways:  {len(items)}")
        print(f"  IPv4 gateways:   {len(v4_gw)}")
        print(f"  IPv6 gateways:   {len(v6_gw)}")

        for gw in items:
            name = gw.get("name", "?")
            addr = gw.get("address", "none")
            gw_status = gw.get("status_translated", gw.get("status", "?"))
            proto = "IPv6" if _is_ipv6(addr) else "IPv4" if addr and addr != "none" else "?"
            print(f"    [{proto:4s}] {name:30s} addr={addr:20s} status={gw_status}")

        if v6_gw:
            readiness["IPv6 Gateway"] = "configured"
        else:
            readiness["IPv6 Gateway"] = "NOT configured"
            recommendations.append("No IPv6 gateway detected. Configure DHCPv6-PD on WAN or a static IPv6 gateway.")
    else:
        print(f"  [{FAIL}] {gw_result}")
        readiness["IPv6 Gateway"] = "unknown"

    # ============================================================
    # 3. Interface IPv6 Configuration
    # ============================================================
    _print_header("3. Interface IPv6 Configuration")

    status, iface_result = await _safe_call("interfaces", opn_get_config_section(ctx, section="interfaces"))
    if status == "ok":
        data = iface_result.get("data", {})
        v6_interfaces = []
        for iface_name, iface_config in data.items():
            if not isinstance(iface_config, dict):
                continue
            ipaddrv6 = iface_config.get("ipaddrv6", "")
            subnetv6 = iface_config.get("subnetv6", "")
            track6_iface = iface_config.get("track6-interface", "")
            track6_prefix = iface_config.get("track6-prefix-id", "")
            descr = iface_config.get("descr", iface_name)
            ipaddr = iface_config.get("ipaddr", "")

            has_v6 = bool(ipaddrv6 or track6_iface)

            if has_v6:
                v6_interfaces.append(iface_name)

            v6_method = "none"
            if ipaddrv6 == "dhcp6":
                v6_method = "DHCPv6-PD"
            elif ipaddrv6 == "track6":
                v6_method = f"Track Interface ({track6_iface}, prefix-id={track6_prefix})"
            elif ipaddrv6 == "slaac":
                v6_method = "SLAAC"
            elif _is_ipv6(ipaddrv6):
                v6_method = f"Static ({ipaddrv6}/{subnetv6})"
            elif ipaddrv6:
                v6_method = ipaddrv6

            status_icon = OK if has_v6 else NONE
            print(f"  [{status_icon}] {descr:20s} ({iface_name:10s})")
            print(f"        IPv4: {ipaddr or 'none'}")
            print(f"        IPv6: {v6_method}")

        if v6_interfaces:
            readiness["IPv6 Interfaces"] = f"{len(v6_interfaces)} configured"
        else:
            readiness["IPv6 Interfaces"] = "NONE configured"
            recommendations.append(
                "No interfaces have IPv6 configured. Configure DHCPv6-PD on WAN and Track Interface on LAN interfaces."
            )
    else:
        print(f"  [{FAIL}] Could not read interface config: {iface_result}")
        readiness["IPv6 Interfaces"] = "unknown"

    # ============================================================
    # 4. IPv6 Firewall Rules
    # ============================================================
    _print_header("4. IPv6 Firewall Rules")

    status, fw_result = await _safe_call("firewall_rules", opn_list_firewall_rules(ctx, limit=500))
    if status == "ok":
        rows = fw_result.get("rows", [])
        total = fw_result.get("rowCount", len(rows))

        v6_rules = []
        v4_rules = []
        dual_rules = []
        for rule in rows:
            ip_proto = rule.get("ipprotocol", rule.get("ip_protocol", ""))
            if ip_proto == "inet6":
                v6_rules.append(rule)
            elif ip_proto in ("inet46", "IPv4+IPv6"):
                dual_rules.append(rule)
            else:
                v4_rules.append(rule)

        print(f"  Total rules:      {total}")
        print(f"  IPv4-only (inet): {len(v4_rules)}")
        print(f"  IPv6-only (inet6):{len(v6_rules)}")
        print(f"  Dual-stack:       {len(dual_rules)}")

        if v6_rules:
            readiness["IPv6 Firewall Rules"] = f"{len(v6_rules)} rules"
            _print_sub("IPv6 Rules Detail")
            for rule in v6_rules:
                desc = rule.get("description", "(no description)")
                enabled = rule.get("enabled", "1")
                action = rule.get("action", "?")
                proto = rule.get("protocol", "any")
                src = rule.get("source_net", "any")
                dst = rule.get("destination_net", "any")
                dst_port = rule.get("destination_port", "")
                status_icon = OK if enabled == "1" else NONE
                port_str = f":{dst_port}" if dst_port else ""
                print(f"    [{status_icon}] {action:5s} {proto:8s} {src:20s} -> {dst}{port_str}  | {desc}")
        else:
            readiness["IPv6 Firewall Rules"] = "NONE"
            recommendations.append(
                "No IPv6 firewall rules found. At minimum, create ICMPv6 rules "
                "(required for NDP, RA, PMTUD) and allow outbound IPv6 traffic."
            )

        # Check for essential ICMPv6 rules
        has_icmpv6 = any(r.get("protocol", "").lower() in ("icmpv6", "icmp6", "ipv6-icmp") for r in v6_rules)
        if v6_rules and not has_icmpv6:
            recommendations.append(
                "IPv6 rules exist but no ICMPv6 rule found. ICMPv6 is essential "
                "for NDP (neighbor discovery), RA, and PMTUD."
            )
    else:
        print(f"  [{FAIL}] {fw_result}")
        readiness["IPv6 Firewall Rules"] = "unknown"

    # ============================================================
    # 5. DHCPv6 / Router Advertisements (dnsmasq)
    # ============================================================
    _print_header("5. DHCPv6 / Router Advertisements (dnsmasq)")

    # 5a. Ranges
    status, ranges_result = await _safe_call("dnsmasq_ranges", opn_list_dnsmasq_ranges(ctx), optional=True)
    if status == "ok":
        ranges_rows = ranges_result.get("rows", [])
        v6_ranges = []
        v4_ranges = []
        for r in ranges_rows:
            start = r.get("start_addr", "")
            if _is_ipv6(start) or r.get("prefix_len"):
                v6_ranges.append(r)
            else:
                v4_ranges.append(r)

        print(f"  Total DHCP ranges:  {len(ranges_rows)}")
        print(f"  IPv4 ranges:        {len(v4_ranges)}")
        print(f"  IPv6/DHCPv6 ranges: {len(v6_ranges)}")

        for r in ranges_rows:
            iface = r.get("interface", "?")
            start = r.get("start_addr", "?")
            end = r.get("end_addr", "?")
            prefix = r.get("prefix_len", "")
            ra = r.get("ra_mode", "")
            enabled = r.get("enabled", "1")
            desc = r.get("description", "")
            is_v6 = _is_ipv6(start) or bool(prefix)
            proto = "IPv6" if is_v6 else "IPv4"
            status_icon = OK if enabled == "1" else NONE
            ra_str = f" RA={ra}" if ra else ""
            prefix_str = f"/{prefix}" if prefix else ""
            desc_str = f" ({desc})" if desc else ""
            print(f"    [{status_icon}] [{proto:4s}] {iface:10s} {start} - {end}{prefix_str}{ra_str}{desc_str}")

        if v6_ranges:
            readiness["DHCPv6 Ranges"] = f"{len(v6_ranges)} ranges"
            ra_modes = [r.get("ra_mode", "") for r in v6_ranges if r.get("ra_mode")]
            if ra_modes:
                readiness["Router Advertisements"] = f"configured ({', '.join(set(ra_modes))})"
            else:
                readiness["Router Advertisements"] = "NOT configured on DHCPv6 ranges"
                recommendations.append(
                    "DHCPv6 ranges exist but no RA mode set. Configure RA mode "
                    "(slaac, ra-stateless, or ra-only) for IPv6 address assignment."
                )
        else:
            readiness["DHCPv6 Ranges"] = "NONE"
            readiness["Router Advertisements"] = "NONE (no DHCPv6 ranges)"
            recommendations.append(
                "No DHCPv6 ranges configured. Use opn_add_dnsmasq_range to create "
                "IPv6 ranges with Router Advertisement configuration."
            )
    elif status == "skip":
        print(f"  [{SKIP}] dnsmasq ranges not available (plugin may not be installed)")
        readiness["DHCPv6 Ranges"] = "n/a (no dnsmasq)"
        readiness["Router Advertisements"] = "n/a (no dnsmasq)"
    else:
        print(f"  [{FAIL}] {ranges_result}")
        readiness["DHCPv6 Ranges"] = "error"

    # 5b. Leases
    _print_sub("DHCPv6 Leases")
    status, leases_result = await _safe_call("dnsmasq_leases", opn_list_dnsmasq_leases(ctx, limit=500), optional=True)
    if status == "ok":
        leases_rows = leases_result.get("rows", [])
        v6_leases = [le for le in leases_rows if _is_ipv6(le.get("address", ""))]
        v4_leases = [le for le in leases_rows if not _is_ipv6(le.get("address", ""))]

        print(f"  Total leases:   {len(leases_rows)}")
        print(f"  IPv4 leases:    {len(v4_leases)}")
        print(f"  IPv6 leases:    {len(v6_leases)}")

        if v6_leases:
            readiness["DHCPv6 Leases"] = f"{len(v6_leases)} active"
            print("\n  IPv6 lease details (first 20):")
            for lease in v6_leases[:20]:
                addr = lease.get("address", "?")
                mac = lease.get("mac", "?")
                hostname = lease.get("hostname", "?")
                iface = lease.get("if", lease.get("interface", "?"))
                print(f"    {addr:40s} {mac:20s} {hostname:20s} ({iface})")
        else:
            readiness["DHCPv6 Leases"] = "none active"
    elif status == "skip":
        print(f"  [{SKIP}] dnsmasq leases not available")
        readiness["DHCPv6 Leases"] = "n/a"
    else:
        print(f"  [{FAIL}] {leases_result}")

    # ============================================================
    # 6. IPv6 DNS Records (AAAA)
    # ============================================================
    _print_header("6. IPv6 DNS Records (AAAA)")

    status, dns_result = await _safe_call("dns_overrides", opn_list_dns_overrides(ctx))
    if status == "ok":
        dns_rows = dns_result.get("rows", [])
        aaaa_records = [r for r in dns_rows if _is_ipv6(r.get("server", ""))]
        a_records = [r for r in dns_rows if not _is_ipv6(r.get("server", ""))]

        print(f"  Total DNS overrides: {len(dns_rows)}")
        print(f"  A records (IPv4):    {len(a_records)}")
        print(f"  AAAA records (IPv6): {len(aaaa_records)}")

        if aaaa_records:
            readiness["IPv6 DNS (AAAA)"] = f"{len(aaaa_records)} records"
            for rec in aaaa_records:
                host = rec.get("hostname", "?")
                domain = rec.get("domain", "?")
                server = rec.get("server", "?")
                enabled = rec.get("enabled", "1")
                status_icon = OK if enabled == "1" else NONE
                print(f"    [{status_icon}] {host}.{domain} -> {server}")
        else:
            readiness["IPv6 DNS (AAAA)"] = "NONE"
            recommendations.append(
                "No AAAA DNS overrides found. Add IPv6 DNS records with opn_add_dns_override for internal hosts."
            )
    else:
        print(f"  [{FAIL}] {dns_result}")
        readiness["IPv6 DNS (AAAA)"] = "unknown"

    # ============================================================
    # 7. IPv6 Static Routes
    # ============================================================
    _print_header("7. IPv6 Static Routes")

    status, routes_result = await _safe_call("static_routes", opn_list_static_routes(ctx))
    if status == "ok":
        routes_rows = routes_result.get("rows", [])
        v6_routes = [r for r in routes_rows if _is_ipv6(r.get("network", "")) or _is_ipv6(r.get("gateway", ""))]

        print(f"  Total static routes: {len(routes_rows)}")
        print(f"  IPv6 routes:         {len(v6_routes)}")

        if v6_routes:
            readiness["IPv6 Routes"] = f"{len(v6_routes)} routes"
            for r in v6_routes:
                net = r.get("network", "?")
                gw = r.get("gateway", "?")
                desc = r.get("descr", r.get("description", ""))
                enabled = r.get("disabled", "0") != "1"
                status_icon = OK if enabled else NONE
                print(f"    [{status_icon}] {net:30s} via {gw} {desc}")
        else:
            readiness["IPv6 Routes"] = "none (may use default gateway)"
            print("  No IPv6 static routes (this is normal if using default gateway only)")
    else:
        print(f"  [{FAIL}] {routes_result}")
        readiness["IPv6 Routes"] = "unknown"

    # ============================================================
    # 8. Dynamic DNS IPv6
    # ============================================================
    _print_header("8. Dynamic DNS (IPv6)")

    status, ddns_result = await _safe_call("ddns_accounts", opn_list_ddns_accounts(ctx), optional=True)
    if status == "ok":
        ddns_rows = ddns_result.get("rows", [])
        v6_ddns = [a for a in ddns_rows if "6" in a.get("checkip", "") or _is_ipv6(a.get("current_ip", ""))]
        v4_ddns = [a for a in ddns_rows if a not in v6_ddns]

        print(f"  Total DDNS accounts: {len(ddns_rows)}")
        print(f"  IPv4 accounts:       {len(v4_ddns)}")
        print(f"  IPv6 accounts:       {len(v6_ddns)}")

        for account in ddns_rows:
            hostname = account.get("hostnames", account.get("hostname", "?"))
            service = account.get("service", "?")
            checkip = account.get("checkip", "?")
            current_ip = account.get("current_ip", "none")
            enabled = account.get("enabled", "1")
            desc = account.get("description", "")
            is_v6 = "6" in checkip or _is_ipv6(current_ip)
            proto = "IPv6" if is_v6 else "IPv4"
            status_icon = OK if enabled == "1" else NONE
            ip_display = current_ip if current_ip else "(no IP — never updated)"
            print(
                f"    [{status_icon}] [{proto:4s}] {hostname:30s} service={service} checkip={checkip} ip={ip_display}"
            )
            if desc:
                print(f"           {desc}")

        if v6_ddns:
            readiness["IPv6 Dynamic DNS"] = f"{len(v6_ddns)} accounts"
        else:
            readiness["IPv6 Dynamic DNS"] = "NONE"
            if ddns_rows:
                recommendations.append(
                    "DDNS accounts exist but none use IPv6 checkip methods. "
                    "Add IPv6 DDNS with checkip='web_dyndns6' or similar, "
                    "and ensure global 'allowipv6' is enabled."
                )
    elif status == "skip":
        print(f"  [{SKIP}] Dynamic DNS plugin not installed")
        readiness["IPv6 Dynamic DNS"] = "n/a (no plugin)"
    else:
        print(f"  [{FAIL}] {ddns_result}")
        readiness["IPv6 Dynamic DNS"] = "error"

    # ============================================================
    # 9. HAProxy IPv6
    # ============================================================
    _print_header("9. HAProxy IPv6 Bindings")

    status, haproxy_result = await _safe_call("haproxy", opn_haproxy_status(ctx), optional=True)
    if status == "ok":
        widget = haproxy_result.get("widget", {})
        ha_status = haproxy_result.get("status", "unknown")
        print(f"  HAProxy status: {ha_status}")

        # Check widget data for IPv6 bindings
        if isinstance(widget, dict):
            servers = widget.get("servers", [])
            for srv in servers if isinstance(servers, list) else []:
                name = srv.get("label", srv.get("name", "?"))
                addr = srv.get("address", "")
                if _is_ipv6(addr):
                    print(f"    [IPv6] {name}: {addr}")

        # Note: detailed HAProxy IPv6 analysis requires haproxy_search which
        # isn't included here to avoid excessive API calls
        print("  (Use opn_haproxy_search for detailed frontend/backend IPv6 analysis)")
        readiness["HAProxy IPv6"] = "installed" if ha_status != "unknown" else "unknown"
    elif status == "skip":
        print(f"  [{SKIP}] HAProxy not installed")
        readiness["HAProxy IPv6"] = "n/a"
    else:
        print(f"  [{FAIL}] {haproxy_result}")
        readiness["HAProxy IPv6"] = "error"

    # ============================================================
    # 10. IPv6 Connectivity Tests
    # ============================================================
    _print_header("10. IPv6 Connectivity Tests")

    # 10a. Ping Google DNS over IPv6
    print("  Testing IPv6 connectivity to 2001:4860:4860::8888 (Google DNS)...")
    status, ping_result = await _safe_call("ipv6_ping", opn_ping(ctx, host="2001:4860:4860::8888", count=3))
    if status == "ok":
        loss = ping_result.get("packet_loss", "?")
        rtt = ping_result.get("round_trip_avg", ping_result.get("rtt_avg", "?"))
        print(f"    [{PASS}] IPv6 ping: loss={loss}, avg_rtt={rtt}")
        readiness["IPv6 Connectivity"] = "working"
    else:
        err = ping_result.get("error", str(ping_result)) if isinstance(ping_result, dict) else str(ping_result)
        print(f"    [{FAIL}] IPv6 ping failed: {err}")
        readiness["IPv6 Connectivity"] = "FAILED"
        recommendations.append(
            "IPv6 ping to Google DNS failed. Check WAN IPv6 configuration, "
            "gateway status, and upstream ISP IPv6 support."
        )

    # 10b. IPv6 traceroute
    print("\n  Tracing IPv6 path to 2001:4860:4860::8888...")
    status, trace_result = await _safe_call(
        "ipv6_traceroute",
        opn_traceroute(ctx, host="2001:4860:4860::8888", ip_version="6"),
    )
    if status == "ok":
        hops = trace_result.get("hops", [])
        print(f"    [{PASS}] IPv6 traceroute: {len(hops)} hops")
        for hop in hops[:15]:
            hop_num = hop.get("hop", "?")
            hop_host = hop.get("host", hop.get("ip", "*"))
            hop_rtt = hop.get("rtt1", hop.get("rtt", "*"))
            print(f"      {hop_num:>3s}  {hop_host:45s}  {hop_rtt}")
    else:
        err = trace_result.get("error", str(trace_result)) if isinstance(trace_result, dict) else str(trace_result)
        print(f"    [{FAIL}] IPv6 traceroute failed: {err}")

    # 10c. DNS AAAA resolution
    print("\n  Testing AAAA DNS resolution for ipv6.google.com...")
    status, dns_result = await _safe_call("ipv6_dns", opn_dns_lookup(ctx, hostname="ipv6.google.com"))
    if status == "ok":
        addresses = dns_result.get("addresses", dns_result.get("results", []))
        if isinstance(addresses, list):
            v6_addrs = [a for a in addresses if isinstance(a, str) and _is_ipv6(a)]
            print(f"    [{PASS}] AAAA resolution: {len(v6_addrs)} IPv6 addresses")
            for addr in v6_addrs[:5]:
                print(f"      {addr}")
        else:
            print(f"    [{INFO}] DNS result: {json.dumps(dns_result, default=str)[:200]}")
        readiness["IPv6 DNS Resolution"] = "working"
    else:
        err = dns_result.get("error", str(dns_result)) if isinstance(dns_result, dict) else str(dns_result)
        print(f"    [{FAIL}] AAAA resolution failed: {err}")
        readiness["IPv6 DNS Resolution"] = "FAILED"

    # ============================================================
    # 11. Security Audit — IPv6 Relevant Findings
    # ============================================================
    _print_header("11. Security Audit — IPv6 Relevant Findings")

    status, audit_result = await _safe_call("security_audit", opn_security_audit(ctx))
    if status == "ok":
        summary = audit_result.get("summary", {})
        print(f"  Total findings: {summary.get('total_findings', '?')}")
        print(
            f"  Critical: {summary.get('critical', 0)}, "
            f"Warning: {summary.get('warning', 0)}, "
            f"Info: {summary.get('info', 0)}"
        )

        # Extract IPv6-relevant findings from all sections
        ipv6_findings: list[dict[str, Any]] = []
        for section_name in (
            "firewall_rules",
            "nat_rules",
            "dns_security",
            "gateways",
            "vpn_security",
            "haproxy",
        ):
            section = audit_result.get(section_name, {})
            for finding in section.get("findings", []):
                msg = finding.get("message", "").lower()
                check = finding.get("check", "").lower()
                if any(kw in msg or kw in check for kw in ("ipv6", "inet6", "v6", "aaaa")):
                    finding["_section"] = section_name
                    ipv6_findings.append(finding)

        if ipv6_findings:
            print(f"\n  IPv6-specific findings ({len(ipv6_findings)}):")
            for f in ipv6_findings:
                sev = f.get("severity", "?").upper()
                msg = f.get("message", "")
                section = f.get("_section", "")
                color = CRIT if sev == "CRITICAL" else WARN if sev == "WARNING" else INFO
                print(f"    [{color}] [{section}] {msg}")
        else:
            print("  No IPv6-specific findings in security audit.")
            print("  (This may mean IPv6 is not configured enough to audit)")
    else:
        print(f"  [{FAIL}] Security audit failed: {audit_result}")

    # ============================================================
    # 12. IPv6 Readiness Summary
    # ============================================================
    _print_header("IPv6 READINESS SUMMARY")

    configured_count = 0
    not_configured_count = 0

    for area, status_text in readiness.items():
        ok_keywords = (
            "configured",
            "working",
            "active",
            "installed",
            "rules",
            "records",
            "ranges",
            "accounts",
            "routes",
        )
        is_ok = (
            any(kw in status_text.lower() for kw in ok_keywords)
            and "not" not in status_text.lower()
            and "none" not in status_text.lower()
        )

        icon = OK if is_ok else WARN if "n/a" in status_text.lower() else FAIL
        print(f"  [{icon}] {area:25s} {status_text}")
        if is_ok:
            configured_count += 1
        elif "n/a" not in status_text.lower() and "unknown" not in status_text.lower():
            not_configured_count += 1

    total_areas = configured_count + not_configured_count
    pct = (configured_count / total_areas * 100) if total_areas > 0 else 0
    print(f"\n  IPv6 readiness: {configured_count}/{total_areas} areas ({pct:.0f}%)")

    # ============================================================
    # 13. Recommendations
    # ============================================================
    if recommendations:
        _print_header("RECOMMENDATIONS")
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")

    print(f"\n{SECTION_SEP}")
    print("  Analysis complete.")
    print(SECTION_SEP)

    await api.close()
    return 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
    except Exception:
        traceback.print_exc()
        exit_code = 2
    sys.exit(exit_code)
