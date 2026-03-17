"""Security tools — comprehensive audit and hardening checks.

Covers 11 security areas: firmware, firewall rules (MVC + legacy), NAT/port
forwarding, DNS resolver security, system hardening, services, certificates,
VPN status, HAProxy reverse proxy, and gateway health.  Findings are tagged
with applicable compliance frameworks (PCI DSS v4.0, BSI IT-Grundschutz,
NIST SP 800-41, CIS Benchmarks).
"""

from __future__ import annotations

import re
from typing import Any

from fastmcp import Context

from opnsense_mcp.api_client import OPNsenseAPI, OPNsenseAPIError
from opnsense_mcp.config_cache import ConfigCache
from opnsense_mcp.server import get_api, get_config_cache, mcp

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CRITICAL_SERVICES: frozenset[str] = frozenset({"unbound", "pf", "syslog-ng", "configd", "ntpd", "openssh", "dpinger"})

_PORT_GROUPS: dict[str, frozenset[int]] = {
    "web": frozenset({80, 443, 8080, 8443}),
    "email": frozenset({25, 465, 587, 993, 995}),
    "ssh": frozenset({22}),
    "dns": frozenset({53, 853}),
    "ntp": frozenset({123}),
    "database": frozenset({3306, 5432, 1433, 27017, 6379}),
    "remote_access": frozenset({3389, 5900, 5901}),
    "file_sharing": frozenset({445, 139, 21}),
}

_DANGEROUS_NAT_PORTS: frozenset[int] = frozenset({22, 23, 139, 445, 3389, 5900, 3306, 5432, 1433, 27017, 6379, 9200})

_UDP_AMPLIFICATION_PORTS: frozenset[int] = frozenset({53, 123, 161, 11211, 1900, 19})

_INSECURE_PORTS: dict[int, dict[str, str]] = {
    21: {"protocol": "FTP", "alternative": "SFTP (port 22) or FTPS (port 990)"},
    23: {"protocol": "Telnet", "alternative": "SSH (port 22)"},
    25: {
        "protocol": "SMTP (plaintext)",
        "alternative": "SMTPS (port 465) or SMTP+STARTTLS (port 587)",
    },
    69: {"protocol": "TFTP", "alternative": "SCP/SFTP (port 22)"},
    80: {"protocol": "HTTP", "alternative": "HTTPS (port 443)"},
    110: {"protocol": "POP3", "alternative": "POP3S (port 995)"},
    143: {"protocol": "IMAP", "alternative": "IMAPS (port 993)"},
    389: {"protocol": "LDAP", "alternative": "LDAPS (port 636)"},
    512: {"protocol": "rexec", "alternative": "SSH (port 22)"},
    513: {"protocol": "rlogin", "alternative": "SSH (port 22)"},
    514: {"protocol": "rsh", "alternative": "SSH (port 22)"},
    873: {"protocol": "rsync (unencrypted)", "alternative": "rsync over SSH"},
}

_MAX_AUDIT_ROWS: int = 10_000

_MANAGEMENT_PORTS: frozenset[int] = frozenset({22, 443, 8443})

_WAN_INTERFACES: frozenset[str] = frozenset({"wan", "WAN", "igb0", "em0", "vtnet0"})

_COMPLIANCE_MAP: dict[str, list[str]] = {
    "permissive_rule": [
        "PCI-DSS-1.2.1",
        "BSI-NET.3.2-A2",
        "NIST-800-41",
        "CIS-FW-2.3",
    ],
    "broad_source": ["PCI-DSS-1.2.1", "NIST-800-41", "CIS-FW-2.3"],
    "broad_destination": ["PCI-DSS-1.2.1", "NIST-800-41", "CIS-FW-2.3"],
    "no_port_restriction": ["PCI-DSS-1.2.1", "NIST-800-41"],
    "broad_port_range": ["PCI-DSS-1.2.1", "NIST-800-41"],
    "wan_inbound_pass": ["PCI-DSS-1.2.1", "BSI-NET.3.2-A2"],
    "management_exposure": ["PCI-DSS-1.2.1", "BSI-NET.3.2-A2", "CIS-FW-2.2"],
    "legacy_rules_present": ["BSI-NET.3.2-A8", "NIST-800-41"],
    "disabled_rules": ["NIST-800-41"],
    "rules_no_description": [
        "PCI-DSS-1.2.2",
        "BSI-NET.3.2-A8",
        "NIST-800-41",
    ],
    "insecure_protocol": ["PCI-DSS-4.1.1", "BSI-NET.3.2-A2"],
    "nat_insecure_protocol": ["PCI-DSS-4.1.1", "BSI-NET.3.2-A2"],
    "dangerous_nat_port": ["PCI-DSS-1.2.1", "BSI-NET.3.2-A2"],
    "nat_unrestricted_source": ["PCI-DSS-1.2.1", "NIST-800-41"],
    "nat_udp_amplification": ["BSI-NET.3.2-A7"],
    "dnssec_disabled": ["CIS-FW-1.4"],
    "plaintext_dns_forwarder": ["PCI-DSS-4.1.1"],
    "webgui_no_https": ["PCI-DSS-4.1.1", "CIS-FW-1.3", "BSI-NET.3.2-A2"],
    "ssh_root_login": ["PCI-DSS-2.1", "CIS-FW-1.2", "BSI-NET.3.2-A2"],
    "ssh_password_auth": ["PCI-DSS-2.1", "CIS-FW-1.2", "BSI-NET.3.2-A2"],
    "no_remote_syslog": [
        "PCI-DSS-10.2.1",
        "BSI-OPS.1.1.5-A1",
        "NIST-800-41",
    ],
    "firmware_update_available": ["PCI-DSS-2.2.1", "CIS-FW-3.1"],
    "service_stopped": ["BSI-NET.3.2-A2"],
    "gateway_down": ["BSI-NET.3.2-A2"],
    "haproxy_http_frontend": ["PCI-DSS-4.1.1", "BSI-NET.3.2-A2"],
    "haproxy_no_https_redirect": ["PCI-DSS-4.1.1"],
    "haproxy_no_healthcheck": ["BSI-NET.3.2-A2"],
    "haproxy_missing_headers": ["PCI-DSS-6.4.1", "CIS-FW-1.3"],
    "wg_stale_peer": ["BSI-NET.3.2-A2"],
}

_COMPLIANCE_FRAMEWORKS: list[dict[str, str]] = [
    {
        "id": "PCI-DSS",
        "name": "PCI DSS v4.0",
        "description": "Payment Card Industry Data Security Standard",
    },
    {
        "id": "BSI",
        "name": "BSI IT-Grundschutz",
        "description": "German Federal Office for Information Security baseline",
    },
    {
        "id": "NIST-800-41",
        "name": "NIST SP 800-41 Rev 1",
        "description": "Guidelines on Firewalls and Firewall Policy",
    },
    {
        "id": "CIS",
        "name": "CIS Benchmarks",
        "description": "Center for Internet Security firewall hardening",
    },
]

_MANUAL_REVIEW_ITEMS: list[str] = [
    "PCI-DSS-1.2.2: Business justification documented for each rule",
    "PCI-DSS-10.3.1: Log integrity protection (immutable storage)",
    "PCI-DSS-10.7: Log retention >= 1 year (90 days immediate access)",
    "BSI-NET.3.2-A8: Quarterly ruleset review with audit trail",
    "NIST-800-41: Periodic penetration testing of firewall rules",
]

_SECURITY_HEADERS: frozenset[str] = frozenset(
    {"strict-transport-security", "x-frame-options", "x-content-type-options"}
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _add_compliance(finding: dict[str, Any]) -> dict[str, Any]:
    """Inject compliance framework references into a finding."""
    check = finding.get("check", "")
    refs = _COMPLIANCE_MAP.get(check)
    if refs:
        finding["compliance"] = refs
    return finding


def _finding(
    *,
    severity: str,
    check: str,
    message: str,
    recommendation: str = "",
    **extra: str | int | float | bool | list[str] | dict[str, str],
) -> dict[str, Any]:
    """Create a finding dict with automatic compliance tagging."""
    f: dict[str, Any] = {"severity": severity, "check": check, "message": message}
    if recommendation:
        f["recommendation"] = recommendation
    f.update(extra)
    return _add_compliance(f)


async def _fetch_all_pages(
    api: OPNsenseAPI,
    endpoint: str,
    page_size: int = 500,
) -> list[dict[str, Any]]:
    """Paginate through all rows of a search endpoint."""
    all_rows: list[dict[str, Any]] = []
    current = 1
    while len(all_rows) < _MAX_AUDIT_ROWS:
        result = await api.post(
            endpoint,
            {"current": current, "rowCount": page_size, "searchPhrase": ""},
        )
        rows: list[dict[str, Any]] = result.get("rows", [])
        if not rows:
            break
        all_rows.extend(rows)
        total = int(result.get("total", result.get("rowCount", 0)))
        if len(all_rows) >= total:
            break
        current += 1
    return all_rows


_PORT_RE = re.compile(r"^\d+$")
_RANGE_RE = re.compile(r"^(\d+)[-:](\d+)$")


def _parse_ports(port_str: str) -> set[int]:
    """Parse an OPNsense port spec to a set of individual port numbers.

    Handles single ports (``"80"``), ranges (``"1000-2000"`` or ``"1000:2000"``),
    and comma-separated combinations.  Returns an empty set for aliases or
    names that cannot be parsed numerically.
    """
    if not port_str or not port_str.strip():
        return set()
    ports: set[int] = set()
    for part in port_str.split(","):
        part = part.strip()
        if _PORT_RE.match(part):
            ports.add(int(part))
        else:
            m = _RANGE_RE.match(part)
            if m:
                lo, hi = int(m.group(1)), int(m.group(2))
                if hi - lo <= 10000:
                    ports.update(range(lo, hi + 1))
    return ports


def _is_broad_port_range(port_str: str, threshold: int = 100) -> bool:
    """Return True if port spec covers more than *threshold* individual ports."""
    return len(_parse_ports(port_str)) > threshold


def _classify_ports(ports: set[int]) -> set[str]:
    """Return which ``_PORT_GROUPS`` categories a set of ports spans."""
    groups: set[str] = set()
    for name, group_ports in _PORT_GROUPS.items():
        if ports & group_ports:
            groups.add(name)
    return groups


def _find_insecure_ports(ports: set[int]) -> list[dict[str, str]]:
    """Return insecure protocol matches from ``_INSECURE_PORTS``."""
    matches: list[dict[str, str]] = []
    for port in sorted(ports):
        info = _INSECURE_PORTS.get(port)
        if info:
            matches.append({"port": str(port), **info})
    return matches


def _is_wan(interface: str) -> bool:
    """Heuristic: return True if *interface* looks like a WAN interface."""
    return interface.lower().strip() in {w.lower() for w in _WAN_INTERFACES}


# ---------------------------------------------------------------------------
# Check functions — each returns a section dict with "status" and "findings"
# ---------------------------------------------------------------------------


async def _check_firmware(
    api: OPNsenseAPI,
    cache: ConfigCache,  # noqa: ARG001
) -> dict[str, Any]:
    """Check firmware version and available updates."""
    try:
        result = await api.get("firmware.status")
    except OPNsenseAPIError as exc:
        return {"status": "skipped", "reason": str(exc), "findings": []}

    # OPNsense 26.x nests product info under "product"; earlier versions
    # have product_version at the top level.
    product = result.get("product", result)
    version = product.get("product_version", "unknown")
    name = product.get("product_name", "OPNsense")
    findings: list[dict[str, Any]] = [
        _finding(
            severity="info",
            check="firmware_version",
            message=f"Running {name} {version}",
        )
    ]

    if result.get("upgrade_sets"):
        findings.append(
            _finding(
                severity="warning",
                check="firmware_update_available",
                message="Firmware update is available — consider upgrading",
                recommendation="Apply latest firmware updates to patch known vulnerabilities",
            )
        )

    return {
        "status": "ok",
        "product_version": version,
        "product_name": name,
        "findings": findings,
    }


async def _check_firewall_rules(
    api: OPNsenseAPI,
    cache: ConfigCache,
) -> dict[str, Any]:
    """Check firewall rules for security issues (MVC + legacy)."""
    findings: list[dict[str, Any]] = []
    mvc_count = 0
    legacy_count = 0

    # --- MVC rules (paginated) ---
    try:
        mvc_rows = await _fetch_all_pages(api, "firewall.search_rule")
        mvc_count = len(mvc_rows)
    except OPNsenseAPIError as exc:
        return {"status": "skipped", "reason": str(exc), "findings": []}

    disabled_count = 0
    no_desc_count = 0

    for rule in mvc_rows:
        _analyze_mvc_rule(rule, findings)
        if str(rule.get("enabled", "1")) in ("0", "false"):
            disabled_count += 1
        desc = str(rule.get("description", "")).strip()
        if not desc:
            no_desc_count += 1

    # --- Legacy rules from config.xml ---
    legacy_rules = _extract_legacy_rules(cache)
    legacy_count = len(legacy_rules)
    for rule in legacy_rules:
        _analyze_legacy_rule(rule, findings)
        if str(rule.get("disabled", "")) == "1":
            disabled_count += 1
        desc = str(rule.get("descr", "")).strip()
        if not desc:
            no_desc_count += 1

    # Legacy rule migration warning
    if legacy_count > 0:
        findings.append(
            _finding(
                severity="warning",
                check="legacy_rules_present",
                message=(
                    f"{legacy_count} firewall rule(s) still in legacy (config.xml) format"
                    f" — {mvc_count} rule(s) in MVC format"
                ),
                recommendation=(
                    "Migrate legacy rules to the MVC filter using the built-in Migration Assistant "
                    "(Firewall > Automation > Migration). Available since OPNsense 26.1. "
                    "MVC rules support API management, versioning, and are the future standard."
                ),
                legacy_count=legacy_count,
                mvc_count=mvc_count,
            )
        )

    # Aggregate hygiene checks
    if disabled_count > 0:
        findings.append(
            _finding(
                severity="warning",
                check="disabled_rules",
                message=f"{disabled_count} disabled rule(s) found — consider removing unused rules",
                recommendation="Remove rules that are no longer needed to reduce attack surface",
                count=disabled_count,
            )
        )

    if no_desc_count > 0:
        findings.append(
            _finding(
                severity="info",
                check="rules_no_description",
                message=f"{no_desc_count} rule(s) without descriptions",
                recommendation="Add descriptions to all rules for audit trail compliance",
                count=no_desc_count,
            )
        )

    return {
        "status": "ok",
        "total_mvc_rules": mvc_count,
        "total_legacy_rules": legacy_count,
        "findings": findings,
    }


def _analyze_mvc_rule(rule: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    """Analyze a single MVC firewall rule for security issues."""
    action = str(rule.get("action", "")).lower()
    if action != "pass":
        return

    source = str(rule.get("source_net", "")).lower()
    dest = str(rule.get("destination_net", "")).lower()
    proto = str(rule.get("protocol", "")).lower()
    port_str = str(rule.get("destination_port", ""))
    interface = str(rule.get("interface", ""))
    uuid = rule.get("uuid", "")
    desc = rule.get("description", "Unnamed rule")

    details = {
        "action": action,
        "source_net": source,
        "destination_net": dest,
        "protocol": proto,
        "interface": interface,
    }

    # Fully permissive (any/any/any)
    if source == "any" and dest == "any" and proto in ("any", ""):
        findings.append(
            _finding(
                severity="critical",
                check="permissive_rule",
                message=f"Rule '{desc}' passes any/any traffic with no protocol restriction",
                recommendation="Restrict source, destination, and protocol to least privilege",
                uuid=uuid,
                details=details,
            )
        )
        return  # Don't duplicate with sub-checks

    # Broad source
    if source == "any":
        findings.append(
            _finding(
                severity="warning",
                check="broad_source",
                message=f"Rule '{desc}' allows traffic from any source",
                recommendation="Restrict source to specific networks or hosts",
                uuid=uuid,
                details=details,
            )
        )

    # Broad destination
    if dest == "any":
        findings.append(
            _finding(
                severity="warning",
                check="broad_destination",
                message=f"Rule '{desc}' allows traffic to any destination",
                recommendation="Restrict destination to specific networks or hosts",
                uuid=uuid,
                details=details,
            )
        )

    # TCP/UDP without port restriction
    if proto in ("tcp", "udp", "tcp/udp") and not port_str:
        findings.append(
            _finding(
                severity="warning",
                check="no_port_restriction",
                message=f"Rule '{desc}' allows {proto.upper()} to all ports",
                recommendation="Specify allowed destination ports",
                uuid=uuid,
                details=details,
            )
        )

    # Broad port range
    if port_str and _is_broad_port_range(port_str):
        findings.append(
            _finding(
                severity="warning",
                check="broad_port_range",
                message=f"Rule '{desc}' covers a broad port range ({port_str})",
                recommendation="Narrow port range to only required services",
                uuid=uuid,
                details=details,
            )
        )

    # WAN inbound pass
    if _is_wan(interface):
        findings.append(
            _finding(
                severity="warning",
                check="wan_inbound_pass",
                message=f"Rule '{desc}' allows inbound traffic on WAN interface",
                recommendation="Ensure WAN pass rules are strictly necessary and scoped",
                uuid=uuid,
                details=details,
            )
        )

    # Management port exposure on WAN
    if _is_wan(interface) and source == "any":
        ports = _parse_ports(port_str)
        exposed_mgmt = ports & _MANAGEMENT_PORTS
        if exposed_mgmt:
            findings.append(
                _finding(
                    severity="critical",
                    check="management_exposure",
                    message=f"Rule '{desc}' exposes management ports {sorted(exposed_mgmt)} on WAN from any source",
                    recommendation="Restrict management access to specific admin IPs/networks",
                    uuid=uuid,
                    details=details,
                )
            )

    # Port analysis
    if port_str:
        ports = _parse_ports(port_str)
        if ports:
            _check_port_hygiene(ports, desc, uuid, details, findings)
            _check_insecure_ports(ports, desc, uuid, details, interface, findings)


def _check_port_hygiene(
    ports: set[int],
    desc: str,
    uuid: str,
    details: dict[str, Any],
    findings: list[dict[str, Any]],
) -> None:
    """Check port grouping best practices."""
    groups = _classify_ports(ports)

    # SSH combined with other ports
    if "ssh" in groups and len(ports) > 1:
        findings.append(
            _finding(
                severity="info",
                check="ssh_not_isolated",
                message=f"Rule '{desc}' combines SSH with other ports — SSH should have its own rule",
                recommendation="Create a dedicated rule for SSH access",
                uuid=uuid,
                details=details,
            )
        )

    # Mixed service types (3+ groups)
    if len(groups) >= 3:
        findings.append(
            _finding(
                severity="info",
                check="mixed_service_ports",
                message=(
                    f"Rule '{desc}' combines ports from {len(groups)} service categories: {', '.join(sorted(groups))}"
                ),
                recommendation="Split into separate rules per service category for better segmentation",
                uuid=uuid,
                details=details,
            )
        )


def _check_insecure_ports(
    ports: set[int],
    desc: str,
    uuid: str,
    details: dict[str, Any],
    interface: str,
    findings: list[dict[str, Any]],
) -> None:
    """Flag insecure (unencrypted) protocols in firewall rules."""
    insecure = _find_insecure_ports(ports)
    for match in insecure:
        # HTTP on non-WAN is common (redirects), report as info
        port_num = int(match["port"])
        if port_num == 80 and not _is_wan(interface):
            continue
        severity = "info" if not _is_wan(interface) else "warning"
        findings.append(
            _finding(
                severity=severity,
                check="insecure_protocol",
                message=f"Rule '{desc}' allows {match['protocol']} (port {match['port']})",
                recommendation=f"Use {match['alternative']} instead",
                uuid=uuid,
                details=details,
            )
        )


def _extract_legacy_rules(cache: ConfigCache) -> list[dict[str, Any]]:
    """Extract legacy firewall rules from config.xml filter section."""
    section = cache.get_section("filter")
    if section is None:
        return []
    data = section.get("data", {})
    if not isinstance(data, dict):
        return []
    rules_data = data.get("rule", [])
    if isinstance(rules_data, dict):
        rules_data = [rules_data]
    if not isinstance(rules_data, list):
        return []
    return [r for r in rules_data if isinstance(r, dict)]


def _analyze_legacy_rule(
    rule: dict[str, Any],
    findings: list[dict[str, Any]],
) -> None:
    """Analyze a single legacy (config.xml) firewall rule."""
    action = str(rule.get("type", "pass")).lower()
    if action != "pass":
        return
    if str(rule.get("disabled", "")) == "1":
        return  # Disabled rules handled in aggregate

    source = rule.get("source", {})
    dest = rule.get("destination", {})
    proto = str(rule.get("protocol", "")).lower()
    desc = rule.get("descr", "Legacy rule")
    interface = str(rule.get("interface", ""))

    src_any = "any" in source if isinstance(source, dict) else str(source).lower() == "any"
    dst_any = "any" in dest if isinstance(dest, dict) else str(dest).lower() == "any"
    dst_port = ""
    if isinstance(dest, dict):
        dst_port = str(dest.get("port", ""))

    details = {
        "action": action,
        "source": "any" if src_any else "specific",
        "destination": "any" if dst_any else "specific",
        "protocol": proto,
        "interface": interface,
        "rule_type": "legacy",
    }

    if src_any and dst_any and proto in ("any", ""):
        findings.append(
            _finding(
                severity="critical",
                check="permissive_rule",
                message=f"Legacy rule '{desc}' passes any/any traffic with no protocol restriction",
                recommendation="Restrict source, destination, and protocol to least privilege",
                details=details,
            )
        )
        return

    if src_any:
        findings.append(
            _finding(
                severity="warning",
                check="broad_source",
                message=f"Legacy rule '{desc}' allows traffic from any source",
                recommendation="Restrict source to specific networks or hosts",
                details=details,
            )
        )

    if dst_any:
        findings.append(
            _finding(
                severity="warning",
                check="broad_destination",
                message=f"Legacy rule '{desc}' allows traffic to any destination",
                recommendation="Restrict destination to specific networks or hosts",
                details=details,
            )
        )

    if proto in ("tcp", "udp", "tcp/udp") and not dst_port:
        findings.append(
            _finding(
                severity="warning",
                check="no_port_restriction",
                message=f"Legacy rule '{desc}' allows {proto.upper()} to all ports",
                recommendation="Specify allowed destination ports",
                details=details,
            )
        )

    if dst_port:
        ports = _parse_ports(dst_port)
        if ports:
            _check_port_hygiene(ports, desc, "", details, findings)
            _check_insecure_ports(ports, desc, "", details, interface, findings)


async def _check_nat_rules(
    api: OPNsenseAPI,
    cache: ConfigCache,  # noqa: ARG001
) -> dict[str, Any]:
    """Check NAT port forwarding rules for security issues."""
    try:
        rows = await _fetch_all_pages(api, "nat.dnat.search_rule")
    except OPNsenseAPIError as exc:
        return {"status": "skipped", "reason": str(exc), "findings": []}

    findings: list[dict[str, Any]] = []

    for rule in rows:
        # Skip deny/block/nordr rules — these prevent NAT, not enable it
        action = str(rule.get("type", rule.get("action", ""))).lower()
        if action in ("nordr", "block", "deny", "reject"):
            continue
        # Skip disabled rules
        enabled = str(rule.get("enabled", "1"))
        if enabled in ("0", "false"):
            continue

        dst_port = str(rule.get("dst_port", rule.get("target_port", "")))
        src = str(rule.get("source_net", rule.get("source", ""))).lower()
        proto = str(rule.get("protocol", "")).lower()
        desc = rule.get("description", "NAT rule")
        uuid = rule.get("uuid", "")

        ports = _parse_ports(dst_port)

        # Dangerous port exposure
        dangerous = ports & _DANGEROUS_NAT_PORTS
        if dangerous:
            findings.append(
                _finding(
                    severity="critical",
                    check="dangerous_nat_port",
                    message=f"NAT rule '{desc}' forwards dangerous port(s) {sorted(dangerous)}",
                    recommendation="Restrict access via VPN or allowlisted source IPs",
                    uuid=uuid,
                )
            )

        # Insecure protocol exposure
        insecure = _find_insecure_ports(ports)
        for match in insecure:
            findings.append(
                _finding(
                    severity="warning",
                    check="nat_insecure_protocol",
                    message=f"NAT rule '{desc}' exposes {match['protocol']} (port {match['port']})",
                    recommendation=f"Use {match['alternative']} instead",
                    uuid=uuid,
                )
            )

        # Unrestricted source
        if not src or src in ("any", ""):
            findings.append(
                _finding(
                    severity="warning",
                    check="nat_unrestricted_source",
                    message=f"NAT rule '{desc}' allows connections from any source",
                    recommendation="Restrict source to known IP ranges",
                    uuid=uuid,
                )
            )

        # Broad port range for NAT (lower threshold)
        if len(ports) > 10:
            findings.append(
                _finding(
                    severity="warning",
                    check="nat_broad_port_range",
                    message=f"NAT rule '{desc}' forwards a broad port range ({dst_port})",
                    recommendation="Narrow port range to only required services",
                    uuid=uuid,
                )
            )

        # UDP amplification
        if proto in ("udp", "tcp/udp"):
            amp_ports = ports & _UDP_AMPLIFICATION_PORTS
            if amp_ports:
                findings.append(
                    _finding(
                        severity="warning",
                        check="nat_udp_amplification",
                        message=f"NAT rule '{desc}' forwards UDP amplification-prone port(s) {sorted(amp_ports)}",
                        recommendation="Ensure rate limiting or access control is in place",
                        uuid=uuid,
                    )
                )

    return {
        "status": "ok",
        "total_nat_rules": len(rows),
        "findings": findings,
    }


async def _check_dns_security(
    api: OPNsenseAPI,
    cache: ConfigCache,  # noqa: ARG001
) -> dict[str, Any]:
    """Check DNS resolver (Unbound) security settings."""
    try:
        settings = await api.get("unbound.settings.get")
    except OPNsenseAPIError as exc:
        return {"status": "skipped", "reason": str(exc), "findings": []}

    unbound = settings.get("unbound", {})
    general = unbound.get("general", {}) if isinstance(unbound, dict) else {}
    if not isinstance(general, dict):
        general = {}

    findings: list[dict[str, Any]] = []

    # DNSSEC
    dnssec = str(general.get("dnssec", "0"))
    if dnssec != "1":
        findings.append(
            _finding(
                severity="warning",
                check="dnssec_disabled",
                message="DNSSEC validation is disabled on Unbound",
                recommendation="Enable DNSSEC to protect against DNS spoofing",
            )
        )

    # Hide identity
    hide_id = str(general.get("hideidentity", "0"))
    if hide_id != "1":
        findings.append(
            _finding(
                severity="info",
                check="dns_hide_identity",
                message="Unbound identity is not hidden",
                recommendation="Enable 'Hide Identity' to prevent resolver fingerprinting",
            )
        )

    # Hide version
    hide_ver = str(general.get("hideversion", "0"))
    if hide_ver != "1":
        findings.append(
            _finding(
                severity="info",
                check="dns_hide_version",
                message="Unbound version is not hidden",
                recommendation="Enable 'Hide Version' to prevent version disclosure",
            )
        )

    # Check forwarding zones for plaintext DNS
    try:
        forwards = await _fetch_all_pages(api, "unbound.search_forward")
    except OPNsenseAPIError:
        forwards = []

    if not forwards:
        findings.append(
            _finding(
                severity="info",
                check="no_dns_forwarders",
                message="No DNS forwarding zones configured",
            )
        )
    else:
        for fwd in forwards:
            port = str(fwd.get("port", fwd.get("forward_port", "53")))
            domain = fwd.get("domain", fwd.get("name", "unknown"))
            if port == "53":
                findings.append(
                    _finding(
                        severity="warning",
                        check="plaintext_dns_forwarder",
                        message=f"DNS forwarder for '{domain}' uses plaintext DNS (port 53)",
                        recommendation="Use DNS-over-TLS (port 853) for encrypted forwarding",
                    )
                )

    return {"status": "ok", "findings": findings}


async def _check_system_hardening(
    api: OPNsenseAPI,  # noqa: ARG001
    cache: ConfigCache,
) -> dict[str, Any]:
    """Check system hardening via config.xml sections."""
    findings: list[dict[str, Any]] = []

    system = cache.get_section("system")
    if system is None:
        return {"status": "skipped", "reason": "Config cache not loaded", "findings": []}

    data = system.get("data", {})
    if not isinstance(data, dict):
        return {"status": "skipped", "reason": "Invalid system config", "findings": []}

    # Web GUI HTTPS
    webgui = data.get("webgui", {})
    if isinstance(webgui, dict):
        protocol = str(webgui.get("protocol", "https"))
        if protocol != "https":
            findings.append(
                _finding(
                    severity="critical",
                    check="webgui_no_https",
                    message=f"Web GUI is using {protocol} instead of HTTPS",
                    recommendation="Switch web GUI to HTTPS to encrypt management traffic",
                )
            )

    # SSH config
    ssh_config = data.get("ssh", {})
    if isinstance(ssh_config, dict):
        if str(ssh_config.get("permitrootlogin", "0")) == "1":
            findings.append(
                _finding(
                    severity="warning",
                    check="ssh_root_login",
                    message="SSH root login is enabled",
                    recommendation="Disable root login and use a regular user with sudo",
                )
            )

        if str(ssh_config.get("passwordauth", "0")) == "1":
            findings.append(
                _finding(
                    severity="critical",
                    check="ssh_password_auth",
                    message="SSH password authentication is enabled — vulnerable to brute-force attacks",
                    recommendation="Disable password authentication and use key-based authentication only",
                )
            )

        port = str(ssh_config.get("port", "22"))
        if port == "22":
            findings.append(
                _finding(
                    severity="info",
                    check="ssh_default_port",
                    message="SSH is running on default port 22",
                    recommendation="Consider a non-standard port to reduce automated scan noise",
                )
            )

    # Remote syslog
    syslog_section = cache.get_section("syslog")
    has_remote = False
    if syslog_section is not None:
        syslog_data = syslog_section.get("data", {})
        if isinstance(syslog_data, dict):
            # Look for remote destinations in various config formats
            for key in ("remoteserver", "remoteserver2", "remoteserver3"):
                if syslog_data.get(key):
                    has_remote = True
                    break
            destinations = syslog_data.get("destination", [])
            if isinstance(destinations, list) and destinations:
                has_remote = True
            elif isinstance(destinations, dict):
                has_remote = True

    if not has_remote:
        findings.append(
            _finding(
                severity="warning",
                check="no_remote_syslog",
                message="No remote syslog destination configured",
                recommendation="Configure remote logging for audit trail and forensics",
            )
        )

    return {"status": "ok", "findings": findings}


async def _check_services(
    api: OPNsenseAPI,
    cache: ConfigCache,  # noqa: ARG001
) -> dict[str, Any]:
    """Check critical service running status."""
    try:
        result = await api.post(
            "core.service.search",
            {"current": 1, "rowCount": 500, "searchPhrase": ""},
        )
    except OPNsenseAPIError as exc:
        return {"status": "skipped", "reason": str(exc), "findings": []}

    rows: list[dict[str, Any]] = result.get("rows", [])
    findings: list[dict[str, Any]] = []
    running = 0
    stopped = 0
    crowdsec_present = False

    for svc in rows:
        is_running = svc.get("running", 0) in (1, "1", True)
        name = str(svc.get("name", svc.get("id", "unknown")))

        if is_running:
            running += 1
        else:
            stopped += 1
            if name in _CRITICAL_SERVICES:
                findings.append(
                    _finding(
                        severity="warning",
                        check="service_stopped",
                        message=f"Critical service '{name}' is not running",
                        recommendation=f"Start the '{name}' service or investigate why it stopped",
                        service=name,
                    )
                )

        if name == "crowdsec":
            crowdsec_present = True
            if not is_running:
                findings.append(
                    _finding(
                        severity="info",
                        check="crowdsec_not_running",
                        message="CrowdSec is installed but not running",
                        recommendation="Start CrowdSec for community-driven threat intelligence",
                    )
                )

    return {
        "status": "ok",
        "total_services": len(rows),
        "running": running,
        "stopped": stopped,
        "crowdsec_installed": crowdsec_present,
        "findings": findings,
    }


async def _check_certificates(
    api: OPNsenseAPI,
    cache: ConfigCache,
) -> dict[str, Any]:
    """Check certificate status (ACME + system certs + CAs)."""
    findings: list[dict[str, Any]] = []
    acme_skipped = False

    # ACME certificates
    try:
        result = await api.post(
            "acmeclient.certs.search",
            {"current": 1, "rowCount": 500, "searchPhrase": ""},
        )
        acme_rows: list[dict[str, Any]] = result.get("rows", [])
        if not acme_rows:
            findings.append(
                _finding(
                    severity="info",
                    check="no_acme_certs",
                    message="No ACME certificates configured (not required if using purchased certs)",
                )
            )
        else:
            for cert in acme_rows:
                status_code = cert.get("statusCode", "")
                name = cert.get("name", cert.get("commonName", "unknown"))
                if status_code and str(status_code) != "200":
                    findings.append(
                        _finding(
                            severity="warning",
                            check="cert_status",
                            message=f"ACME certificate '{name}' has status code {status_code}",
                            recommendation="Investigate and renew the certificate",
                            certificate=name,
                        )
                    )
    except OPNsenseAPIError:
        acme_skipped = True

    # System certificates from config.xml
    cert_section = cache.get_section("cert")
    cert_count = 0
    if cert_section is not None:
        cert_data = cert_section.get("data", [])
        if isinstance(cert_data, list):
            cert_count = len(cert_data)
        elif isinstance(cert_data, dict):
            cert_count = 1

    if cert_count > 0:
        findings.append(
            _finding(
                severity="info",
                check="system_cert_count",
                message=f"{cert_count} system certificate(s) in certificate store",
                count=cert_count,
            )
        )

    # CA certificates
    ca_section = cache.get_section("ca")
    ca_count = 0
    if ca_section is not None:
        ca_data = ca_section.get("data", [])
        if isinstance(ca_data, list):
            ca_count = len(ca_data)
        elif isinstance(ca_data, dict):
            ca_count = 1

    if ca_count > 0:
        findings.append(
            _finding(
                severity="info",
                check="ca_count",
                message=f"{ca_count} CA certificate(s) in certificate store",
                count=ca_count,
            )
        )

    if acme_skipped:
        return {
            "status": "skipped",
            "reason": "ACME client plugin (os-acme-client) not installed or not accessible",
            "system_certs": cert_count,
            "ca_certs": ca_count,
            "findings": findings,
        }

    return {
        "status": "ok",
        "system_certs": cert_count,
        "ca_certs": ca_count,
        "findings": findings,
    }


async def _check_vpn_security(
    api: OPNsenseAPI,
    cache: ConfigCache,  # noqa: ARG001
) -> dict[str, Any]:
    """Check VPN service status and WireGuard configuration."""
    findings: list[dict[str, Any]] = []
    vpn_found = False

    # --- WireGuard ---
    try:
        wg_status = await api.get("wireguard.service.show")
        # Response may use "items" or "rows" depending on OPNsense version
        wg_items: list[dict[str, Any]] = wg_status.get("items", wg_status.get("rows", []))
        if not isinstance(wg_items, list):
            wg_items = []
        if wg_items:
            vpn_found = True
            # Count servers/peers from config
            wg_servers: list[dict[str, Any]] = []
            wg_peers: list[dict[str, Any]] = []
            try:
                wg_servers = await _fetch_all_pages(api, "wireguard.server.search_server")
            except OPNsenseAPIError:
                pass
            try:
                wg_peers = await _fetch_all_pages(api, "wireguard.client.search_client")
            except OPNsenseAPIError:
                pass

            findings.append(
                _finding(
                    severity="info",
                    check="vpn_wireguard_status",
                    message=f"WireGuard active: {len(wg_servers)} server(s), {len(wg_peers)} peer(s)",
                    servers=len(wg_servers),
                    peers=len(wg_peers),
                )
            )

            # Check for stale peers (no handshake in >5 min)
            for item in wg_items:
                peers = item.get("peers", [])
                if not isinstance(peers, list):
                    continue
                for peer in peers:
                    handshake = peer.get("latest-handshake", peer.get("latestHandshake", ""))
                    name = peer.get("name", peer.get("publicKey", "unknown")[:12])
                    if handshake == "0" or handshake == "" or handshake == "0 seconds ago":
                        continue  # Never connected — not stale
                    # Try to detect very old handshakes
                    stale_keywords = ("minute", "hour", "day")
                    if isinstance(handshake, str) and any(kw in handshake for kw in stale_keywords):
                        findings.append(
                            _finding(
                                severity="warning",
                                check="wg_stale_peer",
                                message=f"WireGuard peer '{name}' last handshake: {handshake}",
                                recommendation="Verify peer connectivity or remove unused peers",
                            )
                        )
    except OPNsenseAPIError:
        pass

    # --- IPsec ---
    try:
        ipsec = await api.get("ipsec.service.status")
        status = ipsec.get("status", "unknown")
        if status != "disabled" and status != "unknown":
            vpn_found = True
        findings.append(
            _finding(
                severity="info",
                check="vpn_ipsec_status",
                message=f"IPsec service status: {status}",
            )
        )
    except OPNsenseAPIError:
        pass

    # --- OpenVPN ---
    try:
        ovpn = await api.post(
            "openvpn.instances",
            {"current": 1, "rowCount": 500, "searchPhrase": ""},
        )
        instances = ovpn.get("rows", [])
        if instances:
            vpn_found = True
        findings.append(
            _finding(
                severity="info",
                check="vpn_openvpn_status",
                message=f"OpenVPN: {len(instances)} instance(s) configured",
                count=len(instances),
            )
        )
    except OPNsenseAPIError:
        pass

    if not vpn_found:
        findings.append(
            _finding(
                severity="info",
                check="no_vpn_configured",
                message="No VPN service detected (WireGuard, IPsec, or OpenVPN)",
                recommendation="Consider deploying a VPN for secure remote access",
            )
        )

    return {"status": "ok", "findings": findings}


async def _check_haproxy_security(
    api: OPNsenseAPI,
    cache: ConfigCache,  # noqa: ARG001
) -> dict[str, Any]:
    """Check HAProxy reverse proxy security (plugin-specific)."""
    # Try frontends first — if this fails, plugin isn't installed
    try:
        frontends = await _fetch_all_pages(api, "haproxy.settings.search_frontends")
    except OPNsenseAPIError:
        return {
            "status": "skipped",
            "reason": "HAProxy plugin not installed or not accessible",
            "findings": [],
        }

    findings: list[dict[str, Any]] = []

    backends: list[dict[str, Any]] = []
    servers: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    try:
        backends = await _fetch_all_pages(api, "haproxy.settings.search_backends")
    except OPNsenseAPIError:
        pass
    try:
        servers = await _fetch_all_pages(api, "haproxy.settings.search_servers")
    except OPNsenseAPIError:
        pass
    try:
        actions = await _fetch_all_pages(api, "haproxy.settings.search_actions")
    except OPNsenseAPIError:
        pass

    # Summary
    findings.append(
        _finding(
            severity="info",
            check="haproxy_summary",
            message=f"HAProxy: {len(frontends)} frontend(s), {len(backends)} backend(s), {len(servers)} server(s)",
            frontends=len(frontends),
            backends=len(backends),
            servers=len(servers),
        )
    )

    # Check frontends for HTTP without HTTPS redirect
    for fe in frontends:
        name = fe.get("name", fe.get("description", "unnamed"))
        bind = str(fe.get("bind", fe.get("listen_address", "")))
        ssl = fe.get("ssl", fe.get("ssl_enabled", ""))
        mode = str(fe.get("mode", "")).lower()

        is_http = ":80" in bind or bind.endswith("80") or str(ssl) in ("0", "", "false")
        if is_http and mode != "tcp":
            findings.append(
                _finding(
                    severity="warning",
                    check="haproxy_http_frontend",
                    message=f"HAProxy frontend '{name}' accepts plain HTTP",
                    recommendation="Redirect HTTP to HTTPS or enforce TLS",
                )
            )

    # Check backends for health checks
    for be in backends:
        name = be.get("name", be.get("description", "unnamed"))
        health_ref = be.get("healthCheck", be.get("health_check", be.get("healthcheck", "")))
        health_enabled = str(be.get("healthCheckEnabled", "0"))
        has_ref = bool(health_ref and str(health_ref) not in ("", "none", "0"))

        if health_enabled != "1":
            # Health checking entirely disabled
            findings.append(
                _finding(
                    severity="warning",
                    check="haproxy_no_healthcheck",
                    message=(f"HAProxy backend '{name}' has health checking disabled"),
                    recommendation=("Enable health checks to detect backend failures"),
                )
            )
        elif not has_ref:
            # Enabled but using default TCP check (no custom health check)
            findings.append(
                _finding(
                    severity="info",
                    check="haproxy_default_healthcheck",
                    message=(f"HAProxy backend '{name}' uses default TCP health check (no custom check configured)"),
                    recommendation=("Consider adding an HTTP health check for better application-level monitoring"),
                )
            )

    # Check for security headers in actions
    found_headers: set[str] = set()
    for action in actions:
        test_type = str(action.get("testType", action.get("type", ""))).lower()
        hdr_name = str(action.get("hdr_name", action.get("name", ""))).lower()

        if "response" in test_type or "header" in test_type:
            for sec_hdr in _SECURITY_HEADERS:
                if sec_hdr in hdr_name:
                    found_headers.add(sec_hdr)

    missing_headers = _SECURITY_HEADERS - found_headers
    if missing_headers and frontends:
        findings.append(
            _finding(
                severity="info",
                check="haproxy_missing_headers",
                message=f"HAProxy missing security headers: {', '.join(sorted(missing_headers))}",
                recommendation="Add response rules for HSTS, X-Frame-Options, and X-Content-Type-Options",
                missing=sorted(missing_headers),
            )
        )

    return {"status": "ok", "findings": findings}


async def _check_gateways(
    api: OPNsenseAPI,
    cache: ConfigCache,  # noqa: ARG001
) -> dict[str, Any]:
    """Check gateway health status."""
    try:
        result = await api.get("gateway.status")
    except OPNsenseAPIError as exc:
        return {"status": "skipped", "reason": str(exc), "findings": []}

    # Gateway status can be dict of dicts or have an "items" key
    gateways: list[dict[str, Any]] = []
    if isinstance(result, dict):
        items = result.get("items", result.get("rows", None))
        if isinstance(items, list):
            gateways = items
        else:
            # Root-level dict of gateway dicts
            for _key, val in result.items():
                if isinstance(val, dict) and "name" in val:
                    gateways.append(val)

    findings: list[dict[str, Any]] = []

    findings.append(
        _finding(
            severity="info",
            check="gateway_count",
            message=f"{len(gateways)} gateway(s) configured",
            count=len(gateways),
        )
    )

    for gw in gateways:
        name = gw.get("name", "unknown")
        status = str(gw.get("status", "")).lower()
        status_translated = str(gw.get("status_translated", "")).lower()

        # Gateway down — but "none" with "online" translation means
        # dpinger hasn't categorized yet while gateway is reachable
        is_down = status in ("down", "offline") or (status == "none" and status_translated != "online")
        if is_down:
            display = status_translated if status_translated else status
            findings.append(
                _finding(
                    severity="critical",
                    check="gateway_down",
                    message=f"Gateway '{name}' is {display}",
                    recommendation="Investigate gateway connectivity",
                    gateway=name,
                )
            )
            continue

        # Packet loss
        loss_str = str(gw.get("loss", gw.get("loss_pct", "0")))
        loss_str = loss_str.replace("%", "").replace("~", "").strip()
        try:
            loss = float(loss_str)
            if loss > 5.0:
                findings.append(
                    _finding(
                        severity="warning",
                        check="gateway_high_loss",
                        message=f"Gateway '{name}' has {loss:.1f}% packet loss",
                        recommendation="Investigate upstream connectivity issues",
                        gateway=name,
                        loss_pct=loss,
                    )
                )
        except (ValueError, TypeError):
            pass

        # High latency
        delay_str = str(gw.get("delay", gw.get("rtt", "0")))
        delay_str = delay_str.replace("ms", "").replace("~", "").strip()
        try:
            delay = float(delay_str)
            if delay > 100.0:
                findings.append(
                    _finding(
                        severity="warning",
                        check="gateway_high_latency",
                        message=f"Gateway '{name}' has {delay:.1f}ms latency",
                        recommendation="Investigate network path or ISP issues",
                        gateway=name,
                        delay_ms=delay,
                    )
                )
        except (ValueError, TypeError):
            pass

    return {"status": "ok", "findings": findings}


# ---------------------------------------------------------------------------
# Main tool
# ---------------------------------------------------------------------------


@mcp.tool()
async def opn_security_audit(ctx: Context) -> dict[str, Any]:
    """Run a comprehensive security audit of the OPNsense firewall.

    Checks 11 security areas: firmware, firewall rules (MVC + legacy), NAT/port
    forwarding, DNS resolver security, system hardening (SSH, HTTPS, syslog),
    services, certificates, VPN status (incl. WireGuard config audit),
    HAProxy reverse proxy security, and gateway health.

    Findings are tagged with applicable compliance frameworks:
    PCI DSS v4.0, BSI IT-Grundschutz, NIST SP 800-41, CIS Benchmarks.

    Returns a structured audit report with findings categorized by severity
    (critical, warning, info).  Each finding includes a recommendation and
    applicable compliance framework references.

    Use this when you need to assess the security posture of the firewall,
    identify misconfigurations, or perform a routine health check.
    """
    api = get_api(ctx)
    cache = get_config_cache(ctx)

    # Pre-load config cache for system hardening / legacy rule checks
    try:
        await cache.load(api)
    except OPNsenseAPIError:
        pass

    sections = {
        "firmware": await _check_firmware(api, cache),
        "firewall_rules": await _check_firewall_rules(api, cache),
        "nat_rules": await _check_nat_rules(api, cache),
        "dns_security": await _check_dns_security(api, cache),
        "system_hardening": await _check_system_hardening(api, cache),
        "services": await _check_services(api, cache),
        "certificates": await _check_certificates(api, cache),
        "vpn_security": await _check_vpn_security(api, cache),
        "haproxy": await _check_haproxy_security(api, cache),
        "gateways": await _check_gateways(api, cache),
    }

    all_findings: list[dict[str, Any]] = []
    sections_skipped = 0
    for section in sections.values():
        all_findings.extend(section.get("findings", []))
        if section.get("status") == "skipped":
            sections_skipped += 1

    return {
        **sections,
        "summary": {
            "total_findings": len(all_findings),
            "critical": sum(1 for f in all_findings if f["severity"] == "critical"),
            "warning": sum(1 for f in all_findings if f["severity"] == "warning"),
            "info": sum(1 for f in all_findings if f["severity"] == "info"),
            "sections_checked": len(sections),
            "sections_skipped": sections_skipped,
        },
        "compliance_frameworks": {
            "note": (
                "Findings are tagged with applicable controls from these frameworks. "
                "Only automated checks are covered — manual review items are noted separately."
            ),
            "frameworks": _COMPLIANCE_FRAMEWORKS,
            "manual_review_needed": _MANUAL_REVIEW_ITEMS,
        },
    }
