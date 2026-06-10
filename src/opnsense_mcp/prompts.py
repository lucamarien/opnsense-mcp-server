"""MCP prompts — guided multi-step workflows.

These encode procedures that previously lived only in the README, where the
model could not see them. Prompts are user-invocable and cost no tool-budget.
"""

from __future__ import annotations

from opnsense_mcp.server import mcp


@mcp.prompt(name="ipv6_migration")
def ipv6_migration(lan_interface: str = "lan") -> str:
    """Guided IPv6 enablement for a LAN interface (RA, firewall, DNS, DDNS)."""
    return f"""You are helping enable IPv6 on the OPNsense interface '{lan_interface}'.
Follow this sequence, confirming with the user before each write step:

1. PREREQUISITES (manual, web GUI — the API cannot do these):
   - WAN IPv6 must be configured (DHCPv6-PD from the ISP, or static).
   - '{lan_interface}' must have IPv6 set to "Track Interface" (or a static /64).
   Ask the user to confirm both before continuing. Verify with opn_ipv6_status.

2. ICMPv6 RULES (mandatory — IPv6 breaks without NDP/RA/PMTUD):
   Call opn_add_icmpv6_rules(interface='{lan_interface}'), then
   opn_confirm_changes with the returned revision within 60 seconds.

3. ROUTER ADVERTISEMENTS via dnsmasq:
   Check opn_list_dnsmasq_ranges for an existing IPv6 range on '{lan_interface}'.
   If missing: opn_manage_dnsmasq_range(action='add', interface='{lan_interface}',
   start_addr='::100', end_addr='::200', prefix_len='64', ra_mode='slaac').
   Never run two RA daemons on one interface (dnsmasq RA vs radvd).

4. DNS RECORDS: add AAAA overrides for internal services with
   opn_manage_dns_override(action='add', ...) using their IPv6 addresses.

5. DDNS (if used): ensure the account uses an IPv6-capable checkip method
   (opn_manage_ddns_account) AND that the global 'allowipv6' setting is on —
   both are required or IPv6 updates silently fail.

6. VERIFY: opn_ipv6_status (addresses assigned), opn_ping(host='ipv6.google.com'),
   opn_traceroute(host='2001:4860:4860::8888', ip_version='6'),
   opn_gateway_status (IPv6 gateway up).

Report what was changed at each step and any savepoint revisions confirmed."""


@mcp.prompt(name="expose_service")
def expose_service(
    service_name: str = "my-service",
    internal_ip: str = "192.168.1.100",
    internal_port: str = "8080",
    external_port: str = "443",
) -> str:
    """Safely expose an internal service to the internet (NAT + scoped firewall rule)."""
    return f"""You are helping expose the internal service '{service_name}'
({internal_ip}:{internal_port}) on external port {external_port}. Work through
this safely, asking the user before every write:

1. ASSESS: is direct exposure necessary? Recommend alternatives first:
   - VPN access (WireGuard) avoids exposure entirely — check opn_wireguard_status.
   - If HTTP(S), prefer the HAProxy reverse proxy with TLS (opn_haproxy_search)
     over a raw port forward.
   Ask the user to choose before continuing.

2. CHECK CURRENT STATE: opn_list_nat_rules and opn_list_firewall_rules for
   existing rules touching port {external_port} or host {internal_ip};
   opn_security_audit findings for context.

3. RESTRICT THE SOURCE if possible: ask whether access can be limited to known
   source IPs/networks. If yes, create an alias first:
   opn_manage_alias(action='add', name='{service_name}_allowed', alias_type='network',
   content='<allowed CIDRs>').

4. CREATE THE PORT FORWARD:
   opn_manage_nat_rule(action='add', destination_port='{external_port}',
   target_ip='{internal_ip}', target_port='{internal_port}',
   description='{service_name}').
   WARNING: NAT changes apply immediately and cannot be auto-reverted —
   double-check parameters with the user before calling.

5. VERIFY: opn_list_nat_rules shows the rule; opn_firewall_log for traffic;
   remind the user to test from an external network.

6. HARDEN: recommend opn_security_audit afterwards; flag if the exposed port
   is on a dangerous-service list (SSH/RDP/SMB/databases) and insist on
   source restrictions or VPN for those."""


@mcp.prompt(name="remediate_audit")
def remediate_audit(max_findings: int = 5) -> str:
    """Run the security audit and walk through fixing the top findings."""
    return f"""Run opn_security_audit, then guide the user through remediation:

1. Summarize the report: critical/warning/info counts per section.
2. Pick the top {max_findings} findings, ordered: critical first, then warnings
   that are quick wins. For each, explain the risk in one sentence and the
   exact tool call that fixes it, for example:
   - permissive/broad rules -> opn_manage_firewall_rule(action='update', ...)
     to narrow source/destination/ports (savepoint-protected; confirm with
     opn_confirm_changes within 60s)
   - dangerous NAT exposure -> opn_manage_nat_rule(action='update'|'delete')
     (applies immediately — no auto-revert; confirm with the user first)
   - DNSSEC disabled / plaintext forwarders -> explain the GUI path; the MCP
     server has no Unbound general-settings write tool
   - SSH/web GUI hardening -> explain the GUI path (System > Settings); these
     are deliberately not writable via this MCP server
3. Apply fixes ONE at a time, each with explicit user approval, verifying after
   each change (re-run the relevant list tool).
4. Finish by re-running opn_security_audit and reporting the before/after
   finding counts. Note findings that need manual review (log retention,
   pentesting cadence) from the report's manual_review_needed list."""
