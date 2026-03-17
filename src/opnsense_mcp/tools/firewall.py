"""Firewall tools — rules, aliases, NAT, logging."""

from __future__ import annotations

import re
from typing import Any

from fastmcp import Context

from opnsense_mcp.api_client import OPNsenseAPIError
from opnsense_mcp.server import get_api, get_config_cache, get_savepoint_manager, mcp

_VALID_ACTIONS = frozenset({"pass", "block", "reject"})
_VALID_DIRECTIONS = frozenset({"in", "out"})
_VALID_IP_PROTOCOLS = frozenset({"inet", "inet6", "inet46"})
_VALID_ALIAS_TYPES = frozenset({"host", "network", "port", "urltable", "geoip"})
_VALID_NAT_PROTOCOLS = frozenset({"TCP", "UDP", "TCP/UDP"})
_ALIAS_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")
_CATEGORY_NAME_RE = re.compile(r"^[^,]{1,255}$")
_HEX_COLOR_RE = re.compile(r"^[0-9a-fA-F]{6}$")


@mcp.tool()
async def opn_list_firewall_rules(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List firewall filter rules configured via the MVC API.

    IMPORTANT: This only returns rules created through the OPNsense MVC filter
    API (Settings > Firewall > Automation). Legacy rules configured via the
    traditional GUI (Firewall > Rules) are NOT visible through this endpoint.
    Most users have legacy rules — a result of 0 rules does not mean no rules exist.

    Use this when you need to inspect MVC-managed firewall filter rules.
    Returns: dict with 'rows' (list of rules) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "firewall.search_rule",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_list_firewall_aliases(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List firewall alias definitions (IP lists, port groups, GeoIP, URLs).

    Use this when you need to see which aliases are defined, their types,
    or what IP addresses/networks they resolve to.
    Returns: dict with 'rows' (list of aliases) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "firewall.alias.search",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_firewall_log(
    ctx: Context,
    source_ip: str = "",
    destination_ip: str = "",
    action: str = "",
    interface: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """Get recent firewall log entries (blocked and passed packets).

    Use this when you need to check what traffic has been blocked or passed,
    troubleshoot connectivity issues, or audit firewall activity.
    All filter parameters are optional substring matches applied client-side.
    Returns: dict with 'entries' (list of log rows) and 'total' (count after filtering).
    """
    api = get_api(ctx)
    raw = await api.get("firewall.log")
    rows: list[dict[str, Any]] = raw if isinstance(raw, list) else raw.get("rows", raw.get("entries", []))

    filters_active = any((source_ip, destination_ip, action, interface))
    if filters_active:
        filtered: list[dict[str, Any]] = []
        for entry in rows:
            if source_ip and source_ip not in str(entry.get("src", "")):
                continue
            if destination_ip and destination_ip not in str(entry.get("dst", "")):
                continue
            if action and action.lower() not in str(entry.get("action", "")).lower():
                continue
            if interface and interface.lower() not in str(entry.get("interface", "")).lower():
                continue
            filtered.append(entry)
        rows = filtered

    limited = rows[: min(limit, 500)]
    return {"entries": limited, "total": len(rows)}


@mcp.tool()
async def opn_confirm_changes(ctx: Context, revision: str) -> dict[str, Any]:
    """Confirm pending firewall changes, cancelling the 60-second auto-rollback.

    Use this AFTER applying firewall changes (rule add/edit/delete) to make them
    permanent. If not called within 60 seconds of applying, OPNsense automatically
    reverts all changes for safety.
    Returns: dict with confirmation status.
    """
    mgr = get_savepoint_manager(ctx)
    return await mgr.confirm(revision)


@mcp.tool()
async def opn_toggle_firewall_rule(
    ctx: Context,
    uuid: str,
) -> dict[str, Any]:
    """Toggle a firewall filter rule's enabled/disabled state with savepoint protection.

    Use this when you need to temporarily disable a rule for testing or re-enable
    a previously disabled rule. The toggle flips the current state. Changes
    auto-revert in 60 seconds unless confirmed with opn_confirm_changes.
    Use opn_list_firewall_rules first to find the UUID of the rule.
    Returns: dict with 'revision' (str) for confirming and 'uuid' (str).
    """
    api = get_api(ctx)
    mgr = get_savepoint_manager(ctx)
    revision = await mgr.create()
    try:
        await api.post("firewall.toggle_rule", path_suffix=uuid)
    except OPNsenseAPIError as exc:
        return {
            "error": str(exc),
            "revision": revision,
            "message": "Savepoint created but toggle failed. Changes will auto-revert.",
        }
    await mgr.apply(revision)
    get_config_cache(ctx).invalidate()
    return {
        "revision": revision,
        "uuid": uuid,
        "message": (
            f"Rule toggled. Call opn_confirm_changes with revision '{revision}' to make permanent (60s auto-revert)."
        ),
    }


@mcp.tool()
async def opn_add_firewall_rule(
    ctx: Context,
    action: str = "pass",
    direction: str = "in",
    interface: str = "lan",
    ip_protocol: str = "inet",
    protocol: str = "any",
    source_net: str = "any",
    destination_net: str = "any",
    destination_port: str = "",
    description: str = "",
) -> dict[str, Any]:
    """Create a new MVC firewall filter rule with savepoint protection.

    Use this when you need to add a firewall rule. Changes auto-revert in 60
    seconds unless confirmed with opn_confirm_changes.

    IMPORTANT: This creates MVC rules (Settings > Firewall > Automation), not
    legacy GUI rules.

    Parameters:
    - action: 'pass', 'block', or 'reject'
    - direction: 'in' or 'out'
    - interface: interface name (e.g. 'lan', 'wan', 'opt1')
    - ip_protocol: 'inet' (IPv4), 'inet6' (IPv6), or 'inet46' (dual-stack)
    - protocol: 'any', 'TCP', 'UDP', 'TCP/UDP', 'ICMP', etc.
    - source_net: source address/network or 'any'
    - destination_net: destination address/network or 'any'
    - destination_port: port number or range (e.g. '80', '1000-2000'), or empty for any
    - description: human-readable rule description

    Returns: dict with 'revision' (str), 'uuid' (str), and 'result' (str).
    """
    if action not in _VALID_ACTIONS:
        return {"error": f"Invalid action '{action}'. Must be one of: pass, block, reject"}
    if direction not in _VALID_DIRECTIONS:
        return {"error": f"Invalid direction '{direction}'. Must be one of: in, out"}
    if ip_protocol not in _VALID_IP_PROTOCOLS:
        return {
            "error": (
                f"Invalid ip_protocol '{ip_protocol}'. Must be 'inet' (IPv4), 'inet6' (IPv6), or 'inet46' (dual-stack)."
            ),
        }

    api = get_api(ctx)
    mgr = get_savepoint_manager(ctx)
    revision = await mgr.create()

    rule: dict[str, str] = {
        "action": action,
        "direction": direction,
        "interface": interface,
        "ipprotocol": ip_protocol,
        "protocol": protocol,
        "source_net": source_net,
        "destination_net": destination_net,
        "quick": "1",
        "enabled": "1",
        "description": description,
    }
    if destination_port:
        rule["destination_port"] = destination_port

    try:
        result = await api.post("firewall.add_rule", {"rule": rule})
    except OPNsenseAPIError as exc:
        return {
            "error": str(exc),
            "revision": revision,
            "message": "Savepoint created but rule creation failed. Changes will auto-revert.",
        }

    new_uuid = result.get("uuid", "")
    await mgr.apply(revision)
    get_config_cache(ctx).invalidate()
    return {
        "revision": revision,
        "uuid": new_uuid,
        "result": result.get("result", ""),
        "message": (
            f"Rule created. Call opn_confirm_changes with revision '{revision}' to make permanent (60s auto-revert)."
        ),
    }


@mcp.tool()
async def opn_delete_firewall_rule(
    ctx: Context,
    uuid: str,
) -> dict[str, Any]:
    """Delete a firewall filter rule by UUID with savepoint protection.

    Use this when you need to remove an existing MVC firewall rule. Changes
    auto-revert in 60 seconds unless confirmed with opn_confirm_changes.
    Use opn_list_firewall_rules first to find the UUID of the rule to delete.
    Returns: dict with 'revision' (str) for confirming and 'result' (str).
    """
    api = get_api(ctx)
    mgr = get_savepoint_manager(ctx)
    revision = await mgr.create()
    try:
        result = await api.post("firewall.del_rule", path_suffix=uuid)
    except OPNsenseAPIError as exc:
        return {
            "error": str(exc),
            "revision": revision,
            "message": "Savepoint created but deletion failed. Changes will auto-revert.",
        }
    await mgr.apply(revision)
    get_config_cache(ctx).invalidate()
    return {
        "revision": revision,
        "uuid": uuid,
        "result": result.get("result", ""),
        "message": (
            f"Rule deleted. Call opn_confirm_changes with revision '{revision}' to make permanent (60s auto-revert)."
        ),
    }


@mcp.tool()
async def opn_add_alias(
    ctx: Context,
    name: str,
    alias_type: str = "host",
    content: str = "",
    description: str = "",
) -> dict[str, Any]:
    """Create a new firewall alias (IP list, network group, port group, etc.).

    Use this when you need to create a reusable alias for use in firewall rules.
    Aliases group IPs, networks, or ports under a single name.

    This does NOT require savepoint protection — aliases are metadata definitions
    that only affect traffic when referenced by a firewall rule.

    Parameters:
    - name: alias name (alphanumeric and underscores only, no spaces)
    - alias_type: 'host' (IPs), 'network' (CIDRs), 'port' (ports/ranges),
      'urltable' (URL-based IP list), 'geoip' (country codes)
    - content: alias entries separated by newlines. For GeoIP, use country codes
      (one per line, e.g. 'DE\\nFR\\nNL'). For host/network, use IPs/CIDRs.
    - description: human-readable description

    Returns: dict with 'result' (str) and 'uuid' (str) of the new alias.
    """
    if alias_type not in _VALID_ALIAS_TYPES:
        return {
            "error": (f"Invalid alias_type '{alias_type}'. Must be one of: host, network, port, urltable, geoip"),
        }
    if not _ALIAS_NAME_RE.match(name):
        return {
            "error": (f"Invalid alias name '{name}'. Must contain only letters, numbers, and underscores."),
        }

    api = get_api(ctx)
    api.require_writes()
    result = await api.post(
        "firewall.alias.add",
        {
            "alias": {
                "name": name,
                "type": alias_type,
                "content": content,
                "description": description,
                "enabled": "1",
                "proto": "",
            },
        },
    )
    get_config_cache(ctx).invalidate()
    return {
        "result": result.get("result", ""),
        "uuid": result.get("uuid", ""),
        "name": name,
    }


@mcp.tool()
async def opn_list_nat_rules(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List NAT port forwarding (DNAT) rules.

    Use this when you need to see which ports are forwarded to internal hosts,
    check NAT rule configuration, or troubleshoot port forwarding issues.

    Like firewall filter rules, this only returns MVC-managed NAT rules.
    Legacy NAT rules from the traditional GUI may not appear here — use
    opn_get_config_section('nat') to see all NAT configuration.

    Returns: dict with 'rows' (list of NAT rules) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "nat.dnat.search_rule",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_add_nat_rule(
    ctx: Context,
    destination_port: str = "",
    target_ip: str = "",
    interface: str = "wan",
    protocol: str = "TCP",
    target_port: str = "",
    description: str = "",
) -> dict[str, Any]:
    """Create a NAT port forwarding rule with savepoint protection.

    Use this when you need to forward an external port to an internal host.
    Changes auto-revert in 60 seconds unless confirmed with opn_confirm_changes.

    Parameters:
    - destination_port: external port to forward (e.g. '8080', '3000-3010') — required
    - target_ip: internal IP address to forward to (e.g. '192.168.1.100') — required
    - interface: source interface (default 'wan')
    - protocol: 'TCP', 'UDP', or 'TCP/UDP' (default 'TCP')
    - target_port: internal port (default: same as destination_port)
    - description: human-readable description

    Returns: dict with 'revision' (str), 'uuid' (str), and 'result' (str).
    """
    if not destination_port:
        return {"error": "destination_port is required"}
    if not target_ip:
        return {"error": "target_ip is required"}
    if protocol not in _VALID_NAT_PROTOCOLS:
        return {
            "error": f"Invalid protocol '{protocol}'. Must be one of: TCP, UDP, TCP/UDP",
        }

    api = get_api(ctx)
    mgr = get_savepoint_manager(ctx)
    revision = await mgr.create()

    rule: dict[str, str] = {
        "interface": interface,
        "ipprotocol": "inet",
        "protocol": protocol,
        "destination_port": destination_port,
        "target_ip": target_ip,
        "target_port": target_port or destination_port,
        "description": description,
        "enabled": "1",
    }

    try:
        result = await api.post("nat.dnat.add_rule", {"rule": rule})
    except OPNsenseAPIError as exc:
        return {
            "error": str(exc),
            "revision": revision,
            "message": "Savepoint created but NAT rule creation failed. Changes will auto-revert.",
        }

    new_uuid = result.get("uuid", "")
    await mgr.apply(revision)
    get_config_cache(ctx).invalidate()
    return {
        "revision": revision,
        "uuid": new_uuid,
        "result": result.get("result", ""),
        "message": (
            f"NAT rule created. Call opn_confirm_changes with revision '{revision}' "
            "to make permanent (60s auto-revert)."
        ),
    }


@mcp.tool()
async def opn_list_firewall_categories(
    ctx: Context,
    search: str = "",
    limit: int = 100,
) -> dict[str, Any]:
    """List firewall rule categories.

    Use this when you need to see which categories exist, check their names
    and colors, or find category UUIDs for assigning to rules.
    Returns: dict with 'rows' (list of categories) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "firewall.category.search",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_add_firewall_category(
    ctx: Context,
    name: str,
    color: str = "000000",
) -> dict[str, Any]:
    """Create a new firewall rule category.

    Use this when you need to create a category for organizing firewall rules.
    Categories are metadata — creating one does not affect traffic or rules.

    Parameters:
    - name: category name (1-255 chars, no commas)
    - color: hex color code without '#' (e.g. 'ff0000' for red, default '000000')

    Returns: dict with 'result' (str), 'uuid' (str), and 'name' (str).
    """
    if not name or not _CATEGORY_NAME_RE.match(name):
        return {
            "error": f"Invalid category name '{name}'. Must be 1-255 characters, no commas.",
        }
    if not _HEX_COLOR_RE.match(color):
        return {
            "error": f"Invalid color '{color}'. Must be 6 hex digits (e.g. 'ff0000').",
        }

    api = get_api(ctx)
    api.require_writes()
    result = await api.post(
        "firewall.category.add",
        {"category": {"name": name, "color": color, "auto": "0"}},
    )
    get_config_cache(ctx).invalidate()
    return {
        "result": result.get("result", ""),
        "uuid": result.get("uuid", ""),
        "name": name,
    }


@mcp.tool()
async def opn_delete_firewall_category(
    ctx: Context,
    uuid: str,
) -> dict[str, Any]:
    """Delete a firewall rule category by UUID with savepoint protection.

    IMPORTANT: Reassign rules to other categories BEFORE deleting to avoid
    orphaned category references. Use opn_list_firewall_categories to find
    categories and opn_set_rule_categories to reassign rules first.

    System default categories (auto=1) cannot be deleted.
    Changes auto-revert in 60 seconds unless confirmed with opn_confirm_changes.
    Returns: dict with 'revision' (str) for confirming and 'result' (str).
    """
    api = get_api(ctx)
    mgr = get_savepoint_manager(ctx)
    revision = await mgr.create()
    try:
        result = await api.post("firewall.category.del", path_suffix=uuid)
    except OPNsenseAPIError as exc:
        return {
            "error": str(exc),
            "revision": revision,
            "message": "Savepoint created but deletion failed. Changes will auto-revert.",
        }
    await mgr.apply(revision)
    get_config_cache(ctx).invalidate()
    return {
        "revision": revision,
        "uuid": uuid,
        "result": result.get("result", ""),
        "message": (
            f"Category deleted. Call opn_confirm_changes with revision '{revision}' "
            "to make permanent (60s auto-revert)."
        ),
    }


@mcp.tool()
async def opn_set_rule_categories(
    ctx: Context,
    uuid: str,
    categories: str = "",
) -> dict[str, Any]:
    """Assign categories to a firewall rule by UUID with savepoint protection.

    Use this when you need to categorize or re-categorize a firewall rule.
    Changes auto-revert in 60 seconds unless confirmed with opn_confirm_changes.

    Parameters:
    - uuid: the firewall rule UUID (from opn_list_firewall_rules)
    - categories: comma-separated category UUIDs (from opn_list_firewall_categories),
      or empty string to clear all categories

    Returns: dict with 'revision' (str) for confirming and 'uuid' (str).
    """
    api = get_api(ctx)
    mgr = get_savepoint_manager(ctx)
    revision = await mgr.create()
    try:
        await api.post(
            "firewall.set_rule",
            {"rule": {"categories": categories}},
            path_suffix=uuid,
        )
    except OPNsenseAPIError as exc:
        return {
            "error": str(exc),
            "revision": revision,
            "message": "Savepoint created but category update failed. Changes will auto-revert.",
        }
    await mgr.apply(revision)
    get_config_cache(ctx).invalidate()
    return {
        "revision": revision,
        "uuid": uuid,
        "message": (
            f"Rule categories updated. Call opn_confirm_changes with revision '{revision}' "
            "to make permanent (60s auto-revert)."
        ),
    }


# ICMPv6 message types essential for IPv6 operation (RFC 4890)
_ICMPV6_ESSENTIAL_RULES: list[dict[str, str]] = [
    {
        "description": "ICMPv6 NDP: Neighbor Solicitation",
        "protocol": "ICMPv6",
        "source_net": "fe80::/10",
        "destination_net": "ff02::/16",
    },
    {
        "description": "ICMPv6 NDP: Neighbor Advertisement",
        "protocol": "ICMPv6",
        "source_net": "fe80::/10",
        "destination_net": "any",
    },
    {
        "description": "ICMPv6 NDP: Router Solicitation",
        "protocol": "ICMPv6",
        "source_net": "fe80::/10",
        "destination_net": "ff02::2",
    },
    {
        "description": "ICMPv6 NDP: Router Advertisement",
        "protocol": "ICMPv6",
        "source_net": "fe80::/10",
        "destination_net": "ff02::1",
    },
    {
        "description": "ICMPv6 Echo (ping6) — inbound",
        "protocol": "ICMPv6",
        "source_net": "any",
        "destination_net": "any",
    },
]


@mcp.tool()
async def opn_add_icmpv6_rules(
    ctx: Context,
    interface: str = "lan",
) -> dict[str, Any]:
    """Create essential ICMPv6 firewall rules required for IPv6 operation.

    Use this when setting up IPv6 on an interface. ICMPv6 is MANDATORY for
    IPv6 — without it, Neighbor Discovery (NDP), Router Advertisements (RA),
    and Path MTU Discovery (PMTUD) all break.

    Creates 5 rules per RFC 4890:
    1. NDP Neighbor Solicitation (link-local -> multicast)
    2. NDP Neighbor Advertisement (link-local -> any)
    3. NDP Router Solicitation (link-local -> all-routers multicast)
    4. NDP Router Advertisement (link-local -> all-nodes multicast)
    5. ICMPv6 Echo (ping6) inbound

    All rules use savepoint protection — auto-revert in 60 seconds unless
    confirmed with opn_confirm_changes.

    Parameters:
    - interface: target interface (e.g. 'lan', 'opt1', 'opt2')

    Returns: dict with 'revision' (str), 'rules' (list of created UUIDs),
    and instructions to confirm.
    """
    api = get_api(ctx)
    mgr = get_savepoint_manager(ctx)
    revision = await mgr.create()

    created_uuids: list[str] = []
    errors: list[str] = []

    for rule_template in _ICMPV6_ESSENTIAL_RULES:
        rule: dict[str, str] = {
            "action": "pass",
            "direction": "in",
            "interface": interface,
            "ipprotocol": "inet6",
            "protocol": rule_template["protocol"],
            "source_net": rule_template["source_net"],
            "destination_net": rule_template["destination_net"],
            "quick": "1",
            "enabled": "1",
            "description": rule_template["description"],
        }
        try:
            result = await api.post("firewall.add_rule", {"rule": rule})
            uuid = result.get("uuid", "")
            if uuid:
                created_uuids.append(uuid)
        except OPNsenseAPIError as exc:
            errors.append(f"{rule_template['description']}: {exc}")

    if created_uuids:
        await mgr.apply(revision)
        get_config_cache(ctx).invalidate()

    return {
        "revision": revision,
        "rules_created": len(created_uuids),
        "uuids": created_uuids,
        "errors": errors,
        "interface": interface,
        "message": (
            f"Created {len(created_uuids)} ICMPv6 rules on '{interface}'. "
            f"Call opn_confirm_changes with revision '{revision}' to make permanent "
            "(60s auto-revert)."
        ),
    }
