"""Network tools — interfaces, ARP, gateways, routing."""

from __future__ import annotations

from typing import Any

from fastmcp import Context

from opnsense_mcp.api_client import OPNsenseAPIError
from opnsense_mcp.server import get_api, mcp


@mcp.tool()
async def opn_interface_stats(ctx: Context) -> dict[str, Any]:
    """Get per-interface traffic statistics (bytes in/out, packets, errors).

    Use this when you need to see network utilization, check for interface
    errors, or compare traffic across interfaces.
    Returns: dict keyed by interface name with statistics fields.
    """
    api = get_api(ctx)
    return await api.get("interface.statistics")


@mcp.tool()
async def opn_arp_table(ctx: Context) -> dict[str, Any]:
    """Get the ARP table showing IP-to-MAC address mappings.

    Use this when you need to find which MAC address is associated with an IP,
    identify devices on a network segment, or troubleshoot connectivity.
    Returns: dict with ARP entries including ip, mac, intf, and hostname fields.
    """
    api = get_api(ctx)
    return await api.get("interface.arp")


@mcp.tool()
async def opn_ndp_table(ctx: Context) -> dict[str, Any]:
    """Get the NDP table showing IPv6-to-MAC address mappings.

    Use this when you need to find which MAC address is associated with an IPv6
    address, identify IPv6-enabled devices on a network segment, or troubleshoot
    IPv6 neighbor reachability. This is the IPv6 equivalent of the ARP table.
    Returns: dict with NDP entries including ip, mac, intf, and manufacturer fields.
    """
    api = get_api(ctx)
    return await api.get("interface.ndp")


@mcp.tool()
async def opn_ipv6_status(ctx: Context) -> dict[str, Any]:
    """Get IPv6 configuration and address status for all interfaces.

    Use this when you need a quick overview of which interfaces have IPv6
    configured, what addresses are assigned, and the IPv6 method (DHCPv6-PD,
    Track Interface, SLAAC, static).

    Returns: dict with 'interfaces' (list of per-interface IPv6 info) and
    'summary' (counts of configured/unconfigured interfaces).
    """
    from opnsense_mcp.server import get_config_cache

    api = get_api(ctx)
    cache = get_config_cache(ctx)

    # Ensure config is loaded
    if not cache.is_loaded or cache.is_stale:
        await cache.load(api)

    # Get interface config from config cache (synchronous after load)
    section_result = cache.get_section("interfaces")
    if section_result is None:
        return {"error": "Could not read interface configuration"}
    iface_data_all: dict[str, Any] = section_result.get("data", {})
    if not isinstance(iface_data_all, dict):
        return {"error": "Unexpected interface configuration format"}

    # Get live interface details for actual assigned addresses
    try:
        live_config = await api.get("interface.config")
    except (OPNsenseAPIError, KeyError):
        live_config = {}

    interfaces: list[dict[str, Any]] = []
    v6_count = 0
    v4_only_count = 0

    for iface_id, iface_data in iface_data_all.items():
        if not isinstance(iface_data, dict):
            continue

        descr = iface_data.get("descr", iface_id)
        ipaddrv6 = iface_data.get("ipaddrv6", "")
        subnetv6 = iface_data.get("subnetv6", "")
        track6_iface = iface_data.get("track6-interface", "")
        track6_prefix = iface_data.get("track6-prefix-id", "")
        ipaddr = iface_data.get("ipaddr", "")

        # Determine IPv6 method
        v6_method = "none"
        if ipaddrv6 == "dhcp6":
            v6_method = "dhcpv6-pd"
        elif ipaddrv6 == "track6":
            v6_method = "track6"
        elif ipaddrv6 == "slaac":
            v6_method = "slaac"
        elif ":" in ipaddrv6:
            v6_method = "static"
        elif ipaddrv6:
            v6_method = ipaddrv6

        has_v6 = v6_method != "none"
        if has_v6:
            v6_count += 1
        elif ipaddr:
            v4_only_count += 1

        # Get live IPv6 addresses from interface config
        live_addrs: list[str] = []
        if iface_id in live_config:
            live_iface = live_config[iface_id]
            if isinstance(live_iface, dict):
                for key, val in live_iface.items():
                    if isinstance(val, str) and ":" in val and key.startswith("ipv6"):
                        live_addrs.append(val)
                # Also check nested addr lists
                for addr_entry in live_iface.get("ipv6", []):
                    if isinstance(addr_entry, dict):
                        addr = addr_entry.get("ipaddr", "")
                        prefix = addr_entry.get("subnetbits", "")
                        if addr:
                            live_addrs.append(f"{addr}/{prefix}" if prefix else addr)
                    elif isinstance(addr_entry, str) and ":" in addr_entry:
                        live_addrs.append(addr_entry)

        entry: dict[str, Any] = {
            "interface": iface_id,
            "description": descr,
            "ipv4_address": ipaddr or "none",
            "ipv6_method": v6_method,
            "ipv6_configured": has_v6,
        }
        if has_v6:
            if v6_method == "static":
                entry["ipv6_address"] = f"{ipaddrv6}/{subnetv6}" if subnetv6 else ipaddrv6
            if v6_method == "track6":
                entry["track6_interface"] = track6_iface
                entry["track6_prefix_id"] = track6_prefix
            if live_addrs:
                entry["ipv6_live_addresses"] = live_addrs

        interfaces.append(entry)

    return {
        "interfaces": interfaces,
        "summary": {
            "total_interfaces": len(interfaces),
            "ipv6_configured": v6_count,
            "ipv4_only": v4_only_count,
        },
    }


@mcp.tool()
async def opn_list_static_routes(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List configured static routes.

    Use this when you need to see custom routing table entries, check which
    networks are routed through which gateways, or troubleshoot routing issues.
    Note: This shows configured static routes, not the full kernel routing table.
    Returns: dict with 'rows' (list of static routes) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "routes.search",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )
