"""DHCP tools — ISC, Kea, and dnsmasq lease listing and range management."""

from __future__ import annotations

from typing import Any

from fastmcp import Context

from opnsense_mcp.server import get_api, get_config_cache, mcp


@mcp.tool()
async def opn_list_dhcp_leases(ctx: Context) -> dict[str, Any]:
    """List current DHCPv4 leases from the ISC DHCP server (legacy).

    Use this when the OPNsense instance uses the ISC DHCP plugin (os-isc-dhcp).
    ISC DHCP is legacy and being phased out — most 26.x instances use dnsmasq or Kea.
    Use opn_scan_config first to check which DHCP backend is active.
    Returns: dict with DHCP lease entries including address, mac, and hostname fields.
    """
    api = get_api(ctx)
    return await api.get("dhcpv4.leases.search")


@mcp.tool()
async def opn_list_kea_leases(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List current DHCPv4 leases from the Kea DHCP server.

    Use this when the OPNsense instance uses Kea for DHCP (available since 24.7).
    Kea is the modern replacement for ISC DHCP, recommended for HA setups.
    Use opn_scan_config first to check which DHCP backend is active.
    Returns: dict with 'rows' (list of leases) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "kea.leases4.search",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_list_dnsmasq_leases(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List current DHCPv4 and DHCPv6 leases from the dnsmasq DNS/DHCP server.

    Use this when the OPNsense instance uses dnsmasq for DHCP (default in 26.x).
    dnsmasq is a lightweight combined DNS/DHCP server that handles both
    DHCPv4 and DHCPv6. IPv6 leases appear alongside IPv4 leases in the results.
    Use opn_scan_config first to check which DHCP backend is active.
    Returns: dict with 'rows' (list of leases) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "dnsmasq.leases.search",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


# --- Dnsmasq DHCP Range Management ---


@mcp.tool()
async def opn_list_dnsmasq_ranges(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List dnsmasq DHCP ranges (both DHCPv4 and DHCPv6 with RA config).

    Use this to see configured DHCP address pools and Router Advertisement
    settings for each interface. Both IPv4 and IPv6 ranges appear in the
    same list.

    Key fields: interface, start_addr, end_addr, prefix_len (IPv6) or
    subnet_mask (IPv4), ra_mode (slaac/ra-stateless/ra-only),
    ra_priority, lease_time, enabled.

    Note: Requires the dnsmasq DNS/DHCP server (os-dnsmasq-dns or built-in).
    Returns: dict with 'rows' (list of ranges) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "dnsmasq.settings.search_range",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_add_dnsmasq_range(
    ctx: Context,
    interface: str,
    start_addr: str,
    end_addr: str,
    prefix_len: str = "",
    ra_mode: str = "",
    lease_time: str = "24h",
    description: str = "",
) -> dict[str, Any]:
    """Create a new dnsmasq DHCP range and apply the configuration.

    Use this to add DHCPv4 or DHCPv6 address ranges with optional Router
    Advertisement (RA) configuration.

    Args:
        interface: Network interface name (e.g. 'lan', 'opt1', 'opt2').
        start_addr: Start of address range. IPv4: '192.168.1.100'.
                    IPv6: uses suffix notation — '::100' (OPNsense auto-prepends
                    the delegated prefix from the interface config).
        end_addr: End of address range. IPv4: '192.168.1.200'. IPv6: '::200'.
        prefix_len: IPv6 prefix length (e.g. '64'). Include this for IPv6 ranges,
                    omit for IPv4 ranges.
        ra_mode: Router Advertisement mode for IPv6. Options:
                 - 'slaac' — clients use SLAAC (stateless autoconfiguration)
                 - 'ra-stateless' — RA + stateless DHCPv6 (DNS via DHCP)
                 - 'ra-only' — RA only, no DHCPv6 address assignment
                 Omit for IPv4 ranges.
        lease_time: Lease duration (e.g. '24h', '1h', '12h'). Default: '24h'.
        description: Optional description for this range.

    NOTE: Only one RA daemon should run per interface. Do not configure both
    dnsmasq RA and radvd on the same interface.

    NOTE: After creation, the service is automatically reconfigured. Changes
    take effect immediately.

    Note: Requires the dnsmasq DNS/DHCP server.
    Returns: dict with 'result', 'uuid' of the new range, and reconfigure status.
    """
    if not interface.strip():
        return {"error": "interface must not be empty"}
    if not start_addr.strip():
        return {"error": "start_addr must not be empty"}
    if not end_addr.strip():
        return {"error": "end_addr must not be empty"}

    api = get_api(ctx)
    api.require_writes()

    range_config: dict[str, str] = {
        "enabled": "1",
        "interface": interface,
        "start_addr": start_addr,
        "end_addr": end_addr,
        "lease_time": lease_time,
    }
    if prefix_len:
        range_config["prefix_len"] = prefix_len
    if ra_mode:
        range_config["ra_mode"] = ra_mode
    if description:
        range_config["description"] = description

    add_result = await api.post("dnsmasq.settings.add_range", {"range": range_config})

    reconfigure_result = await api.post("dnsmasq.service.reconfigure")
    get_config_cache(ctx).invalidate()

    return {
        "result": add_result.get("result", "unknown"),
        "uuid": add_result.get("uuid", ""),
        "reconfigure_status": reconfigure_result.get("status", "unknown"),
    }


@mcp.tool()
async def opn_reconfigure_dnsmasq(ctx: Context) -> dict[str, Any]:
    """Apply pending dnsmasq DNS/DHCP configuration changes.

    Use this after manually editing dnsmasq settings to apply the changes
    to the running dnsmasq service.

    Note: opn_add_dnsmasq_range auto-reconfigures, so this is only needed
    for manual edits or troubleshooting.

    Note: Requires the dnsmasq DNS/DHCP server.
    Returns: dict with 'status' indicating success or failure.
    """
    api = get_api(ctx)
    api.require_writes()
    result = await api.post("dnsmasq.service.reconfigure")
    get_config_cache(ctx).invalidate()
    return {"status": result.get("status", "unknown"), "service": "dnsmasq"}
