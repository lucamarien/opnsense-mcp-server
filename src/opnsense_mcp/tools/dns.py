"""DNS tools — Unbound overrides, forward zones, statistics."""

from __future__ import annotations

import re
from typing import Any

from fastmcp import Context

from opnsense_mcp.server import get_api, get_config_cache, mcp

_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)
_IP_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
    r"|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
)


@mcp.tool()
async def opn_list_dns_overrides(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List Unbound DNS host overrides (local DNS records).

    Use this when you need to see which hostnames are overridden to specific
    IP addresses in the local DNS resolver.
    Returns: dict with 'rows' (list of overrides) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "unbound.search_override",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_list_dns_forwards(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List Unbound DNS forward zones (domain-specific DNS servers).

    Use this when you need to check which domains are forwarded to specific
    upstream DNS servers or DNS-over-TLS resolvers.
    Returns: dict with 'rows' (list of forward zones) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "unbound.search_forward",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_dns_stats(ctx: Context) -> dict[str, Any]:
    """Get Unbound DNS resolver statistics (queries, cache hits, uptime).

    Use this when you need to check DNS resolver performance, cache hit rates,
    or troubleshoot DNS resolution issues.
    Returns: dict with resolver statistics fields.
    """
    api = get_api(ctx)
    return await api.get("unbound.stats")


@mcp.tool()
async def opn_reconfigure_unbound(ctx: Context) -> dict[str, Any]:
    """Apply pending Unbound DNS resolver configuration changes.

    Use this after making DNS configuration changes (adding overrides, forward
    zones, etc.) to apply them to the running Unbound service. This restarts
    Unbound with the new configuration.

    NOTE: This does not use savepoint protection. DNS changes take effect
    immediately and cannot be auto-reverted. Verify settings before calling.
    Returns: dict with 'status' indicating success or failure.
    """
    api = get_api(ctx)
    api.require_writes()
    result = await api.post("unbound.service.reconfigure")
    get_config_cache(ctx).invalidate()
    return {"status": result.get("status", "unknown"), "service": "unbound"}


@mcp.tool()
async def opn_add_dns_override(
    ctx: Context,
    hostname: str,
    domain: str,
    server: str,
    description: str = "",
) -> dict[str, Any]:
    """Add an Unbound DNS host override (A/AAAA record) and apply immediately.

    Use this when you need to create a local DNS record that resolves a hostname
    to a specific IP address. Useful for split-horizon DNS, internal services,
    or overriding external DNS for specific hosts.

    Changes are applied immediately (Unbound is reconfigured automatically).
    DNS overrides cannot be auto-reverted — verify settings before calling.
    Use opn_list_dns_overrides to check existing overrides first.

    Parameters:
    - hostname: the hostname part (e.g. 'myserver')
    - domain: the domain part (e.g. 'local.lan')
    - server: the IP address to resolve to (IPv4 or IPv6)
    - description: optional description

    Returns: dict with 'result', 'uuid', 'hostname', 'server', and 'applied' status.
    """
    if not hostname or not _HOSTNAME_RE.match(hostname):
        return {"error": f"Invalid hostname '{hostname}'. Must be alphanumeric with hyphens."}
    if not domain or not _DOMAIN_RE.match(domain):
        return {"error": f"Invalid domain '{domain}'. Must be a valid domain name."}
    if not server or not _IP_RE.match(server):
        return {"error": f"Invalid server IP '{server}'. Must be an IPv4 or IPv6 address."}

    api = get_api(ctx)
    api.require_writes()

    result = await api.post(
        "unbound.add_host_override",
        {
            "host": {
                "hostname": hostname,
                "domain": domain,
                "server": server,
                "description": description,
                "enabled": "1",
            },
        },
    )

    reconfigure = await api.post("unbound.service.reconfigure")
    get_config_cache(ctx).invalidate()

    return {
        "result": result.get("result", ""),
        "uuid": result.get("uuid", ""),
        "hostname": f"{hostname}.{domain}",
        "server": server,
        "applied": reconfigure.get("status", "unknown"),
    }
