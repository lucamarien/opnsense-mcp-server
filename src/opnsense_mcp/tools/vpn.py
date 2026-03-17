"""VPN tools — WireGuard, OpenVPN, IPsec status."""

from __future__ import annotations

from typing import Any

from fastmcp import Context

from opnsense_mcp.server import get_api, mcp


@mcp.tool()
async def opn_wireguard_status(ctx: Context) -> dict[str, Any]:
    """Get WireGuard VPN tunnel and peer status.

    Use this when you need to check WireGuard tunnel health, peer handshake
    times, transferred bytes, or endpoint information.
    Note: Requires the WireGuard plugin (os-wireguard).
    Returns: dict with tunnel and peer details including endpoints and transfer stats.
    """
    api = get_api(ctx)
    return await api.get("wireguard.service.show")


@mcp.tool()
async def opn_ipsec_status(ctx: Context) -> dict[str, Any]:
    """Get IPsec VPN tunnel status (IKE and ESP phases).

    Use this when you need to check IPsec site-to-site tunnel health,
    see connected peers, or troubleshoot VPN connectivity. Shows both
    Phase 1 (IKE negotiation) and Phase 2 (ESP/AH tunnels).
    Note: Requires IPsec to be configured. Based on strongSwan (OPNsense 23.1+).
    Returns: dict with 'service_status', 'phase1' (IKE sessions), and 'phase2' (tunnels).
    """
    api = get_api(ctx)
    _search = {"current": 1, "rowCount": 500, "searchPhrase": ""}
    status = await api.get("ipsec.service.status")
    phase1 = await api.post("ipsec.sessions.phase1", _search)
    phase2 = await api.post("ipsec.sessions.phase2", _search)
    return {
        "service_status": status.get("status", "unknown"),
        "phase1": phase1.get("rows", []),
        "phase2": phase2.get("rows", []),
    }


@mcp.tool()
async def opn_openvpn_status(ctx: Context) -> dict[str, Any]:
    """Get OpenVPN connection status (instances, sessions, routes).

    Use this when you need to check OpenVPN server/client status, see
    connected clients, active VPN routes, or troubleshoot OpenVPN tunnels.
    Note: OpenVPN is built-in (no plugin needed) but must be configured.
    Returns: dict with 'instances', 'sessions' (connected clients), and 'routes'.
    """
    api = get_api(ctx)
    _search = {"current": 1, "rowCount": 500, "searchPhrase": ""}
    instances = await api.post("openvpn.instances", _search)
    sessions = await api.post("openvpn.sessions", _search)
    routes = await api.post("openvpn.routes", _search)
    return {
        "instances": instances.get("rows", []),
        "sessions": sessions.get("rows", []),
        "routes": routes.get("rows", []),
    }
