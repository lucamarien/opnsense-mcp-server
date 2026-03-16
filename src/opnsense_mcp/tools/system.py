"""System tools — status, firmware, services, gateways, config backup, config scan."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from fastmcp import Context

from opnsense_mcp.config_cache import SENSITIVE_TAGS
from opnsense_mcp.server import get_api, get_config_cache, mcp


def _strip_sensitive_data(xml_text: str) -> str:
    """Replace sensitive element text with [REDACTED] in config XML."""
    try:
        # Source is trusted (OPNsense API response), not user input
        root = ET.fromstring(xml_text)  # noqa: S314
    except ET.ParseError:
        return xml_text

    for elem in root.iter():
        if elem.tag.lower() in SENSITIVE_TAGS and elem.text:
            elem.text = "[REDACTED]"

    return ET.tostring(root, encoding="unicode", xml_declaration=True)


@mcp.tool()
async def opn_system_status(ctx: Context) -> dict[str, Any]:
    """Get OPNsense system status including firmware version and product info.

    Use this when you need to check the current firmware version, system name,
    or verify the OPNsense appliance is reachable and responding.
    Returns: dict with 'product_version', 'product_name', and other system fields.
    """
    api = get_api(ctx)
    return await api.get("firmware.status")


@mcp.tool()
async def opn_list_services(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List system services and their running status.

    Use this when you need to check which services are running, stopped, or
    available on the OPNsense instance.
    Returns: dict with 'rows' (list of services) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "core.service.search",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_gateway_status(ctx: Context) -> dict[str, Any]:
    """Get gateway status including dpinger health checks.

    Use this when you need to check if WAN gateways are up, their latency,
    packet loss, or failover state.
    Returns: dict with gateway items including status, loss, and delay fields.
    """
    api = get_api(ctx)
    return await api.get("gateway.status")


@mcp.tool()
async def opn_download_config(
    ctx: Context,
    include_sensitive: bool = False,
) -> dict[str, Any]:
    """Download OPNsense config.xml backup as raw XML.

    Use this ONLY when you need a full XML backup for archival purposes.
    For analyzing specific config sections, use opn_scan_config to build a
    cached inventory, then opn_get_config_section to query individual sections.

    By default, sensitive data (passwords, keys, secrets) is redacted.
    Returns: dict with 'config_xml' (str), 'stripped' (bool), 'size_bytes' (int).
    """
    api = get_api(ctx)
    xml_text = await api.get_text("core.backup.download")

    if not include_sensitive:
        xml_text = _strip_sensitive_data(xml_text)

    return {
        "config_xml": xml_text,
        "stripped": not include_sensitive,
        "size_bytes": len(xml_text),
    }


@mcp.tool()
async def opn_scan_config(ctx: Context, force: bool = False) -> dict[str, Any]:
    """Scan the OPNsense configuration and build a cached inventory.

    Use this FIRST when starting a new session. Downloads the full config,
    parses it into queryable sections, and detects runtime state (services,
    DHCP backend, DNS servers). Results are cached for the session — subsequent
    calls return the cached version unless force=True.

    Call with force=True to rescan after manual config changes on the firewall.
    Use opn_get_config_section(section) to drill into specific sections.

    Returns: dict with 'firmware', 'plugins', 'dhcp', 'dns', 'interfaces',
    'services', and 'config_sections' (list of available sections with sizes).
    """
    api = get_api(ctx)
    cache = get_config_cache(ctx)
    return await cache.load(api, force=force)


@mcp.tool()
async def opn_get_config_section(
    ctx: Context,
    section: str,
    include_sensitive: bool = False,
) -> dict[str, Any]:
    """Get a specific configuration section as structured JSON.

    Use this after opn_scan_config to drill into a specific area of the
    OPNsense configuration. If the config hasn't been scanned yet, it will
    be loaded automatically.

    Available sections vary by OPNsense installation. Common sections include:
    system, interfaces, vlans, filter (legacy firewall rules), nat, OPNsense
    (MVC plugin config), unbound, dnsmasq, dhcpd, staticroutes, syslog.

    The 'filter' section is particularly useful — it contains legacy GUI
    firewall rules that are NOT visible via opn_list_firewall_rules.

    Returns: dict with 'section' name and 'data' (structured config data).
    """
    api = get_api(ctx)
    cache = get_config_cache(ctx)

    if not cache.is_loaded or cache.is_stale:
        await cache.load(api)

    result = cache.get_section(section, include_sensitive=include_sensitive)
    if result is None:
        return {
            "error": f"Section '{section}' not found",
            "available_sections": cache.available_sections(),
        }
    return result
