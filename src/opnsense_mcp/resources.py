"""MCP resources — URI-addressable read-only context.

Dual-exposed alongside the equivalent tools (opn_scan_config /
opn_get_config_section): resources let clients attach config context without
a model round-trip, while the tools remain available for mid-task fetches.
Sensitive values are always redacted in resources.
"""

from __future__ import annotations

from typing import Any

from fastmcp import Context

from opnsense_mcp.server import get_api, get_config_cache, mcp


@mcp.resource("opnsense://inventory")
async def inventory(ctx: Context) -> dict[str, Any]:
    """Runtime inventory: firmware, plugins, DHCP/DNS backends, interfaces, services."""
    api = get_api(ctx)
    cache = get_config_cache(ctx)
    return await cache.load(api)


@mcp.resource("opnsense://config/{section}")
async def config_section(section: str, ctx: Context) -> dict[str, Any]:
    """A parsed config.xml section as structured JSON (sensitive values redacted)."""
    api = get_api(ctx)
    cache = get_config_cache(ctx)
    if not cache.is_loaded or cache.is_stale:
        await cache.load(api)
    result = cache.get_section(section)
    if result is None:
        return {
            "error": f"Section '{section}' not found",
            "available_sections": cache.available_sections(),
        }
    return result
