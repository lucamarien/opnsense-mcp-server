"""OPNsense MCP Server — FastMCP entrypoint.

Registers all tool modules and starts the STDIO server.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from fastmcp import Context, FastMCP
from fastmcp.server.lifespan import lifespan

from opnsense_mcp.api_client import OPNsenseAPI, SavepointManager
from opnsense_mcp.config import load_config
from opnsense_mcp.config_cache import ConfigCache


@lifespan
async def app_lifespan(server: FastMCP) -> AsyncIterator[dict[str, Any]]:
    """Initialize the OPNsense API client, savepoint manager, and config cache."""
    config = load_config()
    api = OPNsenseAPI(config)
    savepoint_mgr = SavepointManager(api)
    config_cache = ConfigCache()
    try:
        yield {"api": api, "savepoint_mgr": savepoint_mgr, "config_cache": config_cache}
    finally:
        await api.close()


mcp = FastMCP("opnsense", lifespan=app_lifespan)


def get_api(ctx: Context) -> OPNsenseAPI:
    """Extract the OPNsense API client from the MCP context.

    Args:
        ctx: The FastMCP context object.

    Returns:
        The OPNsenseAPI client instance.

    Raises:
        RuntimeError: If the API client is not initialized.
    """
    api: Any = ctx.lifespan_context.get("api")
    if not isinstance(api, OPNsenseAPI):
        msg = "OPNsense API client not initialized"
        raise RuntimeError(msg)
    return api


def get_config_cache(ctx: Context) -> ConfigCache:
    """Extract the ConfigCache from the MCP context.

    Args:
        ctx: The FastMCP context object.

    Returns:
        The ConfigCache instance.

    Raises:
        RuntimeError: If the config cache is not initialized.
    """
    cache: Any = ctx.lifespan_context.get("config_cache")
    if not isinstance(cache, ConfigCache):
        msg = "Config cache not initialized"
        raise RuntimeError(msg)
    return cache


def get_savepoint_manager(ctx: Context) -> SavepointManager:
    """Extract the SavepointManager from the MCP context.

    Args:
        ctx: The FastMCP context object.

    Returns:
        The SavepointManager instance.

    Raises:
        RuntimeError: If the savepoint manager is not initialized.
    """
    mgr: Any = ctx.lifespan_context.get("savepoint_mgr")
    if not isinstance(mgr, SavepointManager):
        msg = "Savepoint manager not initialized"
        raise RuntimeError(msg)
    return mgr


# Import tool modules to register their @mcp.tool() decorators.
from opnsense_mcp.tools import (  # noqa: E402
    dhcp,  # noqa: F401
    diagnostics,  # noqa: F401
    dns,  # noqa: F401
    firewall,  # noqa: F401
    haproxy,  # noqa: F401
    network,  # noqa: F401
    security,  # noqa: F401
    services,  # noqa: F401
    system,  # noqa: F401
    vpn,  # noqa: F401
)


def main() -> None:
    """Entry point for the OPNsense MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
