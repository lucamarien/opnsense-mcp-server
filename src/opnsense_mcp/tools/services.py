"""Service tools — ACME, CrowdSec, Cron, Dynamic DNS."""

from __future__ import annotations

from typing import Any

from fastmcp import Context

from opnsense_mcp.server import get_api, get_config_cache, mcp

_SENSITIVE_FIELDS = frozenset({"password", "%password"})

# --- Dynamic DNS ---


@mcp.tool()
async def opn_list_ddns_accounts(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List Dynamic DNS (DDNS) accounts and their update status.

    Use this to check which hostnames have DDNS configured, their current
    IP addresses, last update time, and which service provider is used.

    Key fields: service (provider), hostname, checkip (method), current_ip,
    current_mtime (last update), interface, enabled.

    For IPv6 DDNS: the global setting 'allowipv6' must be enabled AND an
    IPv6-capable checkip method must be used (e.g. 'cloudflare-ipv6').
    Both must be set or IPv6 updates silently fail.

    Note: Requires the Dynamic DNS plugin (os-ddclient).
    Returns: dict with 'rows' (list of accounts) and 'rowCount' (total).
    """
    api = get_api(ctx)
    result = await api.post(
        "dyndns.accounts.search",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )
    # Sanitize: strip credentials from search results
    for row in result.get("rows", []):
        for field in _SENSITIVE_FIELDS:
            if field in row:
                row[field] = "***"
    return result


@mcp.tool()
async def opn_add_ddns_account(
    ctx: Context,
    service: str,
    hostname: str,
    username: str = "",
    password: str = "",
    checkip: str = "web_dyndns",
    interface: str = "",
    description: str = "",
) -> dict[str, Any]:
    """Create a new Dynamic DNS account and apply the configuration.

    Use this to register a hostname with a DDNS provider so the firewall
    automatically updates the DNS record when the public IP changes.

    Args:
        service: DDNS provider name (e.g. 'cloudflare', 'dyndns', 'noip',
                 'freedns', 'he', 'namecheap', 'desec', 'godaddy').
        hostname: Fully qualified domain name to update (e.g. 'fw.example.com').
        username: Provider username or API key (leave empty for token-only providers).
        password: Provider password or API token.
        checkip: IP check method — 'web_dyndns' (default), 'web_freedns',
                 'web_he', 'if' (use interface IP), or 'cmd'.
                 For IPv6: use 'web_dyndns6', 'web_freedns6', etc. The global
                 'allowipv6' setting must ALSO be enabled or IPv6 updates silently fail.
        interface: Network interface name (e.g. 'wan', 'opt1'). Required when
                   checkip='if'. Optional otherwise.
        description: Optional description for this account.

    NOTE: After creation, the service is automatically reconfigured. Changes
    take effect immediately.

    Note: Requires the Dynamic DNS plugin (os-ddclient).
    Returns: dict with 'result', 'uuid' of the new account, and reconfigure status.
    """
    if not service.strip():
        return {"error": "service must not be empty"}
    if not hostname.strip():
        return {"error": "hostname must not be empty"}

    api = get_api(ctx)
    api.require_writes()

    account_config: dict[str, str] = {
        "enabled": "1",
        "service": service,
        "hostname": hostname,
        "checkip": checkip,
    }
    if username:
        account_config["username"] = username
    if password:
        account_config["password"] = password
    if interface:
        account_config["interface"] = interface
    if description:
        account_config["description"] = description

    add_result = await api.post("dyndns.accounts.add", {"account": account_config})

    reconfigure_result = await api.post("dyndns.service.reconfigure")
    get_config_cache(ctx).invalidate()

    return {
        "result": add_result.get("result", "unknown"),
        "uuid": add_result.get("uuid", ""),
        "reconfigure_status": reconfigure_result.get("status", "unknown"),
    }


@mcp.tool()
async def opn_update_ddns_account(
    ctx: Context,
    uuid: str,
    service: str | None = None,
    hostname: str | None = None,
    username: str | None = None,
    password: str | None = None,
    checkip: str | None = None,
    interface: str | None = None,
    description: str | None = None,
    enabled: bool | None = None,
) -> dict[str, Any]:
    """Update a Dynamic DNS account by UUID and apply the configuration.

    Use this when you need to change the hostname, provider, credentials, or
    other properties of a DDNS account. Only the parameters you provide are
    changed; all other settings are preserved.

    After update, the ddclient service is automatically reconfigured. Changes
    take effect immediately.
    Use opn_list_ddns_accounts first to find the UUID.

    Parameters:
    - uuid: account UUID (from opn_list_ddns_accounts)
    - service: DDNS provider name (e.g. 'cloudflare', 'dyndns', 'noip')
    - hostname: fully qualified domain name to update
    - username: provider username or API key
    - password: provider password or API token
    - checkip: IP check method (e.g. 'web_dyndns', 'if')
    - interface: network interface name (e.g. 'wan')
    - description: human-readable description
    - enabled: enable/disable the account

    Returns: dict with 'result' (str), 'uuid' (str), and 'reconfigure_status'.
    """
    api = get_api(ctx)
    api.require_writes()

    account_config: dict[str, str] = {}
    if service is not None:
        account_config["service"] = service
    if hostname is not None:
        account_config["hostname"] = hostname
    if username is not None:
        account_config["username"] = username
    if password is not None:
        account_config["password"] = password
    if checkip is not None:
        account_config["checkip"] = checkip
    if interface is not None:
        account_config["interface"] = interface
    if description is not None:
        account_config["description"] = description
    if enabled is not None:
        account_config["enabled"] = "1" if enabled else "0"

    result = await api.post("dyndns.accounts.set", {"account": account_config}, path_suffix=uuid)
    reconfigure_result = await api.post("dyndns.service.reconfigure")
    get_config_cache(ctx).invalidate()

    return {
        "result": result.get("result", ""),
        "uuid": uuid,
        "reconfigure_status": reconfigure_result.get("status", "unknown"),
    }


@mcp.tool()
async def opn_delete_ddns_account(
    ctx: Context,
    uuid: str,
) -> dict[str, Any]:
    """Delete a Dynamic DNS account by UUID and apply the configuration.

    The deletion is applied immediately (ddclient is reconfigured automatically).
    Use opn_list_ddns_accounts first to find the UUID.
    Returns: dict with 'result' (str), 'uuid' (str), and 'reconfigure_status'.
    """
    api = get_api(ctx)
    api.require_writes()
    result = await api.post("dyndns.accounts.del", path_suffix=uuid)
    reconfigure_result = await api.post("dyndns.service.reconfigure")
    get_config_cache(ctx).invalidate()

    return {
        "result": result.get("result", ""),
        "uuid": uuid,
        "reconfigure_status": reconfigure_result.get("status", "unknown"),
    }


@mcp.tool()
async def opn_reconfigure_ddclient(ctx: Context) -> dict[str, Any]:
    """Apply pending Dynamic DNS configuration changes.

    Use this after manually editing DDNS account settings to apply the
    changes to the running ddclient service.

    Note: opn_add_ddns_account auto-reconfigures, so this is only needed
    for manual edits or troubleshooting.

    Note: Requires the Dynamic DNS plugin (os-ddclient).
    Returns: dict with 'status' indicating success or failure.
    """
    api = get_api(ctx)
    api.require_writes()
    result = await api.post("dyndns.service.reconfigure")
    get_config_cache(ctx).invalidate()
    return {"status": result.get("status", "unknown"), "service": "ddclient"}


@mcp.tool()
async def opn_list_acme_certs(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List ACME (Let's Encrypt) certificates and their status.

    Use this when you need to check certificate expiry dates, renewal status,
    or which domains have ACME certificates configured.
    Note: Requires the ACME client plugin (os-acme-client).
    Returns: dict with 'rows' (list of certificates) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "acmeclient.certs.search",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_list_cron_jobs(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List scheduled cron jobs configured in OPNsense.

    Use this when you need to check what scheduled tasks are configured,
    their frequency, or which commands they run.
    Returns: dict with 'rows' (list of cron jobs) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "cron.search_jobs",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_crowdsec_status(ctx: Context) -> dict[str, Any]:
    """Get CrowdSec security engine status and active decisions summary.

    Use this when you need to check if CrowdSec is running, see how many
    active security decisions (bans/captchas) are in effect, and get a
    quick overview of the threat protection state.
    Note: Requires the CrowdSec plugin (os-crowdsec).
    Returns: dict with 'service_status', 'decisions_count', and 'alerts_count'.
    """
    api = get_api(ctx)
    _search = {"current": 1, "rowCount": 500, "searchPhrase": ""}
    status = await api.get("crowdsec.service.status")
    decisions = await api.post("crowdsec.decisions.search", _search)
    alerts = await api.post("crowdsec.alerts.search", _search)

    decision_rows: list[dict[str, Any]] = decisions.get("rows", [])
    alert_rows: list[dict[str, Any]] = alerts.get("rows", [])

    return {
        "service_status": status.get("status", "unknown"),
        "decisions_count": len(decision_rows),
        "alerts_count": len(alert_rows),
        "decisions": decision_rows[:20],
        "alerts": alert_rows[:20],
    }


@mcp.tool()
async def opn_crowdsec_alerts(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List CrowdSec security alerts (detected threats and attacks).

    Use this when you need to review security events detected by CrowdSec,
    including brute-force attempts, port scans, and other threats.
    Note: Requires the CrowdSec plugin (os-crowdsec).
    Returns: dict with 'rows' (list of alerts) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "crowdsec.alerts.search",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


# --- mDNS Repeater ---


@mcp.tool()
async def opn_mdns_repeater_status(ctx: Context) -> dict[str, Any]:
    """Get mDNS Repeater service status and configuration.

    Use this to check if the mDNS Repeater is installed, enabled, running,
    and which interfaces it is configured to relay multicast DNS between.

    The mDNS Repeater relays mDNS (224.0.0.251:5353) packets between selected
    interfaces, enabling device discovery (HomeKit, Chromecast, AirPlay, etc.)
    across VLANs.

    Note: Requires the mDNS Repeater plugin (os-mdns-repeater).
    Returns: dict with 'service_running', 'enabled', 'interfaces', 'blocklist'.
    """
    api = get_api(ctx)
    settings = await api.get("mdnsrepeater.settings.get")
    status = await api.get("mdnsrepeater.service.status")

    mdns_cfg = settings.get("mdnsrepeater", settings)
    return {
        "service_running": status.get("status", "unknown"),
        "enabled": mdns_cfg.get("enabled", "0"),
        "interfaces": mdns_cfg.get("interfaces", ""),
        "blocklist": mdns_cfg.get("blocklist", ""),
        "enable_carp": mdns_cfg.get("enablecarp", "0"),
    }


@mcp.tool()
async def opn_configure_mdns_repeater(
    ctx: Context,
    enabled: bool = True,
    interfaces: str = "lan",
) -> dict[str, Any]:
    """Enable and configure the mDNS Repeater to relay multicast DNS between interfaces.

    Use this to set up cross-VLAN mDNS discovery. The repeater relays mDNS
    packets (224.0.0.251:5353) between selected interfaces, enabling HomeKit,
    Chromecast, AirPlay, and other mDNS-based device discovery across VLANs.

    Args:
        enabled: Whether to enable the mDNS Repeater service.
        interfaces: Comma-separated list of interface names to relay between
                    (e.g. 'lan,opt1'). Minimum 2 interfaces required for
                    cross-VLAN relay. Maximum 5 interfaces supported.

    Note: Requires the mDNS Repeater plugin (os-mdns-repeater) to be installed.
    Returns: dict with 'result' and 'reconfigure_status'.
    """
    api = get_api(ctx)
    api.require_writes()

    settings_payload = {
        "mdnsrepeater": {
            "enabled": "1" if enabled else "0",
            "interfaces": interfaces,
        },
    }
    set_result = await api.post("mdnsrepeater.settings.set", settings_payload)
    reconfigure_result = await api.post("mdnsrepeater.service.reconfigure")
    get_config_cache(ctx).invalidate()

    return {
        "result": set_result.get("result", "unknown"),
        "reconfigure_status": reconfigure_result.get("status", "unknown"),
        "enabled": "1" if enabled else "0",
        "interfaces": interfaces,
    }
