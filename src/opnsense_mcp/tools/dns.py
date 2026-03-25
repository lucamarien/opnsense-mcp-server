"""DNS tools — Unbound overrides, forward zones, statistics, DNSBL management."""

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


# ---------------------------------------------------------------------------
# DNSBL (DNS Blocklist) tools
# ---------------------------------------------------------------------------


def _extract_dnsbl_values(form: dict[str, Any]) -> dict[str, str]:
    """Extract simple string values from a getDnsbl form model response.

    The OPNsense MVC ``getDnsbl`` endpoint returns option-dict fields like
    ``{"shortcode": {"value": "Name", "selected": 0|1}}``.  This helper
    converts them to the flat strings expected by ``setDnsbl``.
    """
    result: dict[str, str] = {}
    # type → comma-separated selected shortcodes
    type_field = form.get("type", {})
    if isinstance(type_field, dict):
        result["type"] = ",".join(k for k, v in type_field.items() if isinstance(v, dict) and v.get("selected") == 1)
    # text fields → newline-separated non-empty keys
    for field in ("lists", "allowlists", "blocklists", "wildcards", "source_nets"):
        entries = form.get(field, {})
        if isinstance(entries, dict):
            result[field] = "\n".join(k for k in entries if k)
    # simple string fields → pass through
    for field in ("enabled", "address", "nxdomain", "cache_ttl", "description"):
        if field in form:
            result[field] = str(form[field])
    return result


async def _apply_dnsbl(ctx: Context) -> dict[str, str]:
    """Regenerate DNSBL blocklist files and restart Unbound to apply them.

    Calls ``service/dnsbl`` to regenerate blocklist files on disk, then
    ``service/reconfigure`` to restart Unbound so the new lists are loaded
    and the DNS cache is flushed.
    """
    api = get_api(ctx)
    dnsbl_result = await api.post("unbound.service.dnsbl")
    reconfigure_result = await api.post("unbound.service.reconfigure")
    get_config_cache(ctx).invalidate()
    return {
        "dnsbl_status": dnsbl_result.get("status", "unknown").strip(),
        "service_status": reconfigure_result.get("status", "unknown").strip(),
    }


@mcp.tool()
async def opn_list_dnsbl(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List DNSBL (DNS Blocklist) configurations with providers and status.

    Use this when you need to see which DNS blocklists are configured, which
    providers are active, and what allowlist/blocklist entries exist.
    Use opn_get_dnsbl with a UUID from the results for full details.
    Returns: dict with 'rows' (list of blocklist configs) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "unbound.search_dnsbl",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_get_dnsbl(
    ctx: Context,
    uuid: str,
) -> dict[str, Any]:
    """Get full DNSBL configuration for a specific blocklist by UUID.

    Use this when you need to see all available providers and their selection
    state, current allowlist/blocklist entries, and other DNSBL settings.
    Get the UUID from opn_list_dnsbl first.

    Returns: dict with 'selected_providers', 'available_providers',
    'allowlists', 'blocklists', 'wildcards', and config fields.
    """
    api = get_api(ctx)
    raw = await api.get("unbound.get_dnsbl", path_suffix=uuid)
    form = raw.get("blocklist", {})

    # Parse type field into selected + available
    type_field = form.get("type", {})
    selected: list[str] = []
    available: dict[str, str] = {}
    if isinstance(type_field, dict):
        for code, info in type_field.items():
            if isinstance(info, dict):
                available[code] = str(info.get("value", code))
                if info.get("selected") == 1:
                    selected.append(code)

    # Parse text fields from option dicts
    def _parse_text_field(field_data: dict[str, Any] | str | None) -> list[str]:
        if isinstance(field_data, dict):
            return [k for k in field_data if k]
        return []

    return {
        "uuid": uuid,
        "enabled": form.get("enabled") == "1",
        "selected_providers": selected,
        "available_providers": available,
        "allowlists": _parse_text_field(form.get("allowlists")),
        "blocklists": _parse_text_field(form.get("blocklists")),
        "wildcards": _parse_text_field(form.get("wildcards")),
        "custom_urls": _parse_text_field(form.get("lists")),
        "source_nets": _parse_text_field(form.get("source_nets")),
        "address": form.get("address", ""),
        "nxdomain": form.get("nxdomain") == "1",
        "cache_ttl": form.get("cache_ttl", ""),
        "description": form.get("description", ""),
    }


@mcp.tool()
async def opn_set_dnsbl(
    ctx: Context,
    uuid: str,
    enabled: bool | None = None,
    providers: str = "",
    custom_urls: str = "",
    allowlists: str = "",
    blocklists: str = "",
    wildcards: str = "",
    source_nets: str = "",
    nxdomain: bool | None = None,
    cache_ttl: int | None = None,
    description: str | None = None,
) -> dict[str, Any]:
    """Update a DNSBL blocklist configuration (read-modify-write).

    Use this when you need to change DNSBL settings — providers, allowlists,
    blocklists, etc. Only the parameters you provide are changed; all other
    settings are preserved. Changes are applied immediately.

    Get the UUID from opn_list_dnsbl first.

    Parameters:
    - uuid: blocklist UUID from opn_list_dnsbl
    - enabled: enable/disable this blocklist
    - providers: comma-separated provider shortcodes (e.g. 'hgz002,hgz011,ag')
    - custom_urls: newline-separated custom blocklist URLs
    - allowlists: newline-separated allowlist entries (domains or regex patterns)
    - blocklists: newline-separated custom block domains
    - wildcards: newline-separated wildcard block domains
    - source_nets: comma-separated source networks (empty = all)
    - nxdomain: return NXDOMAIN instead of 0.0.0.0 for blocked domains
    - cache_ttl: cache TTL in seconds for DNSBL responses
    - description: human-readable description

    Returns: dict with 'result', 'dnsbl_status', and 'service_status'.
    """
    api = get_api(ctx)
    api.require_writes()

    # Read current config
    raw = await api.get("unbound.get_dnsbl", path_suffix=uuid)
    form = raw.get("blocklist", {})
    current = _extract_dnsbl_values(form)

    # Merge user changes
    if enabled is not None:
        current["enabled"] = "1" if enabled else "0"
    if providers:
        current["type"] = providers
    if custom_urls:
        current["lists"] = custom_urls
    if allowlists:
        current["allowlists"] = allowlists
    if blocklists:
        current["blocklists"] = blocklists
    if wildcards:
        current["wildcards"] = wildcards
    if source_nets:
        current["source_nets"] = source_nets
    if nxdomain is not None:
        current["nxdomain"] = "1" if nxdomain else "0"
    if cache_ttl is not None:
        current["cache_ttl"] = str(cache_ttl)
    if description is not None:
        current["description"] = description

    # Write + apply (regenerate blocklists and restart Unbound)
    result = await api.post("unbound.set_dnsbl", {"blocklist": current}, path_suffix=uuid)
    apply = await _apply_dnsbl(ctx)

    return {
        "result": result.get("result", ""),
        **apply,
    }


@mcp.tool()
async def opn_add_dnsbl_allowlist(
    ctx: Context,
    uuid: str,
    domains: str,
) -> dict[str, Any]:
    """Add domains to a DNSBL allowlist (whitelist) without overwriting existing entries.

    Use this when a domain is blocked by DNSBL and you need to allowlist it
    (e.g. googleads.g.doubleclick.net blocking YouTube). Existing allowlist
    entries are preserved. Changes are applied immediately.

    Get the UUID from opn_list_dnsbl first.

    Parameters:
    - uuid: blocklist UUID from opn_list_dnsbl
    - domains: domains to add, comma or newline-separated

    Returns: dict with 'added' (list), 'already_present' (list),
    'dnsbl_status', and 'service_status'.
    """
    if not domains.strip():
        return {"error": "No domains provided."}

    api = get_api(ctx)
    api.require_writes()

    # Parse input domains
    new_domains = [d.strip() for d in domains.replace(",", "\n").split("\n") if d.strip()]

    # Read current config
    raw = await api.get("unbound.get_dnsbl", path_suffix=uuid)
    form = raw.get("blocklist", {})
    current = _extract_dnsbl_values(form)

    # Parse existing allowlist
    existing = set(current.get("allowlists", "").split("\n"))
    existing.discard("")

    # Merge
    added = [d for d in new_domains if d not in existing]
    already_present = [d for d in new_domains if d in existing]
    merged = sorted(existing | set(new_domains))
    current["allowlists"] = "\n".join(merged)

    # Write + apply (regenerate blocklists and restart Unbound)
    result = await api.post("unbound.set_dnsbl", {"blocklist": current}, path_suffix=uuid)
    apply = await _apply_dnsbl(ctx)

    return {
        "result": result.get("result", ""),
        "added": added,
        "already_present": already_present,
        **apply,
    }


@mcp.tool()
async def opn_remove_dnsbl_allowlist(
    ctx: Context,
    uuid: str,
    domains: str,
) -> dict[str, Any]:
    """Remove domains from a DNSBL allowlist.

    Use this when you no longer need a domain allowlisted and want to re-enable
    DNSBL blocking for it. Changes are applied immediately.

    Get the UUID from opn_list_dnsbl first.

    Parameters:
    - uuid: blocklist UUID from opn_list_dnsbl
    - domains: domains to remove, comma or newline-separated

    Returns: dict with 'removed' (list), 'not_found' (list),
    'dnsbl_status', and 'service_status'.
    """
    if not domains.strip():
        return {"error": "No domains provided."}

    api = get_api(ctx)
    api.require_writes()

    # Parse input domains
    remove_domains = [d.strip() for d in domains.replace(",", "\n").split("\n") if d.strip()]

    # Read current config
    raw = await api.get("unbound.get_dnsbl", path_suffix=uuid)
    form = raw.get("blocklist", {})
    current = _extract_dnsbl_values(form)

    # Parse existing allowlist
    existing = set(current.get("allowlists", "").split("\n"))
    existing.discard("")

    # Remove
    removed = [d for d in remove_domains if d in existing]
    not_found = [d for d in remove_domains if d not in existing]
    remaining = sorted(existing - set(remove_domains))
    current["allowlists"] = "\n".join(remaining)

    # Write + apply (regenerate blocklists and restart Unbound)
    result = await api.post("unbound.set_dnsbl", {"blocklist": current}, path_suffix=uuid)
    apply = await _apply_dnsbl(ctx)

    return {
        "result": result.get("result", ""),
        "removed": removed,
        "not_found": not_found,
        **apply,
    }


@mcp.tool()
async def opn_update_dnsbl(ctx: Context) -> dict[str, Any]:
    """Reload DNSBL blocklist files and restart Unbound to apply them.

    Use this when DNSBL lists need to be refreshed without changing the
    configuration — for example after a service restart that lost loaded
    lists, or to force Unbound to pick up previously generated blocklist
    files. This flushes the DNS cache, so previously cached blocked
    (or unblocked) domains will be re-evaluated.

    NOTE: This does not use savepoint protection. DNS changes take effect
    immediately and cannot be auto-reverted.
    Returns: dict with 'dnsbl_status' and 'service_status'.
    """
    api = get_api(ctx)
    api.require_writes()
    return await _apply_dnsbl(ctx)
