"""DNS tools — Unbound overrides, forward zones, statistics, DNSBL management.

Surface pattern: ``opn_list_*``/``opn_get_*`` for reads,
``opn_manage_dns_override(action=...)`` and DNSBL tools for writes. DNS
changes apply immediately (Unbound is reconfigured automatically) and are
NOT savepoint-protected — they cannot be auto-reverted.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from fastmcp import Context

from opnsense_mcp.server import get_api, get_config_cache, mcp
from opnsense_mcp.tools._util import (
    DESTRUCTIVE,
    READ_ONLY,
    WRITE,
    WRITE_IDEMPOTENT,
    catch_api_errors,
    clamp_limit,
)

_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)
_IP_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
    r"|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
)


@mcp.tool(annotations=READ_ONLY)
@catch_api_errors
async def opn_list_dns_overrides(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List Unbound DNS host overrides (local DNS records).

    Use this when you need to see which hostnames are overridden to specific
    IP addresses in the local DNS resolver, or to find a UUID for
    opn_manage_dns_override.
    Returns: dict with 'rows' (list of overrides) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "unbound.search_override",
        {"current": 1, "rowCount": clamp_limit(limit), "searchPhrase": search},
    )


@mcp.tool(annotations=READ_ONLY)
@catch_api_errors
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
        {"current": 1, "rowCount": clamp_limit(limit), "searchPhrase": search},
    )


@mcp.tool(annotations=READ_ONLY)
@catch_api_errors
async def opn_dns_stats(ctx: Context) -> dict[str, Any]:
    """Get Unbound DNS resolver statistics (queries, cache hits, uptime).

    Use this when you need to check DNS resolver performance, cache hit rates,
    or troubleshoot DNS resolution issues.
    Returns: dict with resolver statistics fields.
    """
    api = get_api(ctx)
    return await api.get("unbound.stats")


@mcp.tool(annotations=WRITE)
@catch_api_errors
async def opn_reconfigure_unbound(ctx: Context) -> dict[str, Any]:
    """Apply pending Unbound DNS resolver configuration changes.

    Use this after making DNS configuration changes outside the MCP tools
    (opn_manage_dns_override applies automatically). This restarts Unbound
    with the new configuration.

    NOTE: No savepoint protection — DNS changes take effect immediately and
    cannot be auto-reverted. Verify settings before calling.
    Returns: dict with 'status' indicating success or failure.
    """
    api = get_api(ctx)
    api.require_writes()
    result = await api.post("unbound.service.reconfigure")
    get_config_cache(ctx).invalidate()
    return {"status": result.get("status", "unknown"), "service": "unbound"}


@mcp.tool(annotations=DESTRUCTIVE)
@catch_api_errors
async def opn_manage_dns_override(
    ctx: Context,
    action: Literal["add", "update", "delete"],
    uuid: str = "",
    hostname: str | None = None,
    domain: str | None = None,
    server: str | None = None,
    description: str | None = None,
    enabled: bool | None = None,
) -> dict[str, Any]:
    """Add, update, or delete an Unbound DNS host override (A/AAAA record).

    Changes are applied immediately (Unbound is reconfigured automatically)
    and CANNOT be auto-reverted — verify parameters before calling.

    Use this for split-horizon DNS, internal services, or overriding external
    DNS for specific hosts.

    Actions:
    - 'add': create an override. Requires hostname, domain, and server.
    - 'update': modify the override identified by uuid. Only provided
      parameters change.
    - 'delete': remove the override identified by uuid.

    Parameters:
    - hostname: the hostname part (e.g. 'myserver')
    - domain: the domain part (e.g. 'local.lan')
    - server: the IP address to resolve to (IPv4 → A record, IPv6 → AAAA)
    - description: optional description
    - enabled: enable/disable the override

    Use opn_list_dns_overrides first to find UUIDs.
    Returns: dict with 'result', 'uuid', and 'applied' (Unbound reconfigure
    status). On failure: 'error' and 'error_type'.
    """
    if action in ("update", "delete") and not uuid:
        return {"error": f"uuid is required for action '{action}'", "error_type": "validation"}
    if hostname is not None and not _HOSTNAME_RE.match(hostname):
        return {
            "error": f"Invalid hostname '{hostname}'. Must be alphanumeric with hyphens.",
            "error_type": "validation",
        }
    if domain is not None and not _DOMAIN_RE.match(domain):
        return {"error": f"Invalid domain '{domain}'. Must be a valid domain name.", "error_type": "validation"}
    if server is not None and not _IP_RE.match(server):
        return {
            "error": f"Invalid server IP '{server}'. Must be an IPv4 or IPv6 address.",
            "error_type": "validation",
        }

    api = get_api(ctx)
    api.require_writes()

    if action == "delete":
        result = await api.post("unbound.del_host_override", path_suffix=uuid)
        reconfigure = await api.post("unbound.service.reconfigure")
        get_config_cache(ctx).invalidate()
        return {
            "result": result.get("result", ""),
            "uuid": uuid,
            "applied": reconfigure.get("status", "unknown"),
        }

    if action == "add":
        missing = [n for n, v in (("hostname", hostname), ("domain", domain), ("server", server)) if not v]
        if missing:
            return {
                "error": f"Required for action 'add': {', '.join(missing)}",
                "error_type": "validation",
            }
        result = await api.post(
            "unbound.add_host_override",
            {
                "host": {
                    "hostname": hostname,
                    "domain": domain,
                    "server": server,
                    "description": description or "",
                    "enabled": "1" if enabled is None or enabled else "0",
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

    # update — send only provided fields
    host: dict[str, str] = {}
    if hostname is not None:
        host["hostname"] = hostname
    if domain is not None:
        host["domain"] = domain
    if server is not None:
        host["server"] = server
    if description is not None:
        host["description"] = description
    if enabled is not None:
        host["enabled"] = "1" if enabled else "0"

    result = await api.post("unbound.set_host_override", {"host": host}, path_suffix=uuid)
    reconfigure = await api.post("unbound.service.reconfigure")
    get_config_cache(ctx).invalidate()
    return {
        "result": result.get("result", ""),
        "uuid": uuid,
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


@mcp.tool(annotations=READ_ONLY)
@catch_api_errors
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
        {"current": 1, "rowCount": clamp_limit(limit), "searchPhrase": search},
    )


@mcp.tool(annotations=READ_ONLY)
@catch_api_errors
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


@mcp.tool(annotations=WRITE_IDEMPOTENT)
@catch_api_errors
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
    settings are preserved. Changes are applied immediately (no auto-revert).

    To add/remove individual allowlist entries without rewriting the whole
    list, prefer opn_edit_dnsbl_allowlist.

    Get the UUID from opn_list_dnsbl first.

    Parameters:
    - uuid: blocklist UUID from opn_list_dnsbl
    - enabled: enable/disable this blocklist
    - providers: comma-separated provider shortcodes (e.g. 'hgz002,hgz011,ag')
    - custom_urls: newline-separated custom blocklist URLs
    - allowlists: newline-separated allowlist entries (REPLACES the list)
    - blocklists: newline-separated custom block domains (REPLACES the list)
    - wildcards: newline-separated wildcard block domains (REPLACES the list)
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


@mcp.tool(annotations=WRITE_IDEMPOTENT)
@catch_api_errors
async def opn_edit_dnsbl_allowlist(
    ctx: Context,
    uuid: str,
    add_domains: str = "",
    remove_domains: str = "",
) -> dict[str, Any]:
    """Add and/or remove domains on a DNSBL allowlist without replacing it.

    Use this when a domain is wrongly blocked by DNSBL and you need to
    allowlist it (e.g. googleads.g.doubleclick.net blocking YouTube), or to
    re-enable blocking for a previously allowlisted domain. Existing entries
    are preserved. Changes are applied immediately.

    Get the UUID from opn_list_dnsbl first.

    Parameters:
    - uuid: blocklist UUID from opn_list_dnsbl
    - add_domains: domains to add, comma or newline-separated
    - remove_domains: domains to remove, comma or newline-separated

    Returns: dict with 'added', 'already_present', 'removed', 'not_found'
    (lists), 'dnsbl_status', and 'service_status'.
    """
    if not add_domains.strip() and not remove_domains.strip():
        return {"error": "Provide add_domains and/or remove_domains.", "error_type": "validation"}

    api = get_api(ctx)
    api.require_writes()

    def _parse(domains: str) -> list[str]:
        return [d.strip() for d in domains.replace(",", "\n").split("\n") if d.strip()]

    to_add = _parse(add_domains)
    to_remove = _parse(remove_domains)

    # Read current config
    raw = await api.get("unbound.get_dnsbl", path_suffix=uuid)
    form = raw.get("blocklist", {})
    current = _extract_dnsbl_values(form)

    existing = set(current.get("allowlists", "").split("\n"))
    existing.discard("")

    added = [d for d in to_add if d not in existing]
    already_present = [d for d in to_add if d in existing]
    removed = [d for d in to_remove if d in existing]
    not_found = [d for d in to_remove if d not in existing]

    merged = sorted((existing | set(to_add)) - set(to_remove))
    current["allowlists"] = "\n".join(merged)

    # Write + apply (regenerate blocklists and restart Unbound)
    result = await api.post("unbound.set_dnsbl", {"blocklist": current}, path_suffix=uuid)
    apply = await _apply_dnsbl(ctx)

    return {
        "result": result.get("result", ""),
        "added": added,
        "already_present": already_present,
        "removed": removed,
        "not_found": not_found,
        **apply,
    }


@mcp.tool(annotations=WRITE_IDEMPOTENT)
@catch_api_errors
async def opn_apply_dnsbl(ctx: Context) -> dict[str, Any]:
    """Reload DNSBL blocklist files and restart Unbound to apply them.

    This does NOT change configuration — use it to refresh blocklists after
    a service restart that lost loaded lists, or to force Unbound to pick up
    previously generated blocklist files. Flushes the DNS cache, so cached
    blocked (or unblocked) domains are re-evaluated.

    To change DNSBL settings, use opn_set_dnsbl or opn_edit_dnsbl_allowlist
    (both apply automatically — calling this afterwards is unnecessary).

    NOTE: No savepoint protection; takes effect immediately.
    Returns: dict with 'dnsbl_status' and 'service_status'.
    """
    api = get_api(ctx)
    api.require_writes()
    return await _apply_dnsbl(ctx)
