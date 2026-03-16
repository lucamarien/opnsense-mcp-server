"""HAProxy tools — status, configuration CRUD, and service management."""

from __future__ import annotations

from typing import Any

from fastmcp import Context

from opnsense_mcp.api_client import ENDPOINT_REGISTRY
from opnsense_mcp.server import get_api, get_config_cache, mcp

# --- Resource type mapping: plural -> singular ---
_HAPROXY_RESOURCES: dict[str, str] = {
    "frontends": "frontend",
    "backends": "backend",
    "servers": "server",
    "actions": "action",
    "acls": "acl",
    "healthchecks": "healthcheck",
    "errorfiles": "errorfile",
    "resolvers": "resolver",
    "mailers": "mailer",
}


def _ensure_haproxy_endpoint(verb: str, singular: str) -> str:
    """Register a HAProxy CRUD endpoint dynamically and return its logical name.

    The OPNsense HAProxy API is uniform: every resource type supports the same
    get/add/set/del pattern. Rather than registering 36+ endpoints statically,
    this function creates registry entries on demand.
    """
    logical = f"haproxy.settings.{verb}_{singular}"
    if logical not in ENDPOINT_REGISTRY:
        camel = f"haproxy/settings/{verb}{singular.capitalize()}"
        snake = f"haproxy/settings/{verb}_{singular}"
        ENDPOINT_REGISTRY[logical] = (camel, snake)
    return logical


def _validate_resource_type(resource_type: str) -> str | None:
    """Validate and return the singular form, or None on error."""
    return _HAPROXY_RESOURCES.get(resource_type)


@mcp.tool()
async def opn_haproxy_status(ctx: Context) -> dict[str, Any]:
    """Get HAProxy load balancer status and backend health.

    Use this when you need to check HAProxy server status, backend availability,
    or connection statistics.
    Note: Requires the HAProxy plugin (os-haproxy).
    Returns: dict with HAProxy status including servers and backends.
    """
    api = get_api(ctx)
    return await api.get("haproxy.service.status")


@mcp.tool()
async def opn_reconfigure_haproxy(ctx: Context) -> dict[str, Any]:
    """Apply pending HAProxy load balancer configuration changes.

    Use this after making HAProxy configuration changes to apply them to the
    running HAProxy service. This reconfigures HAProxy with the new settings.

    NOTE: This does not use savepoint protection. HAProxy changes take effect
    immediately. Requires the HAProxy plugin (os-haproxy).
    IMPORTANT: Do NOT call haproxy/service/start after reconfigure — reconfigure
    already starts the service, and start will error if already running.
    IMPORTANT: Always call opn_haproxy_configtest before reconfiguring to
    validate the configuration syntax.
    Returns: dict with 'status' indicating success or failure.
    """
    api = get_api(ctx)
    api.require_writes()
    result = await api.post("haproxy.service.reconfigure")
    get_config_cache(ctx).invalidate()
    return {"status": result.get("status", "unknown"), "service": "haproxy"}


@mcp.tool()
async def opn_haproxy_search(
    ctx: Context,
    resource_type: str,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """Search HAProxy resources by type.

    Use this to list and search any HAProxy resource. All resource types use
    the same paginated search pattern.

    Resource types and their key fields:
    - frontends: name, bind (IPv6: [::]:443), mode (http/ssl/tcp), ssl_enabled, defaultBackend
    - backends: name, mode, algorithm (roundrobin/leastconn/source), linkedServers, healthCheck
    - servers: name, address (IPv4/IPv6), port, mode (active/backup/disabled), weight, ssl
    - actions: name, testType, operator (AND/OR), linkedAcls, useBackend
    - acls: name, expression, negate
    - healthchecks: name, type (http/tcp/agent/ldap/mysql/pgsql/redis/smtp), interval
    - errorfiles: name, code (HTTP status), content
    - resolvers: name, nameserver, timeout
    - mailers: name, mailserver, port

    Returns: dict with 'rows' (list of resources) and 'rowCount' (total).
    """
    singular = _validate_resource_type(resource_type)
    if singular is None:
        valid = ", ".join(sorted(_HAPROXY_RESOURCES))
        return {"error": f"Invalid resource_type '{resource_type}'. Must be one of: {valid}"}

    api = get_api(ctx)
    endpoint = f"haproxy.settings.search_{resource_type}"
    return await api.post(
        endpoint,
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_haproxy_get(
    ctx: Context,
    resource_type: str,
    uuid: str,
) -> dict[str, Any]:
    """Get detailed configuration for a specific HAProxy resource.

    Use this to inspect all fields of a single resource before modifying it.
    Returns the full field set including SSL, tuning, persistence, and linked
    resources.

    Resource types: frontends, backends, servers, actions, acls, healthchecks,
    errorfiles, resolvers, mailers.

    Returns: dict with the resource type as key containing all field values.
    """
    singular = _validate_resource_type(resource_type)
    if singular is None:
        valid = ", ".join(sorted(_HAPROXY_RESOURCES))
        return {"error": f"Invalid resource_type '{resource_type}'. Must be one of: {valid}"}

    api = get_api(ctx)
    logical = _ensure_haproxy_endpoint("get", singular)
    return await api.get(logical, path_suffix=uuid)


@mcp.tool()
async def opn_haproxy_add(
    ctx: Context,
    resource_type: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    """Create a new HAProxy resource.

    Use this to add frontends, backends, servers, actions, ACLs, health checks,
    error files, resolvers, or mailers.

    The config dict contains field name-value pairs. Only specify fields you
    want to set — the API fills in defaults for omitted fields.

    Health check example:
    - config={"name": "hc_web", "type": "http", "interval": "5000",
      "checkport": "8080", "http_method": "get", "http_uri": "/",
      "http_version": "http11"}
    - For apps returning non-2xx (e.g. 401 behind auth), add:
      "http_expressionEnabled": "1", "http_expression": "rstatus",
      "http_value": "^[2-4][0-9]{2}$"
    - After creating, link to a backend with opn_haproxy_update:
      config={"healthCheck": "<health-check-uuid>"}

    IPv6 examples:
    - Frontend bind: config={"name": "web-v6", "bind": "[::]:443,0.0.0.0:443",
      "mode": "http", "ssl_enabled": "1", "defaultBackend": "<backend-uuid>"}
    - Server address: config={"name": "srv1", "address": "2001:db8::1", "port": "8080"}
    - Backend resolvePrefer: config={"name": "pool1", "mode": "http",
      "algorithm": "roundrobin", "resolvePrefer": "ipv6"}

    NOTE: Changes are NOT applied until you call opn_reconfigure_haproxy.
    Call opn_haproxy_configtest first to validate the configuration.

    Returns: dict with 'result' (str) and 'uuid' (str) of the new resource.
    """
    singular = _validate_resource_type(resource_type)
    if singular is None:
        valid = ", ".join(sorted(_HAPROXY_RESOURCES))
        return {"error": f"Invalid resource_type '{resource_type}'. Must be one of: {valid}"}

    if not config:
        return {"error": "config must not be empty"}

    api = get_api(ctx)
    api.require_writes()
    logical = _ensure_haproxy_endpoint("add", singular)
    result = await api.post(logical, {singular: config})
    get_config_cache(ctx).invalidate()
    return result


@mcp.tool()
async def opn_haproxy_update(
    ctx: Context,
    resource_type: str,
    uuid: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    """Update an existing HAProxy resource.

    Use this to modify any field on a HAProxy resource. Only provide the fields
    you want to change — omitted fields keep their current values.

    To enable/disable a resource, set config={"enabled": "1"} or {"enabled": "0"}.

    Resource types: frontends, backends, servers, actions, acls, healthchecks,
    errorfiles, resolvers, mailers.

    NOTE: Changes are NOT applied until you call opn_reconfigure_haproxy.
    Call opn_haproxy_configtest first to validate the configuration.

    Returns: dict with 'result' indicating success.
    """
    singular = _validate_resource_type(resource_type)
    if singular is None:
        valid = ", ".join(sorted(_HAPROXY_RESOURCES))
        return {"error": f"Invalid resource_type '{resource_type}'. Must be one of: {valid}"}

    if not config:
        return {"error": "config must not be empty"}

    api = get_api(ctx)
    api.require_writes()
    logical = _ensure_haproxy_endpoint("set", singular)
    result = await api.post(logical, {singular: config}, path_suffix=uuid)
    get_config_cache(ctx).invalidate()
    return result


@mcp.tool()
async def opn_haproxy_delete(
    ctx: Context,
    resource_type: str,
    uuid: str,
) -> dict[str, Any]:
    """Delete a HAProxy resource by UUID.

    IMPORTANT: Check for dependencies before deleting:
    - Delete servers before deleting backends that reference them
    - Delete actions/ACLs before deleting frontends/backends that link them
    - Delete backends before deleting frontends that use them as defaultBackend

    Resource types: frontends, backends, servers, actions, acls, healthchecks,
    errorfiles, resolvers, mailers.

    NOTE: Changes are NOT applied until you call opn_reconfigure_haproxy.

    Returns: dict with 'result' indicating success.
    """
    singular = _validate_resource_type(resource_type)
    if singular is None:
        valid = ", ".join(sorted(_HAPROXY_RESOURCES))
        return {"error": f"Invalid resource_type '{resource_type}'. Must be one of: {valid}"}

    api = get_api(ctx)
    api.require_writes()
    logical = _ensure_haproxy_endpoint("del", singular)
    result = await api.post(logical, path_suffix=uuid)
    get_config_cache(ctx).invalidate()
    return result


@mcp.tool()
async def opn_haproxy_configtest(ctx: Context) -> dict[str, Any]:
    """Validate HAProxy configuration syntax before applying.

    Use this BEFORE calling opn_reconfigure_haproxy to verify the configuration
    is valid. This runs 'haproxy -c' internally and reports any syntax errors.

    Returns: dict with validation result (typically 'status' key).
    """
    api = get_api(ctx)
    return await api.get("haproxy.service.configtest")
