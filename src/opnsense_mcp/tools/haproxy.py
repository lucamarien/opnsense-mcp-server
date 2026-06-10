"""HAProxy tools — status, configuration CRUD, and service management.

HAProxy keeps the generic resource_type CRUD pattern (rather than per-entity
manage tools) because all 9 resource types share an identical uniform API.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from fastmcp import Context

from opnsense_mcp.api_client import ENDPOINT_REGISTRY
from opnsense_mcp.server import get_api, get_config_cache, mcp
from opnsense_mcp.tools._util import (
    DESTRUCTIVE,
    READ_ONLY,
    WRITE,
    WRITE_IDEMPOTENT,
    catch_api_errors,
    clamp_limit,
)

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

_ResourceType = Literal[
    "frontends",
    "backends",
    "servers",
    "actions",
    "acls",
    "healthchecks",
    "errorfiles",
    "resolvers",
    "mailers",
]

# The OPNsense HAProxy API is uniform: every resource type supports the same
# get/add/set/del pattern. Register all CRUD endpoints at import time.
for _singular in _HAPROXY_RESOURCES.values():
    for _verb in ("get", "add", "set", "del"):
        _logical = f"haproxy.settings.{_verb}_{_singular}"
        ENDPOINT_REGISTRY.setdefault(
            _logical,
            (
                f"haproxy/settings/{_verb}{_singular.capitalize()}",
                f"haproxy/settings/{_verb}_{_singular}",
            ),
        )

# Strings in `haproxy -c` output that indicate a broken configuration.
_CONFIGTEST_FAILURE_MARKERS = ("alert", "error", "fatal")


def _configtest_failed(result: dict[str, Any]) -> bool:
    """Heuristic: does a configtest response indicate a broken config?"""
    text = json.dumps(result).lower()
    return any(marker in text for marker in _CONFIGTEST_FAILURE_MARKERS)


@mcp.tool(annotations=READ_ONLY)
@catch_api_errors
async def opn_haproxy_status(ctx: Context) -> dict[str, Any]:
    """Get HAProxy load balancer status and backend health.

    Use this when you need to check HAProxy server status, backend availability,
    or connection statistics.
    Note: Requires the HAProxy plugin (os-haproxy).
    Returns: dict with HAProxy status including servers and backends.
    """
    api = get_api(ctx)
    return await api.get("haproxy.service.status")


@mcp.tool(annotations=READ_ONLY)
@catch_api_errors
async def opn_haproxy_search(
    ctx: Context,
    resource_type: _ResourceType,
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
    api = get_api(ctx)
    endpoint = f"haproxy.settings.search_{resource_type}"
    return await api.post(
        endpoint,
        {"current": 1, "rowCount": clamp_limit(limit), "searchPhrase": search},
    )


@mcp.tool(annotations=READ_ONLY)
@catch_api_errors
async def opn_haproxy_get(
    ctx: Context,
    resource_type: _ResourceType,
    uuid: str,
) -> dict[str, Any]:
    """Get detailed configuration for a specific HAProxy resource.

    Use this to inspect all fields of a single resource before modifying it.
    Returns the full field set including SSL, tuning, persistence, and linked
    resources.

    Returns: dict with the resource type as key containing all field values.
    """
    api = get_api(ctx)
    singular = _HAPROXY_RESOURCES[resource_type]
    return await api.get(f"haproxy.settings.get_{singular}", path_suffix=uuid)


@mcp.tool(annotations=WRITE)
@catch_api_errors
async def opn_haproxy_add(
    ctx: Context,
    resource_type: _ResourceType,
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

    NOTE: Changes are NOT applied until you call opn_reconfigure_haproxy
    (which validates the configuration first and refuses to apply a broken one).

    Returns: dict with 'result' (str) and 'uuid' (str) of the new resource.
    """
    if not config:
        return {"error": "config must not be empty", "error_type": "validation"}

    api = get_api(ctx)
    api.require_writes()
    singular = _HAPROXY_RESOURCES[resource_type]
    result = await api.post(f"haproxy.settings.add_{singular}", {singular: config})
    get_config_cache(ctx).invalidate()
    return result


@mcp.tool(annotations=WRITE_IDEMPOTENT)
@catch_api_errors
async def opn_haproxy_update(
    ctx: Context,
    resource_type: _ResourceType,
    uuid: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    """Update an existing HAProxy resource.

    Use this to modify any field on a HAProxy resource. Only provide the fields
    you want to change — omitted fields keep their current values.

    To enable/disable a resource, set config={"enabled": "1"} or {"enabled": "0"}.

    NOTE: Changes are NOT applied until you call opn_reconfigure_haproxy
    (which validates the configuration first and refuses to apply a broken one).

    Returns: dict with 'result' indicating success.
    """
    if not config:
        return {"error": "config must not be empty", "error_type": "validation"}

    api = get_api(ctx)
    api.require_writes()
    singular = _HAPROXY_RESOURCES[resource_type]
    result = await api.post(f"haproxy.settings.set_{singular}", {singular: config}, path_suffix=uuid)
    get_config_cache(ctx).invalidate()
    return result


@mcp.tool(annotations=DESTRUCTIVE)
@catch_api_errors
async def opn_haproxy_delete(
    ctx: Context,
    resource_type: _ResourceType,
    uuid: str,
) -> dict[str, Any]:
    """Delete a HAProxy resource by UUID.

    IMPORTANT: Check for dependencies before deleting:
    - Delete servers before deleting backends that reference them
    - Delete actions/ACLs before deleting frontends/backends that link them
    - Delete backends before deleting frontends that use them as defaultBackend

    NOTE: Changes are NOT applied until you call opn_reconfigure_haproxy.

    Returns: dict with 'result' indicating success.
    """
    api = get_api(ctx)
    api.require_writes()
    singular = _HAPROXY_RESOURCES[resource_type]
    result = await api.post(f"haproxy.settings.del_{singular}", path_suffix=uuid)
    get_config_cache(ctx).invalidate()
    return result


@mcp.tool(annotations=READ_ONLY)
@catch_api_errors
async def opn_haproxy_configtest(ctx: Context) -> dict[str, Any]:
    """Validate HAProxy configuration syntax without applying it.

    Runs 'haproxy -c' internally and reports any syntax errors.
    opn_reconfigure_haproxy already runs this check automatically and refuses
    to apply a broken config — call this directly when you want to validate
    without applying yet.

    Returns: dict with validation result (typically 'status'/'result' keys).
    """
    api = get_api(ctx)
    return await api.get("haproxy.service.configtest")


@mcp.tool(annotations=WRITE)
@catch_api_errors
async def opn_reconfigure_haproxy(ctx: Context) -> dict[str, Any]:
    """Validate, then apply pending HAProxy configuration changes.

    Runs the configuration test first and REFUSES to reconfigure if the test
    reports errors — a broken HAProxy config would take down every site behind
    the reverse proxy. On a passing test, reconfigures the running service.

    NOTE: No savepoint protection — HAProxy changes take effect immediately
    once applied. Requires the HAProxy plugin (os-haproxy).
    Returns: dict with 'status' and 'configtest' (the validation output).
    On a failed test: 'error', 'error_type'='configtest', and 'configtest'.
    """
    api = get_api(ctx)
    api.require_writes()

    configtest = await api.get("haproxy.service.configtest")
    if _configtest_failed(configtest):
        return {
            "error": "HAProxy configuration test failed — reconfigure refused. Fix the config first.",
            "error_type": "configtest",
            "configtest": configtest,
        }

    result = await api.post("haproxy.service.reconfigure")
    get_config_cache(ctx).invalidate()
    return {
        "status": result.get("status", "unknown"),
        "service": "haproxy",
        "configtest": configtest,
    }
