"""OPNsense REST API client.

Handles authentication, SSL, endpoint versioning (camelCase vs snake_case),
endpoint blocklist, and error response parsing.
"""

from __future__ import annotations

from typing import Any

import httpx

from opnsense_mcp.config import OPNsenseConfig

# --- Dangerous endpoints that execute immediately with no confirmation ---
BLOCKED_ENDPOINTS: frozenset[str] = frozenset(
    {
        "core/system/halt",
        "core/system/reboot",
        "core/firmware/poweroff",
        "core/firmware/update",
        "core/firmware/upgrade",
    }
)

# --- Endpoint registry: logical_name -> (camelCase, snake_case) ---
ENDPOINT_REGISTRY: dict[str, tuple[str, str]] = {
    # Firmware (unchanged across versions)
    "firmware.status": ("core/firmware/status", "core/firmware/status"),
    # Diagnostics / Interfaces
    "interface.arp": (
        "diagnostics/interface/getArp",
        "diagnostics/interface/get_arp",
    ),
    "interface.statistics": (
        "diagnostics/interface/getInterfaceStatistics",
        "diagnostics/interface/get_interface_statistics",
    ),
    "interface.names": (
        "diagnostics/interface/getInterfaceNames",
        "diagnostics/interface/get_interface_names",
    ),
    "interface.ndp": (
        "diagnostics/interface/getNdp",
        "diagnostics/interface/get_ndp",
    ),
    # Firewall
    "firewall.search_rule": (
        "firewall/filter/searchRule",
        "firewall/filter/search_rule",
    ),
    "firewall.alias.search": (
        "firewall/alias/searchItem",
        "firewall/alias/search_item",
    ),
    # Unbound DNS
    "unbound.search_override": (
        "unbound/settings/searchHostOverride",
        "unbound/settings/search_host_override",
    ),
    # Core services
    "core.service.search": ("core/service/search", "core/service/search"),
    # Gateway status
    "gateway.status": ("routes/gateway/status", "routes/gateway/status"),
    # Firewall diagnostics
    "firewall.log": ("diagnostics/firewall/log", "diagnostics/firewall/log"),
    # Unbound DNS (additional)
    "unbound.search_forward": (
        "unbound/settings/searchForward",
        "unbound/settings/search_forward",
    ),
    "unbound.stats": ("unbound/diagnostics/stats", "unbound/diagnostics/stats"),
    # DHCPv4 leases
    "dhcpv4.leases.search": (
        "dhcpv4/leases/searchLease",
        "dhcpv4/leases/search_lease",
    ),
    # WireGuard
    "wireguard.service.show": ("wireguard/service/show", "wireguard/service/show"),
    # HAProxy
    "haproxy.service.status": ("haproxy/service/status", "haproxy/service/status"),
    # ACME client
    "acmeclient.certs.search": (
        "acmeclient/certificates/search",
        "acmeclient/certificates/search",
    ),
    # Cron
    "cron.search_jobs": (
        "cron/settings/searchJobs",
        "cron/settings/search_jobs",
    ),
    # Firewall savepoint/rollback
    "firewall.savepoint": ("firewall/filter/savepoint", "firewall/filter/savepoint"),
    "firewall.apply": ("firewall/filter/apply", "firewall/filter/apply"),
    "firewall.cancel_rollback": (
        "firewall/filter/cancelRollback",
        "firewall/filter/cancel_rollback",
    ),
    # Firewall rule write operations
    "firewall.add_rule": ("firewall/filter/addRule", "firewall/filter/add_rule"),
    "firewall.set_rule": ("firewall/filter/setRule", "firewall/filter/set_rule"),
    "firewall.del_rule": ("firewall/filter/delRule", "firewall/filter/del_rule"),
    "firewall.toggle_rule": (
        "firewall/filter/toggleRule",
        "firewall/filter/toggle_rule",
    ),
    # Firewall alias write
    "firewall.alias.add": ("firewall/alias/addItem", "firewall/alias/add_item"),
    # Firewall categories
    "firewall.category.search": (
        "firewall/category/searchItem",
        "firewall/category/search_item",
    ),
    "firewall.category.add": (
        "firewall/category/addItem",
        "firewall/category/add_item",
    ),
    "firewall.category.set": (
        "firewall/category/setItem",
        "firewall/category/set_item",
    ),
    "firewall.category.del": (
        "firewall/category/delItem",
        "firewall/category/del_item",
    ),
    # Service reconfigure (single-word actions — same both versions)
    "unbound.service.reconfigure": (
        "unbound/service/reconfigure",
        "unbound/service/reconfigure",
    ),
    "haproxy.service.reconfigure": (
        "haproxy/service/reconfigure",
        "haproxy/service/reconfigure",
    ),
    # Config backup
    "core.backup.download": (
        "core/backup/download/this",
        "core/backup/download/this",
    ),
    # Diagnostics — ping (job-based)
    "diagnostics.ping.set": ("diagnostics/ping/set", "diagnostics/ping/set"),
    "diagnostics.ping.start": ("diagnostics/ping/start", "diagnostics/ping/start"),
    "diagnostics.ping.search_jobs": (
        "diagnostics/ping/searchJobs",
        "diagnostics/ping/search_jobs",
    ),
    "diagnostics.ping.remove": ("diagnostics/ping/remove", "diagnostics/ping/remove"),
    # Diagnostics — traceroute (synchronous)
    "diagnostics.traceroute.set": (
        "diagnostics/traceroute/set",
        "diagnostics/traceroute/set",
    ),
    # Diagnostics — DNS lookup (synchronous)
    "diagnostics.dns_diagnostics.set": (
        "diagnostics/dns_diagnostics/set",
        "diagnostics/dns_diagnostics/set",
    ),
    # Diagnostics — PF state table
    "diagnostics.firewall.query_states": (
        "diagnostics/firewall/queryStates",
        "diagnostics/firewall/query_states",
    ),
    # Firmware info (installed packages/plugins)
    "firmware.info": ("core/firmware/info", "core/firmware/info"),
    # Interface configuration details
    "interface.config": (
        "diagnostics/interface/getInterfaceConfig",
        "diagnostics/interface/get_interface_config",
    ),
    # Kea DHCP
    "kea.leases4.search": ("kea/leases4/search", "kea/leases4/search"),
    "kea.dhcpv4.get": ("kea/dhcpv4/get", "kea/dhcpv4/get"),
    "kea.service.status": ("kea/service/status", "kea/service/status"),
    # dnsmasq DHCP/DNS
    "dnsmasq.leases.search": ("dnsmasq/leases/search", "dnsmasq/leases/search"),
    "dnsmasq.settings.get": ("dnsmasq/settings/get", "dnsmasq/settings/get"),
    "dnsmasq.service.status": ("dnsmasq/service/status", "dnsmasq/service/status"),
    # CrowdSec
    "crowdsec.service.status": ("crowdsec/service/status", "crowdsec/service/status"),
    "crowdsec.alerts.search": ("crowdsec/alerts/search", "crowdsec/alerts/search"),
    "crowdsec.decisions.search": (
        "crowdsec/decisions/search",
        "crowdsec/decisions/search",
    ),
    # Unbound settings (for inventory DNS detection)
    "unbound.settings.get": ("unbound/settings/get", "unbound/settings/get"),
    # NAT / DNAT port forwarding
    "nat.dnat.search_rule": (
        "firewall/d_nat/searchRule",
        "firewall/d_nat/search_rule",
    ),
    "nat.dnat.add_rule": (
        "firewall/d_nat/addRule",
        "firewall/d_nat/add_rule",
    ),
    # IPsec VPN
    "ipsec.sessions.phase1": (
        "ipsec/sessions/searchPhase1",
        "ipsec/sessions/search_phase1",
    ),
    "ipsec.sessions.phase2": (
        "ipsec/sessions/searchPhase2",
        "ipsec/sessions/search_phase2",
    ),
    "ipsec.service.status": ("ipsec/service/status", "ipsec/service/status"),
    # OpenVPN
    "openvpn.sessions": (
        "openvpn/service/searchSessions",
        "openvpn/service/search_sessions",
    ),
    "openvpn.routes": (
        "openvpn/service/searchRoutes",
        "openvpn/service/search_routes",
    ),
    "openvpn.instances": ("openvpn/instances/search", "openvpn/instances/search"),
    # Unbound DNS host override write
    "unbound.add_host_override": (
        "unbound/settings/addHostOverride",
        "unbound/settings/add_host_override",
    ),
    "unbound.del_host_override": (
        "unbound/settings/delHostOverride",
        "unbound/settings/del_host_override",
    ),
    # Static routes
    "routes.search": ("routes/routes/searchroute", "routes/routes/search_route"),
    # WireGuard server/client config (read-only, for security audit)
    "wireguard.server.search_server": (
        "wireguard/server/searchServer",
        "wireguard/server/search_server",
    ),
    "wireguard.client.search_client": (
        "wireguard/client/searchClient",
        "wireguard/client/search_client",
    ),
    # HAProxy config (read-only, for security audit)
    "haproxy.settings.search_frontends": (
        "haproxy/settings/searchFrontends",
        "haproxy/settings/search_frontends",
    ),
    "haproxy.settings.search_backends": (
        "haproxy/settings/searchBackends",
        "haproxy/settings/search_backends",
    ),
    "haproxy.settings.search_servers": (
        "haproxy/settings/searchServers",
        "haproxy/settings/search_servers",
    ),
    "haproxy.settings.search_actions": (
        "haproxy/settings/searchActions",
        "haproxy/settings/search_actions",
    ),
    "haproxy.settings.search_acls": (
        "haproxy/settings/searchAcls",
        "haproxy/settings/search_acls",
    ),
    "haproxy.settings.search_healthchecks": (
        "haproxy/settings/searchHealthchecks",
        "haproxy/settings/search_healthchecks",
    ),
    "haproxy.settings.search_errorfiles": (
        "haproxy/settings/searchErrorfiles",
        "haproxy/settings/search_errorfiles",
    ),
    "haproxy.settings.search_resolvers": (
        "haproxy/settings/searchResolvers",
        "haproxy/settings/search_resolvers",
    ),
    "haproxy.settings.search_mailers": (
        "haproxy/settings/searchMailers",
        "haproxy/settings/search_mailers",
    ),
    "haproxy.service.configtest": (
        "haproxy/service/configtest",
        "haproxy/service/configtest",
    ),
    # Dynamic DNS (os-ddclient plugin)
    "dyndns.accounts.search": (
        "dyndns/accounts/searchItem",
        "dyndns/accounts/search_item",
    ),
    "dyndns.accounts.add": (
        "dyndns/accounts/addItem",
        "dyndns/accounts/add_item",
    ),
    "dyndns.service.reconfigure": (
        "dyndns/service/reconfigure",
        "dyndns/service/reconfigure",
    ),
    # dnsmasq DHCP ranges and service
    "dnsmasq.settings.search_range": (
        "dnsmasq/settings/searchRange",
        "dnsmasq/settings/search_range",
    ),
    "dnsmasq.settings.add_range": (
        "dnsmasq/settings/addRange",
        "dnsmasq/settings/add_range",
    ),
    "dnsmasq.service.reconfigure": (
        "dnsmasq/service/reconfigure",
        "dnsmasq/service/reconfigure",
    ),
    # mDNS Repeater (os-mdns-repeater plugin)
    "mdnsrepeater.settings.get": (
        "mdnsrepeater/settings/get",
        "mdnsrepeater/settings/get",
    ),
    "mdnsrepeater.settings.set": (
        "mdnsrepeater/settings/set",
        "mdnsrepeater/settings/set",
    ),
    "mdnsrepeater.service.status": (
        "mdnsrepeater/service/status",
        "mdnsrepeater/service/status",
    ),
    "mdnsrepeater.service.reconfigure": (
        "mdnsrepeater/service/reconfigure",
        "mdnsrepeater/service/reconfigure",
    ),
    "mdnsrepeater.service.start": (
        "mdnsrepeater/service/start",
        "mdnsrepeater/service/start",
    ),
    "mdnsrepeater.service.stop": (
        "mdnsrepeater/service/stop",
        "mdnsrepeater/service/stop",
    ),
}

_VERSION_THRESHOLD = (25, 7)


class OPNsenseAPIError(Exception):
    """Raised when the OPNsense API returns an error."""

    def __init__(self, message: str, status_code: int = 0) -> None:
        super().__init__(message)
        self.status_code = status_code


class BlockedEndpointError(OPNsenseAPIError):
    """Raised when a blocked/dangerous endpoint is requested."""


class WriteDisabledError(OPNsenseAPIError):
    """Raised when a write operation is attempted with writes disabled."""


class SavepointError(OPNsenseAPIError):
    """Raised when a savepoint operation fails."""


class OPNsenseAPI:
    """Async HTTP client for the OPNsense REST API.

    Provides version-aware endpoint resolution, blocklist enforcement,
    and structured error parsing.
    """

    def __init__(self, config: OPNsenseConfig) -> None:
        self._config = config
        self._client = httpx.AsyncClient(
            base_url=config.url,
            auth=httpx.BasicAuth(config.api_key, config.api_secret),
            verify=config.verify_ssl,
            timeout=httpx.Timeout(30.0),
            follow_redirects=True,
        )
        self._detected_version: tuple[int, int] | None = None
        self._use_snake_case: bool = False

    def require_writes(self) -> None:
        """Raise if write operations are disabled.

        Raises:
            WriteDisabledError: If OPNSENSE_ALLOW_WRITES is not true.
        """
        if not self._config.allow_writes:
            msg = "Write operations disabled. Set OPNSENSE_ALLOW_WRITES=true to enable."
            raise WriteDisabledError(msg)

    async def get(
        self,
        endpoint: str,
        *,
        path_suffix: str = "",
    ) -> dict[str, Any]:
        """Send a GET request to an OPNsense API endpoint.

        Args:
            endpoint: Logical endpoint name (e.g. "firmware.status").
            path_suffix: Optional suffix appended to the resolved path
                (e.g. a UUID for item-level GET requests).

        Returns:
            Parsed JSON response as a dict.

        Raises:
            BlockedEndpointError: If the endpoint is on the blocklist.
            OPNsenseAPIError: If the API returns an error.
        """
        await self._ensure_version_detected()
        path = self._resolve_endpoint(endpoint)
        if path_suffix:
            path = f"{path}/{path_suffix}"
        self._check_blocklist(path)
        return await self._request("GET", path)

    async def post(
        self,
        endpoint: str,
        data: dict[str, Any] | None = None,
        *,
        path_suffix: str = "",
    ) -> dict[str, Any]:
        """Send a POST request to an OPNsense API endpoint.

        Args:
            endpoint: Logical endpoint name (e.g. "firewall.search_rule").
            data: Optional JSON body to send.
            path_suffix: Optional suffix appended to the resolved path
                (e.g. a revision UUID for savepoint apply/cancel).

        Returns:
            Parsed JSON response as a dict.

        Raises:
            BlockedEndpointError: If the endpoint is on the blocklist.
            OPNsenseAPIError: If the API returns an error.
        """
        await self._ensure_version_detected()
        path = self._resolve_endpoint(endpoint)
        if path_suffix:
            path = f"{path}/{path_suffix}"
        self._check_blocklist(path)
        return await self._request("POST", path, data=data)

    async def get_text(self, endpoint: str) -> str:
        """Send a GET request expecting a plain-text response.

        Args:
            endpoint: Logical endpoint name (e.g. "core.backup.download").

        Returns:
            Raw text response body.

        Raises:
            BlockedEndpointError: If the endpoint is on the blocklist.
            OPNsenseAPIError: If the API returns an error.
        """
        await self._ensure_version_detected()
        path = self._resolve_endpoint(endpoint)
        self._check_blocklist(path)
        return await self._request_text("GET", path)

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    # --- Internal methods ---

    async def _request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute an HTTP request and parse the response."""
        try:
            if method == "GET":
                response = await self._client.get(f"/{path}")
            else:
                response = await self._client.post(f"/{path}", json=data)
        except httpx.TimeoutException as exc:
            msg = f"Request timed out: {path}"
            raise OPNsenseAPIError(msg) from exc
        except httpx.ConnectError as exc:
            msg = f"Connection failed: {path}"
            raise OPNsenseAPIError(msg) from exc

        if response.status_code >= 400:
            error_msg = self._parse_error_response(response)
            raise OPNsenseAPIError(error_msg, status_code=response.status_code)

        try:
            result: dict[str, Any] = response.json()
        except (ValueError, TypeError) as exc:
            msg = f"Invalid JSON response from {path}"
            raise OPNsenseAPIError(msg) from exc

        return result

    async def _request_text(
        self,
        method: str,
        path: str,
    ) -> str:
        """Execute an HTTP request and return the raw text response."""
        try:
            if method == "GET":
                response = await self._client.get(f"/{path}")
            else:
                response = await self._client.post(f"/{path}")
        except httpx.TimeoutException as exc:
            msg = f"Request timed out: {path}"
            raise OPNsenseAPIError(msg) from exc
        except httpx.ConnectError as exc:
            msg = f"Connection failed: {path}"
            raise OPNsenseAPIError(msg) from exc

        if response.status_code >= 400:
            error_msg = self._parse_error_response(response)
            raise OPNsenseAPIError(error_msg, status_code=response.status_code)

        result: str = response.text
        return result

    async def _ensure_version_detected(self) -> None:
        """Detect OPNsense version on first call (lazy, cached)."""
        if self._detected_version is not None:
            return

        path = ENDPOINT_REGISTRY["firmware.status"][0]
        self._check_blocklist(path)

        try:
            response = await self._client.get(f"/{path}")
        except (httpx.TimeoutException, httpx.ConnectError) as exc:
            msg = "Failed to connect to OPNsense for version detection"
            raise OPNsenseAPIError(msg) from exc

        if response.status_code >= 400:
            msg = f"Version detection failed: HTTP {response.status_code}"
            raise OPNsenseAPIError(msg, status_code=response.status_code)

        try:
            body: dict[str, Any] = response.json()
            # OPNsense 26.x nests product info under body["product"];
            # earlier versions put product_version at the top level.
            product = body.get("product", body)
            version_str: str = product["product_version"]
            parts = version_str.split(".")[:2]
            self._detected_version = (int(parts[0]), int(parts[1]))
        except (ValueError, TypeError, KeyError, IndexError) as exc:
            msg = "Failed to parse OPNsense version from firmware status"
            raise OPNsenseAPIError(msg) from exc

        self._use_snake_case = self._detected_version >= _VERSION_THRESHOLD

    def _resolve_endpoint(self, logical_name: str) -> str:
        """Resolve a logical endpoint name to an API path.

        Args:
            logical_name: Registry key (e.g. "interface.arp").

        Returns:
            The versioned API path string.

        Raises:
            ValueError: If the logical name is not in the registry.
        """
        entry = ENDPOINT_REGISTRY.get(logical_name)
        if entry is None:
            msg = f"Unknown endpoint: {logical_name}"
            raise ValueError(msg)
        return entry[1] if self._use_snake_case else entry[0]

    @staticmethod
    def _check_blocklist(path: str) -> None:
        """Raise if the resolved path matches a blocked endpoint.

        Checks are normalized (stripped slashes, lowercased) and match
        both exact paths and prefix patterns.
        """
        normalized = path.strip("/").lower()
        for blocked in BLOCKED_ENDPOINTS:
            if normalized == blocked or normalized.startswith(f"{blocked}/"):
                msg = f"Endpoint is blocked for safety: {blocked}"
                raise BlockedEndpointError(msg)

    @staticmethod
    def _parse_error_response(response: httpx.Response) -> str:
        """Extract a human-readable error from an OPNsense error response."""
        try:
            body: dict[str, Any] = response.json()
        except (ValueError, TypeError):
            return f"HTTP {response.status_code}"

        if "message" in body and isinstance(body["message"], str):
            return body["message"]
        if "errorMessage" in body and isinstance(body["errorMessage"], str):
            return body["errorMessage"]
        if "validations" in body and isinstance(body["validations"], dict):
            errors = [f"{field}: {err}" for field, err in body["validations"].items()]
            return f"Validation errors: {', '.join(errors)}"
        if body.get("status") == "failed":
            return "Request failed"

        return f"HTTP {response.status_code}"


class SavepointManager:
    """Manages OPNsense firewall savepoint lifecycle.

    Provides atomic firewall changes with automatic 60-second rollback.
    Flow: create() → [make changes] → apply() → confirm() or auto-revert.
    """

    def __init__(self, api: OPNsenseAPI) -> None:
        self._api = api
        self._active_revision: str | None = None

    async def create(self) -> str:
        """Create a firewall savepoint.

        Returns:
            The revision UUID for this savepoint.

        Raises:
            WriteDisabledError: If writes are disabled.
            SavepointError: If the API returns no revision.
        """
        self._api.require_writes()
        result = await self._api.post("firewall.savepoint")
        revision = result.get("revision", "")
        if not isinstance(revision, str) or not revision:
            msg = "Savepoint creation returned no revision"
            raise SavepointError(msg)
        self._active_revision = revision
        return revision

    async def apply(self, revision: str) -> dict[str, Any]:
        """Apply firewall changes with 60-second auto-revert timer.

        Args:
            revision: The savepoint revision UUID.

        Returns:
            API response dict.

        Raises:
            WriteDisabledError: If writes are disabled.
        """
        self._api.require_writes()
        return await self._api.post("firewall.apply", path_suffix=revision)

    async def confirm(self, revision: str) -> dict[str, Any]:
        """Cancel auto-rollback, making changes permanent.

        Args:
            revision: The savepoint revision UUID.

        Returns:
            API response dict.

        Raises:
            WriteDisabledError: If writes are disabled.
        """
        self._api.require_writes()
        result = await self._api.post("firewall.cancel_rollback", path_suffix=revision)
        if self._active_revision == revision:
            self._active_revision = None
        return result

    @property
    def active_revision(self) -> str | None:
        """The currently active savepoint revision, or None."""
        return self._active_revision
