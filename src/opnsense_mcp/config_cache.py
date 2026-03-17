"""Session-scoped config cache with XML→dict parsing and runtime inventory."""

from __future__ import annotations

import json
import time
import xml.etree.ElementTree as ET
from typing import Any

from opnsense_mcp.api_client import OPNsenseAPI, OPNsenseAPIError

# Sensitive XML elements redacted by default
SENSITIVE_TAGS: frozenset[str] = frozenset(
    {
        "password",
        "bcrypt-hash",
        "key",
        "secret",
        "pre-shared-key",
        "crypto_password",
        "privatekey",
        "certdata",
        "shared_secret",
    }
)

_ZENARMOR_PREFIXES = ("os-sensei", "os-sunnyvalley")


def _xml_to_dict(elem: ET.Element) -> dict[str, Any] | str:
    """Convert an XML element tree to a Python dict recursively.

    - Leaf nodes (text only) → string value
    - Parent nodes → nested dict
    - Repeated sibling tags → list
    - Self-closing tags (<any/>) → empty string
    """
    children = list(elem)
    if not children:
        return elem.text or ""

    result: dict[str, Any] = {}
    for child in children:
        key = child.tag
        value = _xml_to_dict(child)

        if key in result:
            existing = result[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                result[key] = [existing, value]
        else:
            result[key] = value

    if elem.text and elem.text.strip():
        result["_text"] = elem.text.strip()

    return result


def _strip_sensitive(data: dict[str, Any] | list[Any] | str) -> dict[str, Any] | list[Any] | str:
    """Recursively redact sensitive values in a parsed config dict."""
    if isinstance(data, dict):
        return {k: "[REDACTED]" if k.lower() in SENSITIVE_TAGS else _strip_sensitive(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_strip_sensitive(item) for item in data]
    return data


async def _get_installed_plugins(api: OPNsenseAPI) -> list[dict[str, str]]:
    """Return installed os-* plugins (excluding -devel and Zenarmor)."""
    try:
        info = await api.get("firmware.info")
    except OPNsenseAPIError:
        return []
    plugins: list[dict[str, str]] = []
    for pkg in info.get("package", []):
        name = pkg.get("name", "")
        if (
            name.startswith("os-")
            and not name.endswith("-devel")
            and pkg.get("installed") == "1"
            and not any(name.startswith(p) for p in _ZENARMOR_PREFIXES)
        ):
            plugins.append(
                {
                    "name": name,
                    "version": pkg.get("version", "unknown"),
                    "comment": pkg.get("comment", ""),
                }
            )
    return plugins


async def _detect_dhcp_backend(api: OPNsenseAPI) -> dict[str, Any]:
    """Detect which DHCP backend is active."""
    backends: list[dict[str, Any]] = []

    # Check dnsmasq (default in 26.x)
    try:
        status = await api.get("dnsmasq.service.status")
        if status.get("status") == "running":
            leases = await api.get("dnsmasq.leases.search")
            backends.append(
                {
                    "backend": "dnsmasq",
                    "status": "running",
                    "lease_count": len(leases.get("rows", [])),
                }
            )
    except OPNsenseAPIError:
        pass

    # Check Kea
    try:
        status = await api.get("kea.service.status")
        svc_status = status.get("status", "unknown")
        if svc_status != "disabled":
            leases = await api.get("kea.leases4.search")
            backends.append(
                {
                    "backend": "kea",
                    "status": svc_status,
                    "lease_count": len(leases.get("rows", [])),
                }
            )
        else:
            backends.append({"backend": "kea", "status": "disabled"})
    except OPNsenseAPIError:
        pass

    # Check ISC DHCP
    try:
        leases = await api.get("dhcpv4.leases.search")
        if isinstance(leases, dict):
            backends.append(
                {
                    "backend": "isc",
                    "status": "available",
                    "lease_count": len(leases.get("rows", [])),
                }
            )
    except OPNsenseAPIError:
        pass

    active = [b for b in backends if b.get("status") == "running"]
    return {
        "active": active[0]["backend"] if active else "none",
        "backends": backends,
    }


async def _detect_dns_servers(api: OPNsenseAPI) -> dict[str, Any]:
    """Detect which DNS servers are configured."""
    servers: list[dict[str, str]] = []

    try:
        settings = await api.get("unbound.settings.get")
        unbound = settings.get("unbound", {})
        general = unbound.get("general", {}) if isinstance(unbound, dict) else {}
        enabled = general.get("enabled", "0") if isinstance(general, dict) else "0"
        servers.append({"server": "unbound", "enabled": str(enabled), "role": "resolver"})
    except OPNsenseAPIError:
        pass

    try:
        settings = await api.get("dnsmasq.settings.get")
        dm = settings.get("dnsmasq", {})
        general = dm.get("general", {}) if isinstance(dm, dict) else {}
        enabled = general.get("enabled", "0") if isinstance(general, dict) else "0"
        servers.append({"server": "dnsmasq", "enabled": str(enabled), "role": "forwarder/dhcp"})
    except OPNsenseAPIError:
        pass

    return {"servers": servers}


async def _get_interfaces(api: OPNsenseAPI) -> list[dict[str, Any]]:
    """Get network interface details from runtime API."""
    try:
        config = await api.get("interface.config")
    except OPNsenseAPIError:
        return []

    names: dict[str, str] = {}
    try:
        names = await api.get("interface.names")
    except OPNsenseAPIError:
        pass

    interfaces: list[dict[str, Any]] = []
    for iface_id, data in sorted(config.items()):
        if not isinstance(data, dict):
            continue
        ipv4 = [a.get("ipaddr", "") for a in data.get("ipv4", []) if isinstance(a, dict)]
        ipv6 = [a.get("ipaddr", "") for a in data.get("ipv6", []) if isinstance(a, dict)]
        interfaces.append(
            {
                "device": iface_id,
                "name": names.get(iface_id, iface_id),
                "status": data.get("status", "unknown"),
                "ipv4": [ip for ip in ipv4 if ip],
                "ipv6": [ip for ip in ipv6 if ip],
                "macaddr": data.get("macaddr", ""),
                "mtu": data.get("mtu", ""),
            }
        )
    return interfaces


class ConfigCache:
    """Session-scoped cache for parsed OPNsense config.xml and runtime inventory."""

    def __init__(self) -> None:
        self._sections: dict[str, dict[str, Any] | list[Any] | str] = {}
        self._section_sizes: dict[str, int] = {}
        self._inventory: dict[str, Any] = {}
        self._loaded_at: float = 0.0
        self._stale: bool = False

    @property
    def is_loaded(self) -> bool:
        """True if config has been downloaded and parsed at least once."""
        return self._loaded_at > 0

    @property
    def is_stale(self) -> bool:
        """True if a write operation invalidated the cache."""
        return self._stale

    def invalidate(self) -> None:
        """Mark cache as stale. Next load() will re-download."""
        self._stale = True

    def available_sections(self) -> list[str]:
        """Return sorted list of section names found in config."""
        return sorted(self._sections.keys())

    def get_section(self, name: str, *, include_sensitive: bool = False) -> dict[str, Any] | None:
        """Return a parsed config section by name, or None if not found."""
        section = self._sections.get(name)
        if section is None:
            return None
        if include_sensitive:
            return {"section": name, "data": section}
        return {"section": name, "data": _strip_sensitive(section)}

    async def load(self, api: OPNsenseAPI, *, force: bool = False) -> dict[str, Any]:
        """Download config.xml, parse sections, collect runtime inventory.

        Returns a summary dict suitable for tool output.
        Skips re-download if already loaded and not stale/forced.
        """
        if self.is_loaded and not self._stale and not force:
            return self.summary()

        # --- Parse config.xml into sections ---
        xml_text = await api.get_text("core.backup.download")
        self._parse_xml(xml_text)

        # --- Collect runtime inventory via API ---
        firmware = await api.get("firmware.status")
        plugins = await _get_installed_plugins(api)
        dhcp = await _detect_dhcp_backend(api)
        dns = await _detect_dns_servers(api)
        interfaces = await _get_interfaces(api)

        services = await api.post(
            "core.service.search",
            {"current": 1, "rowCount": 500, "searchPhrase": ""},
        )
        svc_rows: list[dict[str, Any]] = services.get("rows", [])
        running = sum(1 for s in svc_rows if s.get("running") in (1, "1", True))

        # OPNsense 26.x nests product info under "product"; earlier versions
        # have product_version at the top level.
        fw_product = firmware.get("product", firmware)
        self._inventory = {
            "firmware": {
                "version": fw_product.get("product_version", "unknown"),
                "product": fw_product.get("product_name", "OPNsense"),
            },
            "plugins": plugins,
            "dhcp": dhcp,
            "dns": dns,
            "interfaces": interfaces,
            "services": {
                "total": len(svc_rows),
                "running": running,
                "stopped": len(svc_rows) - running,
            },
        }

        self._loaded_at = time.time()
        self._stale = False

        return self.summary()

    def summary(self) -> dict[str, Any]:
        """Return inventory overview + list of available config sections."""
        section_info: list[dict[str, Any]] = []
        for name in sorted(self._sections.keys()):
            info: dict[str, Any] = {
                "name": name,
                "size_bytes": self._section_sizes.get(name, 0),
            }
            section = self._sections[name]
            if isinstance(section, dict):
                info["keys"] = sorted(section.keys())[:20]
            elif isinstance(section, list):
                info["count"] = len(section)
            section_info.append(info)

        result = dict(self._inventory)
        result["config_sections"] = section_info
        result["cache_status"] = "stale" if self._stale else "fresh"
        return result

    def _parse_xml(self, xml_text: str) -> None:
        """Parse config.xml into top-level sections."""
        self._sections.clear()
        self._section_sizes.clear()

        try:
            # Source is trusted (OPNsense API response)
            root = ET.fromstring(xml_text)  # noqa: S314
        except ET.ParseError:
            return

        for child in root:
            tag = child.tag
            parsed = _xml_to_dict(child)
            self._sections[tag] = parsed
            self._section_sizes[tag] = len(json.dumps(parsed, default=str).encode())
