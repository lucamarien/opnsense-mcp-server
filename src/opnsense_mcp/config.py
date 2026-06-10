"""Configuration management via environment variables.

Environment variables:
    OPNSENSE_URL: API base URL (required, https:// unless explicitly overridden)
    OPNSENSE_API_KEY: API key (required)
    OPNSENSE_API_SECRET: API secret (required)
    OPNSENSE_VERIFY_SSL: Verify SSL certificate (default: true)
    OPNSENSE_ALLOW_WRITES: Enable write operations (default: false)
    OPNSENSE_ALLOW_INSECURE_HTTP: Permit http:// URLs (default: false).
        API credentials are sent as Basic Auth on every request — over
        plain http they cross the network in cleartext.
    OPNSENSE_ALLOW_SENSITIVE: Permit include_sensitive=true on config
        tools (default: false). Without this, passwords/keys are always
        redacted regardless of tool parameters.
    OPNSENSE_API_STYLE: 'auto' (default), 'camel', or 'snake'. Forces the
        API endpoint naming style and skips version detection — useful for
        API users whose key lacks the firmware/status privilege.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

_TRUTHY = frozenset({"true", "1", "yes"})
_FALSY = frozenset({"false", "0", "no"})


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True, repr=False)
class OPNsenseConfig:
    """Immutable configuration loaded from environment variables."""

    url: str
    api_key: str
    api_secret: str
    verify_ssl: bool
    allow_writes: bool
    allow_sensitive: bool = False
    api_style: str = "auto"

    def __repr__(self) -> str:
        return f"OPNsenseConfig(url={self.url!r}, verify_ssl={self.verify_ssl}, allow_writes={self.allow_writes})"


def _parse_bool(value: str, var_name: str) -> bool:
    """Parse a boolean environment variable value.

    Accepts: true/false, 1/0, yes/no (case-insensitive).

    Raises:
        ConfigError: If the value is not a recognized boolean string.
    """
    lower = value.lower()
    if lower in _TRUTHY:
        return True
    if lower in _FALSY:
        return False
    msg = f"{var_name} must be true/false, 1/0, or yes/no (got {value!r})"
    raise ConfigError(msg)


def load_config() -> OPNsenseConfig:
    """Load and validate configuration from environment variables.

    Returns:
        Frozen dataclass with validated configuration.

    Raises:
        ConfigError: If required variables are missing or values are invalid.
    """
    missing: list[str] = []
    for var in ("OPNSENSE_URL", "OPNSENSE_API_KEY", "OPNSENSE_API_SECRET"):
        if not os.environ.get(var, "").strip():
            missing.append(var)

    if missing:
        msg = f"Required environment variable(s) not set: {', '.join(missing)}"
        raise ConfigError(msg)

    url = os.environ["OPNSENSE_URL"].strip().rstrip("/")
    api_key = os.environ["OPNSENSE_API_KEY"].strip()
    api_secret = os.environ["OPNSENSE_API_SECRET"].strip()

    verify_ssl_raw = os.environ.get("OPNSENSE_VERIFY_SSL", "true").strip()
    verify_ssl = _parse_bool(verify_ssl_raw, "OPNSENSE_VERIFY_SSL")

    allow_writes_raw = os.environ.get("OPNSENSE_ALLOW_WRITES", "false").strip()
    allow_writes = _parse_bool(allow_writes_raw, "OPNSENSE_ALLOW_WRITES")

    allow_http_raw = os.environ.get("OPNSENSE_ALLOW_INSECURE_HTTP", "false").strip()
    allow_http = _parse_bool(allow_http_raw, "OPNSENSE_ALLOW_INSECURE_HTTP")

    allow_sensitive_raw = os.environ.get("OPNSENSE_ALLOW_SENSITIVE", "false").strip()
    allow_sensitive = _parse_bool(allow_sensitive_raw, "OPNSENSE_ALLOW_SENSITIVE")

    api_style = os.environ.get("OPNSENSE_API_STYLE", "auto").strip().lower()
    if api_style not in ("auto", "camel", "snake"):
        msg = f"OPNSENSE_API_STYLE must be 'auto', 'camel', or 'snake' (got {api_style!r})"
        raise ConfigError(msg)

    if url.startswith("http://") and not allow_http:
        msg = (
            "OPNSENSE_URL uses http:// — API credentials would be sent in cleartext. "
            "Use https://, or set OPNSENSE_ALLOW_INSECURE_HTTP=true to override."
        )
        raise ConfigError(msg)
    if not url.startswith(("http://", "https://")):
        msg = f"OPNSENSE_URL must start with https:// (got {url!r})"
        raise ConfigError(msg)

    return OPNsenseConfig(
        url=url,
        api_key=api_key,
        api_secret=api_secret,
        verify_ssl=verify_ssl,
        allow_writes=allow_writes,
        allow_sensitive=allow_sensitive,
        api_style=api_style,
    )
