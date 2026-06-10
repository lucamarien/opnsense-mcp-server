"""Tests for shared tool utilities (_util.py)."""

from __future__ import annotations

from opnsense_mcp.api_client import (
    BlockedEndpointError,
    OPNsenseAPIError,
    SavepointError,
    WriteDisabledError,
)
from opnsense_mcp.tools._util import (
    DESTRUCTIVE,
    READ_ONLY,
    READ_PROBE,
    WRITE,
    catch_api_errors,
    clamp_limit,
)


class TestClampLimit:
    def test_within_range_unchanged(self):
        assert clamp_limit(50) == 50

    def test_capped_above(self):
        assert clamp_limit(9999) == 500

    def test_clamped_below(self):
        assert clamp_limit(0) == 1
        assert clamp_limit(-5) == 1

    def test_custom_cap(self):
        assert clamp_limit(2000, cap=1000) == 1000


class TestAnnotationPresets:
    def test_read_only_is_read_only(self):
        assert READ_ONLY.readOnlyHint is True
        assert READ_ONLY.openWorldHint is False

    def test_probe_is_open_world(self):
        assert READ_PROBE.readOnlyHint is True
        assert READ_PROBE.openWorldHint is True

    def test_write_not_destructive(self):
        assert WRITE.readOnlyHint is False
        assert WRITE.destructiveHint is False

    def test_destructive(self):
        assert DESTRUCTIVE.destructiveHint is True


class TestCatchApiErrors:
    async def _run(self, exc: Exception):
        @catch_api_errors
        async def failing() -> dict:
            raise exc

        return await failing()

    async def test_passes_through_success(self):
        @catch_api_errors
        async def ok() -> dict:
            return {"rows": []}

        assert await ok() == {"rows": []}

    async def test_write_disabled(self):
        result = await self._run(WriteDisabledError("writes off"))
        assert result["error_type"] == "writes_disabled"

    async def test_blocked_endpoint(self):
        result = await self._run(BlockedEndpointError("blocked"))
        assert result["error_type"] == "blocked_endpoint"

    async def test_savepoint(self):
        result = await self._run(SavepointError("pending"))
        assert result["error_type"] == "savepoint"

    async def test_api_error_with_plugin_hint(self):
        result = await self._run(OPNsenseAPIError("nope", status_code=400))
        assert result["error_type"] == "api"
        assert result["status_code"] == 400
        assert "plugin" in result["hint"]

    async def test_api_error_no_status(self):
        result = await self._run(OPNsenseAPIError("timeout"))
        assert result["error_type"] == "api"
        assert "status_code" not in result

    async def test_preserves_docstring(self):
        @catch_api_errors
        async def documented() -> dict:
            """My docstring."""
            return {}

        assert documented.__doc__ == "My docstring."


class TestSensitiveTagPatterns:
    def test_exact_tags_still_match(self):
        from opnsense_mcp.config_cache import is_sensitive_tag

        for tag in ("password", "key", "secret", "pre-shared-key"):
            assert is_sensitive_tag(tag)

    def test_substring_patterns(self):
        from opnsense_mcp.config_cache import is_sensitive_tag

        assert is_sensitive_tag("radius_secret2")
        assert is_sensitive_tag("proxy_passwd")
        assert is_sensitive_tag("api_token")
        assert is_sensitive_tag("apikey")
        assert is_sensitive_tag("cf_credentials")

    def test_key_suffix_redacted_unless_public(self):
        from opnsense_mcp.config_cache import is_sensitive_tag

        assert is_sensitive_tag("authkey")
        assert is_sensitive_tag("sharedkey")
        assert is_sensitive_tag("hostkey")
        assert not is_sensitive_tag("pubkey")
        assert not is_sensitive_tag("publickey")

    def test_benign_tags_untouched(self):
        from opnsense_mcp.config_cache import is_sensitive_tag

        for tag in ("hostname", "descr", "interfaces", "enabled", "keyboard"):
            assert not is_sensitive_tag(tag)

    def test_allowlisted_flags_not_redacted(self):
        from opnsense_mcp.config_cache import is_sensitive_tag

        assert not is_sensitive_tag("passwordauth")
        assert not is_sensitive_tag("nopasswd")
