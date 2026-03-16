"""Tests for OPNsense API client."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from opnsense_mcp.api_client import (
    BLOCKED_ENDPOINTS,
    ENDPOINT_REGISTRY,
    BlockedEndpointError,
    OPNsenseAPI,
    OPNsenseAPIError,
    SavepointError,
    SavepointManager,
    WriteDisabledError,
)


def _make_response(status_code=200, json_data=None):
    """Create a mock httpx.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else {}
    return resp


def _make_api(mock_config, mock_httpx_client, firmware_response=None):
    """Create an OPNsenseAPI with a mocked httpx client and pre-detected version."""
    api = OPNsenseAPI(mock_config)
    api._client = mock_httpx_client

    if firmware_response is not None:
        # Pre-inject version detection
        mock_httpx_client.get.return_value = _make_response(
            json_data=firmware_response,
        )
    return api


def _make_api_with_version(mock_config, mock_httpx_client, version_tuple):
    """Create an OPNsenseAPI with version already detected (skip detection call)."""
    api = OPNsenseAPI(mock_config)
    api._client = mock_httpx_client
    api._detected_version = version_tuple
    api._use_snake_case = version_tuple >= (25, 7)
    return api


# --- Blocklist Tests ---


class TestBlocklist:
    """Tests for endpoint blocklist enforcement."""

    @pytest.mark.parametrize("endpoint", sorted(BLOCKED_ENDPOINTS))
    def test_blocked_endpoint_raises_error(self, endpoint):
        with pytest.raises(BlockedEndpointError, match="blocked for safety"):
            OPNsenseAPI._check_blocklist(endpoint)

    def test_blocked_with_subpath(self):
        with pytest.raises(BlockedEndpointError):
            OPNsenseAPI._check_blocklist("core/system/halt/extra")

    def test_allowed_endpoint_passes(self):
        OPNsenseAPI._check_blocklist("core/firmware/status")

    def test_blocklist_is_frozenset(self):
        assert isinstance(BLOCKED_ENDPOINTS, frozenset)

    def test_blocklist_contains_all_dangerous(self):
        expected = {
            "core/system/halt",
            "core/system/reboot",
            "core/firmware/poweroff",
            "core/firmware/update",
            "core/firmware/upgrade",
        }
        assert BLOCKED_ENDPOINTS == expected


# --- Endpoint Resolution Tests ---


class TestEndpointResolution:
    """Tests for version-aware endpoint resolution."""

    def test_resolve_camel_case_pre_25_7(self, mock_config):
        api = OPNsenseAPI(mock_config)
        api._use_snake_case = False
        path = api._resolve_endpoint("interface.arp")
        assert path == "diagnostics/interface/getArp"

    def test_resolve_snake_case_25_7(self, mock_config):
        api = OPNsenseAPI(mock_config)
        api._use_snake_case = True
        path = api._resolve_endpoint("interface.arp")
        assert path == "diagnostics/interface/get_arp"

    def test_unknown_endpoint_raises_error(self, mock_config):
        api = OPNsenseAPI(mock_config)
        with pytest.raises(ValueError, match="Unknown endpoint"):
            api._resolve_endpoint("nonexistent.endpoint")

    def test_firmware_status_same_both_versions(self, mock_config):
        api = OPNsenseAPI(mock_config)
        api._use_snake_case = False
        camel = api._resolve_endpoint("firmware.status")
        api._use_snake_case = True
        snake = api._resolve_endpoint("firmware.status")
        assert camel == snake == "core/firmware/status"

    def test_all_registry_entries_have_two_paths(self):
        for name, entry in ENDPOINT_REGISTRY.items():
            assert len(entry) == 2, f"Registry entry {name} should have 2 paths"
            assert isinstance(entry[0], str)
            assert isinstance(entry[1], str)


# --- Version Detection Tests ---


class TestVersionDetection:
    """Tests for automatic OPNsense version detection."""

    async def test_detects_pre_25_7(self, mock_config, mock_httpx_client, firmware_status_pre25_7):
        api = _make_api(mock_config, mock_httpx_client, firmware_status_pre25_7)
        await api._ensure_version_detected()
        assert api._detected_version == (25, 1)
        assert api._use_snake_case is False

    async def test_detects_25_7(self, mock_config, mock_httpx_client, firmware_status_25_7):
        api = _make_api(mock_config, mock_httpx_client, firmware_status_25_7)
        await api._ensure_version_detected()
        assert api._detected_version == (25, 7)
        assert api._use_snake_case is True

    async def test_detection_cached(self, mock_config, mock_httpx_client, firmware_status_pre25_7):
        api = _make_api(mock_config, mock_httpx_client, firmware_status_pre25_7)
        await api._ensure_version_detected()
        await api._ensure_version_detected()
        # Only one HTTP call for version detection
        assert mock_httpx_client.get.call_count == 1

    async def test_detection_failure_raises_error(self, mock_config, mock_httpx_client):
        mock_httpx_client.get.side_effect = httpx.ConnectError("refused")
        api = _make_api(mock_config, mock_httpx_client)
        with pytest.raises(OPNsenseAPIError, match="Failed to connect"):
            await api._ensure_version_detected()

    async def test_detection_http_error(self, mock_config, mock_httpx_client):
        mock_httpx_client.get.return_value = _make_response(status_code=401)
        api = _make_api(mock_config, mock_httpx_client)
        with pytest.raises(OPNsenseAPIError, match="Version detection failed"):
            await api._ensure_version_detected()

    async def test_version_25_6_99_is_pre_25_7(self, mock_config, mock_httpx_client):
        firmware = {"product_version": "25.6.99", "product_name": "OPNsense"}
        api = _make_api(mock_config, mock_httpx_client, firmware)
        await api._ensure_version_detected()
        assert api._detected_version == (25, 6)
        assert api._use_snake_case is False

    async def test_version_26_1_is_snake_case(self, mock_config, mock_httpx_client):
        firmware = {"product_version": "26.1.0", "product_name": "OPNsense"}
        api = _make_api(mock_config, mock_httpx_client, firmware)
        await api._ensure_version_detected()
        assert api._detected_version == (26, 1)
        assert api._use_snake_case is True

    async def test_invalid_version_string(self, mock_config, mock_httpx_client):
        firmware = {"product_version": "invalid", "product_name": "OPNsense"}
        api = _make_api(mock_config, mock_httpx_client, firmware)
        with pytest.raises(OPNsenseAPIError, match="Failed to parse"):
            await api._ensure_version_detected()


# --- HTTP Method Tests ---


class TestHTTPMethods:
    """Tests for get() and post() methods."""

    async def test_get_sends_get_request(self, mock_config, mock_httpx_client):
        # Set up: first call is version detection, second is the actual GET
        version_resp = _make_response(
            json_data={"product_version": "25.1.2", "product_name": "OPNsense"},
        )
        data_resp = _make_response(json_data={"status": "running"})
        mock_httpx_client.get.side_effect = [version_resp, data_resp]

        api = _make_api(mock_config, mock_httpx_client)
        result = await api.get("firmware.status")
        assert result == {"status": "running"}
        assert mock_httpx_client.get.call_count == 2

    async def test_get_with_pre_detected_version(self, mock_config, mock_httpx_client):
        data_resp = _make_response(json_data={"arp": []})
        mock_httpx_client.get.return_value = data_resp

        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        result = await api.get("interface.arp")
        mock_httpx_client.get.assert_called_once_with("/diagnostics/interface/getArp")
        assert result == {"arp": []}

    async def test_get_snake_case_version(self, mock_config, mock_httpx_client):
        data_resp = _make_response(json_data={"arp": []})
        mock_httpx_client.get.return_value = data_resp

        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 7))
        await api.get("interface.arp")
        mock_httpx_client.get.assert_called_once_with("/diagnostics/interface/get_arp")

    async def test_post_sends_post_request(self, mock_config, mock_httpx_client):
        post_resp = _make_response(json_data={"rows": [], "total": 0})
        mock_httpx_client.post.return_value = post_resp

        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        result = await api.post("firewall.search_rule", {"searchPhrase": "test"})
        mock_httpx_client.post.assert_called_once_with("/firewall/filter/searchRule", json={"searchPhrase": "test"})
        assert result == {"rows": [], "total": 0}

    async def test_post_without_data(self, mock_config, mock_httpx_client):
        post_resp = _make_response(json_data={"status": "ok"})
        mock_httpx_client.post.return_value = post_resp

        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        await api.post("core.service.search")
        mock_httpx_client.post.assert_called_once_with("/core/service/search", json=None)

    async def test_get_blocked_endpoint_raises(self, mock_config, mock_httpx_client):
        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        with pytest.raises(BlockedEndpointError):
            # Manually put a blocked path in the registry for testing
            ENDPOINT_REGISTRY["_test_blocked"] = (
                "core/system/halt",
                "core/system/halt",
            )
            try:
                await api.get("_test_blocked")
            finally:
                del ENDPOINT_REGISTRY["_test_blocked"]

    async def test_timeout_raises_api_error(self, mock_config, mock_httpx_client):
        mock_httpx_client.get.side_effect = httpx.TimeoutException("timed out")
        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        with pytest.raises(OPNsenseAPIError, match="timed out"):
            await api.get("firmware.status")

    async def test_connect_error_raises_api_error(self, mock_config, mock_httpx_client):
        mock_httpx_client.get.side_effect = httpx.ConnectError("refused")
        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        with pytest.raises(OPNsenseAPIError, match="Connection failed"):
            await api.get("firmware.status")


# --- Error Parsing Tests ---


class TestErrorParsing:
    """Tests for OPNsense error response parsing."""

    def test_message_format(self, mock_config):
        api = OPNsenseAPI(mock_config)
        resp = _make_response(400, {"message": "Not found"})
        assert api._parse_error_response(resp) == "Not found"

    def test_error_message_format(self, mock_config):
        api = OPNsenseAPI(mock_config)
        resp = _make_response(400, {"errorMessage": "Auth failed"})
        assert api._parse_error_response(resp) == "Auth failed"

    def test_validations_format(self, mock_config):
        api = OPNsenseAPI(mock_config)
        resp = _make_response(400, {"validations": {"name": "required", "port": "invalid"}})
        result = api._parse_error_response(resp)
        assert "Validation errors:" in result
        assert "name: required" in result
        assert "port: invalid" in result

    def test_status_failed_format(self, mock_config):
        api = OPNsenseAPI(mock_config)
        resp = _make_response(400, {"status": "failed"})
        assert api._parse_error_response(resp) == "Request failed"

    def test_unparseable_json(self, mock_config):
        api = OPNsenseAPI(mock_config)
        resp = MagicMock()
        resp.status_code = 500
        resp.json.side_effect = ValueError("invalid json")
        assert api._parse_error_response(resp) == "HTTP 500"

    def test_unknown_json_format(self, mock_config):
        api = OPNsenseAPI(mock_config)
        resp = _make_response(400, {"some_other_key": "data"})
        assert api._parse_error_response(resp) == "HTTP 400"

    async def test_4xx_raises_api_error(self, mock_config, mock_httpx_client):
        mock_httpx_client.get.return_value = _make_response(404, {"message": "Not found"})
        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        with pytest.raises(OPNsenseAPIError, match="Not found") as exc_info:
            await api.get("firmware.status")
        assert exc_info.value.status_code == 404

    async def test_5xx_raises_api_error(self, mock_config, mock_httpx_client):
        mock_httpx_client.get.return_value = _make_response(500, {"status": "failed"})
        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        with pytest.raises(OPNsenseAPIError) as exc_info:
            await api.get("firmware.status")
        assert exc_info.value.status_code == 500


# --- Client Lifecycle Tests ---


class TestClientLifecycle:
    """Tests for client initialization and cleanup."""

    async def test_close_closes_httpx_client(self, mock_config, mock_httpx_client):
        api = OPNsenseAPI(mock_config)
        api._client = mock_httpx_client
        await api.close()
        mock_httpx_client.aclose.assert_called_once()

    def test_client_uses_basic_auth(self, mock_config):
        api = OPNsenseAPI(mock_config)
        auth = api._client.auth
        assert isinstance(auth, httpx.BasicAuth)

    def test_client_timeout_is_30s(self, mock_config):
        api = OPNsenseAPI(mock_config)
        assert api._client.timeout.connect == 30.0
        assert api._client.timeout.read == 30.0

    def test_client_ssl_follows_config(self, mock_config):
        api = OPNsenseAPI(mock_config)
        assert api._client._transport._pool._ssl_context.verify_mode.name == "CERT_NONE"

    def test_initial_version_is_none(self, mock_config):
        api = OPNsenseAPI(mock_config)
        assert api._detected_version is None
        assert api._use_snake_case is False


# --- Write Guard Tests ---


class TestWriteGuard:
    """Tests for the require_writes() write guard."""

    def test_raises_when_writes_disabled(self, mock_config):
        api = OPNsenseAPI(mock_config)
        with pytest.raises(WriteDisabledError, match="Write operations disabled"):
            api.require_writes()

    def test_passes_when_writes_enabled(self, mock_config_writes):
        api = OPNsenseAPI(mock_config_writes)
        api.require_writes()  # Should not raise

    def test_error_message_includes_env_var(self, mock_config):
        api = OPNsenseAPI(mock_config)
        with pytest.raises(WriteDisabledError, match="OPNSENSE_ALLOW_WRITES"):
            api.require_writes()

    def test_write_disabled_error_is_api_error(self):
        assert issubclass(WriteDisabledError, OPNsenseAPIError)


# --- Path Suffix Tests ---


class TestPathSuffix:
    """Tests for post() path_suffix parameter."""

    async def test_post_without_suffix_unchanged(self, mock_config, mock_httpx_client):
        post_resp = _make_response(json_data={"rows": []})
        mock_httpx_client.post.return_value = post_resp
        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        await api.post("firewall.search_rule")
        mock_httpx_client.post.assert_called_once_with("/firewall/filter/searchRule", json=None)

    async def test_get_text_returns_raw_text(self, mock_config, mock_httpx_client):
        text_resp = MagicMock()
        text_resp.status_code = 200
        text_resp.text = "<?xml version='1.0'?><opnsense></opnsense>"
        mock_httpx_client.get.return_value = text_resp

        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        result = await api.get_text("core.backup.download")
        assert result == "<?xml version='1.0'?><opnsense></opnsense>"
        mock_httpx_client.get.assert_called_once_with("/core/backup/download/this")

    async def test_get_text_raises_on_http_error(self, mock_config, mock_httpx_client):
        error_resp = _make_response(status_code=403, json_data={"message": "Access denied"})
        error_resp.text = "Forbidden"
        mock_httpx_client.get.return_value = error_resp

        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        with pytest.raises(OPNsenseAPIError, match="Access denied"):
            await api.get_text("core.backup.download")

    async def test_get_text_raises_on_timeout(self, mock_config, mock_httpx_client):
        mock_httpx_client.get.side_effect = httpx.TimeoutException("timed out")
        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        with pytest.raises(OPNsenseAPIError, match="timed out"):
            await api.get_text("core.backup.download")

    async def test_get_text_blocked_endpoint_raises(self, mock_config, mock_httpx_client):
        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        ENDPOINT_REGISTRY["_test_blocked_text"] = ("core/system/halt", "core/system/halt")
        try:
            with pytest.raises(BlockedEndpointError):
                await api.get_text("_test_blocked_text")
        finally:
            del ENDPOINT_REGISTRY["_test_blocked_text"]

    async def test_post_with_suffix_appends(self, mock_config_writes, mock_httpx_client):
        post_resp = _make_response(json_data={"status": "ok"})
        mock_httpx_client.post.return_value = post_resp
        api = _make_api_with_version(mock_config_writes, mock_httpx_client, (25, 1))
        await api.post("firewall.apply", path_suffix="abc123")
        mock_httpx_client.post.assert_called_once_with("/firewall/filter/apply/abc123", json=None)

    async def test_suffix_checked_against_blocklist(self, mock_config_writes, mock_httpx_client):
        api = _make_api_with_version(mock_config_writes, mock_httpx_client, (25, 1))
        ENDPOINT_REGISTRY["_test_suffix"] = ("core/system/halt", "core/system/halt")
        try:
            with pytest.raises(BlockedEndpointError):
                await api.post("_test_suffix", path_suffix="extra")
        finally:
            del ENDPOINT_REGISTRY["_test_suffix"]


# --- Savepoint Manager Tests ---


class TestSavepointManager:
    """Tests for SavepointManager lifecycle."""

    async def test_create_returns_revision(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(return_value={"revision": "rev-abc-123"})
        mgr = SavepointManager(mock_api_writes)
        revision = await mgr.create()
        assert revision == "rev-abc-123"
        mock_api_writes.post.assert_called_once_with("firewall.savepoint")

    async def test_create_stores_active_revision(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(return_value={"revision": "rev-abc-123"})
        mgr = SavepointManager(mock_api_writes)
        await mgr.create()
        assert mgr.active_revision == "rev-abc-123"

    async def test_create_raises_on_empty_revision(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(return_value={"revision": ""})
        mgr = SavepointManager(mock_api_writes)
        with pytest.raises(SavepointError, match="no revision"):
            await mgr.create()

    async def test_create_raises_on_missing_revision(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        mgr = SavepointManager(mock_api_writes)
        with pytest.raises(SavepointError, match="no revision"):
            await mgr.create()

    async def test_create_raises_when_writes_disabled(self, mock_api):
        mgr = SavepointManager(mock_api)
        with pytest.raises(WriteDisabledError):
            await mgr.create()

    async def test_apply_calls_firewall_apply(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        mgr = SavepointManager(mock_api_writes)
        result = await mgr.apply("rev-abc-123")
        mock_api_writes.post.assert_called_once_with("firewall.apply", path_suffix="rev-abc-123")
        assert result == {"status": "ok"}

    async def test_apply_raises_when_writes_disabled(self, mock_api):
        mgr = SavepointManager(mock_api)
        with pytest.raises(WriteDisabledError):
            await mgr.apply("rev-abc-123")

    async def test_confirm_calls_cancel_rollback(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        mgr = SavepointManager(mock_api_writes)
        result = await mgr.confirm("rev-abc-123")
        mock_api_writes.post.assert_called_once_with("firewall.cancel_rollback", path_suffix="rev-abc-123")
        assert result == {"status": "ok"}

    async def test_confirm_clears_matching_revision(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(return_value={"revision": "rev-abc-123"})
        mgr = SavepointManager(mock_api_writes)
        await mgr.create()
        assert mgr.active_revision == "rev-abc-123"

        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        await mgr.confirm("rev-abc-123")
        assert mgr.active_revision is None

    async def test_confirm_keeps_different_revision(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(return_value={"revision": "rev-abc-123"})
        mgr = SavepointManager(mock_api_writes)
        await mgr.create()

        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        await mgr.confirm("rev-OTHER")
        assert mgr.active_revision == "rev-abc-123"

    async def test_confirm_raises_when_writes_disabled(self, mock_api):
        mgr = SavepointManager(mock_api)
        with pytest.raises(WriteDisabledError):
            await mgr.confirm("rev-abc-123")

    def test_initial_active_revision_is_none(self, mock_api_writes):
        mgr = SavepointManager(mock_api_writes)
        assert mgr.active_revision is None

    async def test_full_lifecycle(self, mock_api_writes):
        """Test create → apply → confirm flow."""
        mgr = SavepointManager(mock_api_writes)

        # Create
        mock_api_writes.post = AsyncMock(return_value={"revision": "rev-lifecycle"})
        revision = await mgr.create()
        assert revision == "rev-lifecycle"
        assert mgr.active_revision == "rev-lifecycle"

        # Apply
        mock_api_writes.post = AsyncMock(return_value={"status": "applied"})
        result = await mgr.apply(revision)
        assert result == {"status": "applied"}
        assert mgr.active_revision == "rev-lifecycle"  # Still active until confirmed

        # Confirm
        mock_api_writes.post = AsyncMock(return_value={"status": "confirmed"})
        result = await mgr.confirm(revision)
        assert result == {"status": "confirmed"}
        assert mgr.active_revision is None
