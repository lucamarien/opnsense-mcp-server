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
            "core/firmware/reboot",
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

    async def test_version_26_x_nested_product(self, mock_config, mock_httpx_client, firmware_status_26_x):
        """OPNsense 26.x nests product info under body['product']."""
        api = _make_api(mock_config, mock_httpx_client, firmware_status_26_x)
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


# --- Response Normalization Tests ---


class TestResponseNormalization:
    """Bare-array API responses must be normalized to a dict at the client boundary.

    Several endpoints (diagnostics/interface/getArp, getNdp,
    getInterfaceStatistics, ...) answer with a bare JSON array instead of
    the {rows, rowCount} envelope. Tools declare a dict return type and
    the MCP transport rejects non-dict structured content — a 500 whose
    error body leaks the full payload. The client normalizes so tools
    always receive a dict.
    """

    # (http method, logical endpoint) — known suspects for bare-array responses
    ENDPOINT_SHAPES = [
        ("get", "interface.arp"),
        ("get", "interface.ndp"),
        ("get", "interface.statistics"),
        ("get", "gateway.status"),
        ("get", "dhcpv4.leases.search"),
        ("post", "diagnostics.firewall.query_states"),
        ("post", "firewall.alias.search"),
        ("post", "firewall.search_rule"),
        ("post", "core.service.search"),
    ]

    def _request(self, api, method, endpoint):
        if method == "get":
            return api.get(endpoint)
        return api.post(endpoint, {"current": 1, "rowCount": 10, "searchPhrase": ""})

    @pytest.mark.parametrize("method,endpoint", ENDPOINT_SHAPES)
    async def test_bare_list_wrapped_in_envelope(self, method, endpoint, mock_config, mock_httpx_client):
        entries = [
            {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "intf": "lan"},
            {"ip": "10.0.0.2", "mac": "11:22:33:44:55:66", "intf": "lan"},
        ]
        getattr(mock_httpx_client, method).return_value = _make_response(json_data=entries)

        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        result = await self._request(api, method, endpoint)

        assert isinstance(result, dict)
        assert result == {"rows": entries, "rowCount": 2}

    @pytest.mark.parametrize("method,endpoint", ENDPOINT_SHAPES)
    async def test_wrapped_dict_passes_through_unchanged(self, method, endpoint, mock_config, mock_httpx_client):
        payload = {
            "rows": [{"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"}],
            "rowCount": 1,
        }
        getattr(mock_httpx_client, method).return_value = _make_response(json_data=payload)

        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        result = await self._request(api, method, endpoint)

        assert result is payload

    @pytest.mark.parametrize("method,endpoint", ENDPOINT_SHAPES)
    async def test_empty_list_wrapped_in_envelope(self, method, endpoint, mock_config, mock_httpx_client):
        getattr(mock_httpx_client, method).return_value = _make_response(json_data=[])

        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        result = await self._request(api, method, endpoint)

        assert isinstance(result, dict)
        assert result == {"rows": [], "rowCount": 0}

    @pytest.mark.parametrize("method,endpoint", ENDPOINT_SHAPES)
    async def test_empty_dict_passes_through(self, method, endpoint, mock_config, mock_httpx_client):
        getattr(mock_httpx_client, method).return_value = _make_response(json_data={})

        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        result = await self._request(api, method, endpoint)

        assert result == {}

    async def test_scalar_payload_wrapped_under_result(self, mock_config, mock_httpx_client):
        """Defensive: any non-dict/non-list payload still yields a dict."""
        mock_httpx_client.get.return_value = _make_response(json_data="ok")

        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        result = await api.get("firmware.status")

        assert isinstance(result, dict)
        assert result == {"result": "ok"}

    async def test_none_payload_wrapped_under_result(self, mock_config, mock_httpx_client):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = None
        mock_httpx_client.get.return_value = resp

        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        result = await api.get("gateway.status")

        assert isinstance(result, dict)
        assert result == {"result": None}


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

    async def test_post_with_empty_suffix_appends_nothing(self, mock_config_writes, mock_httpx_client):
        """OPNsense 26.7+ applies without a revision — the URL must have no trailing segment."""
        post_resp = _make_response(json_data={"status": "ok"})
        mock_httpx_client.post.return_value = post_resp
        api = _make_api_with_version(mock_config_writes, mock_httpx_client, (26, 7))
        await api.post("firewall.apply", path_suffix="")
        mock_httpx_client.post.assert_called_once_with("/firewall/filter/apply", json=None)

    async def test_suffix_checked_against_blocklist(self, mock_config_writes, mock_httpx_client):
        api = _make_api_with_version(mock_config_writes, mock_httpx_client, (25, 1))
        ENDPOINT_REGISTRY["_test_suffix"] = ("core/system/halt", "core/system/halt")
        try:
            with pytest.raises(BlockedEndpointError):
                await api.post("_test_suffix", path_suffix="extra")
        finally:
            del ENDPOINT_REGISTRY["_test_suffix"]

    @pytest.mark.parametrize(
        "suffix",
        [
            "../../../core/system/halt",
            "x/../../../core/firmware/poweroff",
            "..%2F..%2F..%2Fcore%2Fsystem%2Fhalt",
            "..",
            ".",
            "a/b",
            "abc?x=1",
            "abc#frag",
            "abc def",
            "abc\\def",
        ],
    )
    async def test_post_rejects_traversal_suffix(self, mock_config_writes, mock_httpx_client, suffix):
        api = _make_api_with_version(mock_config_writes, mock_httpx_client, (25, 1))
        with pytest.raises(BlockedEndpointError, match="Invalid path suffix"):
            await api.post("firewall.alias.del", path_suffix=suffix)
        mock_httpx_client.post.assert_not_called()

    async def test_get_rejects_traversal_suffix(self, mock_config, mock_httpx_client):
        api = _make_api_with_version(mock_config, mock_httpx_client, (25, 1))
        with pytest.raises(BlockedEndpointError, match="Invalid path suffix"):
            await api.get("firewall.alias.get", path_suffix="../../../core/system/halt")
        mock_httpx_client.get.assert_not_called()

    @pytest.mark.parametrize(
        "suffix",
        ["0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", "1700000000.1234", "lan,wan,opt1", "abc_123"],
    )
    async def test_plain_segment_suffix_allowed(self, mock_config_writes, mock_httpx_client, suffix):
        mock_httpx_client.post.return_value = _make_response(json_data={"result": "ok"})
        api = _make_api_with_version(mock_config_writes, mock_httpx_client, (25, 1))
        await api.post("firewall.apply", path_suffix=suffix)
        mock_httpx_client.post.assert_called_once_with(f"/firewall/filter/apply/{suffix}", json=None)

    def test_blocklist_collapses_dot_segments(self):
        with pytest.raises(BlockedEndpointError):
            OPNsenseAPI._check_blocklist("firewall/alias/delItem/../../../core/system/halt")


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

    # --- OPNsense 26.7+ (savepoint API removed upstream) ---

    async def test_create_degrades_on_missing_endpoint(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Endpoint not found", status_code=404))
        mgr = SavepointManager(mock_api_writes)
        assert await mgr.create() == ""
        assert mgr.supported is False
        assert mgr.active_revision is None

    async def test_create_does_not_degrade_without_404(self, mock_api_writes):
        """A savepoint message without OPNsense's 404 is not proof the endpoint is gone."""
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Endpoint not found"))
        mgr = SavepointManager(mock_api_writes)
        with pytest.raises(OPNsenseAPIError):
            await mgr.create()
        assert mgr.supported is None

    async def test_create_does_not_degrade_on_bare_proxy_404(self, mock_api_writes):
        """A proxy 404 on a pre-26.7 box must not silently strip the rollback net."""
        assert mock_api_writes.detected_version == (25, 1)
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("HTTP 404", status_code=404))
        mgr = SavepointManager(mock_api_writes)
        with pytest.raises(OPNsenseAPIError, match="HTTP 404"):
            await mgr.create()
        assert mgr.supported is None

    async def test_create_degrades_on_bare_404_when_version_removed_it(self, mock_api_writes):
        """Localised error bodies won't match the marker; the detected version corroborates."""
        mock_api_writes._detected_version = (26, 7)
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Endpunkt nicht gefunden", status_code=404))
        mgr = SavepointManager(mock_api_writes)
        assert await mgr.create() == ""
        assert mgr.supported is False

    async def test_create_does_not_degrade_on_405(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Method Not Allowed", status_code=405))
        mgr = SavepointManager(mock_api_writes)
        with pytest.raises(OPNsenseAPIError):
            await mgr.create()
        assert mgr.supported is None

    async def test_create_reraises_404_once_savepoints_are_known_to_work(self, mock_api_writes):
        """A transient 404 after a proven savepoint is an error, not a version difference."""
        mock_api_writes.post = AsyncMock(return_value={"revision": "rev-1"})
        mgr = SavepointManager(mock_api_writes)
        await mgr.create()
        assert mgr.supported is True

        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Endpoint not found", status_code=404))
        with pytest.raises(OPNsenseAPIError, match="Endpoint not found"):
            await mgr.create()
        assert mgr.supported is True

    async def test_confirm_reraises_404_while_a_rollback_timer_may_be_armed(self, mock_api_writes):
        """Never answer 'not_applicable' when a savepoint of this session could still revert."""
        mock_api_writes.post = AsyncMock(return_value={"revision": "rev-1"})
        mgr = SavepointManager(mock_api_writes)
        await mgr.create()

        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Endpoint not found", status_code=404))
        with pytest.raises(OPNsenseAPIError, match="Endpoint not found"):
            await mgr.confirm("rev-1")
        assert mgr.supported is True
        assert mgr.active_revision == "rev-1"

    async def test_create_skips_probe_once_unsupported(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Endpoint not found", status_code=404))
        mgr = SavepointManager(mock_api_writes)
        await mgr.create()
        await mgr.create()
        assert mock_api_writes.post.await_count == 1

    async def test_create_reraises_unrelated_api_error(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Internal error", status_code=500))
        mgr = SavepointManager(mock_api_writes)
        with pytest.raises(OPNsenseAPIError, match="Internal error"):
            await mgr.create()
        assert mgr.supported is None

    async def test_create_marks_supported_on_success(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(return_value={"revision": "rev-abc-123"})
        mgr = SavepointManager(mock_api_writes)
        await mgr.create()
        assert mgr.supported is True

    async def test_apply_without_revision_sends_no_suffix(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        mgr = SavepointManager(mock_api_writes)
        await mgr.apply("")
        mock_api_writes.post.assert_called_once_with("firewall.apply", path_suffix="")

    async def test_confirm_is_noop_when_unsupported(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Endpoint not found", status_code=404))
        mgr = SavepointManager(mock_api_writes)
        await mgr.create()
        mock_api_writes.post.reset_mock()
        result = await mgr.confirm("rev-abc-123")
        assert result["status"] == "not_applicable"
        mock_api_writes.post.assert_not_called()

    async def test_confirm_is_noop_on_empty_revision(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        mgr = SavepointManager(mock_api_writes)
        result = await mgr.confirm("")
        assert result["status"] == "not_applicable"
        mock_api_writes.post.assert_not_called()

    async def test_confirm_degrades_on_missing_endpoint(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Endpoint not found", status_code=404))
        mgr = SavepointManager(mock_api_writes)
        result = await mgr.confirm("rev-abc-123")
        assert result["status"] == "not_applicable"
        assert mgr.supported is False

    async def test_confirm_reraises_unrelated_api_error(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Internal error", status_code=500))
        mgr = SavepointManager(mock_api_writes)
        with pytest.raises(OPNsenseAPIError, match="Internal error"):
            await mgr.confirm("rev-abc-123")

    async def test_lifecycle_without_savepoints(self, mock_api_writes):
        """OPNsense 26.7+: create degrades, apply runs bare, confirm is a no-op."""
        mgr = SavepointManager(mock_api_writes)

        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Endpoint not found", status_code=404))
        revision = await mgr.create()
        assert revision == ""

        mock_api_writes.post = AsyncMock(return_value={"status": "applied"})
        assert await mgr.apply(revision) == {"status": "applied"}
        mock_api_writes.post.assert_called_once_with("firewall.apply", path_suffix="")

        assert (await mgr.confirm(revision))["status"] == "not_applicable"

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


class TestForcedApiStyle:
    """Tests for OPNSENSE_API_STYLE forced endpoint style (skips detection)."""

    def _make_api(self, style: str) -> OPNsenseAPI:
        from opnsense_mcp.config import OPNsenseConfig

        config = OPNsenseConfig(
            url="https://10.0.0.1/api",
            api_key="k",
            api_secret="s",
            verify_ssl=False,
            allow_writes=False,
            api_style=style,
        )
        api = OPNsenseAPI(config)
        api._client = AsyncMock()
        return api

    async def test_snake_forced_skips_detection(self, mock_httpx_client):
        api = self._make_api("snake")
        api._client = mock_httpx_client
        mock_httpx_client.get.return_value.json.return_value = {"rows": []}
        await api.get("interface.arp")
        # Only one GET: the endpoint itself, no firmware/status detection call
        assert mock_httpx_client.get.call_count == 1
        mock_httpx_client.get.assert_called_once_with("/diagnostics/interface/get_arp")

    async def test_camel_forced_skips_detection(self, mock_httpx_client):
        api = self._make_api("camel")
        api._client = mock_httpx_client
        mock_httpx_client.get.return_value.json.return_value = {"rows": []}
        await api.get("interface.arp")
        assert mock_httpx_client.get.call_count == 1
        mock_httpx_client.get.assert_called_once_with("/diagnostics/interface/getArp")

    async def test_auto_still_detects(self, mock_config, mock_httpx_client, firmware_status_25_7):
        api = OPNsenseAPI(mock_config)
        api._client = mock_httpx_client
        mock_httpx_client.get.return_value.json.return_value = firmware_status_25_7
        await api.get("interface.arp")
        # Two GETs: detection + endpoint
        assert mock_httpx_client.get.call_count == 2

    async def test_detection_failure_mentions_override(self, mock_config, mock_httpx_client):
        api = OPNsenseAPI(mock_config)
        api._client = mock_httpx_client
        mock_httpx_client.get.return_value.status_code = 403
        with pytest.raises(OPNsenseAPIError, match="OPNSENSE_API_STYLE"):
            await api.get("interface.arp")


class TestSavepointOverlapGuard:
    """Tests for the pending-savepoint guard in SavepointManager.create()."""

    async def test_create_refused_while_pending(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(return_value={"revision": "rev-1"})
        mgr = SavepointManager(mock_api_writes)
        await mgr.create()
        await mgr.apply("rev-1")
        with pytest.raises(SavepointError, match="pending"):
            await mgr.create()

    async def test_create_allowed_after_window(self, mock_api_writes, monkeypatch):
        import time as time_mod

        mock_api_writes.post = AsyncMock(return_value={"revision": "rev-1"})
        mgr = SavepointManager(mock_api_writes)
        await mgr.create()
        await mgr.apply("rev-1")

        # Pretend the apply happened 80 seconds ago
        assert mgr._applied_at is not None
        mgr._applied_at = time_mod.monotonic() - 80.0
        mock_api_writes.post = AsyncMock(return_value={"revision": "rev-2"})
        revision = await mgr.create()
        assert revision == "rev-2"

    async def test_create_allowed_after_confirm(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(return_value={"revision": "rev-1"})
        mgr = SavepointManager(mock_api_writes)
        await mgr.create()
        await mgr.apply("rev-1")
        await mgr.confirm("rev-1")
        mock_api_writes.post = AsyncMock(return_value={"revision": "rev-2"})
        revision = await mgr.create()
        assert revision == "rev-2"

    async def test_create_allowed_when_never_applied(self, mock_api_writes):
        # A savepoint that was created but whose change failed (never applied)
        # must not block the next attempt.
        mock_api_writes.post = AsyncMock(return_value={"revision": "rev-1"})
        mgr = SavepointManager(mock_api_writes)
        await mgr.create()
        mock_api_writes.post = AsyncMock(return_value={"revision": "rev-2"})
        revision = await mgr.create()
        assert revision == "rev-2"

    async def test_apply_unknown_revision_does_not_start_window(self, mock_api_writes):
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        mgr = SavepointManager(mock_api_writes)
        await mgr.apply("rev-foreign")
        assert mgr._applied_at is None
