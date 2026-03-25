"""Tests for system tools."""

from __future__ import annotations

from unittest.mock import AsyncMock

from opnsense_mcp.api_client import OPNsenseAPIError
from opnsense_mcp.tools.system import (
    opn_download_config,
    opn_gateway_status,
    opn_get_config_section,
    opn_list_services,
    opn_mcp_info,
    opn_scan_config,
    opn_system_status,
)


class TestOpnSystemStatus:
    """Tests for opn_system_status."""

    async def test_calls_firmware_status(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"product_version": "25.1.2"})
        result = await opn_system_status(mock_ctx)
        mock_api.get.assert_called_once_with("firmware.status")
        assert result == {"product_version": "25.1.2"}


class TestOpnListServices:
    """Tests for opn_list_services."""

    async def test_calls_service_search(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_list_services(mock_ctx)
        mock_api.post.assert_called_once_with(
            "core.service.search",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_phrase(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_services(mock_ctx, search="unbound")
        mock_api.post.assert_called_once_with(
            "core.service.search",
            {"current": 1, "rowCount": 50, "searchPhrase": "unbound"},
        )

    async def test_passes_custom_limit(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_services(mock_ctx, limit=100)
        mock_api.post.assert_called_once_with(
            "core.service.search",
            {"current": 1, "rowCount": 100, "searchPhrase": ""},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_services(mock_ctx, limit=9999)
        mock_api.post.assert_called_once_with(
            "core.service.search",
            {"current": 1, "rowCount": 500, "searchPhrase": ""},
        )


class TestOpnGatewayStatus:
    """Tests for opn_gateway_status."""

    async def test_calls_gateway_status(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"items": []})
        result = await opn_gateway_status(mock_ctx)
        mock_api.get.assert_called_once_with("gateway.status")
        assert result == {"items": []}


class TestOpnDownloadConfig:
    """Tests for opn_download_config."""

    _SAMPLE_XML = (
        "<?xml version='1.0'?>"
        "<opnsense>"
        "<system><hostname>firewall</hostname>"
        "<user><name>root</name><password>$2y$10$hash</password></user>"
        "</system>"
        "<OPNsense><API>"
        "<key>test-api-key</key>"
        "<secret>test-api-secret</secret>"
        "</API></OPNsense>"
        "</opnsense>"
    )

    async def test_downloads_config_with_stripping(self, mock_api, mock_ctx):
        mock_api.get_text = AsyncMock(return_value=self._SAMPLE_XML)

        result = await opn_download_config(mock_ctx)

        mock_api.get_text.assert_called_once_with("core.backup.download")
        assert result["stripped"] is True
        assert "[REDACTED]" in result["config_xml"]
        assert "test-api-key" not in result["config_xml"]
        assert "test-api-secret" not in result["config_xml"]
        assert "$2y$10$hash" not in result["config_xml"]
        assert "firewall" in result["config_xml"]
        assert result["size_bytes"] > 0

    async def test_downloads_config_without_stripping(self, mock_api, mock_ctx):
        mock_api.get_text = AsyncMock(return_value=self._SAMPLE_XML)

        result = await opn_download_config(mock_ctx, include_sensitive=True)

        assert result["stripped"] is False
        assert "$2y$10$hash" in result["config_xml"]
        assert "test-api-key" in result["config_xml"]
        assert "[REDACTED]" not in result["config_xml"]

    async def test_handles_malformed_xml(self, mock_api, mock_ctx):
        malformed = "<opnsense><unclosed>"
        mock_api.get_text = AsyncMock(return_value=malformed)

        result = await opn_download_config(mock_ctx)

        assert result["config_xml"] == malformed
        assert result["stripped"] is True

    async def test_returns_metadata(self, mock_api, mock_ctx):
        mock_api.get_text = AsyncMock(return_value="<opnsense />")

        result = await opn_download_config(mock_ctx)

        assert "config_xml" in result
        assert "stripped" in result
        assert "size_bytes" in result
        assert isinstance(result["size_bytes"], int)


class TestOpnScanConfig:
    """Tests for opn_scan_config."""

    def _setup_mock_api(self, mock_api):
        """Configure mock API with standard responses for scanning."""
        mock_api.get_text = AsyncMock(
            return_value=(
                "<?xml version='1.0'?>"
                "<opnsense>"
                "<system><hostname>firewall</hostname></system>"
                "<interfaces><lan><if>igb0</if></lan></interfaces>"
                "</opnsense>"
            )
        )

        async def mock_get(endpoint):
            responses = {
                "firmware.status": {
                    "product_version": "26.1",
                    "product_name": "OPNsense",
                },
                "firmware.info": {
                    "package": [
                        {
                            "name": "os-haproxy",
                            "version": "5.0",
                            "comment": "HAProxy",
                            "installed": "1",
                        },
                    ],
                },
                "dnsmasq.service.status": {"status": "running"},
                "dnsmasq.leases.search": {"rows": [], "rowCount": 0},
                "kea.service.status": {"status": "disabled"},
                "unbound.settings.get": {
                    "unbound": {"general": {"enabled": "1"}},
                },
                "dnsmasq.settings.get": {
                    "dnsmasq": {"general": {"enabled": "1"}},
                },
                "interface.config": {
                    "igb0": {
                        "status": "active",
                        "ipv4": [{"ipaddr": "192.168.1.1"}],
                        "macaddr": "aa:bb:cc:dd:ee:ff",
                        "mtu": "1500",
                    },
                },
                "interface.names": {"igb0": "LAN"},
            }
            if endpoint in responses:
                return responses[endpoint]
            raise OPNsenseAPIError(f"Endpoint not found: {endpoint}")

        mock_api.get = AsyncMock(side_effect=mock_get)
        mock_api.post = AsyncMock(
            return_value={"rows": [{"name": "pf", "running": 1}], "rowCount": 1},
        )

    async def test_returns_inventory_and_sections(self, mock_api, mock_ctx):
        self._setup_mock_api(mock_api)
        result = await opn_scan_config(mock_ctx)
        assert "firmware" in result
        assert "plugins" in result
        assert "dhcp" in result
        assert "dns" in result
        assert "interfaces" in result
        assert "services" in result
        assert "config_sections" in result

    async def test_firmware_version(self, mock_api, mock_ctx):
        self._setup_mock_api(mock_api)
        result = await opn_scan_config(mock_ctx)
        assert result["firmware"]["version"] == "26.1"
        assert result["firmware"]["product"] == "OPNsense"

    async def test_lists_config_sections(self, mock_api, mock_ctx):
        self._setup_mock_api(mock_api)
        result = await opn_scan_config(mock_ctx)
        section_names = [s["name"] for s in result["config_sections"]]
        assert "system" in section_names
        assert "interfaces" in section_names

    async def test_cache_status_fresh(self, mock_api, mock_ctx):
        self._setup_mock_api(mock_api)
        result = await opn_scan_config(mock_ctx)
        assert result["cache_status"] == "fresh"

    async def test_force_rescan(self, mock_api, mock_ctx):
        self._setup_mock_api(mock_api)
        await opn_scan_config(mock_ctx)
        first_call_count = mock_api.get_text.call_count

        await opn_scan_config(mock_ctx, force=True)
        assert mock_api.get_text.call_count == first_call_count + 1


class TestOpnGetConfigSection:
    """Tests for opn_get_config_section."""

    def _setup_mock_api(self, mock_api):
        """Configure mock API for section tests."""
        mock_api.get_text = AsyncMock(
            return_value=(
                "<opnsense>"
                "<system><hostname>firewall</hostname>"
                "<password>secret123</password></system>"
                "<filter><rule><type>pass</type></rule></filter>"
                "</opnsense>"
            )
        )
        mock_api.get = AsyncMock(
            return_value={"product_version": "26.1", "product_name": "OPNsense"},
        )
        mock_api.post = AsyncMock(
            return_value={"rows": [], "rowCount": 0},
        )

    async def test_returns_section_data(self, mock_api, mock_ctx):
        self._setup_mock_api(mock_api)
        result = await opn_get_config_section(mock_ctx, section="system")
        assert result["section"] == "system"
        assert result["data"]["hostname"] == "firewall"

    async def test_strips_sensitive_by_default(self, mock_api, mock_ctx):
        self._setup_mock_api(mock_api)
        result = await opn_get_config_section(mock_ctx, section="system")
        assert result["data"]["password"] == "[REDACTED]"

    async def test_include_sensitive(self, mock_api, mock_ctx):
        self._setup_mock_api(mock_api)
        result = await opn_get_config_section(mock_ctx, section="system", include_sensitive=True)
        assert result["data"]["password"] == "secret123"

    async def test_section_not_found(self, mock_api, mock_ctx):
        self._setup_mock_api(mock_api)
        result = await opn_get_config_section(mock_ctx, section="nonexistent")
        assert "error" in result
        assert "available_sections" in result

    async def test_auto_loads_cache(self, mock_api, mock_ctx):
        self._setup_mock_api(mock_api)
        # Don't call scan_config first — get_config_section should auto-load
        result = await opn_get_config_section(mock_ctx, section="system")
        assert result["section"] == "system"
        mock_api.get_text.assert_called()


class TestOpnMcpInfo:
    """Tests for opn_mcp_info."""

    async def test_returns_expected_keys(self, mock_api, mock_ctx):
        result = await opn_mcp_info(mock_ctx)
        assert "mcp_version" in result
        assert "write_mode" in result
        assert "opnsense_version" in result
        assert "api_style" in result

    async def test_returns_version_string(self, mock_api, mock_ctx):
        result = await opn_mcp_info(mock_ctx)
        assert isinstance(result["mcp_version"], str)
        assert result["mcp_version"]  # non-empty

    async def test_write_mode_disabled(self, mock_api, mock_ctx):
        result = await opn_mcp_info(mock_ctx)
        assert result["write_mode"] is False

    async def test_write_mode_enabled(self, mock_api_writes, mock_ctx_writes):
        result = await opn_mcp_info(mock_ctx_writes)
        assert result["write_mode"] is True

    async def test_opnsense_version_detected(self, mock_api, mock_ctx):
        result = await opn_mcp_info(mock_ctx)
        assert result["opnsense_version"] == "25.1"

    async def test_opnsense_version_not_detected(self, mock_api, mock_ctx):
        mock_api._detected_version = None
        result = await opn_mcp_info(mock_ctx)
        assert result["opnsense_version"] is None

    async def test_api_style_camelcase(self, mock_api, mock_ctx):
        result = await opn_mcp_info(mock_ctx)
        assert result["api_style"] == "camelCase"

    async def test_api_style_snake_case(self, mock_api, mock_ctx):
        mock_api._use_snake_case = True
        result = await opn_mcp_info(mock_ctx)
        assert result["api_style"] == "snake_case"
