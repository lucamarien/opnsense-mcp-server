"""Tests for ConfigCache — XML parsing, caching, and sensitive data stripping."""

from __future__ import annotations

from unittest.mock import AsyncMock

from opnsense_mcp.config_cache import ConfigCache, _strip_sensitive, _xml_to_dict


class TestXmlToDict:
    """Tests for _xml_to_dict recursive converter."""

    def test_simple_text_element(self):
        import xml.etree.ElementTree as ET

        elem = ET.fromstring("<hostname>firewall</hostname>")  # noqa: S314
        assert _xml_to_dict(elem) == "firewall"

    def test_nested_elements(self):
        import xml.etree.ElementTree as ET

        elem = ET.fromstring("<system><hostname>fw</hostname><timezone>UTC</timezone></system>")  # noqa: S314
        result = _xml_to_dict(elem)
        assert result == {"hostname": "fw", "timezone": "UTC"}

    def test_repeated_elements_become_list(self):
        import xml.etree.ElementTree as ET

        xml = "<users><user><name>root</name></user><user><name>admin</name></user></users>"
        elem = ET.fromstring(xml)  # noqa: S314
        result = _xml_to_dict(elem)
        assert isinstance(result["user"], list)
        assert len(result["user"]) == 2
        assert result["user"][0] == {"name": "root"}
        assert result["user"][1] == {"name": "admin"}

    def test_empty_element(self):
        import xml.etree.ElementTree as ET

        elem = ET.fromstring("<any/>")  # noqa: S314
        assert _xml_to_dict(elem) == ""

    def test_deeply_nested(self):
        import xml.etree.ElementTree as ET

        xml = "<a><b><c>deep</c></b></a>"
        result = _xml_to_dict(ET.fromstring(xml))  # noqa: S314
        assert result == {"b": {"c": "deep"}}

    def test_three_repeated_elements(self):
        import xml.etree.ElementTree as ET

        xml = "<root><item>a</item><item>b</item><item>c</item></root>"
        result = _xml_to_dict(ET.fromstring(xml))  # noqa: S314
        assert result["item"] == ["a", "b", "c"]


class TestStripSensitive:
    """Tests for _strip_sensitive dict redaction."""

    def test_redacts_password(self):
        data = {"username": "root", "password": "secret123"}
        result = _strip_sensitive(data)
        assert result["username"] == "root"
        assert result["password"] == "[REDACTED]"

    def test_redacts_nested(self):
        data = {"user": {"name": "admin", "secret": "mysecret"}}
        result = _strip_sensitive(data)
        assert result["user"]["name"] == "admin"
        assert result["user"]["secret"] == "[REDACTED]"

    def test_redacts_in_list(self):
        data = [{"password": "abc"}, {"password": "def"}]
        result = _strip_sensitive(data)
        assert result[0]["password"] == "[REDACTED]"
        assert result[1]["password"] == "[REDACTED]"

    def test_preserves_non_sensitive(self):
        data = {"hostname": "firewall", "timezone": "UTC"}
        result = _strip_sensitive(data)
        assert result == data

    def test_case_insensitive_tags(self):
        data = {"Password": "test", "KEY": "test2"}
        result = _strip_sensitive(data)
        # SENSITIVE_TAGS are lowercase, matching is by .lower()
        assert result["Password"] == "[REDACTED]"


class TestConfigCache:
    """Tests for ConfigCache lifecycle."""

    _SAMPLE_XML = (
        "<?xml version='1.0'?>"
        "<opnsense>"
        "<system><hostname>firewall</hostname></system>"
        "<interfaces><lan><if>igb0</if></lan></interfaces>"
        "<filter><rule><type>pass</type></rule></filter>"
        "</opnsense>"
    )

    def _make_mock_api(self) -> AsyncMock:
        """Create a mock API with standard responses for cache loading."""
        api = AsyncMock()
        api.get_text = AsyncMock(return_value=self._SAMPLE_XML)

        async def mock_get(endpoint: str) -> dict:
            responses: dict[str, dict] = {
                "firmware.status": {"product_version": "26.1", "product_name": "OPNsense"},
                "firmware.info": {"package": []},
                "dnsmasq.service.status": {"status": "running"},
                "dnsmasq.leases.search": {"rows": [], "rowCount": 0},
                "kea.service.status": {"status": "disabled"},
                "unbound.settings.get": {"unbound": {"general": {"enabled": "1"}}},
                "dnsmasq.settings.get": {"dnsmasq": {"general": {"enabled": "1"}}},
                "interface.config": {"igb0": {"status": "active", "ipv4": [], "macaddr": "aa:bb"}},
                "interface.names": {"igb0": "LAN"},
            }
            if endpoint in responses:
                return responses[endpoint]
            from opnsense_mcp.api_client import OPNsenseAPIError

            raise OPNsenseAPIError(f"Not found: {endpoint}")

        api.get = AsyncMock(side_effect=mock_get)
        api.post = AsyncMock(return_value={"rows": [{"name": "pf", "running": 1}], "rowCount": 1})
        return api

    async def test_not_loaded_initially(self):
        cache = ConfigCache()
        assert cache.is_loaded is False
        assert cache.is_stale is False

    async def test_load_parses_sections(self):
        cache = ConfigCache()
        api = self._make_mock_api()
        await cache.load(api)

        assert cache.is_loaded is True
        sections = cache.available_sections()
        assert "system" in sections
        assert "interfaces" in sections
        assert "filter" in sections

    async def test_get_section_returns_data(self):
        cache = ConfigCache()
        api = self._make_mock_api()
        await cache.load(api)

        result = cache.get_section("system")
        assert result is not None
        assert result["section"] == "system"
        assert result["data"]["hostname"] == "firewall"

    async def test_get_section_not_found(self):
        cache = ConfigCache()
        api = self._make_mock_api()
        await cache.load(api)

        result = cache.get_section("nonexistent")
        assert result is None

    async def test_get_section_strips_sensitive(self):
        api = AsyncMock()
        api.get_text = AsyncMock(
            return_value=("<opnsense><system><hostname>fw</hostname><password>secret123</password></system></opnsense>")
        )
        api.get = AsyncMock(return_value={"product_version": "26.1", "product_name": "OPNsense"})
        api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})

        cache = ConfigCache()
        await cache.load(api)

        result = cache.get_section("system")
        assert result is not None
        assert result["data"]["password"] == "[REDACTED]"
        assert result["data"]["hostname"] == "fw"

    async def test_get_section_include_sensitive(self):
        api = AsyncMock()
        api.get_text = AsyncMock(return_value=("<opnsense><system><password>secret123</password></system></opnsense>"))
        api.get = AsyncMock(return_value={"product_version": "26.1", "product_name": "OPNsense"})
        api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})

        cache = ConfigCache()
        await cache.load(api)

        result = cache.get_section("system", include_sensitive=True)
        assert result is not None
        assert result["data"]["password"] == "secret123"

    async def test_invalidate_marks_stale(self):
        cache = ConfigCache()
        api = self._make_mock_api()
        await cache.load(api)

        assert cache.is_stale is False
        cache.invalidate()
        assert cache.is_stale is True

    async def test_load_skips_when_fresh(self):
        cache = ConfigCache()
        api = self._make_mock_api()
        await cache.load(api)
        first_call_count = api.get_text.call_count

        await cache.load(api)
        assert api.get_text.call_count == first_call_count  # no re-download

    async def test_load_redownloads_when_stale(self):
        cache = ConfigCache()
        api = self._make_mock_api()
        await cache.load(api)
        first_call_count = api.get_text.call_count

        cache.invalidate()
        await cache.load(api)
        assert api.get_text.call_count == first_call_count + 1

    async def test_load_redownloads_when_forced(self):
        cache = ConfigCache()
        api = self._make_mock_api()
        await cache.load(api)
        first_call_count = api.get_text.call_count

        await cache.load(api, force=True)
        assert api.get_text.call_count == first_call_count + 1

    async def test_summary_contains_inventory(self):
        cache = ConfigCache()
        api = self._make_mock_api()
        await cache.load(api)

        summary = cache.summary()
        assert "firmware" in summary
        assert summary["firmware"]["version"] == "26.1"
        assert "plugins" in summary
        assert "dhcp" in summary
        assert "dns" in summary
        assert "interfaces" in summary
        assert "services" in summary
        assert "config_sections" in summary
        assert summary["cache_status"] == "fresh"

    async def test_summary_26_x_nested_firmware(self):
        """OPNsense 26.x nests product info under firmware['product']."""
        cache = ConfigCache()
        api = self._make_mock_api()
        # Override firmware.status to return 26.x nested format
        original_get = api.get.side_effect

        async def mock_get_26x(endpoint: str) -> dict:
            if endpoint == "firmware.status":
                return {
                    "product": {
                        "product_version": "26.1.3",
                        "product_name": "OPNsense",
                    },
                    "status_msg": "",
                    "status": "update",
                }
            return await original_get(endpoint)

        api.get = AsyncMock(side_effect=mock_get_26x)
        await cache.load(api)

        summary = cache.summary()
        assert summary["firmware"]["version"] == "26.1.3"
        assert summary["firmware"]["product"] == "OPNsense"

    async def test_summary_section_info(self):
        cache = ConfigCache()
        api = self._make_mock_api()
        await cache.load(api)

        summary = cache.summary()
        section_names = [s["name"] for s in summary["config_sections"]]
        assert "system" in section_names
        assert "filter" in section_names

        for section_info in summary["config_sections"]:
            assert "size_bytes" in section_info
            assert section_info["size_bytes"] > 0

    async def test_handles_malformed_xml(self):
        api = AsyncMock()
        api.get_text = AsyncMock(return_value="<opnsense><unclosed>")
        api.get = AsyncMock(return_value={"product_version": "26.1", "product_name": "OPNsense"})
        api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})

        cache = ConfigCache()
        await cache.load(api)
        assert cache.is_loaded is True
        assert cache.available_sections() == []
