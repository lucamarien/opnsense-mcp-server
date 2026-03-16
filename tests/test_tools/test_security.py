"""Tests for comprehensive security audit tool."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

from opnsense_mcp.api_client import OPNsenseAPIError
from opnsense_mcp.tools.security import (
    _classify_ports,
    _find_insecure_ports,
    _is_broad_port_range,
    _parse_ports,
    opn_security_audit,
)

# ---------------------------------------------------------------------------
# Section keys used across the audit report
# ---------------------------------------------------------------------------

_ALL_SECTIONS = (
    "firmware",
    "firewall_rules",
    "nat_rules",
    "dns_security",
    "system_hardening",
    "services",
    "certificates",
    "vpn_security",
    "haproxy",
    "gateways",
)


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


def _mock_api_calls(  # noqa: C901, PLR0912
    mock_api: MagicMock,
    *,
    firmware: dict[str, Any] | OPNsenseAPIError | None = None,
    rules: dict[str, Any] | OPNsenseAPIError | None = None,
    nat_rules: dict[str, Any] | OPNsenseAPIError | None = None,
    services: dict[str, Any] | OPNsenseAPIError | None = None,
    certs: dict[str, Any] | OPNsenseAPIError | None = None,
    unbound_settings: dict[str, Any] | OPNsenseAPIError | None = None,
    unbound_forwards: dict[str, Any] | OPNsenseAPIError | None = None,
    gateway_status: dict[str, Any] | OPNsenseAPIError | None = None,
    wireguard_show: dict[str, Any] | OPNsenseAPIError | None = None,
    wireguard_servers: dict[str, Any] | OPNsenseAPIError | None = None,
    wireguard_clients: dict[str, Any] | OPNsenseAPIError | None = None,
    ipsec_status: dict[str, Any] | OPNsenseAPIError | None = None,
    openvpn_instances: dict[str, Any] | OPNsenseAPIError | None = None,
    haproxy_frontends: dict[str, Any] | OPNsenseAPIError | None = None,
    haproxy_backends: dict[str, Any] | OPNsenseAPIError | None = None,
    haproxy_servers: dict[str, Any] | OPNsenseAPIError | None = None,
    haproxy_actions: dict[str, Any] | OPNsenseAPIError | None = None,
) -> None:
    """Configure mock_api.get and mock_api.post for all audit endpoints."""
    if firmware is None:
        firmware = {"product_version": "25.1.2", "product_name": "OPNsense"}
    if rules is None:
        rules = {"rows": [], "rowCount": 0, "total": 0}
    if nat_rules is None:
        nat_rules = {"rows": [], "rowCount": 0, "total": 0}
    if services is None:
        services = {"rows": [], "rowCount": 0}
    if certs is None:
        certs = {"rows": [], "rowCount": 0}
    if unbound_settings is None:
        unbound_settings = {"unbound": {"general": {"dnssec": "1", "hideidentity": "1", "hideversion": "1"}}}
    if unbound_forwards is None:
        unbound_forwards = {"rows": [], "rowCount": 0, "total": 0}
    if gateway_status is None:
        gateway_status = {}
    if wireguard_show is None:
        wireguard_show = {"items": []}
    if wireguard_servers is None:
        wireguard_servers = {"rows": [], "rowCount": 0, "total": 0}
    if wireguard_clients is None:
        wireguard_clients = {"rows": [], "rowCount": 0, "total": 0}
    if ipsec_status is None:
        ipsec_status = {"status": "disabled"}
    if openvpn_instances is None:
        openvpn_instances = {"rows": [], "rowCount": 0}
    if haproxy_frontends is None:
        haproxy_frontends = OPNsenseAPIError("HAProxy not installed", status_code=404)
    if haproxy_backends is None:
        haproxy_backends = {"rows": [], "rowCount": 0, "total": 0}
    if haproxy_servers is None:
        haproxy_servers = {"rows": [], "rowCount": 0, "total": 0}
    if haproxy_actions is None:
        haproxy_actions = {"rows": [], "rowCount": 0, "total": 0}

    async def fake_get(endpoint: str) -> dict[str, Any]:
        dispatch: dict[str, dict[str, Any] | OPNsenseAPIError] = {
            "firmware.status": firmware,
            "unbound.settings.get": unbound_settings,
            "gateway.status": gateway_status,
            "wireguard.service.show": wireguard_show,
            "ipsec.service.status": ipsec_status,
        }
        val = dispatch.get(endpoint)
        if val is None:
            return {}
        if isinstance(val, OPNsenseAPIError):
            raise val
        return val

    async def fake_post(
        endpoint: str,
        data: dict[str, Any] | None = None,
        *,
        path_suffix: str = "",
    ) -> dict[str, Any]:
        dispatch: dict[str, dict[str, Any] | OPNsenseAPIError] = {
            "firewall.search_rule": rules,
            "nat.dnat.search_rule": nat_rules,
            "core.service.search": services,
            "acmeclient.certs.search": certs,
            "unbound.search_forward": unbound_forwards,
            "openvpn.instances": openvpn_instances,
            "wireguard.server.search_server": wireguard_servers,
            "wireguard.client.search_client": wireguard_clients,
            "haproxy.settings.search_frontends": haproxy_frontends,
            "haproxy.settings.search_backends": haproxy_backends,
            "haproxy.settings.search_servers": haproxy_servers,
            "haproxy.settings.search_actions": haproxy_actions,
        }
        val = dispatch.get(endpoint)
        if val is None:
            return {}
        if isinstance(val, OPNsenseAPIError):
            raise val
        return val

    mock_api.get = AsyncMock(side_effect=fake_get)
    mock_api.post = AsyncMock(side_effect=fake_post)
    # Mock get_text for config cache loading (returns minimal valid XML)
    mock_api.get_text = AsyncMock(return_value="<opnsense></opnsense>")


def _setup_config_cache(
    mock_ctx: MagicMock,
    sections: dict[str, Any] | None = None,
) -> None:
    """Populate the ConfigCache in mock_ctx with the given sections."""
    cache = mock_ctx.lifespan_context["config_cache"]
    cache._loaded_at = 1.0  # Mark as loaded
    cache._stale = False
    if sections:
        for name, data in sections.items():
            cache._sections[name] = data


# ---------------------------------------------------------------------------
# Rule / service / gateway helpers
# ---------------------------------------------------------------------------


def _make_rule(
    *,
    action: str = "pass",
    source_net: str = "any",
    destination_net: str = "any",
    protocol: str = "any",
    destination_port: str = "",
    enabled: str = "1",
    description: str = "Test rule",
    uuid: str = "rule-uuid-1",
    interface: str = "lan",
) -> dict[str, Any]:
    return {
        "action": action,
        "source_net": source_net,
        "destination_net": destination_net,
        "protocol": protocol,
        "destination_port": destination_port,
        "enabled": enabled,
        "description": description,
        "uuid": uuid,
        "interface": interface,
    }


def _make_nat_rule(
    *,
    dst_port: str = "80",
    source_net: str = "any",
    protocol: str = "tcp",
    description: str = "NAT rule",
    uuid: str = "nat-uuid-1",
    type: str = "",
    enabled: str = "1",
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "dst_port": dst_port,
        "source_net": source_net,
        "protocol": protocol,
        "description": description,
        "uuid": uuid,
        "enabled": enabled,
    }
    if type:
        result["type"] = type
    return result


def _make_service(
    *,
    name: str = "unbound",
    running: int | str = 1,
) -> dict[str, Any]:
    return {"name": name, "running": running}


def _make_gateway(
    *,
    name: str = "WAN_GW",
    status: str = "online",
    status_translated: str = "",
    loss: str = "0.0%",
    delay: str = "5.0ms",
) -> dict[str, Any]:
    gw: dict[str, Any] = {
        "name": name,
        "status": status,
        "loss": loss,
        "delay": delay,
    }
    if status_translated:
        gw["status_translated"] = status_translated
    return gw


def _find_findings(result: dict[str, Any], *, check: str) -> list[dict[str, Any]]:
    """Collect all findings with the given check name across all sections."""
    findings: list[dict[str, Any]] = []
    for section_key in _ALL_SECTIONS:
        section = result.get(section_key, {})
        for f in section.get("findings", []):
            if f.get("check") == check:
                findings.append(f)
    return findings


def _all_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect all findings from all sections."""
    findings: list[dict[str, Any]] = []
    for section_key in _ALL_SECTIONS:
        section = result.get(section_key, {})
        findings.extend(section.get("findings", []))
    return findings


# ---------------------------------------------------------------------------
# Port helper tests
# ---------------------------------------------------------------------------


class TestParsePortsHelper:
    """Tests for _parse_ports."""

    def test_single_port(self) -> None:
        assert _parse_ports("80") == {80}

    def test_range_dash(self) -> None:
        assert _parse_ports("100-103") == {100, 101, 102, 103}

    def test_range_colon(self) -> None:
        assert _parse_ports("200:202") == {200, 201, 202}

    def test_empty(self) -> None:
        assert _parse_ports("") == set()

    def test_alias_returns_empty(self) -> None:
        assert _parse_ports("http_ports") == set()

    def test_comma_separated(self) -> None:
        assert _parse_ports("80,443") == {80, 443}


class TestBroadPortRange:
    """Tests for _is_broad_port_range."""

    def test_narrow_range(self) -> None:
        assert _is_broad_port_range("80") is False

    def test_broad_range(self) -> None:
        assert _is_broad_port_range("1000-2000") is True

    def test_custom_threshold(self) -> None:
        assert _is_broad_port_range("1-20", threshold=10) is True
        assert _is_broad_port_range("1-5", threshold=10) is False


class TestClassifyPorts:
    """Tests for _classify_ports."""

    def test_web_ports(self) -> None:
        assert "web" in _classify_ports({80, 443})

    def test_multiple_groups(self) -> None:
        groups = _classify_ports({22, 80, 443, 53})
        assert "ssh" in groups
        assert "web" in groups
        assert "dns" in groups

    def test_empty(self) -> None:
        assert _classify_ports(set()) == set()


class TestFindInsecurePorts:
    """Tests for _find_insecure_ports."""

    def test_ftp(self) -> None:
        results = _find_insecure_ports({21})
        assert len(results) == 1
        assert results[0]["protocol"] == "FTP"

    def test_secure_port(self) -> None:
        assert _find_insecure_ports({443}) == []

    def test_multiple_insecure(self) -> None:
        results = _find_insecure_ports({21, 23, 443})
        assert len(results) == 2


# ---------------------------------------------------------------------------
# Compliance tagging tests
# ---------------------------------------------------------------------------


class TestComplianceTagging:
    """Tests for compliance framework tagging."""

    async def test_findings_have_compliance_tags(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_rule(description="Wide open")
        _mock_api_calls(mock_api, rules={"rows": [rule], "rowCount": 1, "total": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)

        findings = _find_findings(result, check="permissive_rule")
        assert len(findings) >= 1
        assert "compliance" in findings[0]
        assert "PCI-DSS-1.2.1" in findings[0]["compliance"]

    async def test_unknown_check_has_no_compliance(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api)
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)

        # firmware_version is info, not in compliance map
        version_findings = _find_findings(result, check="firmware_version")
        assert len(version_findings) >= 1
        assert "compliance" not in version_findings[0]

    async def test_summary_includes_compliance_frameworks(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api)
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)

        assert "compliance_frameworks" in result
        cf = result["compliance_frameworks"]
        assert "frameworks" in cf
        assert len(cf["frameworks"]) == 4
        assert "manual_review_needed" in cf


# ---------------------------------------------------------------------------
# Firmware tests
# ---------------------------------------------------------------------------


class TestCheckFirmware:
    """Tests for firmware section."""

    async def test_firmware_reports_version(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            firmware={"product_version": "25.7.1", "product_name": "OPNsense"},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert result["firmware"]["product_version"] == "25.7.1"

    async def test_firmware_upgrade_available(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            firmware={
                "product_version": "25.1.2",
                "product_name": "OPNsense",
                "upgrade_sets": "25.7",
            },
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="firmware_update_available")
        assert len(findings) == 1
        assert findings[0]["severity"] == "warning"

    async def test_firmware_api_failure(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api, firmware=OPNsenseAPIError("Connection failed"))
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert result["firmware"]["status"] == "skipped"


# ---------------------------------------------------------------------------
# Firewall rules tests
# ---------------------------------------------------------------------------


class TestCheckFirewallRules:
    """Tests for firewall rules section."""

    async def test_clean_audit(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            services={"rows": [_make_service(name="unbound", running=1)], "rowCount": 1},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert result["firewall_rules"]["status"] == "ok"
        assert result["summary"]["critical"] == 0

    async def test_detects_permissive_any_any_rule(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_rule(
            action="pass",
            source_net="any",
            destination_net="any",
            protocol="any",
            uuid="bad-rule-1",
            description="Allow all",
        )
        _mock_api_calls(mock_api, rules={"rows": [rule], "rowCount": 1, "total": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)

        findings = _find_findings(result, check="permissive_rule")
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"
        assert findings[0]["uuid"] == "bad-rule-1"

    async def test_detects_permissive_empty_protocol(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_rule(protocol="", description="Wide open")
        _mock_api_calls(mock_api, rules={"rows": [rule], "rowCount": 1, "total": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="permissive_rule")
        assert len(findings) == 1

    async def test_ignores_block_any_any(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_rule(action="block")
        _mock_api_calls(mock_api, rules={"rows": [rule], "rowCount": 1, "total": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert len(_find_findings(result, check="permissive_rule")) == 0

    async def test_ignores_pass_specific_source(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_rule(source_net="192.168.1.0/24")
        _mock_api_calls(mock_api, rules={"rows": [rule], "rowCount": 1, "total": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert len(_find_findings(result, check="permissive_rule")) == 0

    async def test_detects_broad_source(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_rule(source_net="any", destination_net="192.168.1.0/24", protocol="tcp")
        _mock_api_calls(mock_api, rules={"rows": [rule], "rowCount": 1, "total": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="broad_source")
        assert len(findings) == 1
        assert findings[0]["severity"] == "warning"

    async def test_detects_broad_destination(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_rule(source_net="10.0.0.0/8", destination_net="any", protocol="tcp")
        _mock_api_calls(mock_api, rules={"rows": [rule], "rowCount": 1, "total": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="broad_destination")
        assert len(findings) == 1

    async def test_detects_no_port_restriction(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_rule(
            source_net="10.0.0.0/8",
            destination_net="10.0.1.0/24",
            protocol="tcp",
            destination_port="",
        )
        _mock_api_calls(mock_api, rules={"rows": [rule], "rowCount": 1, "total": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="no_port_restriction")
        assert len(findings) == 1

    async def test_detects_broad_port_range(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_rule(
            source_net="10.0.0.0/8",
            destination_net="10.0.1.0/24",
            protocol="tcp",
            destination_port="1000-5000",
        )
        _mock_api_calls(mock_api, rules={"rows": [rule], "rowCount": 1, "total": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="broad_port_range")
        assert len(findings) == 1

    async def test_detects_wan_inbound(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_rule(
            source_net="10.0.0.0/8",
            destination_net="10.0.1.0/24",
            protocol="tcp",
            destination_port="443",
            interface="wan",
        )
        _mock_api_calls(mock_api, rules={"rows": [rule], "rowCount": 1, "total": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="wan_inbound_pass")
        assert len(findings) == 1

    async def test_detects_management_exposure(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_rule(
            source_net="any",
            destination_net="10.0.0.1",
            protocol="tcp",
            destination_port="22,443",
            interface="wan",
        )
        _mock_api_calls(mock_api, rules={"rows": [rule], "rowCount": 1, "total": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="management_exposure")
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    async def test_detects_disabled_rules(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rules = [
            _make_rule(enabled="0", uuid="dis-1"),
            _make_rule(enabled="0", uuid="dis-2"),
            _make_rule(enabled="1", uuid="en-1", source_net="10.0.0.0/8"),
        ]
        _mock_api_calls(mock_api, rules={"rows": rules, "rowCount": 3, "total": 3})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="disabled_rules")
        assert len(findings) == 1
        assert findings[0]["count"] == 2

    async def test_detects_rules_no_description(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rules = [
            _make_rule(description="", source_net="10.0.0.0/8"),
            _make_rule(description="Good rule", source_net="10.0.0.0/8"),
        ]
        _mock_api_calls(mock_api, rules={"rows": rules, "rowCount": 2, "total": 2})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="rules_no_description")
        assert len(findings) == 1
        assert findings[0]["count"] == 1

    async def test_detects_ssh_not_isolated(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_rule(
            source_net="10.0.0.0/8",
            destination_net="10.0.1.0/24",
            protocol="tcp",
            destination_port="22,80,443",
        )
        _mock_api_calls(mock_api, rules={"rows": [rule], "rowCount": 1, "total": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="ssh_not_isolated")
        assert len(findings) == 1

    async def test_detects_mixed_service_ports(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_rule(
            source_net="10.0.0.0/8",
            destination_net="10.0.1.0/24",
            protocol="tcp",
            destination_port="22,80,53",
        )
        _mock_api_calls(mock_api, rules={"rows": [rule], "rowCount": 1, "total": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="mixed_service_ports")
        assert len(findings) == 1

    async def test_detects_insecure_protocol_on_wan(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_rule(
            source_net="10.0.0.0/8",
            destination_net="10.0.1.0/24",
            protocol="tcp",
            destination_port="21",
            interface="wan",
        )
        _mock_api_calls(mock_api, rules={"rows": [rule], "rowCount": 1, "total": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="insecure_protocol")
        assert len(findings) == 1
        assert "FTP" in findings[0]["message"]

    async def test_http_on_lan_not_flagged(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_rule(
            source_net="10.0.0.0/8",
            destination_net="10.0.1.0/24",
            protocol="tcp",
            destination_port="80",
            interface="lan",
        )
        _mock_api_calls(mock_api, rules={"rows": [rule], "rowCount": 1, "total": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="insecure_protocol")
        assert len(findings) == 0

    async def test_legacy_rules_analyzed(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api)
        _setup_config_cache(
            mock_ctx,
            sections={
                "filter": {
                    "rule": [
                        {
                            "type": "pass",
                            "source": {"any": ""},
                            "destination": {"any": ""},
                            "protocol": "",
                            "descr": "Legacy wide open",
                            "interface": "lan",
                        }
                    ]
                }
            },
        )
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="permissive_rule")
        assert len(findings) >= 1
        assert result["firewall_rules"]["total_legacy_rules"] == 1

    async def test_legacy_rules_migration_warning(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        """Legacy rules should trigger a migration recommendation."""
        _mock_api_calls(mock_api)
        _setup_config_cache(
            mock_ctx,
            sections={
                "filter": {
                    "rule": [
                        {
                            "type": "pass",
                            "source": {"network": "lan"},
                            "destination": {"network": "lan"},
                            "protocol": "tcp",
                            "descr": "LAN rule",
                            "interface": "lan",
                        }
                    ]
                }
            },
        )
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="legacy_rules_present")
        assert len(findings) == 1
        assert findings[0]["severity"] == "warning"
        assert "Migration Assistant" in findings[0]["recommendation"]
        assert findings[0]["legacy_count"] == 1
        assert findings[0]["mvc_count"] == 0

    async def test_no_legacy_migration_warning_when_mvc_only(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        """No migration warning when all rules are in MVC format."""
        rule = _make_rule(source_net="10.0.0.0/8", destination_net="10.0.1.0/24", protocol="tcp")
        _mock_api_calls(mock_api, rules={"rows": [rule], "rowCount": 1, "total": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="legacy_rules_present")
        assert len(findings) == 0

    async def test_firewall_api_failure(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api, rules=OPNsenseAPIError("Connection refused"))
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert result["firewall_rules"]["status"] == "skipped"


# ---------------------------------------------------------------------------
# NAT rules tests
# ---------------------------------------------------------------------------


class TestCheckNatRules:
    """Tests for NAT port forwarding section."""

    async def test_dangerous_nat_port(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_nat_rule(dst_port="22")
        _mock_api_calls(
            mock_api,
            nat_rules={"rows": [rule], "rowCount": 1, "total": 1},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="dangerous_nat_port")
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    async def test_nat_insecure_protocol(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_nat_rule(dst_port="23")  # Telnet
        _mock_api_calls(
            mock_api,
            nat_rules={"rows": [rule], "rowCount": 1, "total": 1},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="nat_insecure_protocol")
        assert len(findings) == 1

    async def test_nat_unrestricted_source(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_nat_rule(source_net="any", dst_port="8080")
        _mock_api_calls(
            mock_api,
            nat_rules={"rows": [rule], "rowCount": 1, "total": 1},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="nat_unrestricted_source")
        assert len(findings) == 1

    async def test_nat_broad_port_range(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_nat_rule(dst_port="8000-9000", source_net="10.0.0.0/8")
        _mock_api_calls(
            mock_api,
            nat_rules={"rows": [rule], "rowCount": 1, "total": 1},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="nat_broad_port_range")
        assert len(findings) == 1

    async def test_nat_udp_amplification(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_nat_rule(dst_port="53", protocol="udp", source_net="10.0.0.0/8")
        _mock_api_calls(
            mock_api,
            nat_rules={"rows": [rule], "rowCount": 1, "total": 1},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="nat_udp_amplification")
        assert len(findings) == 1

    async def test_nat_nordr_rule_skipped(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        """Deny/nordr NAT rules should not generate findings."""
        rule = _make_nat_rule(source_net="any", dst_port="22", type="nordr")
        _mock_api_calls(
            mock_api,
            nat_rules={"rows": [rule], "rowCount": 1, "total": 1},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert len(_find_findings(result, check="nat_unrestricted_source")) == 0
        assert len(_find_findings(result, check="dangerous_nat_port")) == 0

    async def test_nat_block_rule_skipped(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        """Block NAT rules should not generate findings."""
        rule = _make_nat_rule(source_net="any", dst_port="22", type="block")
        _mock_api_calls(
            mock_api,
            nat_rules={"rows": [rule], "rowCount": 1, "total": 1},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert len(_find_findings(result, check="nat_unrestricted_source")) == 0

    async def test_nat_disabled_rule_skipped(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        """Disabled NAT rules should not generate findings."""
        rule = _make_nat_rule(source_net="any", dst_port="22", enabled="0")
        _mock_api_calls(
            mock_api,
            nat_rules={"rows": [rule], "rowCount": 1, "total": 1},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert len(_find_findings(result, check="nat_unrestricted_source")) == 0
        assert len(_find_findings(result, check="dangerous_nat_port")) == 0

    async def test_nat_safe_rule(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        rule = _make_nat_rule(dst_port="443", source_net="10.0.0.0/8")
        _mock_api_calls(
            mock_api,
            nat_rules={"rows": [rule], "rowCount": 1, "total": 1},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert result["nat_rules"]["status"] == "ok"
        assert len(_find_findings(result, check="dangerous_nat_port")) == 0

    async def test_nat_api_failure(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api, nat_rules=OPNsenseAPIError("NAT API error"))
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert result["nat_rules"]["status"] == "skipped"


# ---------------------------------------------------------------------------
# DNS security tests
# ---------------------------------------------------------------------------


class TestCheckDnsSecurity:
    """Tests for DNS resolver security section."""

    async def test_dnssec_disabled(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            unbound_settings={"unbound": {"general": {"dnssec": "0", "hideidentity": "1", "hideversion": "1"}}},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="dnssec_disabled")
        assert len(findings) == 1

    async def test_dns_hide_identity(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            unbound_settings={"unbound": {"general": {"dnssec": "1", "hideidentity": "0", "hideversion": "1"}}},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="dns_hide_identity")
        assert len(findings) == 1

    async def test_dns_hide_version(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            unbound_settings={"unbound": {"general": {"dnssec": "1", "hideidentity": "1", "hideversion": "0"}}},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="dns_hide_version")
        assert len(findings) == 1

    async def test_plaintext_dns_forwarder(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            unbound_forwards={
                "rows": [{"domain": "example.com", "port": "53"}],
                "rowCount": 1,
                "total": 1,
            },
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="plaintext_dns_forwarder")
        assert len(findings) == 1

    async def test_dot_forwarder_no_finding(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            unbound_forwards={
                "rows": [{"domain": "example.com", "port": "853"}],
                "rowCount": 1,
                "total": 1,
            },
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="plaintext_dns_forwarder")
        assert len(findings) == 0

    async def test_no_dns_forwarders(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api)
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="no_dns_forwarders")
        assert len(findings) == 1
        assert findings[0]["severity"] == "info"

    async def test_dns_api_failure(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            unbound_settings=OPNsenseAPIError("Unbound not installed"),
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert result["dns_security"]["status"] == "skipped"


# ---------------------------------------------------------------------------
# System hardening tests
# ---------------------------------------------------------------------------


class TestCheckSystemHardening:
    """Tests for system hardening section."""

    async def test_webgui_no_https(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api)
        _setup_config_cache(
            mock_ctx,
            sections={"system": {"webgui": {"protocol": "http"}}},
        )
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="webgui_no_https")
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    async def test_webgui_https_ok(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api)
        _setup_config_cache(
            mock_ctx,
            sections={"system": {"webgui": {"protocol": "https"}}},
        )
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="webgui_no_https")
        assert len(findings) == 0

    async def test_ssh_root_login(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api)
        _setup_config_cache(
            mock_ctx,
            sections={
                "system": {
                    "webgui": {"protocol": "https"},
                    "ssh": {"permitrootlogin": "1"},
                }
            },
        )
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="ssh_root_login")
        assert len(findings) == 1

    async def test_ssh_password_auth(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api)
        _setup_config_cache(
            mock_ctx,
            sections={
                "system": {
                    "webgui": {"protocol": "https"},
                    "ssh": {"passwordauth": "1", "port": "2222"},
                }
            },
        )
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="ssh_password_auth")
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"
        assert "PCI-DSS-2.1" in findings[0].get("compliance", [])

    async def test_ssh_default_port(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api)
        _setup_config_cache(
            mock_ctx,
            sections={
                "system": {
                    "webgui": {"protocol": "https"},
                    "ssh": {"port": "22"},
                }
            },
        )
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="ssh_default_port")
        assert len(findings) == 1

    async def test_no_remote_syslog(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api)
        _setup_config_cache(
            mock_ctx,
            sections={"system": {"webgui": {"protocol": "https"}}},
        )
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="no_remote_syslog")
        assert len(findings) == 1

    async def test_remote_syslog_present(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api)
        _setup_config_cache(
            mock_ctx,
            sections={
                "system": {"webgui": {"protocol": "https"}},
                "syslog": {"remoteserver": "10.0.0.100"},
            },
        )
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="no_remote_syslog")
        assert len(findings) == 0

    async def test_config_not_loaded(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api)
        # Don't call _setup_config_cache — cache not loaded
        result = await opn_security_audit(mock_ctx)
        assert result["system_hardening"]["status"] == "skipped"


# ---------------------------------------------------------------------------
# Services tests
# ---------------------------------------------------------------------------


class TestCheckServices:
    """Tests for services section."""

    async def test_stopped_critical_service(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        svcs = [
            _make_service(name="unbound", running=0),
            _make_service(name="pf", running=1),
        ]
        _mock_api_calls(mock_api, services={"rows": svcs, "rowCount": 2})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="service_stopped")
        assert len(findings) == 1
        assert findings[0]["service"] == "unbound"

    async def test_expanded_critical_services(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        svcs = [_make_service(name="dpinger", running=0)]
        _mock_api_calls(mock_api, services={"rows": svcs, "rowCount": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="service_stopped")
        assert len(findings) == 1

    async def test_ignores_stopped_non_critical(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        svcs = [_make_service(name="squid", running=0)]
        _mock_api_calls(mock_api, services={"rows": svcs, "rowCount": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="service_stopped")
        assert len(findings) == 0

    async def test_crowdsec_not_running(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        svcs = [_make_service(name="crowdsec", running=0)]
        _mock_api_calls(mock_api, services={"rows": svcs, "rowCount": 1})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="crowdsec_not_running")
        assert len(findings) == 1
        assert result["services"]["crowdsec_installed"] is True

    async def test_services_api_failure(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api, services=OPNsenseAPIError("Service API error"))
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert result["services"]["status"] == "skipped"


# ---------------------------------------------------------------------------
# Certificates tests
# ---------------------------------------------------------------------------


class TestCheckCertificates:
    """Tests for certificates section."""

    async def test_acme_bad_status(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        certs_data = {
            "rows": [{"name": "example.com", "statusCode": "500"}],
            "rowCount": 1,
        }
        _mock_api_calls(mock_api, certs=certs_data)
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="cert_status")
        assert len(findings) == 1

    async def test_acme_plugin_missing(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api, certs=OPNsenseAPIError("HTTP 404", status_code=404))
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert result["certificates"]["status"] == "skipped"

    async def test_no_acme_certs(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api, certs={"rows": [], "rowCount": 0})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="no_acme_certs")
        assert len(findings) == 1
        assert findings[0]["severity"] == "info"

    async def test_system_cert_count(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api)
        _setup_config_cache(
            mock_ctx,
            sections={"cert": [{"descr": "cert1"}, {"descr": "cert2"}]},
        )
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="system_cert_count")
        assert len(findings) == 1
        assert findings[0]["count"] == 2

    async def test_ca_count(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api)
        _setup_config_cache(
            mock_ctx,
            sections={"ca": [{"descr": "My CA"}]},
        )
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="ca_count")
        assert len(findings) == 1
        assert findings[0]["count"] == 1

    async def test_purchased_certs_not_alarming(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api, certs={"rows": [], "rowCount": 0})
        _setup_config_cache(
            mock_ctx,
            sections={"cert": [{"descr": "Purchased cert"}]},
        )
        result = await opn_security_audit(mock_ctx)
        # no_acme_certs should be info (not warning)
        findings = _find_findings(result, check="no_acme_certs")
        assert findings[0]["severity"] == "info"
        # System cert counted
        cert_findings = _find_findings(result, check="system_cert_count")
        assert len(cert_findings) == 1


# ---------------------------------------------------------------------------
# VPN security tests
# ---------------------------------------------------------------------------


class TestCheckVpnSecurity:
    """Tests for VPN security section."""

    async def test_wireguard_active(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            wireguard_show={"items": [{"name": "wg0", "peers": []}]},
            wireguard_servers={"rows": [{"name": "wg0"}], "rowCount": 1, "total": 1},
            wireguard_clients={"rows": [{"name": "peer1"}], "rowCount": 1, "total": 1},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="vpn_wireguard_status")
        assert len(findings) == 1

    async def test_wireguard_stale_peer(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            wireguard_show={
                "items": [
                    {
                        "name": "wg0",
                        "peers": [{"name": "stale-peer", "latest-handshake": "5 minutes ago"}],
                    }
                ]
            },
            wireguard_servers={"rows": [{"name": "wg0"}], "rowCount": 1, "total": 1},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="wg_stale_peer")
        assert len(findings) == 1

    async def test_ipsec_status(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api, ipsec_status={"status": "running"})
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="vpn_ipsec_status")
        assert len(findings) == 1

    async def test_openvpn_instances(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            openvpn_instances={
                "rows": [{"description": "vpn1"}],
                "rowCount": 1,
            },
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="vpn_openvpn_status")
        assert len(findings) == 1

    async def test_no_vpn_configured(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api)
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="no_vpn_configured")
        assert len(findings) == 1
        assert findings[0]["severity"] == "info"

    async def test_vpn_all_fail_gracefully(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        err = OPNsenseAPIError("Connection refused")
        _mock_api_calls(
            mock_api,
            wireguard_show=err,
            ipsec_status=err,
            openvpn_instances=err,
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert result["vpn_security"]["status"] == "ok"

    async def test_wireguard_active_via_rows_key(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        """WireGuard response may use 'rows' instead of 'items'."""
        _mock_api_calls(
            mock_api,
            wireguard_show={"rows": [{"name": "wg0", "peers": []}], "rowCount": 1},
            wireguard_servers={"rows": [{"name": "wg0"}], "rowCount": 1, "total": 1},
            wireguard_clients={"rows": [{"name": "peer1"}], "rowCount": 1, "total": 1},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="vpn_wireguard_status")
        assert len(findings) == 1
        # Should NOT report no_vpn_configured
        assert len(_find_findings(result, check="no_vpn_configured")) == 0

    async def test_wireguard_seconds_ago_not_stale(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            wireguard_show={
                "items": [
                    {
                        "name": "wg0",
                        "peers": [{"name": "active", "latest-handshake": "30 seconds ago"}],
                    }
                ]
            },
            wireguard_servers={"rows": [{"name": "wg0"}], "rowCount": 1, "total": 1},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="wg_stale_peer")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# HAProxy tests
# ---------------------------------------------------------------------------

# Reusable SSL frontend fixture (avoids long lines)
_FE_SSL: dict[str, Any] = {
    "rows": [{"name": "fe1", "bind": ":443", "ssl": "1"}],
    "rowCount": 1,
    "total": 1,
}


class TestCheckHaproxySecurity:
    """Tests for HAProxy reverse proxy section."""

    async def test_haproxy_not_installed(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api)  # Default: haproxy_frontends = 404
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert result["haproxy"]["status"] == "skipped"

    async def test_haproxy_summary(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            haproxy_frontends={"rows": [{"name": "fe1", "bind": ":443", "ssl": "1"}], "rowCount": 1, "total": 1},
            haproxy_backends={"rows": [{"name": "be1", "healthCheck": "http"}], "rowCount": 1, "total": 1},
            haproxy_servers={"rows": [{"name": "srv1"}], "rowCount": 1, "total": 1},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="haproxy_summary")
        assert len(findings) == 1

    async def test_haproxy_http_frontend(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            haproxy_frontends={
                "rows": [{"name": "http-fe", "bind": ":80", "ssl": "0", "mode": "http"}],
                "rowCount": 1,
                "total": 1,
            },
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="haproxy_http_frontend")
        assert len(findings) == 1

    async def test_haproxy_no_healthcheck(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        be = {"name": "be1", "healthCheck": "", "healthCheckEnabled": "0"}
        _mock_api_calls(
            mock_api,
            haproxy_frontends=_FE_SSL,
            haproxy_backends={"rows": [be], "rowCount": 1, "total": 1},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="haproxy_no_healthcheck")
        assert len(findings) == 1
        assert "disabled" in findings[0]["message"]

    async def test_haproxy_missing_headers(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            haproxy_frontends={"rows": [{"name": "fe1", "bind": ":443", "ssl": "1"}], "rowCount": 1, "total": 1},
            haproxy_actions={"rows": [], "rowCount": 0, "total": 0},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="haproxy_missing_headers")
        assert len(findings) == 1
        assert "strict-transport-security" in findings[0]["missing"]

    async def test_haproxy_headers_present(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        actions = [
            {"testType": "http-response", "hdr_name": "Strict-Transport-Security"},
            {"testType": "http-response", "hdr_name": "X-Frame-Options"},
            {"testType": "http-response", "hdr_name": "X-Content-Type-Options"},
        ]
        _mock_api_calls(
            mock_api,
            haproxy_frontends={"rows": [{"name": "fe1", "bind": ":443", "ssl": "1"}], "rowCount": 1, "total": 1},
            haproxy_actions={"rows": actions, "rowCount": 3, "total": 3},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="haproxy_missing_headers")
        assert len(findings) == 0

    async def test_haproxy_ssl_frontend_not_http(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            haproxy_frontends={
                "rows": [{"name": "ssl-fe", "bind": ":443", "ssl": "1", "mode": "http"}],
                "rowCount": 1,
                "total": 1,
            },
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="haproxy_http_frontend")
        assert len(findings) == 0

    async def test_haproxy_backend_with_healthcheck(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        """Backend with healthCheckEnabled=1 and a named check reference — no warnings."""
        be = {"name": "be1", "healthCheck": "http", "healthCheckEnabled": "1"}
        _mock_api_calls(
            mock_api,
            haproxy_frontends=_FE_SSL,
            haproxy_backends={"rows": [be], "rowCount": 1, "total": 1},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert len(_find_findings(result, check="haproxy_no_healthcheck")) == 0
        assert len(_find_findings(result, check="haproxy_default_healthcheck")) == 0

    async def test_haproxy_default_healthcheck_info(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        """Backend with healthCheckEnabled=1 but no named check — info-level finding."""
        be = {"name": "be1", "healthCheck": "", "healthCheckEnabled": "1"}
        _mock_api_calls(
            mock_api,
            haproxy_frontends=_FE_SSL,
            haproxy_backends={"rows": [be], "rowCount": 1, "total": 1},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert len(_find_findings(result, check="haproxy_no_healthcheck")) == 0
        findings = _find_findings(result, check="haproxy_default_healthcheck")
        assert len(findings) == 1
        assert findings[0]["severity"] == "info"


# ---------------------------------------------------------------------------
# Gateway tests
# ---------------------------------------------------------------------------


class TestCheckGateways:
    """Tests for gateway health section."""

    async def test_healthy_gateway(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            gateway_status={"items": [_make_gateway(status="online", loss="0.0%", delay="5.0ms")]},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert len(_find_findings(result, check="gateway_down")) == 0
        assert len(_find_findings(result, check="gateway_high_loss")) == 0

    async def test_gateway_down(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            gateway_status={"items": [_make_gateway(status="down")]},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="gateway_down")
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    async def test_gateway_none_status_online(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        """OPNsense returns status='none' with status_translated='Online' for reachable gateways."""
        _mock_api_calls(
            mock_api,
            gateway_status={
                "items": [
                    _make_gateway(status="none", status_translated="Online"),
                ]
            },
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert len(_find_findings(result, check="gateway_down")) == 0

    async def test_gateway_none_status_no_translation(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        """status='none' without 'Online' translation should still flag as down."""
        _mock_api_calls(
            mock_api,
            gateway_status={"items": [_make_gateway(status="none")]},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="gateway_down")
        assert len(findings) == 1

    async def test_gateway_high_loss(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            gateway_status={"items": [_make_gateway(loss="10.5%")]},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="gateway_high_loss")
        assert len(findings) == 1

    async def test_gateway_high_latency(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            gateway_status={"items": [_make_gateway(delay="150.3ms")]},
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        findings = _find_findings(result, check="gateway_high_latency")
        assert len(findings) == 1

    async def test_gateway_api_failure(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api, gateway_status=OPNsenseAPIError("Gateway API error"))
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        assert result["gateways"]["status"] == "skipped"


# ---------------------------------------------------------------------------
# Integration / summary tests
# ---------------------------------------------------------------------------


class TestIntegration:
    """End-to-end audit tests."""

    async def test_full_clean_audit(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(
            mock_api,
            services={
                "rows": [_make_service(name="unbound", running=1)],
                "rowCount": 1,
            },
        )
        _setup_config_cache(
            mock_ctx,
            sections={"system": {"webgui": {"protocol": "https"}}},
        )
        result = await opn_security_audit(mock_ctx)
        assert result["summary"]["critical"] == 0
        assert "sections_checked" in result["summary"]
        assert result["summary"]["sections_checked"] == 10

    async def test_all_sections_fail_gracefully(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        err = OPNsenseAPIError("Connection refused")
        _mock_api_calls(
            mock_api,
            firmware=err,
            rules=err,
            nat_rules=err,
            services=err,
            certs=err,
            unbound_settings=err,
            gateway_status=err,
            wireguard_show=err,
            ipsec_status=err,
            openvpn_instances=err,
            haproxy_frontends=err,
        )
        # No config cache loaded
        result = await opn_security_audit(mock_ctx)
        assert result["summary"]["total_findings"] >= 0
        # Multiple sections skipped
        assert result["summary"]["sections_skipped"] >= 4

    async def test_summary_aggregation(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        """Combine findings from multiple sections and verify counts."""
        permissive = _make_rule(description="Allow all", uuid="perm-1")
        _mock_api_calls(
            mock_api,
            firmware={
                "product_version": "25.1.2",
                "product_name": "OPNsense",
                "upgrade_sets": "25.7",
            },
            rules={"rows": [permissive], "rowCount": 1, "total": 1},
            services={
                "rows": [_make_service(name="unbound", running=0)],
                "rowCount": 1,
            },
            certs=OPNsenseAPIError("HTTP 404", status_code=404),
        )
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)

        summary = result["summary"]
        assert summary["critical"] >= 1
        assert summary["warning"] >= 1
        assert summary["total_findings"] >= 3

    async def test_section_count(self, mock_api: MagicMock, mock_ctx: MagicMock) -> None:
        _mock_api_calls(mock_api)
        _setup_config_cache(mock_ctx)
        result = await opn_security_audit(mock_ctx)
        # Should have all 10 sections
        for section in _ALL_SECTIONS:
            assert section in result, f"Missing section: {section}"
