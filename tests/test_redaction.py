"""Redaction of every secret-bearing tag in a realistic config.xml fixture."""

from __future__ import annotations

import json
import re
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.config_cache import ConfigCache, is_sensitive_tag
from opnsense_mcp.tools.system import opn_download_config

_FIXTURE = (Path(__file__).parent / "fixtures" / "sensitive_config.xml").read_text()
_CANARIES = re.findall(r">(CANARY-[^<]+)<", _FIXTURE)
_VISIBLE = re.findall(r">(VISIBLE-[^<]+)<", _FIXTURE)
_SECRET_TAGS = sorted(set(re.findall(r"<([\w.-]+)>CANARY-", _FIXTURE)))
_VISIBLE_TAGS = sorted(set(re.findall(r"<([\w.-]+)>VISIBLE-", _FIXTURE)))

# Secret tags the exact list + substring + *key rules let through
_PREVIOUSLY_MISSED = (
    "prv",
    "authorizedkeys",
    "otp_seed",
    "ldap_bindpw",
    "passphrase",
    "keys",
    "tls",
    "auth_pass",
    "keydata",
    "psk",
    "encryptionpsk",
    "community",
    "eab_hmac",
    "dns_netcup_pw",
    "dns_pleskxml_pass",
    "dns_kas_authdata",
    "basicauthpass",
)


def test_fixture_covers_every_previously_missed_tag():
    assert set(_PREVIOUSLY_MISSED) <= set(_SECRET_TAGS)


@pytest.mark.parametrize("tag", _SECRET_TAGS)
def test_secret_tag_is_sensitive(tag):
    assert is_sensitive_tag(tag)


@pytest.mark.parametrize("tag", _VISIBLE_TAGS)
def test_visible_tag_is_not_sensitive(tag):
    assert not is_sensitive_tag(tag)


@pytest.mark.parametrize("tag", ["pass", "bypass", "enableRosenpass", "logdefaultpass", "tls4", "communitylists"])
def test_lookalike_settings_are_not_sensitive(tag):
    assert not is_sensitive_tag(tag)


class TestDownloadConfigRedaction:
    async def test_no_secret_survives(self, mock_api, mock_ctx):
        mock_api.get_text = AsyncMock(return_value=_FIXTURE)

        result = await opn_download_config(mock_ctx)

        assert result["stripped"] is True
        assert [c for c in _CANARIES if c in result["config_xml"]] == []

    async def test_non_secrets_survive(self, mock_api, mock_ctx):
        mock_api.get_text = AsyncMock(return_value=_FIXTURE)

        result = await opn_download_config(mock_ctx)

        assert [v for v in _VISIBLE if v not in result["config_xml"]] == []


class TestConfigSectionRedaction:
    def test_no_secret_survives_any_section(self):
        cache = ConfigCache()
        cache._parse_xml(_FIXTURE)

        dumped = json.dumps([cache.get_section(name) for name in cache.available_sections()])

        assert [c for c in _CANARIES if c in dumped] == []
        assert [v for v in _VISIBLE if v not in dumped] == []
