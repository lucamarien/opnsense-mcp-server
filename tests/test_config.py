"""Tests for configuration loading and validation."""

from __future__ import annotations

import dataclasses
from unittest.mock import patch

import pytest

from opnsense_mcp.config import ConfigError, load_config


class TestLoadConfig:
    """Tests for the load_config function."""

    def test_load_valid_config(self, env_vars):
        config = load_config()
        assert config.url == "https://10.0.0.1/api"
        assert config.api_key == "test-key-abc123"
        assert config.api_secret == "test-secret-xyz789"
        assert config.verify_ssl is False
        assert config.allow_writes is False

    def test_missing_url_raises_error(self):
        env = {
            "OPNSENSE_API_KEY": "key",
            "OPNSENSE_API_SECRET": "secret",
        }
        with patch.dict("os.environ", env, clear=True):
            with pytest.raises(ConfigError, match="OPNSENSE_URL"):
                load_config()

    def test_missing_api_key_raises_error(self):
        env = {
            "OPNSENSE_URL": "https://10.0.0.1/api",
            "OPNSENSE_API_SECRET": "secret",
        }
        with patch.dict("os.environ", env, clear=True):
            with pytest.raises(ConfigError, match="OPNSENSE_API_KEY"):
                load_config()

    def test_missing_api_secret_raises_error(self):
        env = {
            "OPNSENSE_URL": "https://10.0.0.1/api",
            "OPNSENSE_API_KEY": "key",
        }
        with patch.dict("os.environ", env, clear=True):
            with pytest.raises(ConfigError, match="OPNSENSE_API_SECRET"):
                load_config()

    def test_missing_multiple_vars_lists_all(self):
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ConfigError) as exc_info:
                load_config()
            msg = str(exc_info.value)
            assert "OPNSENSE_URL" in msg
            assert "OPNSENSE_API_KEY" in msg
            assert "OPNSENSE_API_SECRET" in msg

    def test_empty_url_raises_error(self):
        env = {
            "OPNSENSE_URL": "   ",
            "OPNSENSE_API_KEY": "key",
            "OPNSENSE_API_SECRET": "secret",
        }
        with patch.dict("os.environ", env, clear=True):
            with pytest.raises(ConfigError, match="OPNSENSE_URL"):
                load_config()

    def test_url_trailing_slash_stripped(self, env_vars):
        with patch.dict("os.environ", {"OPNSENSE_URL": "https://10.0.0.1/api/"}):
            config = load_config()
        assert config.url == "https://10.0.0.1/api"

    def test_url_multiple_trailing_slashes_stripped(self, env_vars):
        with patch.dict("os.environ", {"OPNSENSE_URL": "https://10.0.0.1/api///"}):
            config = load_config()
        assert config.url == "https://10.0.0.1/api"


class TestVerifySsl:
    """Tests for OPNSENSE_VERIFY_SSL parsing."""

    def _load_with_ssl(self, value: str | None):
        env = {
            "OPNSENSE_URL": "https://10.0.0.1/api",
            "OPNSENSE_API_KEY": "key",
            "OPNSENSE_API_SECRET": "secret",
        }
        if value is not None:
            env["OPNSENSE_VERIFY_SSL"] = value
        with patch.dict("os.environ", env, clear=True):
            return load_config()

    def test_default_true(self):
        config = self._load_with_ssl(None)
        assert config.verify_ssl is True

    def test_true(self):
        config = self._load_with_ssl("true")
        assert config.verify_ssl is True

    def test_false(self):
        config = self._load_with_ssl("false")
        assert config.verify_ssl is False

    def test_one(self):
        config = self._load_with_ssl("1")
        assert config.verify_ssl is True

    def test_zero(self):
        config = self._load_with_ssl("0")
        assert config.verify_ssl is False

    def test_yes(self):
        config = self._load_with_ssl("yes")
        assert config.verify_ssl is True

    def test_no(self):
        config = self._load_with_ssl("no")
        assert config.verify_ssl is False

    def test_case_insensitive(self):
        config = self._load_with_ssl("TRUE")
        assert config.verify_ssl is True

    def test_invalid_raises_error(self):
        with pytest.raises(ConfigError, match="OPNSENSE_VERIFY_SSL"):
            self._load_with_ssl("maybe")


class TestAllowWrites:
    """Tests for OPNSENSE_ALLOW_WRITES parsing."""

    def _load_with_writes(self, value: str | None):
        env = {
            "OPNSENSE_URL": "https://10.0.0.1/api",
            "OPNSENSE_API_KEY": "key",
            "OPNSENSE_API_SECRET": "secret",
        }
        if value is not None:
            env["OPNSENSE_ALLOW_WRITES"] = value
        with patch.dict("os.environ", env, clear=True):
            return load_config()

    def test_default_false(self):
        config = self._load_with_writes(None)
        assert config.allow_writes is False

    def test_true(self):
        config = self._load_with_writes("true")
        assert config.allow_writes is True

    def test_false(self):
        config = self._load_with_writes("false")
        assert config.allow_writes is False

    def test_invalid_raises_error(self):
        with pytest.raises(ConfigError, match="OPNSENSE_ALLOW_WRITES"):
            self._load_with_writes("sometimes")


class TestConfigFrozen:
    """Tests that the config object is immutable."""

    def test_cannot_modify_url(self, env_vars):
        config = load_config()
        with pytest.raises(dataclasses.FrozenInstanceError):
            config.url = "https://evil.example.com"  # type: ignore[misc]
