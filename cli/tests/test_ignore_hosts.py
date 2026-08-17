"""Tests for exact operator-managed TLS passthrough hosts."""

from unittest.mock import MagicMock, patch

import pytest
import yaml

from safeyolo.cli import app
from safeyolo.ignore_hosts import (
    BUILTIN_IGNORE_PATTERNS,
    build_ignore_patterns,
    ignore_host_to_regex,
    normalize_ignore_host,
    normalize_ignore_hosts,
)


class TestNormalizeIgnoreHost:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("Service.Example.Test", "service.example.test"),
            (" service.example.test:443 ", "service.example.test:443"),
            ("192.0.2.10", "192.0.2.10"),
            ("192.0.2.10:8443", "192.0.2.10:8443"),
        ],
    )
    def test_canonicalizes_exact_entries(self, value, expected):
        assert normalize_ignore_host(value) == expected

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "*.example.test",
            "https://service.example.test",
            "service.example.test/path",
            "service_example.test",
            "service.example.test:0",
            "service.example.test:65536",
            "service.example.test:https",
            "2001:db8::1",
            "999.999.999.999",
        ],
    )
    def test_rejects_broad_or_malformed_entries(self, value):
        with pytest.raises(ValueError):
            normalize_ignore_host(value)

    def test_list_is_deduplicated_after_canonicalization(self):
        assert normalize_ignore_hosts(
            ["SERVICE.EXAMPLE.TEST:443", "service.example.test:443"]
        ) == ["service.example.test:443"]

    def test_rejects_non_list_config(self):
        with pytest.raises(ValueError, match="must be a list"):
            normalize_ignore_hosts("service.example.test")


class TestIgnorePatterns:
    def test_host_without_port_matches_any_numeric_port(self):
        assert ignore_host_to_regex("service.example.test") == (
            r"^service\.example\.test(?::\d+)?$"
        )

    def test_host_with_port_is_exact(self):
        assert ignore_host_to_regex("service.example.test:443") == (
            r"^service\.example\.test:443$"
        )

    def test_complete_list_includes_builtin_cidr_and_operator_entries(self, monkeypatch):
        monkeypatch.setenv("SAFEYOLO_IGNORE_CIDRS", "192.0.2.0/24")
        patterns = build_ignore_patterns(["service.example.test:443"])
        assert patterns[0] == BUILTIN_IGNORE_PATTERNS[0]
        assert r"^192\.0\.2\.\d+(?::\d+)?$" in patterns
        assert r"^service\.example\.test:443$" in patterns


class TestIgnoreHostCLI:
    def test_add_persists_for_next_start(self, cli_runner, tmp_config_dir):
        with patch("safeyolo.commands.proxy.is_proxy_running", return_value=False):
            result = cli_runner.invoke(
                app, ["proxy", "ignore-host", "add", "Service.Example.Test:443"]
            )

        assert result.exit_code == 0
        assert "service.example.test:443" in result.output
        assert "applies on next start" in result.output
        config = yaml.safe_load((tmp_config_dir / "config.yaml").read_text())
        assert config["proxy"]["ignore_hosts"] == ["service.example.test:443"]
        assert not list(tmp_config_dir.glob(".config.yaml.*.tmp"))

    def test_add_hot_reloads_running_proxy(self, cli_runner, tmp_config_dir):
        with (
            patch("safeyolo.commands.proxy.is_proxy_running", return_value=True),
            patch("safeyolo.commands.proxy.sync_proxy_ignore_hosts", return_value=True) as sync,
        ):
            result = cli_runner.invoke(
                app, ["proxy", "ignore-host", "add", "service.example.test"]
            )

        assert result.exit_code == 0
        assert "applied to running proxy" in result.output
        sync.assert_called_once_with(["service.example.test"], admin_port=9090)

    def test_sync_failure_is_loud_but_keeps_persisted_config(
        self, cli_runner, tmp_config_dir
    ):
        with (
            patch("safeyolo.commands.proxy.is_proxy_running", return_value=True),
            patch("safeyolo.commands.proxy.sync_proxy_ignore_hosts", return_value=False),
        ):
            result = cli_runner.invoke(
                app, ["proxy", "ignore-host", "add", "service.example.test:443"]
            )

        assert result.exit_code == 1
        assert "could not be updated" in result.output
        config = yaml.safe_load((tmp_config_dir / "config.yaml").read_text())
        assert config["proxy"]["ignore_hosts"] == ["service.example.test:443"]

    def test_remove_and_list(self, cli_runner, tmp_config_dir):
        config_path = tmp_config_dir / "config.yaml"
        config = yaml.safe_load(config_path.read_text())
        config["proxy"]["ignore_hosts"] = ["service.example.test:443"]
        config_path.write_text(yaml.safe_dump(config, sort_keys=False))

        listed = cli_runner.invoke(app, ["proxy", "ignore-host", "list"])
        assert listed.exit_code == 0
        assert "service.example.test:443" in listed.output

        with patch("safeyolo.commands.proxy.is_proxy_running", return_value=False):
            removed = cli_runner.invoke(
                app, ["proxy", "ignore-host", "remove", "service.example.test:443"]
            )
        assert removed.exit_code == 0
        config = yaml.safe_load(config_path.read_text())
        assert config["proxy"]["ignore_hosts"] == []


class TestSyncProxyIgnoreHosts:
    def test_sends_normalized_hosts_to_authenticated_admin_endpoint(
        self, tmp_config_dir, monkeypatch
    ):
        from safeyolo.proxy import sync_proxy_ignore_hosts

        (tmp_config_dir / "data" / "admin_token").write_text("operator-token")
        response = MagicMock(status_code=200, text="ok")
        put = MagicMock(return_value=response)
        monkeypatch.setattr("httpx.put", put)

        assert sync_proxy_ignore_hosts(["Service.Example.Test:443"], admin_port=9191)
        put.assert_called_once_with(
            "http://127.0.0.1:9191/admin/proxy/ignore-hosts",
            json={"hosts": ["service.example.test:443"]},
            headers={"Authorization": "Bearer operator-token"},
            timeout=5.0,
        )
