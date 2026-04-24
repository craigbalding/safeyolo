"""Tests for the socket-path helpers (cli/src/safeyolo/sockets.py)."""
from __future__ import annotations

import pytest

from safeyolo.sockets import _SUN_PATH_MAX, parse, path_for


class TestPathFor:
    """`path_for(agent, ip)` round-trips with `parse()` and validates inputs."""

    def test_happy_path(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        p = path_for("alice", "10.200.0.5")
        assert p.name == "10.200.0.5_alice.sock"
        assert p.parent.name == "sockets"

    def test_parse_round_trip(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        p = path_for("my-agent", "10.200.1.2")
        ip, agent = parse(p)
        assert ip == "10.200.1.2"
        assert agent == "my-agent"

    def test_rejects_underscore_in_name(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        with pytest.raises(ValueError, match="invalid agent name"):
            path_for("my_agent", "10.200.0.5")

    def test_rejects_uppercase_in_name(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        with pytest.raises(ValueError, match="invalid agent name"):
            path_for("MyAgent", "10.200.0.5")

    def test_rejects_malformed_ip(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        with pytest.raises(ValueError):
            path_for("alice", "not-an-ip")

    def test_rejects_path_over_sun_limit(self, tmp_path, monkeypatch):
        """Very long home dirs + long agent names trip the sun_path cap."""
        # Cover both platform caps (104 on darwin, 108 elsewhere) by
        # padding well past either — any agent name will bust.
        long_dir = tmp_path / ("x" * 120)
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(long_dir))
        with pytest.raises(ValueError, match="sun_path"):
            path_for("long-agent-name-here", "10.200.0.5")

    def test_sun_path_constant_matches_platform(self):
        # Linux: 108, BSD/macOS: 104. `sockets.py` picks by `sys.platform`.
        import sys
        expected = 104 if sys.platform == "darwin" else 108
        assert _SUN_PATH_MAX == expected


class TestParse:
    """`parse(path)` — independent of `path_for`."""

    def test_valid_path(self):
        ip, agent = parse("/any/where/10.200.0.5_alice.sock")
        assert ip == "10.200.0.5"
        assert agent == "alice"

    def test_agent_name_with_hyphen(self):
        ip, agent = parse("/s/10.200.0.5_my-agent.sock")
        assert agent == "my-agent"

    def test_missing_sock_suffix(self):
        with pytest.raises(ValueError, match=".sock suffix"):
            parse("/s/10.200.0.5_alice.unix")

    def test_missing_underscore(self):
        with pytest.raises(ValueError, match="expected '<ip>_<agent>"):
            parse("/s/10.200.0.5-alice.sock")

    def test_malformed_ip_in_path(self):
        with pytest.raises(ValueError):
            parse("/s/999.888.777.666_alice.sock")

    def test_invalid_agent_name_in_path(self):
        with pytest.raises(ValueError, match="invalid agent name"):
            parse("/s/10.0.0.1_Alice.sock")
