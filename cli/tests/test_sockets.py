"""Tests for the socket-path helpers (cli/src/safeyolo/sockets.py)."""
from __future__ import annotations

import socket

import pytest

from safeyolo.sockets import _SUN_PATH_MAX, parse, path_for, remove_stale_sockets


class TestPathFor:
    """`path_for(agent, ip)` round-trips with `parse()` and validates inputs."""

    def test_happy_path(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        p = path_for("alice", "10.200.0.5")
        assert p.name == "proxy.sock"
        assert p.parent.name == "10.200.0.5_alice"
        assert p.parent.parent.name == "sockets"

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
        ip, agent = parse("/any/where/10.200.0.5_alice/proxy.sock")
        assert ip == "10.200.0.5"
        assert agent == "alice"

    def test_agent_name_with_hyphen(self):
        ip, agent = parse("/s/10.200.0.5_my-agent/proxy.sock")
        assert agent == "my-agent"

    def test_missing_sock_suffix(self):
        with pytest.raises(ValueError, match="proxy.sock filename"):
            parse("/s/10.200.0.5_alice.unix")

    def test_missing_underscore(self):
        with pytest.raises(ValueError, match="expected '<ip>_<agent>"):
            parse("/s/10.200.0.5-alice/proxy.sock")

    def test_malformed_ip_in_path(self):
        with pytest.raises(ValueError):
            parse("/s/999.888.777.666_alice/proxy.sock")

    def test_invalid_agent_name_in_path(self):
        with pytest.raises(ValueError, match="invalid agent name"):
            parse("/s/10.0.0.1_Alice/proxy.sock")


def test_remove_stale_sockets_only_removes_socket_inodes(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    directory = tmp_path / "data" / "sockets"
    directory.mkdir(parents=True)
    stale = directory / "10.200.0.1_demo" / "proxy.sock"
    stale.parent.mkdir()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(stale))
    ordinary = directory / "do-not-delete.sock"
    ordinary.write_text("not a socket")
    try:
        assert remove_stale_sockets() == [stale]
    finally:
        listener.close()

    assert not stale.exists()
    assert ordinary.exists()


def test_rebinding_replaces_socket_inside_stable_agent_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    path = path_for("demo", "10.200.0.1")
    path.parent.mkdir(parents=True)
    directory_inode = path.parent.stat().st_ino

    first = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    first.bind(str(path))
    first.close()
    path.unlink()

    second = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        second.bind(str(path))
        assert path.parent.stat().st_ino == directory_inode
        assert path.is_socket()
        assert parse(path) == ("10.200.0.1", "demo")
    finally:
        second.close()


def test_agents_have_distinct_private_socket_directories(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))

    alice = path_for("alice", "10.200.0.1")
    bob = path_for("bob", "10.200.0.2")

    assert alice.parent != bob.parent
    assert alice.parent.parent == bob.parent.parent
