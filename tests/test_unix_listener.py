"""Tests for addons/unix_listener.py.

Focus on the parts we can unit-test without a running mitmproxy:
  - `_parse_sock_path` (filename → (ip, agent)) handles valid / invalid
  - `UnixMode.__post_init__` validates the `data` field (the socket path)
  - `UnixMode.ip` / `UnixMode.agent` properties expose parsed values

Lifecycle tests (`_start`, `handle_stream`) need a live mitmproxy master
and are exercised by the blackbox end-to-end suite rather than here.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make addons/ importable as top-level modules (mitmproxy loads addons
# the same way via `-s <path>`).
ADDONS_DIR = Path(__file__).parent.parent / "addons"
sys.path.insert(0, str(ADDONS_DIR))

pytest.importorskip("mitmproxy", reason="unix_listener depends on mitmproxy")

import unix_listener  # noqa: E402


class TestParseSockPath:
    def test_valid(self):
        ip, agent = unix_listener._parse_sock_path("/s/10.0.0.1_alice.sock")
        assert (ip, agent) == ("10.0.0.1", "alice")

    def test_hyphen_in_agent(self):
        ip, agent = unix_listener._parse_sock_path("/s/10.0.0.1_my-agent.sock")
        assert agent == "my-agent"

    def test_rejects_missing_sock(self):
        with pytest.raises(ValueError):
            unix_listener._parse_sock_path("/s/10.0.0.1_alice.unix")

    def test_rejects_no_underscore(self):
        with pytest.raises(ValueError):
            unix_listener._parse_sock_path("/s/10.0.0.1-alice.sock")

    def test_rejects_bad_ip(self):
        with pytest.raises(ValueError):
            unix_listener._parse_sock_path("/s/999.0.0.1_alice.sock")


class TestUnixMode:
    def test_parse_registers_mode(self):
        from mitmproxy.proxy import mode_specs

        mode = mode_specs.ProxyMode.parse("unix:/tmp/10.200.0.5_alice.sock")
        assert isinstance(mode, unix_listener.UnixMode)
        assert mode.path == "/tmp/10.200.0.5_alice.sock"
        assert mode.ip == "10.200.0.5"
        assert mode.agent == "alice"

    def test_rejects_relative_path(self):
        from mitmproxy.proxy import mode_specs

        with pytest.raises(ValueError, match="absolute path"):
            mode_specs.ProxyMode.parse("unix:relative/10.0.0.1_alice.sock")

    def test_rejects_missing_data(self):
        from mitmproxy.proxy import mode_specs

        with pytest.raises(ValueError):
            mode_specs.ProxyMode.parse("unix:")

    def test_transport_protocol_is_tcp(self):
        from mitmproxy.proxy import mode_specs

        mode = mode_specs.ProxyMode.parse("unix:/tmp/10.200.0.5_bob.sock")
        assert mode.transport_protocol == "tcp"
