"""Tests for SafeYolo's packaged Unix listener mode.

Focus on the parts we can unit-test without a running mitmproxy:
  - `_parse_sock_path` (directory → (ip, agent)) handles valid / invalid
  - `UnixMode.__post_init__` validates the `data` field (the socket path)
  - `UnixMode.ip` / `UnixMode.agent` properties expose parsed values

Lifecycle tests (`_start`, `handle_stream`) need a live mitmproxy master
and are exercised by the blackbox end-to-end suite rather than here.
"""
from __future__ import annotations

import pytest

pytest.importorskip("mitmproxy", reason="unix_listener depends on mitmproxy")

from safeyolo.proxy_modes import unix_listener  # noqa: E402


class TestParseSockPath:
    def test_valid(self):
        ip, agent = unix_listener._parse_sock_path("/s/10.0.0.1_alice/proxy.sock")
        assert (ip, agent) == ("10.0.0.1", "alice")

    def test_hyphen_in_agent(self):
        ip, agent = unix_listener._parse_sock_path("/s/10.0.0.1_my-agent/proxy.sock")
        assert agent == "my-agent"

    def test_rejects_missing_sock(self):
        with pytest.raises(ValueError):
            unix_listener._parse_sock_path("/s/10.0.0.1_alice.unix")

    def test_rejects_no_underscore(self):
        with pytest.raises(ValueError):
            unix_listener._parse_sock_path("/s/10.0.0.1-alice/proxy.sock")

    def test_rejects_bad_ip(self):
        with pytest.raises(ValueError):
            unix_listener._parse_sock_path("/s/999.0.0.1_alice/proxy.sock")


class TestUnixMode:
    def test_parse_registers_mode(self):
        from mitmproxy.proxy import mode_specs

        mode = mode_specs.ProxyMode.parse("unix:/tmp/10.200.0.5_alice/proxy.sock")
        assert isinstance(mode, unix_listener.UnixMode)
        assert mode.path == "/tmp/10.200.0.5_alice/proxy.sock"
        assert mode.ip == "10.200.0.5"
        assert mode.agent == "alice"

    def test_rejects_relative_path(self):
        from mitmproxy.proxy import mode_specs

        with pytest.raises(ValueError, match="absolute path"):
            mode_specs.ProxyMode.parse("unix:relative/10.0.0.1_alice/proxy.sock")

    def test_rejects_missing_data(self):
        from mitmproxy.proxy import mode_specs

        with pytest.raises(ValueError):
            mode_specs.ProxyMode.parse("unix:")

    def test_transport_protocol_is_tcp(self):
        from mitmproxy.proxy import mode_specs

        mode = mode_specs.ProxyMode.parse("unix:/tmp/10.200.0.5_bob/proxy.sock")
        assert mode.transport_protocol == "tcp"


class TestUnixUpstreamMode:
    def test_explicit_parent_uses_native_upstream_http_layer(self, monkeypatch):
        from mitmproxy import connection, options
        from mitmproxy.proxy import mode_specs
        from mitmproxy.proxy.context import Context
        from mitmproxy.proxy.layers import modes

        monkeypatch.setenv("SAFEYOLO_UPSTREAM_PROXY", "http://127.0.0.1:8080")
        unix_mode = mode_specs.ProxyMode.parse(
            "unix:/tmp/10.200.0.8_nested-agent/proxy.sock"
        )
        client = connection.Client(
            peername=("10.200.0.8", 0),
            sockname=("127.0.0.1", 0),
            proxy_mode=unix_mode,
        )
        context = Context(client, options.Options())

        instance = type("Instance", (), {"mode": unix_mode})()
        layer = unix_listener.UnixInstance.make_top_layer(instance, context)

        assert isinstance(layer, modes.HttpUpstreamProxy)
        assert isinstance(context.client.proxy_mode, mode_specs.UpstreamMode)
        assert context.client.proxy_mode.address == ("127.0.0.1", 8080)
        # The UDS-derived attribution identity remains unchanged.
        assert context.client.peername == ("10.200.0.8", 0)
        assert context.client.proxy_mode.agent == "nested-agent"

    def test_no_parent_keeps_regular_http_layer(self, monkeypatch):
        from mitmproxy import connection, options
        from mitmproxy.proxy import mode_specs
        from mitmproxy.proxy.context import Context
        from mitmproxy.proxy.layers import modes

        monkeypatch.delenv("SAFEYOLO_UPSTREAM_PROXY", raising=False)
        unix_mode = mode_specs.ProxyMode.parse(
            "unix:/tmp/10.200.0.9_plain-agent/proxy.sock"
        )
        context = Context(
            connection.Client(
                peername=("10.200.0.9", 0),
                sockname=("127.0.0.1", 0),
                proxy_mode=unix_mode,
            ),
            options.Options(),
        )

        instance = type("Instance", (), {"mode": unix_mode})()
        layer = unix_listener.UnixInstance.make_top_layer(instance, context)

        assert isinstance(layer, modes.HttpProxy)
        assert isinstance(context.client.proxy_mode, unix_listener.UnixMode)
