"""Tests for ignored-host connection lifecycle audit events."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest


@pytest.fixture
def connection_data():
    return SimpleNamespace(
        server=SimpleNamespace(
            id="server-connection-1",
            peername=("192.0.2.20", 443),
            address=("service.example.test", 443),
            transport_protocol="tcp",
            error=None,
        ),
        client=SimpleNamespace(
            sni="service.example.test",
            peername=("192.0.2.2", 0),
            proxy_mode=SimpleNamespace(agent="test-agent"),
        ),
    )


def test_logs_successful_passthrough_start_and_end(connection_data):
    from ignored_host_logger import IgnoredHostLogger

    addon = IgnoredHostLogger()
    options = SimpleNamespace(ignore_hosts=[r"^service\.example\.test:443$"])
    with (
        patch("ignored_host_logger.ctx.options", options, create=True),
        patch("ignored_host_logger.write_event", autospec=True,) as write_event,
        patch("ignored_host_logger.time.monotonic", side_effect=[10.0, 10.125], autospec=True,),
    ):
        addon.server_connect(connection_data)
        addon.server_connected(connection_data)
        addon.server_disconnected(connection_data)

    assert write_event.call_count == 2
    start = write_event.call_args_list[0]
    assert start.args[0] == "traffic.passthrough_start"
    assert start.kwargs["host"] == "service.example.test"
    assert start.kwargs["agent"] == "test-agent"
    end = write_event.call_args_list[1]
    assert end.args[0] == "traffic.passthrough_end"
    assert end.kwargs["details"]["duration_ms"] == 125


def test_logs_passthrough_connection_error(connection_data):
    from ignored_host_logger import IgnoredHostLogger

    addon = IgnoredHostLogger()
    connection_data.server.error = "connection refused\nunsafe"
    options = SimpleNamespace(ignore_hosts=[r"^service\.example\.test:443$"])
    with (
        patch("ignored_host_logger.ctx.options", options, create=True),
        patch("ignored_host_logger.write_event", autospec=True,) as write_event,
        patch("ignored_host_logger.time.monotonic", return_value=10.0, autospec=True,),
    ):
        addon.server_connect(connection_data)
        addon.server_connect_error(connection_data)
        addon.server_disconnected(connection_data)

    write_event.assert_called_once()
    event = write_event.call_args
    assert event.args[0] == "traffic.passthrough_error"
    assert "\n" not in event.kwargs["details"]["error"]


def test_non_ignored_connection_is_not_logged(connection_data):
    from ignored_host_logger import IgnoredHostLogger

    addon = IgnoredHostLogger()
    options = SimpleNamespace(ignore_hosts=[r"^other\.example\.test:443$"])
    with (
        patch("ignored_host_logger.ctx.options", options, create=True),
        patch("ignored_host_logger.write_event", autospec=True,) as write_event,
    ):
        addon.server_connect(connection_data)
        addon.server_connected(connection_data)
        addon.server_disconnected(connection_data)

    write_event.assert_not_called()
