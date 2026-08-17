"""Tests for ignored-host connection lifecycle audit events."""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def connection_data():
    data = MagicMock()
    data.server.id = "server-connection-1"
    data.server.peername = ("192.0.2.20", 443)
    data.server.address = ("service.example.test", 443)
    data.server.transport_protocol = "tcp"
    data.server.error = None
    data.client.sni = "service.example.test"
    data.client.peername = ("192.0.2.2", 0)
    data.client.proxy_mode.agent = "test-agent"
    return data


def test_logs_successful_passthrough_start_and_end(connection_data):
    from ignored_host_logger import IgnoredHostLogger

    addon = IgnoredHostLogger()
    options = MagicMock(ignore_hosts=[r"^service\.example\.test:443$"])
    with (
        patch("ignored_host_logger.ctx.options", options, create=True),
        patch("ignored_host_logger.write_event") as write_event,
        patch("ignored_host_logger.time.monotonic", side_effect=[10.0, 10.125]),
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
    options = MagicMock(ignore_hosts=[r"^service\.example\.test:443$"])
    with (
        patch("ignored_host_logger.ctx.options", options, create=True),
        patch("ignored_host_logger.write_event") as write_event,
        patch("ignored_host_logger.time.monotonic", return_value=10.0),
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
    options = MagicMock(ignore_hosts=[r"^other\.example\.test:443$"])
    with (
        patch("ignored_host_logger.ctx.options", options, create=True),
        patch("ignored_host_logger.write_event") as write_event,
    ):
        addon.server_connect(connection_data)
        addon.server_connected(connection_data)
        addon.server_disconnected(connection_data)

    write_event.assert_not_called()
