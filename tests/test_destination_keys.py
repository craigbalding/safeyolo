"""Keep shared CLI endpoint and approval keys independent of the old proxy."""

import json

import pytest

from safeyolo.core.destination import (
    destination_key,
    network_approval_key,
    split_destination,
    validate_port,
)


@pytest.mark.parametrize("value,parts", [
    ("example.com", ("example.com", None)),
    ("example.com:443", ("example.com", 443)),
    ("*.example.com:443", ("*.example.com", 443)),
    ("127.0.0.1:22", ("127.0.0.1", 22)),
    ("[::1]:22", ("::1", 22)),
    ("::1", ("::1", None)),
])
def test_endpoint_key_round_trip(value, parts):
    assert split_destination(value) == parts
    assert destination_key(*parts) == value


@pytest.mark.parametrize("value", [
    "example.com:0", "example.com:65536", "example.com:ssh",
    "[::1]:", ":22", "[xyz]:22",
])
def test_invalid_endpoint_is_rejected(value):
    with pytest.raises(ValueError):
        split_destination(value)


@pytest.mark.parametrize("port", [0, -1, 65536, True, "22", 22.0])
def test_invalid_port_is_rejected(port):
    with pytest.raises(ValueError):
        validate_port(port)


def test_approval_key_separates_agents_and_ports():
    keys = {
        network_approval_key(agent, host, port)
        for agent, host, port in [
            ("alice", "::1", 22), ("alice", "::1", 443), ("bob", "::1", 22),
        ]
    }
    assert len(keys) == 3
    assert json.loads(network_approval_key("alice", "::1", 22)) == ["alice", "::1", 22]
