"""First shared HTTP contracts; transport/TLS/WS coverage remains explicit."""

import pytest

from tests.proxy_migration.scenarios import network_scenario, reserved_scenario


@pytest.mark.parametrize("parent", [False, True], ids=["direct", "parent"])
def test_two_agent_http_policy_and_attribution(proxy_backend, tmp_path, parent):
    network_scenario(proxy_backend, tmp_path / proxy_backend, parent=parent)


def test_reserved_hosts_never_resolve_or_contact_parent(proxy_backend, tmp_path):
    reserved_scenario(proxy_backend, tmp_path / proxy_backend)
