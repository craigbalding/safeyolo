"""YAML temporal values through the actual configured policy loader and API.

Retained Any values can make /policy serialization fail while that loaded
policy continues enforcing traffic. Declared string fields instead reject
temporal values at load. These policies contain no gateway grants or bearers.
"""

import pytest

from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import origin_server
from tests.proxy_migration.test_agent_api_contract import api_request, assert_api_response
from tests.proxy_migration.test_agent_api_policy import EMPTY_BASELINE, assert_policy_response
from tests.proxy_migration.test_native_network_policy import assert_rejection, policy_proxy, replace_policy

TYPE_ERROR = {"error": "Internal error: TypeError"}
YAML_ADDON = "addons:\n  synthetic:\n    settings:\n"
QUOTED_SETTINGS = {
    "observed": "2001-02-03",
    "at": "2001-02-03T04:05:06Z",
    "nested": {"2001-02-03": {"2001-02-03T04:05:06Z": "value"}},
}


def addon_baseline(settings):
    return {**EMPTY_BASELINE, "addons": {"synthetic": {"enabled": True, "settings": settings}}}


def local_policy_read(proxy, parent, agent="alice"):
    before = parent.accepts, len(proxy.events("proxy.egress"))
    result = api_request(proxy, "/policy", agent=agent)
    assert (parent.accepts, len(proxy.events("proxy.egress"))) == before
    return result


@pytest.mark.parametrize("source,baseline", [
    (YAML_ADDON + "      observed: 2001-02-03\n", None),
    (YAML_ADDON + "      observed: 2001-02-03T04:05:06Z\n", None),
    (YAML_ADDON + "      nested:\n        - {2001-02-03: value}\n", None),
    (YAML_ADDON + "      nested:\n        - {2001-02-03T04:05:06Z: value}\n", None),
    (YAML_ADDON + '''      observed: "2001-02-03"
      at: "2001-02-03T04:05:06Z"
      nested:
        "2001-02-03": {"2001-02-03T04:05:06Z": value}
''', addon_baseline(QUOTED_SETTINGS)),
    (YAML_ADDON + '      observed: {yaml_date: "2001-02-03"}\n',
     addon_baseline({"observed": {"yaml_date": "2001-02-03"}})),
    ("unknown_dropped:\n  nested: {2001-02-03: 2001-02-03T04:05:06Z}\n", EMPTY_BASELINE),
], ids=["date-value", "datetime-value", "nested-date-key", "nested-datetime-key",
        "quoted-values-and-keys", "authored-date-like-object", "dropped-temporal-field"])
def test_agent_api_yaml_temporal_values_preserve_source_types(proxy_backend, tmp_path, source, baseline):
    with origin_server() as parent:
        with policy_proxy(proxy_backend, tmp_path / proxy_backend, source, policy_format="yaml", agent_api=True,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            for agent in ("alice", "bob"):
                result = local_policy_read(proxy, parent, agent)
                if baseline is None:
                    assert_api_response(result, 500, TYPE_ERROR)
                else:
                    assert_policy_response(result, baseline)
            assert parent.accepts == 0 and parent.requests == []
            assert proxy.events("proxy.egress") == []


NETWORK_POLICY = '''permissions:
  - action: network:request
    resource: alpha.invalid/*
    effect: allow
  - action: network:request
    resource: omega.invalid/*
    effect: deny
'''
NETWORK_BASELINE = {
    **addon_baseline({"observed": "2001-02-03"}),
    "permissions": [
        {"action": "network:request", "resource": "alpha.invalid/*", "effect": "allow", "budget": None,
         "tier": "explicit", "condition": None},
        {"action": "network:request", "resource": "omega.invalid/*", "effect": "deny", "budget": None,
         "tier": "explicit", "condition": None},
    ],
}


def check_network_policy(proxy, parent, *, reversed_policy):
    for host, expected in (("alpha.invalid", 403 if reversed_policy else 200),
                           ("omega.invalid", 200 if reversed_policy else 403)):
        before = parent.accepts, len(proxy.events("proxy.egress"))
        result = send_request(proxy.paths["alice"], f"http://{host}/metadata-only")
        assert result[0] == expected
        if expected == 403:
            assert_rejection(*result, 403, host)
            assert (parent.accepts, len(proxy.events("proxy.egress"))) == before
        else:
            assert result[2] == b"hello"
            assert parent.accepts == before[0] + 1


def test_agent_api_yaml_serialization_failure_keeps_loaded_enforcement(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    initial = NETWORK_POLICY + YAML_ADDON + '      observed: "2001-02-03"\n'
    reversed_network = NETWORK_POLICY.replace("effect: allow", "effect: swapped").replace(
        "effect: deny", "effect: allow").replace("effect: swapped", "effect: deny")
    retained_temporal = reversed_network + YAML_ADDON + "      observed: 2001-02-03\n"
    # metadata.created is a declared string, unlike the Any addon setting.
    rejected_metadata = initial + "metadata:\n  created: 2001-02-03T04:05:06Z\n"
    with origin_server() as parent:
        with policy_proxy(proxy_backend, directory, initial, policy_format="yaml", agent_api=True,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            assert_policy_response(local_policy_read(proxy, parent), NETWORK_BASELINE)
            check_network_policy(proxy, parent, reversed_policy=False)

            replace_policy(proxy, proxy_backend, directory, retained_temporal)
            assert_api_response(local_policy_read(proxy, parent), 500, TYPE_ERROR)
            check_network_policy(proxy, parent, reversed_policy=True)

            replace_policy(proxy, proxy_backend, directory, rejected_metadata, valid=False)
            assert_api_response(local_policy_read(proxy, parent, "bob"), 500, TYPE_ERROR)
            check_network_policy(proxy, parent, reversed_policy=True)
            assert parent.accepts == 3
