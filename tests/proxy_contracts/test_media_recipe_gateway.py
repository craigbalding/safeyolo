"""Exercise the shipped media dispatch shape through the native gateway.

Loopback HTTP is a controlled transport fixture, not installed Rundeck/library
proof. The adopted service example retains HTTPS credential injection.
"""

import json
from pathlib import Path

import yaml

from tests.proxy_contracts.harness import launch_proxy, request
from tests.proxy_contracts.test_gateway_redirect import (
    AGENT_API,
    AGENT_TOKEN,
    VAULT_CREDENTIAL,
    VAULT_NAME,
    _fixture_state,
    _origin,
    _wire,
)

RECIPE = (Path(__file__).resolve().parents[2] /
          "cli/src/safeyolo/agent_context/skills/safeyolo-commission/recipes/media-ingestion/v1")
RUN_PATH = "/api/56/job/REPLACE-OWNED-JOB-ID/run"


def test_media_dispatch_cannot_change_source_destination_job_or_command(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _fixture_state(directory)
    (directory / "services/redirect.yaml").unlink()
    service = yaml.safe_load((RECIPE / "service.example.yaml").read_text())
    service["default_host"] = "127.0.0.1"
    service["auth"]["allow_http"] = True  # Only the loopback fixture uses HTTP.
    (directory / "services/media-ingestion.yaml").write_text(yaml.safe_dump(service))
    policy = (RECIPE / "policy.example.toml").read_text().replace(
        "rundeck.example.test", "127.0.0.1").replace("movie-worker", "alice").replace(
        "operator-owned-media-job-credential", VAULT_NAME)
    with _origin("127.0.0.1") as origin:
        policy += f'\n[hosts."127.0.0.1:{origin.server_address[1]}"]\negress="allow"\n[agents.bob]\n'
        with launch_proxy(proxy_backend, directory, policy, native_policy=True, agent_api=True,
                          gateway_services_dir=directory / "services",
                          gateway_builtin_services_dir=directory / "builtin",
                          network_guard_enabled=True, network_guard_block=True) as proxy:
            status, _, raw = request(proxy.paths["alice"], AGENT_API + "/gateway/services",
                                     headers={"Authorization": f"Bearer {AGENT_TOKEN}"})
            assert status == 200, raw
            token = json.loads(raw)["authorized"]["media-ingestion"]["token"]
            headers = {"X-Rundeck-Auth-Token": token}
            base = f"http://127.0.0.1:{origin.server_address[1]}"
            status, _, raw = request(proxy.paths["alice"], base + RUN_PATH, method="POST", headers=headers)
            assert status == 200, raw
            assert len(origin.requests) == 1
            wire = _wire(origin.requests[0])
            assert VAULT_CREDENTIAL.encode() in wire and token.encode() not in wire
            cases = [
                ("alice", "POST", RUN_PATH + "?argString=untrusted", None),
                ("alice", "POST", RUN_PATH + "?filter=other-host", None),
                ("alice", "POST", RUN_PATH, b'{"options":{"source":"untrusted","destination":"other"}}'),
                ("alice", "POST", RUN_PATH, b'{"command":"untrusted"}'),
                ("alice", "POST", RUN_PATH.replace("REPLACE-OWNED-JOB-ID", "other-job"), None),
                ("alice", "PUT", RUN_PATH.removesuffix("/run"), b'{}'),
                ("bob", "POST", RUN_PATH, None),
            ]
            for caller, method, path, body in cases:
                status, _, raw = request(proxy.paths[caller], base + path, method=method,
                                         headers={**headers, **({"Content-Type": "application/json"} if body else {})},
                                         body=body)
                assert status == 403, (caller, method, path, status, raw)
                assert len(origin.requests) == 1
