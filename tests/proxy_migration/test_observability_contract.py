"""Observability boundaries at the selected proxy's real request path."""

from tests.proxy_migration.harness import read_events
from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import POLICY
from tests.proxy_migration.test_native_network_policy import policy_proxy, raw_parent

CANARY = "defect-control-canary-621"


def test_routine_observations_do_not_capture_unrelated_header_bytes(proxy_backend, tmp_path):
    """Routine event and process records omit an unrelated request canary."""
    directory = tmp_path / proxy_backend
    with raw_parent() as origin:
        authority = f"127.0.0.1:{origin.server_address[1]}"
        with policy_proxy(proxy_backend, directory, POLICY) as proxy:
            status, _headers, body = send_request(
                proxy.paths["alice"],
                f"http://{authority}/observability",
                headers={"X-Defect-Canary": CANARY},
            )
            assert status == 200
            assert body == b"hello"
            assert origin.accepts == 1

        # The request reached the independently controlled origin, but the
        # proxy's routine records contain only the fields intended for
        # correlation and policy evidence.  Check every emitted text record
        # so a logging-path mutation cannot hide behind one selected sink.
        records = [directory / "process.log", directory / "events.jsonl"]
        records.extend(directory.glob("*.jsonl"))
        assert records
        assert all(CANARY not in path.read_text() for path in set(records) if path.exists())
        assert read_events(directory / "events.jsonl")
