"""Full production startup, authenticated API and durable network approvals.

The fixture runs only its own synthetic UDS/loopback endpoints. Cleanup of
stale pathnames is a separately reported baseline failure, not API acceptance.
"""

import json
import subprocess
import sys

import pytest

from tests.proxy_migration.harness import REPO

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="This baseline capture measures Linux /proc RSS")


@pytest.fixture(scope="module")
def production_result(tmp_path_factory):
    directory = tmp_path_factory.mktemp("full-production") / "capture"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "tests.proxy_migration.full_production",
            "--output",
            str(directory),
            "--api-requests",
            "12",
            "--approvals",
            "3",
            "--api-workers",
            "2",
        ],
        cwd=REPO,
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads((directory / "result.json").read_text())
    assert result["status"] in {"passed", "completed_with_gaps"}, result
    return result


def test_full_production_authenticated_api_and_network_approvals(production_result):
    """Run healthy APIs, auth negatives, exact-agent grants and concurrent load."""
    assert len(production_result["production_chain"]) == 27
    workload = production_result["workloads"][0]
    assert workload["api_requests"] == 24
    assert workload["approval_transactions"] == 3
    assert production_result["origin_accepts"] == 1
    assert not any(probe["accepting"] for probe in production_result["shutdown"]["socket_accept_checks"].values())


@pytest.mark.xfail(
    strict=True, reason="Baseline production SIGTERM leaves dead UDS pathnames; proxy.py::stop_proxy claims removal"
)
def test_full_production_shutdown_removes_socket_files(production_result):
    """Retain the observed baseline cleanup defect as an explicit failed check."""
    assert production_result["shutdown"]["stale_socket_files"] == []
