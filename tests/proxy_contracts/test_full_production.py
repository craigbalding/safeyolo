"""Full production startup, authenticated API and durable network approvals.

The fixture runs only its own synthetic UDS/loopback endpoints. Cleanup of
stale pathnames is a separately reported baseline failure, not API acceptance.
"""

import json
import os
import subprocess
import sys

import pytest

from tests.proxy_contracts.full_production import historical_addon_chain
from tests.proxy_contracts.harness import REPO, python_proxy_environment

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="This baseline capture measures Linux /proc RSS")


def test_full_production_chain_requires_historical_source(tmp_path):
    with pytest.raises(FileNotFoundError):
        historical_addon_chain(tmp_path)


@pytest.fixture(scope="module")
def production_result(tmp_path_factory, request):
    if "python" not in (request.config.getoption("--proxy-backend") or ["rust"]):
        pytest.skip("Historical production capture runs in the Python comparator leg")
    source = os.environ.get("SAFEYOLO_PYTHON_SOURCE")
    environment = python_proxy_environment(python_source=source)
    executable = os.environ.get("SAFEYOLO_PYTHON_EXECUTABLE", sys.executable)
    directory = tmp_path_factory.mktemp("full-production") / "capture"
    completed = subprocess.run(
        [
            executable,
            str(REPO / "tests/proxy_contracts/full_production.py"),
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
        env=environment,
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
