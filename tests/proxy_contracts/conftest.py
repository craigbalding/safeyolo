"""Select the native proxy and classify its readiness failures."""

import os
import subprocess
from pathlib import Path

import pytest

_READINESS_FAILURE = False


def pytest_addoption(parser):
    parser.addoption("--proxy-backend", action="append", choices=("rust",), default=[])


@pytest.fixture(params=None)
def proxy_backend(request):
    return request.param


def pytest_generate_tests(metafunc):
    if "proxy_backend" in metafunc.fixturenames:
        backends = metafunc.config.getoption("--proxy-backend") or ["rust"]
        metafunc.parametrize("proxy_backend", backends, indirect=True)


def pytest_runtest_logreport(report):
    """Treat a proxy startup/readiness failure as runner infrastructure."""
    global _READINESS_FAILURE
    if report.failed and "ReadinessError" in str(report.longrepr):
        _READINESS_FAILURE = True


def pytest_sessionfinish(session, exitstatus):
    if _READINESS_FAILURE:
        session.exitstatus = 2


@pytest.fixture(scope="module")
def blackbox_chain_material(tmp_path_factory):
    """Use the existing chain producer with private keys outside the checkout."""
    directory = tmp_path_factory.mktemp("origin-chains")
    public, private = directory / "public", directory / "private"
    script = Path(__file__).resolve().parents[1] / "blackbox/certs/generate-certs.sh"
    subprocess.run([str(script), "--force"], check=True, capture_output=True, timeout=90,
                   env=dict(os.environ, SAFEYOLO_TEST_CERT_DIR=str(public),
                            SAFEYOLO_TEST_KEY_DIR=str(private)))
    return public, private
