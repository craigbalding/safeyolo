"""Explicit backend selection keeps the historical comparator optional."""

import pytest

_READINESS_FAILURE = False

_READINESS_FAILURE = False


def pytest_addoption(parser):
    parser.addoption("--proxy-backend", action="append", choices=("python", "rust"), default=[])


@pytest.fixture(params=None)
def proxy_backend(request):
    return request.param


def pytest_generate_tests(metafunc):
    if "proxy_backend" in metafunc.fixturenames:
        backends = metafunc.config.getoption("--proxy-backend") or ["python"]
        metafunc.parametrize("proxy_backend", backends, indirect=True)


def pytest_runtest_logreport(report):
    """Treat a proxy startup/readiness failure as runner infrastructure."""
    global _READINESS_FAILURE
    if report.failed and "ReadinessError" in str(report.longrepr):
        _READINESS_FAILURE = True


def pytest_sessionfinish(session, exitstatus):
    if _READINESS_FAILURE:
        session.exitstatus = 2
