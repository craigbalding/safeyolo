"""Hermetic regressions for the live HTTP integration precondition gate."""

from tests.test_http_integration import _integration_runtime_skip_reason


def test_token_present_proxy_absent_skips_before_admin_probe() -> None:
    probes: list[tuple[str, int]] = []

    def endpoint_is_listening(host: str, port: int) -> bool:
        probes.append((host, port))
        return False

    reason = _integration_runtime_skip_reason(
        "token-present",
        proxy_host="configured-proxy",
        proxy_port=18080,
        admin_host="configured-admin",
        admin_port=19090,
        endpoint_is_listening=endpoint_is_listening,
    )

    assert reason == (
        "SafeYolo proxy is not listening at configured-proxy:18080; "
        "real HTTP integration runtime required"
    )
    assert probes == [("configured-proxy", 18080)]


def test_complete_configured_runtime_passes_precondition() -> None:
    probes: list[tuple[str, int]] = []

    def endpoint_is_listening(host: str, port: int) -> bool:
        probes.append((host, port))
        return True

    reason = _integration_runtime_skip_reason(
        "token-present",
        proxy_host="configured-proxy",
        proxy_port=28080,
        admin_host="configured-admin",
        admin_port=29090,
        endpoint_is_listening=endpoint_is_listening,
    )

    assert reason is None
    assert probes == [
        ("configured-proxy", 28080),
        ("configured-admin", 29090),
    ]


def test_token_and_proxy_present_admin_absent_skips() -> None:
    probes: list[tuple[str, int]] = []

    def endpoint_is_listening(host: str, port: int) -> bool:
        probes.append((host, port))
        return host == "configured-proxy"

    reason = _integration_runtime_skip_reason(
        "token-present",
        proxy_host="configured-proxy",
        proxy_port=38080,
        admin_host="configured-admin",
        admin_port=39090,
        endpoint_is_listening=endpoint_is_listening,
    )

    assert reason == (
        "SafeYolo admin API is not listening at configured-admin:39090; "
        "real HTTP integration runtime required"
    )
    assert probes == [
        ("configured-proxy", 38080),
        ("configured-admin", 39090),
    ]


def test_missing_admin_token_skips_without_endpoint_probe() -> None:
    def unexpected_probe(_host: str, _port: int) -> bool:
        raise AssertionError("endpoints must not be probed without an admin token")

    assert _integration_runtime_skip_reason(
        "", endpoint_is_listening=unexpected_probe
    ) == "ADMIN_API_TOKEN not set and no admin_token file was found"
