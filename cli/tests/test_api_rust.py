"""Native AdminAPI target/ownership controls; all process and HTTP calls mocked."""

import json
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import create_autospec

import pytest

from safeyolo import api, config, rust_proxy
from safeyolo.commands import watch


@pytest.fixture
def native(tmp_path, monkeypatch, mock_httpx):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path / "logs"))
    monkeypatch.delenv("SAFEYOLO_ADMIN_TOKEN", raising=False)
    legacy = config.get_admin_token_path()
    legacy.parent.mkdir(parents=True)
    legacy.write_text("owned-legacy-token\n")
    token = tmp_path / "native-token"
    token.write_text("owned-native-token\n")
    ready = tmp_path / "native-ready.json"
    process = rust_proxy.RustProcess(
        pid=24680,
        start_token="owned-process-generation",
        readiness_file=str(ready),
        admin_port=19261,
        admin_token_file=str(token),
    )
    marker = {
        "ready": True,
        "pid": process.pid,
        "backend": "rust-m2",
        "instance_id": "owned-instance",
        "listeners": 1,
        "admin_port": 19261,
    }
    ready.write_text(json.dumps(marker))
    read = create_autospec(rust_proxy.read_process, spec_set=True, return_value=process)
    alive = create_autospec(rust_proxy.is_alive, spec_set=True, return_value=True)
    # The strict boundary executes only the real marker parser over this test's
    # owned file; it cannot reach a process, socket, or operational pathname.
    readiness = create_autospec(rust_proxy.readiness, spec_set=True, side_effect=rust_proxy.readiness)
    load = create_autospec(
        api.load_config,
        spec_set=True,
        return_value={"proxy": {"backend": "python", "admin_port": 19472}},
    )
    monkeypatch.setattr(rust_proxy, "read_process", read)
    monkeypatch.setattr(rust_proxy, "is_alive", alive)
    monkeypatch.setattr(rust_proxy, "readiness", readiness)
    monkeypatch.setattr(api, "load_config", load)
    mock_httpx["response"].json.return_value = {"owned": "response"}
    return SimpleNamespace(
        process=process,
        marker=marker,
        ready=ready,
        token=token,
        legacy=legacy,
        read=read,
        alive=alive,
        readiness=readiness,
        load=load,
        factory=mock_httpx["client_class"],
        http=mock_httpx["client"],
    )


def test_default_native_target_uses_receipt_despite_python_selection_and_no_ready_file(native):
    native.ready.unlink()
    client = api.AdminAPI(timeout=3.5)
    assert client.base_url == "http://127.0.0.1:19261"
    assert client.stats() == {"owned": "response"}
    native.http.request.assert_called_once_with(
        "GET",
        "http://127.0.0.1:19261/stats",
        headers={"Authorization": "Bearer owned-native-token"},
        json=None,
    )
    native.factory.assert_called_once_with(timeout=3.5)
    native.readiness.assert_not_called()
    native.load.assert_not_called()


def test_pending_ephemeral_port_uses_only_matching_published_readiness(native):
    native.process.admin_port = 0
    native.marker["admin_port"] = 19731
    native.ready.write_text(json.dumps(native.marker))
    client = api.AdminAPI()
    assert client.base_url == "http://127.0.0.1:19731"
    client.health()
    native.http.request.assert_called_once_with(
        "GET",
        "http://127.0.0.1:19731/health",
        headers={},
        json=None,
    )
    native.load.assert_not_called()


@pytest.mark.parametrize("invalid", ["missing", "wrong_pid", "not_ready", "wrong_backend", "port_zero"])
def test_pending_port_rejects_missing_or_nonmatching_marker_without_http(native, invalid):
    native.process.admin_port = 0
    if invalid == "missing":
        native.ready.unlink()
    else:
        field, value = {
            "wrong_pid": ("pid", 24681),
            "not_ready": ("ready", False),
            "wrong_backend": ("backend", "python"),
            "port_zero": ("admin_port", 0),
        }[invalid]
        native.marker[field] = value
        native.ready.write_text(json.dumps(native.marker))
    with pytest.raises(api.APIError):
        api.AdminAPI()
    native.factory.assert_not_called()
    native.load.assert_not_called()


def test_no_native_admin_listener_is_a_visible_error(native):
    native.process.admin_port = None
    with pytest.raises(api.APIError):
        api.AdminAPI()
    native.factory.assert_not_called()
    native.load.assert_not_called()


def test_pending_port_rechecks_identity_after_reading_ready_marker(native):
    native.process.admin_port = 0
    native.alive.side_effect = [True, False]
    with pytest.raises(api.APIError):
        api.AdminAPI()
    native.readiness.assert_called_once_with(native.process)
    native.factory.assert_not_called()


@pytest.mark.parametrize("failure", ["corrupt", "read_error", "exited_or_reused", "identity_unknown"])
def test_unusable_native_receipt_cannot_fall_back_to_legacy_http(native, failure):
    if failure == "corrupt":
        native.read.side_effect = RuntimeError("owned corrupt receipt")
    elif failure == "read_error":
        native.read.side_effect = PermissionError("owned unreadable receipt")
    elif failure == "exited_or_reused":
        native.alive.return_value = False
    else:
        native.alive.side_effect = RuntimeError("owned unavailable start token")
    with pytest.raises(api.APIError):
        api.AdminAPI()
    native.factory.assert_not_called()
    native.load.assert_not_called()


@pytest.mark.parametrize(
    ("argument", "environment", "expected"),
    [
        ("owned-explicit-token", "owned-environment-token", "owned-explicit-token"),
        (None, "owned-environment-token", "owned-environment-token"),
        ("", "owned-environment-token", "owned-environment-token"),
        (None, "", "owned-native-token"),
    ],
)
def test_native_auth_precedence(native, monkeypatch, argument, environment, expected):
    monkeypatch.setenv("SAFEYOLO_ADMIN_TOKEN", environment)
    client = api.AdminAPI(token=argument)
    client.stats()
    assert native.http.request.call_args.kwargs["headers"] == {"Authorization": f"Bearer {expected}"}


@pytest.mark.parametrize("source", ["explicit", "environment"])
def test_auth_override_does_not_read_unusable_native_token_file(native, monkeypatch, source):
    native.token.unlink()
    native.token.mkdir()
    argument = "owned-override-token" if source == "explicit" else None
    if source == "environment":
        monkeypatch.setenv("SAFEYOLO_ADMIN_TOKEN", "owned-override-token")
    client = api.AdminAPI(token=argument)
    client.stats()
    assert native.http.request.call_args.kwargs["headers"] == {"Authorization": "Bearer owned-override-token"}


@pytest.mark.parametrize("failure", ["directory", "invalid_utf8"])
def test_unreadable_native_token_is_visible_and_never_uses_legacy_token(native, failure):
    native.token.unlink()
    if failure == "directory":
        native.token.mkdir()
    else:
        native.token.write_bytes(b"\xff")
    with pytest.raises(api.APIError):
        api.AdminAPI()
    native.factory.assert_not_called()


@pytest.mark.parametrize("absence", ["no_path", "missing_file", "empty_file"])
def test_missing_native_token_never_reads_legacy_token(native, absence):
    if absence == "no_path":
        native.process.admin_token_file = None
    elif absence == "missing_file":
        native.token.unlink()
    else:
        native.token.write_text("")
    client = api.AdminAPI()
    client.stats()
    assert native.http.request.call_args.kwargs["headers"] == {}
    assert native.legacy.read_text() == "owned-legacy-token\n"


@pytest.mark.parametrize(
    ("argument", "environment", "expected"),
    [
        ("owned-custom-token", "owned-environment-token", "owned-custom-token"),
        (None, "owned-environment-token", "owned-environment-token"),
        (None, None, "owned-legacy-token"),
    ],
)
def test_explicit_url_bypasses_native_lookup_and_preserves_legacy_auth(
    native,
    monkeypatch,
    argument,
    environment,
    expected,
):
    if environment is not None:
        monkeypatch.setenv("SAFEYOLO_ADMIN_TOKEN", environment)
    native.read.side_effect = AssertionError("explicit URL must not inspect native ownership")
    client = api.AdminAPI(base_url="http://owned-custom.invalid:19473/", token=argument)
    assert client.base_url == "http://owned-custom.invalid:19473"
    client.stats()
    native.http.request.assert_called_once_with(
        "GET",
        "http://owned-custom.invalid:19473/stats",
        headers={"Authorization": f"Bearer {expected}"},
        json=None,
    )
    native.read.assert_not_called()
    native.alive.assert_not_called()
    native.readiness.assert_not_called()
    native.load.assert_not_called()


def test_without_native_receipt_default_python_target_and_auth_are_unchanged(native):
    native.read.return_value = None
    client = api.AdminAPI()
    # This instance selected Python; a later native receipt must not retarget it.
    native.read.return_value = native.process
    client.stats()
    native.http.request.assert_called_once_with(
        "GET",
        "http://localhost:19472/stats",
        headers={"Authorization": "Bearer owned-legacy-token"},
        json=None,
    )
    native.alive.assert_not_called()
    native.readiness.assert_not_called()


@pytest.mark.parametrize("later_identity", [False, RuntimeError("owned identity became unknown")])
def test_each_native_request_rechecks_current_identity_before_http(native, later_identity):
    client = api.AdminAPI()
    client.stats()
    sent = native.http.request.call_count
    created = native.factory.call_count
    if isinstance(later_identity, Exception):
        native.alive.side_effect = later_identity
    else:
        native.alive.return_value = later_identity
    with pytest.raises(api.APIError):
        client.health()
    assert native.http.request.call_count == sent
    assert native.factory.call_count == created
    native.load.assert_not_called()


def test_config_token_path_override_uses_owned_file_and_environment(native, monkeypatch):
    assert config.get_admin_token(token_path=native.token) == "owned-native-token"
    monkeypatch.setenv("SAFEYOLO_ADMIN_TOKEN", "owned-environment-token")
    assert config.get_admin_token(token_path=native.token) == "owned-environment-token"
    monkeypatch.delenv("SAFEYOLO_ADMIN_TOKEN")
    native.token.unlink()
    assert config.get_admin_token(token_path=native.token) is None
    assert config.get_admin_token() == "owned-legacy-token"


def test_one_client_follows_verified_restart_to_new_port_and_token(native):
    client = api.AdminAPI()
    client.stats()
    next_token = native.token.with_name("next-native-token")
    next_token.write_text("owned-next-token\n")
    native.read.return_value = replace(
        native.process,
        pid=24681,
        start_token="next-generation",
        admin_port=19333,
        admin_token_file=str(next_token),
    )
    client.stats()
    requests = native.http.request.call_args_list
    assert [(request.args[1], request.kwargs["headers"]) for request in requests] == [
        ("http://127.0.0.1:19261/stats", {"Authorization": "Bearer owned-native-token"}),
        ("http://127.0.0.1:19333/stats", {"Authorization": "Bearer owned-next-token"}),
    ]
    native.load.assert_not_called()


def test_explicit_constructor_token_survives_verified_restart(native):
    client = api.AdminAPI(token="owned-explicit-token")
    client.stats()
    native.token.unlink()
    native.token.mkdir()
    native.read.return_value = replace(native.process, pid=24681, start_token="next-generation", admin_port=19333)
    client.stats()
    request = native.http.request.call_args
    assert request.args == ("GET", "http://127.0.0.1:19333/stats")
    assert request.kwargs["headers"] == {"Authorization": "Bearer owned-explicit-token"}


@pytest.mark.parametrize("unavailable", ["missing", "corrupt", "no_admin"])
def test_client_can_retry_after_unusable_replacement_without_legacy_fallback(native, unavailable):
    client = api.AdminAPI()
    if unavailable == "missing":
        native.read.return_value = None
    elif unavailable == "corrupt":
        native.read.side_effect = RuntimeError("owned corrupt replacement receipt")
    else:
        native.read.return_value = replace(native.process, pid=24681, start_token="next-generation", admin_port=None)
    with pytest.raises(api.APIError):
        client.stats()
    native.factory.assert_not_called()
    native.load.assert_not_called()
    native.read.side_effect = None
    native.read.return_value = replace(native.process, pid=24681, start_token="next-generation", admin_port=19333)
    client.stats()
    native.http.request.assert_called_once_with(
        "GET",
        "http://127.0.0.1:19333/stats",
        headers={"Authorization": "Bearer owned-native-token"},
        json=None,
    )


def test_failed_replacement_token_resolution_does_not_publish_partial_client_state(native):
    client = api.AdminAPI()
    client.stats()
    next_token = native.token.with_name("next-native-token")
    next_token.mkdir()
    native.read.return_value = replace(
        native.process,
        pid=24681,
        start_token="next-generation",
        admin_port=19333,
        admin_token_file=str(next_token),
    )
    with pytest.raises(api.APIError):
        client.stats()
    # Only the original request was sent. After repairing this same replacement
    # receipt's token, retry must resolve it rather than reuse stale credentials.
    assert native.http.request.call_count == 1
    next_token.rmdir()
    next_token.write_text("owned-recovered-token\n")
    client.stats()
    requests = native.http.request.call_args_list
    assert [(request.args[1], request.kwargs["headers"]) for request in requests] == [
        ("http://127.0.0.1:19261/stats", {"Authorization": "Bearer owned-native-token"}),
        ("http://127.0.0.1:19333/stats", {"Authorization": "Bearer owned-recovered-token"}),
    ]


def test_same_process_generation_keeps_the_cached_default_token(native):
    client = api.AdminAPI()
    native.token.write_text("owned-changed-file-token\n")
    # Equal identity from a fresh receipt object is still the same generation.
    native.read.return_value = replace(native.process)
    client.stats()
    native.http.request.assert_called_once_with(
        "GET",
        "http://127.0.0.1:19261/stats",
        headers={"Authorization": "Bearer owned-native-token"},
        json=None,
    )


def test_watch_budget_action_uses_restarted_native_endpoint_and_token(native):
    client = api.AdminAPI()
    next_token = native.token.with_name("watch-next-token")
    next_token.write_text("owned-watch-next-token\n")
    replacement = replace(
        native.process,
        pid=24681,
        start_token="next-generation",
        admin_port=19333,
        admin_token_file=str(next_token),
    )
    native.read.return_value = replacement
    native.alive.side_effect = lambda observed: observed == replacement
    event = {
        "event": "security.network_guard",
        "kind": "security",
        "decision": "budget_exceeded",
        "host": "owned.invalid",
        "details": {"budget": 3, "host": "owned.invalid"},
    }
    assert watch._exec_reset_budget(event, client) == "Budget reset for owned.invalid"
    native.http.request.assert_called_once_with(
        "POST",
        "http://127.0.0.1:19333/admin/budgets/reset",
        headers={"Authorization": "Bearer owned-watch-next-token"},
        json={"resource": "network:request:owned.invalid"},
    )
    native.load.assert_not_called()
