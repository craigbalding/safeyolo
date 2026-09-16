"""Focused local tests for selected-flow export transport and UI queueing."""

import asyncio
import os
import stat
import tempfile
import threading
from pathlib import Path
from unittest.mock import create_autospec, patch

import httpx
import pytest
from prompt_toolkit.application import create_app_session
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from safeyolo.api import AdminAPI, APIError, ExportCancelled, ExportPublicationState, TrafficExportResult
from safeyolo.traffic_inspector import TrafficInspector


class _StreamResponse:
    def __init__(
        self,
        chunks: list[bytes],
        *,
        status_code: int = 200,
        headers: dict | None = None,
        exit_error: OSError | None = None,
    ):
        self.status_code = status_code
        self.headers = {"content-type": "application/octet-stream", **(headers or {})}
        self._chunks = chunks
        self._exit_error = exit_error
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True
        if self._exit_error is not None:
            raise self._exit_error

    def iter_bytes(self, *, chunk_size: int):
        assert chunk_size == 64 * 1024
        yield from self._chunks


def _stream_client(response: _StreamResponse):
    client = create_autospec(httpx.Client, instance=True, spec_set=True)
    client.__enter__.return_value = client
    client.__exit__.return_value = None
    client.stream.return_value = response
    return client


def test_export_quotes_route_refreshes_auth_and_publishes_bounded_binary_stream(tmp_path):
    destination = tmp_path / "export.bin"
    response = _StreamResponse([b"\x00" * 65_537, b"\xff"], headers={"content-length": "65538"})
    client = _stream_client(response)
    api = AdminAPI(base_url="http://stale.invalid", token="stale-token")

    def refresh_connection():
        api.base_url = "http://refreshed.invalid"
        api.token = "fresh-token"

    with patch("safeyolo.api.httpx.Client", return_value=client, autospec=True), patch.object(
        api, "_refresh_rust_connection", autospec=True
    ) as refresh:
        refresh.side_effect = refresh_connection
        result = api.traffic_export("flow/with?#", "raw/request", destination)

    refresh.assert_called_once_with()
    client.stream.assert_called_once_with(
        "GET",
        "http://refreshed.invalid/admin/traffic/flows/flow%2Fwith%3F%23/export?format=raw%2Frequest",
        headers={"Authorization": "Bearer fresh-token"},
    )
    assert result.status_code == 200
    assert result.content_type == "application/octet-stream"
    assert result.bytes_written == 65_538
    assert destination.read_bytes() == b"\x00" * 65_537 + b"\xff"
    assert response.closed
    assert not list(tmp_path.glob(".export-*"))


def test_export_stream_errors_and_statuses_preserve_destination_without_retry(tmp_path):
    destination = tmp_path / "export.bin"
    destination.write_bytes(b"prior")
    response = _StreamResponse([b"partial"], headers={"content-length": "99"})
    client = _stream_client(response)
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    with patch("safeyolo.api.httpx.Client", return_value=client, autospec=True):
        with pytest.raises(APIError, match="truncated"):
            api.traffic_export("one", "raw", destination)

    assert destination.read_bytes() == b"prior"
    client.stream.assert_called_once()
    assert not list(tmp_path.glob(".export-*"))


def test_export_primary_stream_error_survives_cleanup_error(tmp_path, monkeypatch):
    destination = tmp_path / "export.bin"
    destination.write_bytes(b"prior")
    primary = APIError("primary stream failure")

    class PrimaryFailure(_StreamResponse):
        def iter_bytes(self, *, chunk_size: int):
            assert chunk_size == 64 * 1024
            if False:
                yield b"unreachable"
            raise primary

    response = PrimaryFailure([])
    client = _stream_client(response)
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    original_cleanup = tempfile.TemporaryDirectory.cleanup

    def cleanup_then_fail(directory):
        original_cleanup(directory)
        raise OSError("cleanup failure")

    monkeypatch.setattr(tempfile.TemporaryDirectory, "cleanup", cleanup_then_fail)
    with patch("safeyolo.api.httpx.Client", return_value=client, autospec=True):
        with pytest.raises(APIError) as raised:
            api.traffic_export("one", "raw", destination)

    assert raised.value is primary
    assert destination.read_bytes() == b"prior"
    assert response.closed
    assert not list(tmp_path.glob(".export-*"))


def test_export_requires_native_success_status_before_publishing(tmp_path):
    destination = tmp_path / "export.bin"
    destination.write_bytes(b"prior")
    response = _StreamResponse([b"should not publish"], status_code=302)
    client = _stream_client(response)
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    with patch("safeyolo.api.httpx.Client", return_value=client, autospec=True):
        with pytest.raises(APIError, match="HTTP 302") as raised:
            api.traffic_export("one", "raw", destination)

    assert raised.value.status_code == 302
    assert destination.read_bytes() == b"prior"
    assert response.closed
    assert not list(tmp_path.glob(".export-*"))


def test_export_publish_failure_preserves_destination_and_cleans_staging(tmp_path, monkeypatch):
    destination = tmp_path / "export.bin"
    destination.write_bytes(b"prior")
    response = _StreamResponse([b"replacement"])
    client = _stream_client(response)
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")

    def fail_replace(_temporary, _destination):
        raise OSError("owned write failure")

    monkeypatch.setattr("safeyolo.api.os.replace", fail_replace)
    with patch("safeyolo.api.httpx.Client", return_value=client, autospec=True):
        with pytest.raises(APIError, match="Cannot write traffic export"):
            api.traffic_export("one", "raw", destination)

    assert destination.read_bytes() == b"prior"
    assert not list(tmp_path.glob(".export-*"))


def test_export_cancel_cleans_temp_and_leaves_old_file(tmp_path):
    destination = tmp_path / "export.bin"
    destination.write_bytes(b"prior")
    cancel = threading.Event()

    class CancelAfterFirst(_StreamResponse):
        def iter_bytes(self, *, chunk_size: int):
            assert chunk_size == 64 * 1024
            yield b"new"
            cancel.set()
            yield b"should never publish"

    response = CancelAfterFirst([])
    client = _stream_client(response)
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    with patch("safeyolo.api.httpx.Client", return_value=client, autospec=True):
        with pytest.raises(ExportCancelled):
            api.traffic_export("one", "raw", destination, cancel_event=cancel)

    assert destination.read_bytes() == b"prior"
    assert not list(tmp_path.glob(".export-*"))


def test_export_publication_state_rejects_cancel_before_commit(tmp_path):
    state = ExportPublicationState()
    state.set()

    with pytest.raises(ExportCancelled):
        state.publish(tmp_path / "staged", tmp_path / "destination")


def test_export_late_cancel_after_replace_reports_success(tmp_path, monkeypatch):
    destination = tmp_path / "export.bin"
    destination.write_bytes(b"prior")
    response = _StreamResponse([b"replacement"])
    client = _stream_client(response)
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    view = TrafficInspector(api)
    original_replace = os.replace
    detach_threads = []

    def replace_then_detach(source, target):
        original_replace(source, target)
        detach_thread = threading.Thread(target=view.cancel_export)
        detach_thread.start()
        detach_threads.append(detach_thread)

    monkeypatch.setattr("safeyolo.api.os.replace", replace_then_detach)
    with patch("safeyolo.api.httpx.Client", return_value=client, autospec=True):
        asyncio.run(view._run_export(("one", "raw", destination)))
    for detach_thread in detach_threads:
        detach_thread.join(timeout=1)

    assert destination.read_bytes() == b"replacement"
    assert view.notice == f"Exported flow one to {destination} (11 bytes)"
    assert "unchanged" not in view.notice


def test_export_detached_worker_rejects_publication_after_staging(tmp_path, monkeypatch):
    destination = tmp_path / "export.bin"
    destination.write_bytes(b"prior")
    response = _StreamResponse([b"replacement"])
    client = _stream_client(response)
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    view = TrafficInspector(api)
    staged = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    original_publish = ExportPublicationState.publish

    def paused_publish(state, temporary, target):
        staged.set()
        try:
            assert release.wait(timeout=2)
            return original_publish(state, temporary, target)
        finally:
            finished.set()

    monkeypatch.setattr(ExportPublicationState, "publish", paused_publish)

    async def run():
        task = asyncio.create_task(view._run_export(("one", "raw", destination)))
        assert await asyncio.to_thread(staged.wait, 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        release.set()
        assert await asyncio.to_thread(finished.wait, 1)

    with patch("safeyolo.api.httpx.Client", return_value=client, autospec=True):
        asyncio.run(run())

    assert destination.read_bytes() == b"prior"
    assert response.closed
    assert not list(tmp_path.glob(".export-*"))


def test_export_cleanup_warning_keeps_published_result(tmp_path, monkeypatch):
    destination = tmp_path / "export.bin"
    destination.write_bytes(b"prior")
    response = _StreamResponse([b"replacement"])
    client = _stream_client(response)
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    original_cleanup = tempfile.TemporaryDirectory.cleanup

    def cleanup_then_fail(directory):
        original_cleanup(directory)
        raise OSError("staging cleanup failure")

    monkeypatch.setattr(tempfile.TemporaryDirectory, "cleanup", cleanup_then_fail)
    with patch("safeyolo.api.httpx.Client", return_value=client, autospec=True):
        result = api.traffic_export("one", "raw", destination)

    assert destination.read_bytes() == b"replacement"
    assert result.cleanup_warning == "staging cleanup warning"
    assert not list(tmp_path.glob(".export-*"))


def test_export_cleanup_warning_is_categorical_success_notice(tmp_path):
    api = create_autospec(AdminAPI, instance=True, spec_set=True)
    api.traffic_export.return_value = TrafficExportResult(
        status_code=200,
        content_type="application/octet-stream",
        bytes_written=11,
        cleanup_warning="staging cleanup warning",
    )
    view = TrafficInspector(api)
    destination = tmp_path / "export.bin"

    asyncio.run(view._run_export(("one", "raw", destination)))

    assert view.notice == f"Exported flow one to {destination} (11 bytes); staging cleanup warning"
    assert "unchanged" not in view.notice


def test_export_supports_long_valid_destination_basename(tmp_path):
    destination = tmp_path / ("x" * 250)
    response = _StreamResponse([b"long-name"])
    client = _stream_client(response)
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    with patch("safeyolo.api.httpx.Client", return_value=client, autospec=True):
        api.traffic_export("one", "raw", destination)

    assert destination.read_bytes() == b"long-name"
    assert not list(tmp_path.glob(".export-*"))


def test_export_empty_response_without_content_length_publishes_empty_file(tmp_path):
    destination = tmp_path / "export.bin"
    destination.write_bytes(b"prior")
    response = _StreamResponse([])
    client = _stream_client(response)
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    with patch("safeyolo.api.httpx.Client", return_value=client, autospec=True):
        result = api.traffic_export("one", "raw", destination)

    assert result.bytes_written == 0
    assert destination.read_bytes() == b""


def test_export_new_file_uses_current_umask(tmp_path):
    destination = tmp_path / "export.bin"
    response = _StreamResponse([b"new-file"])
    client = _stream_client(response)
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    previous_umask = os.umask(0o077)
    try:
        with patch("safeyolo.api.httpx.Client", return_value=client, autospec=True):
            api.traffic_export("one", "raw", destination)
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_export_fsync_failure_preserves_destination(tmp_path, monkeypatch):
    destination = tmp_path / "export.bin"
    destination.write_bytes(b"prior")
    response = _StreamResponse([b"replacement"])
    client = _stream_client(response)
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")

    def fail_fsync(_descriptor):
        raise OSError("fsync failure")

    monkeypatch.setattr("safeyolo.api.os.fsync", fail_fsync)
    with patch("safeyolo.api.httpx.Client", return_value=client, autospec=True):
        with pytest.raises(APIError, match="Cannot write traffic export"):
            api.traffic_export("one", "raw", destination)

    assert destination.read_bytes() == b"prior"
    assert response.closed
    assert not list(tmp_path.glob(".export-*"))


def test_export_response_close_failure_preserves_destination(tmp_path):
    destination = tmp_path / "export.bin"
    destination.write_bytes(b"prior")
    response = _StreamResponse([b"replacement"], exit_error=OSError("response close failure"))
    client = _stream_client(response)
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    with patch("safeyolo.api.httpx.Client", return_value=client, autospec=True):
        with pytest.raises(APIError, match="Cannot write traffic export"):
            api.traffic_export("one", "raw", destination)

    assert destination.read_bytes() == b"prior"
    assert response.closed
    assert not list(tmp_path.glob(".export-*"))


def test_export_client_close_failure_preserves_destination(tmp_path):
    destination = tmp_path / "export.bin"
    destination.write_bytes(b"prior")
    response = _StreamResponse([b"replacement"])
    client = _stream_client(response)
    client.__exit__.side_effect = OSError("client close failure")
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    with patch("safeyolo.api.httpx.Client", return_value=client, autospec=True):
        with pytest.raises(APIError, match="Cannot write traffic export"):
            api.traffic_export("one", "raw", destination)

    assert destination.read_bytes() == b"prior"
    assert response.closed
    assert not list(tmp_path.glob(".export-*"))


def test_export_output_close_failure_preserves_destination(tmp_path, monkeypatch):
    destination = tmp_path / "export.bin"
    destination.write_bytes(b"prior")
    response = _StreamResponse([b"replacement"])
    client = _stream_client(response)
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    original_open = Path.open

    class CloseFailure:
        def __init__(self, context):
            self._context = context

        def __enter__(self):
            return self._context.__enter__()

        def __exit__(self, *args):
            self._context.__exit__(*args)
            raise OSError("output close failure")

    def open_with_failure(path, *args, **kwargs):
        return CloseFailure(original_open(path, *args, **kwargs))

    monkeypatch.setattr(Path, "open", open_with_failure)
    with patch("safeyolo.api.httpx.Client", return_value=client, autospec=True):
        with pytest.raises(APIError, match="Cannot write traffic export"):
            api.traffic_export("one", "raw", destination)

    monkeypatch.undo()
    assert destination.read_bytes() == b"prior"
    assert response.closed
    assert not list(tmp_path.glob(".export-*"))


def test_export_midstream_httpx_failure_preserves_destination(tmp_path):
    destination = tmp_path / "export.bin"
    destination.write_bytes(b"prior")

    class MidstreamFailure(_StreamResponse):
        def iter_bytes(self, *, chunk_size: int):
            assert chunk_size == 64 * 1024
            yield b"partial"
            raise httpx.ReadError("mid-stream failure")

    response = MidstreamFailure([])
    client = _stream_client(response)
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    with patch("safeyolo.api.httpx.Client", return_value=client, autospec=True):
        with pytest.raises(APIError, match="Traffic export stream failed"):
            api.traffic_export("one", "raw", destination)

    assert destination.read_bytes() == b"prior"
    assert response.closed
    assert not list(tmp_path.glob(".export-*"))


def test_export_preserves_existing_symlink_target_and_mode(tmp_path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"prior")
    target.chmod(0o640)
    destination = tmp_path / "export.bin"
    destination.symlink_to(target)
    response = _StreamResponse([b"replacement"])
    client = _stream_client(response)
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    with patch("safeyolo.api.httpx.Client", return_value=client, autospec=True):
        api.traffic_export("one", "raw", destination)

    assert destination.is_symlink()
    assert target.read_bytes() == b"replacement"
    assert target.stat().st_mode & 0o777 == 0o640


def test_export_ui_freezes_flow_and_uses_local_path_while_websocket_mode(tmp_path):
    api = create_autospec(AdminAPI, instance=True, spec_set=True)
    api.traffic_flows.return_value = {"flows": [{"id": "one", "websocket": {}}], "scope": {}}
    api.traffic_flow.return_value = {"id": "one", "websocket": {"state": "open"}}
    api.traffic_websocket_messages.return_value = {"websocket": {}, "messages": []}
    api.traffic_export.return_value = TrafficExportResult(
        status_code=200,
        content_type="application/octet-stream",
        bytes_written=3,
    )
    view = TrafficInspector(api)

    async def wait_until(predicate):
        while not predicate():
            await asyncio.sleep(0.01)

    async def run():
        with create_pipe_input() as keyboard, create_app_session(input=keyboard, output=DummyOutput()):
            app = view.application()
            app.ttimeoutlen = 0.01

            async def operator():
                await wait_until(lambda: view.detail is not None)
                keyboard.send_text("w")
                await wait_until(lambda: view.websocket_mode)
                rows_buffer = app.layout.current_buffer
                keyboard.send_text("x")
                await wait_until(lambda: app.layout.current_buffer is not rows_buffer)
                keyboard.send_text("raw\r")
                await asyncio.sleep(0.03)
                view._select("redirected")
                keyboard.send_text(str(tmp_path / "captured.bin") + "\r")
                await asyncio.sleep(0.05)
                await wait_until(lambda: view._export_cancel_event is None and view._notice_hold is None)
                keyboard.send_text("q")

            app.pre_run_callables.append(lambda: app.create_background_task(operator()))
            await asyncio.wait_for(app.run_async(), timeout=3)

    asyncio.run(run())
    api.traffic_export.assert_called_once()
    assert api.traffic_export.call_args.args[:2] == ("one", "raw")
    assert api.traffic_export.call_args.args[2] == Path(tmp_path / "captured.bin")


def test_export_failure_notice_is_categorical_and_survives_one_poll(tmp_path):
    api = create_autospec(AdminAPI, instance=True, spec_set=True)
    api.traffic_flows.return_value = {"flows": [{"id": "one"}], "scope": {}}
    api.traffic_flow.return_value = {"id": "one"}
    api.traffic_export.side_effect = APIError("private payload", 422)
    view = TrafficInspector(api)
    view.snapshot(api.traffic_flows.return_value)
    view.queue_export("one", "raw", str(tmp_path / "export.bin"))

    asyncio.run(view.refresh())

    assert view.notice == "Export unavailable (APIError 422); destination unchanged"
    assert "private payload" not in view.notice
    asyncio.run(view.refresh())
    api.traffic_export.assert_called_once()


def test_cancelled_export_worker_signals_thread_before_task_detaches(tmp_path):
    api = create_autospec(AdminAPI, instance=True, spec_set=True)
    entered = threading.Event()
    received: list[threading.Event] = []

    def wait_for_cancel(_flow_id, _format_name, _destination, *, cancel_event):
        received.append(cancel_event)
        entered.set()
        cancel_event.wait(timeout=2)
        raise ExportCancelled()

    api.traffic_export.side_effect = wait_for_cancel
    view = TrafficInspector(api)

    async def run():
        task = asyncio.create_task(view._run_export(("one", "raw", tmp_path / "export.bin")))
        await asyncio.to_thread(entered.wait, 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert received and received[0].is_set()
