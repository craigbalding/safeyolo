"""Owned data and strict API mocks; no terminal or listener is started."""

import asyncio
import base64
from unittest.mock import create_autospec, patch

import pytest
from prompt_toolkit.application import Application, create_app_session
from prompt_toolkit.input import DummyInput, create_pipe_input
from prompt_toolkit.key_binding.key_processor import KeyPressEvent
from prompt_toolkit.keys import Keys
from prompt_toolkit.output import DummyOutput

from safeyolo.api import AdminAPI, APIError
from safeyolo.traffic_inspector import (
    BODY_PREVIEW_BYTES,
    TrafficInspector,
    body_preview,
    bulk_export_filename,
    plain_text,
)


def flow(name="one", **changes):
    return {"id": name, "agent": "alice", "method": "GET", "url": "http://owned.invalid/",
            "state": "complete", "status": 200, "request_headers": [["X-Same", "first"], ["X-Same", "second"]],
            "response_headers": [], "request_body": {"available": True, "size": 0, "reason": None},
            "response_body": {"available": False, "size": None, "reason": "streamed_or_unavailable"},
            "metadata": {"test_agent": "declared", "test_id": "case"}, **changes}


def client():
    api = create_autospec(AdminAPI, instance=True, spec_set=True)
    api.traffic_flows.return_value = {"flows": [flow()], "scope": {"agent": "alice"}}
    api.traffic_flow.return_value = flow()
    return api


def test_plain_rendering_escapes_terminal_controls_without_parsing_markup():
    attack = "[bold]\x1b[2J\x1b]52;c;copied\x07\x9b31m\r\n\u202e"
    text = plain_text(attack)
    assert text == r"[bold]\x1b[2J\x1b]52;c;copied\x07\x9b31m\x0d\x0a\u202e"
    assert plain_text("one\ntwo\tend", multiline=True) == "one\ntwo\\x09end"


def test_body_preview_distinguishes_absent_empty_and_bounded_raw_bytes():
    assert body_preview({"available": False, "reason": "pending"}) == "absent: pending"
    assert body_preview({"available": True, "data_base64": ""}) == "(present, empty body)"
    raw = b"\xff\x1b]52;x\x07" + b"a" * BODY_PREVIEW_BYTES
    value = {"available": True, "data_base64": base64.b64encode(raw).decode()}
    text = body_preview(value)
    assert text.startswith(r"\xff\x1b]52;x\x07")
    assert "[preview: first" in text
    assert "\x1b" not in text
    with pytest.raises(ValueError, match="Invalid retained body"):
        body_preview({"available": True, "data_base64": "not base64!"})


def test_selection_survives_newest_insert_and_clears_details_on_eviction():
    view = TrafficInspector(client())
    view.snapshot({"flows": [flow("two"), flow("one")], "scope": {}})
    view.select(1)
    view.detail = flow("one")
    view.body = "old preview"
    view.snapshot({"flows": [flow("three"), flow("two"), flow("one")], "scope": {}})
    assert view.selected == "one"
    assert view.body == "old preview"
    view.snapshot({"flows": [flow("three"), flow("two")], "scope": {}})
    assert view.selected == "three"
    assert view.detail is None and view.body == ""
    view.snapshot({"flows": [], "scope": {}})
    assert view.selected is None


def test_marked_flows_are_distinct_from_focus_and_hidden_marks_are_dropped():
    view = TrafficInspector(client())
    view.snapshot({"flows": [flow("one"), flow("two"), flow("three")], "scope": {}})
    view.toggle_mark()
    view.select(1)
    view.toggle_mark()

    assert view.selected == "two"
    assert view.marked == {"one", "two"}
    assert view.export_flow_ids() == ("one", "two")
    assert view.rows_text().splitlines()[:2] == [
        " * 200 complete alice GET http://owned.invalid/",
        ">* 200 complete alice GET http://owned.invalid/",
    ]
    assert "> focus" in view.help_text()
    assert "* marked" in view.help_text()
    assert "m mark/unmark" in view.help_text()
    assert "x export marked (or focused)" in view.help_text()

    # The refreshed scope/list is authoritative for marks as well as focus.
    view.snapshot({"flows": [flow("two", agent="bob")], "scope": {"agent": "bob"}})
    assert view.selected == "two"
    assert view.marked == {"two"}
    assert view.export_flow_ids() == ("two",)


def test_bulk_export_filename_is_stable_safe_and_distinguishes_normalized_ids():
    first = bulk_export_filename("flow/one?", "raw_request")
    second = bulk_export_filename("flow:one?", "raw_request")

    assert first == bulk_export_filename("flow/one?", "raw_request")
    assert first != second
    assert "/" not in first and "?" not in first
    assert first.endswith(".raw_request")


def test_detail_retains_duplicate_headers_metadata_and_body_facts():
    view = TrafficInspector(client())
    view.detail = flow(url="http://owned.invalid/\x1b[2J")
    text = view.detail_text()
    assert "X-Same: first\nX-Same: second" in text
    assert "Request body: retained: 0 bytes" in text
    assert "Response body: absent: streamed_or_unavailable" in text
    assert '"test_agent": "declared"' in text
    assert r"\x1b[2J" in text and "\x1b" not in text


def test_refresh_fetches_body_only_on_request_and_updates_shared_scope():
    api = client()
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        api.traffic_body.assert_not_called()
        view.request_body("response")
        api.traffic_body.return_value = {"available": True, "data_base64": "aGVsbG8="}
        await view.refresh()
        assert view.body.endswith("hello")
        view.set_scope("test_id", "new-case")
        await view.refresh()
        api.set_traffic_scope.assert_called_once_with(agent="alice", unattributed=False, test_id="new-case")
        view.pending_scope = {}
        await view.refresh()
        assert api.set_traffic_scope.call_args.kwargs == {}

    asyncio.run(run())
    api.traffic_body.assert_called_once_with("one", "response")


def test_error_notice_omits_response_content_and_next_refresh_recovers():
    api = client()
    view = TrafficInspector(api)
    api.traffic_flows.side_effect = APIError("private traffic payload\x1b[2J", 503)
    asyncio.run(view.refresh())
    assert view.notice == "View unavailable (APIError 503); retrying"
    api.traffic_flows.side_effect = None
    asyncio.run(view.refresh())
    assert view.selected == "one" and "1 visible" in view.notice


def test_changed_body_facts_clear_fetched_snapshot():
    api = client()
    view = TrafficInspector(api)
    asyncio.run(view.refresh())
    view.body = "earlier fetched body"
    api.traffic_flow.return_value = flow(response_body={"available": True, "size": 4})
    asyncio.run(view.refresh())
    assert view.body == ""


def test_headless_real_application_polls_cancels_prompt_and_detaches():
    api = client()
    view = TrafficInspector(api)

    async def run():
        with create_pipe_input() as keyboard, create_app_session(input=keyboard, output=DummyOutput()):
            app = view.application()
            app.ttimeoutlen = 0.01

            async def operator():
                while view.detail is None:
                    await asyncio.sleep(0.01)
                keyboard.send_text("a")
                await asyncio.sleep(0.03)
                keyboard.send_text("discarded\x1b")
                await asyncio.sleep(0.04)
                keyboard.send_text("q")

            app.pre_run_callables.append(lambda: app.create_background_task(operator()))
            await asyncio.wait_for(app.run_async(), timeout=3)

    asyncio.run(run())
    api.traffic_flows.assert_called()
    api.traffic_flow.assert_called_with("one")
    api.set_traffic_scope.assert_not_called()


def test_real_application_quit_binding_only_exits_ui():
    view = TrafficInspector(client())
    with create_app_session(input=DummyInput(), output=DummyOutput()):
        app = view.application()
    event = create_autospec(KeyPressEvent, instance=True, spec_set=True)
    event.app = create_autospec(Application, instance=True, spec_set=True)
    app.key_bindings.get_bindings_for_keys((Keys.ControlC,))[0].handler(event)
    event.app.exit.assert_called_once_with()
    view.api.traffic_flows.assert_not_called()


def test_api_helpers_keep_ids_within_the_route_and_validate_body_side():
    # Explicit URL and token avoid any receipt/default-file lookup.
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    assert not api.is_native
    with patch.object(AdminAPI, "_request", autospec=True) as request:
        api.traffic_flows()
        request.assert_called_with(api, "GET", "/admin/traffic/flows")
        api.traffic_flow("one/two?#")
        request.assert_called_with(api, "GET", "/admin/traffic/flows/one%2Ftwo%3F%23")
        api.traffic_body("one/two", "response")
        request.assert_called_with(api, "GET", "/admin/traffic/flows/one%2Ftwo/body?side=response")
        api.traffic_facets()
        request.assert_called_with(api, "GET", "/admin/traffic/facets")
        request.reset_mock()
        with pytest.raises(ValueError, match="body side"):
            api.traffic_body("one", "wrong")
        request.assert_not_called()


def test_filter_api_preserves_expression_and_returns_accepted_scope():
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    accepted = {"status": "updated", "agent": "alice", "user_filter": "  ~m GET  ",
                "effective_filter": '~meta "^agent: alice$" & (~m GET)'}
    with patch.object(AdminAPI, "_request", autospec=True, spec_set=True) as request:
        request.return_value = accepted
        assert api.set_traffic_filter("  ~m GET  ") is accepted
        request.assert_called_once_with(api, "PUT", "/admin/traffic/filter", json={"user_filter": "  ~m GET  "})
        api.set_traffic_filter("")
        request.assert_called_with(api, "PUT", "/admin/traffic/filter", json={"user_filter": ""})


def test_invalid_filter_retains_view_and_scope_clear_keeps_authoritative_filter():
    api = client()
    accepted = {"agent": "alice", "user_filter": "~m GET", "effective_filter": 'agent alice & (~m GET)'}
    api.traffic_flows.return_value["scope"] = accepted
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        previous = view.flows, view.detail, view.scope, view.selected
        api.reset_mock()
        api.set_traffic_filter.side_effect = APIError("private search\x1b]52;value", 400)
        view.set_filter("~b private search\x1b]52;value")
        assert view.scope == accepted
        api.set_traffic_filter.assert_not_called()  # queued for the existing worker
        await view.refresh()
        assert (view.flows, view.detail, view.scope, view.selected) == previous
        assert view.notice == "View unavailable (APIError 400); retrying"
        assert view.pending_filter is None
        api.traffic_flows.assert_not_called()
        api.get_traffic_scope.assert_not_called()
        api.set_traffic_scope.assert_not_called()
        view.pending_scope = {}
        # A later accepted list is authoritative, including changes by another operator.
        api.traffic_flows.return_value = {"flows": [flow()], "scope": {
            "agent": None, "user_filter": "~m GET", "effective_filter": "(~m GET)",
        }}
        await view.refresh()
        api.set_traffic_scope.assert_called_once_with()
        assert api.set_traffic_filter.call_count == 1  # no automatic rejected-edit retry
        assert view.scope["user_filter"] == "~m GET" and view.scope["agent"] is None
        assert view.scope["effective_filter"] == "(~m GET)"
        assert "1 visible" in view.notice

    asyncio.run(run())


def test_headless_filter_editor_prefills_cancels_clears_and_preserves_whitespace():
    api = client()
    original = "  ~m GET  "
    api.traffic_flows.return_value["scope"] = {
        "agent": "alice", "user_filter": original, "effective_filter": "agent alice & (~m GET)",
    }

    def accepted(expression):
        scope = {"agent": "alice", "user_filter": expression,
                 "effective_filter": "agent alice" + (f" & ({expression.strip()})" if expression else "")}
        api.traffic_flows.return_value["scope"] = scope
        return {"status": "updated", **scope}

    api.set_traffic_filter.side_effect = accepted
    view = TrafficInspector(api)

    async def until(predicate):
        while not predicate():
            await asyncio.sleep(0.01)

    async def run():
        with create_pipe_input() as keyboard, create_app_session(input=keyboard, output=DummyOutput()):
            app = view.application()
            app.ttimeoutlen = 0.01

            async def operator():
                await until(lambda: view.detail is not None)
                rows = app.layout.current_buffer
                keyboard.send_text("f")
                await until(lambda: app.layout.current_buffer is not rows)
                assert app.layout.current_buffer.text == original
                assert app.layout.current_buffer.cursor_position == len(original)
                keyboard.send_text("discarded\x1b")
                await until(lambda: app.layout.current_buffer is rows)
                api.set_traffic_filter.assert_not_called()
                keyboard.send_text("f")
                await until(lambda: app.layout.current_buffer is not rows)
                assert app.layout.current_buffer.text == original
                keyboard.send_text("\x01\x0b\r")  # Ctrl-A, Ctrl-K, Enter: clear only the filter
                await until(lambda: view.scope.get("user_filter") == "")
                api.set_traffic_filter.assert_called_once_with("")
                assert view.scope["agent"] == "alice" and view.selected == "one"
                keyboard.send_text("f")
                await until(lambda: app.layout.current_buffer is not rows)
                keyboard.send_text("  ~b marker  \r")
                await until(lambda: view.scope.get("user_filter") == "  ~b marker  ")
                assert view.scope["effective_filter"] == "agent alice & (~b marker)"
                assert view.selected == "one" and "f filter" in view.help_text()
                keyboard.send_text("q")

            app.pre_run_callables.append(lambda: app.create_background_task(operator()))
            await asyncio.wait_for(app.run_async(), timeout=3)

    asyncio.run(run())
    assert [call.args for call in api.set_traffic_filter.call_args_list] == [("",), ("  ~b marker  ",)]
    api.set_traffic_scope.assert_not_called()


def test_accepted_filter_and_scope_remain_editable_when_flow_matching_fails():
    api = client()
    api.traffic_flows.return_value["scope"] = {
        "agent": "alice", "user_filter": "~m GET", "effective_filter": "agent alice & (~m GET)",
    }
    view = TrafficInspector(api)
    expression = "  ~b retained  "

    async def run():
        await view.refresh()
        previous_rows, previous_detail = view.flows, view.detail
        accepted = {"status": "updated", "agent": "alice", "user_filter": expression,
                    "effective_filter": "agent alice & (~b retained)"}
        api.set_traffic_filter.return_value = accepted
        api.traffic_flows.side_effect = APIError("private retained content", 500)
        view.set_filter(expression)
        await view.refresh()
        assert view.scope is accepted and view.scope["user_filter"] == expression
        assert view.flows == previous_rows and view.detail == previous_detail
        assert view.notice == "View unavailable (APIError 500); retrying"
        view.pending_scope = {}
        accepted_unpinned = {**accepted, "agent": None, "effective_filter": "(~b retained)"}
        api.set_traffic_scope.return_value = accepted_unpinned
        await view.refresh()
        assert view.scope is accepted_unpinned
        assert view.scope["user_filter"] == expression
        assert view.flows == previous_rows and "APIError 500" in view.notice
        # Clearing still targets the actual active expression after a failed list read.
        cleared = {"status": "updated", "agent": None, "user_filter": "", "effective_filter": ""}
        api.set_traffic_filter.return_value = cleared
        api.traffic_flows.side_effect = None
        api.traffic_flows.return_value = {"flows": [flow()], "scope": cleared}
        view.set_filter("")
        await view.refresh()
        assert view.scope is cleared and "1 visible" in view.notice

    asyncio.run(run())
    assert [call.args for call in api.set_traffic_filter.call_args_list] == [(expression,), ("",)]
    api.set_traffic_scope.assert_called_once_with()


@pytest.mark.parametrize("already_attached", [False, True])
def test_list_failure_fetches_other_operators_filter_without_replacing_rows(already_attached):
    api = client()
    view = TrafficInspector(api)
    actual = {"agent": "bob", "user_filter": "  ~b changed  ", "effective_filter": "agent bob & (~b changed)"}

    async def run():
        if already_attached:
            await view.refresh()
        previous_rows, previous_detail, previous_selected = view.flows, view.detail, view.selected
        api.reset_mock()
        api.traffic_flows.side_effect = APIError("sensitive match failure", 500)
        api.get_traffic_scope.return_value = actual
        await view.refresh()
        assert view.scope is actual and view.scope["user_filter"] == "  ~b changed  "
        assert (view.flows, view.detail, view.selected) == (previous_rows, previous_detail, previous_selected)
        assert view.notice == "View unavailable (APIError 500); retrying"
        assert [call[0] for call in api.method_calls] == ["traffic_flows", "get_traffic_scope"]
        api.set_traffic_filter.assert_not_called()
        api.set_traffic_scope.assert_not_called()

    asyncio.run(run())


def test_failed_scope_recovery_keeps_previous_projection_and_original_list_error():
    api = client()
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        previous = view.flows, view.detail, view.scope, view.selected
        api.reset_mock()
        api.traffic_flows.side_effect = APIError("original private match error", 500)
        api.get_traffic_scope.side_effect = APIError("later private scope error", 503)
        await view.refresh()
        assert (view.flows, view.detail, view.scope, view.selected) == previous
        assert view.notice == "View unavailable (APIError 500); retrying"
        assert [call[0] for call in api.method_calls] == ["traffic_flows", "get_traffic_scope"]
        api.traffic_flow.assert_not_called()
        api.set_traffic_filter.assert_not_called()

    asyncio.run(run())


def websocket_session(**changes):
    return {"state": "open", "started": 1.25, "timestamp_end": None, "closed_by_client": None,
            "close_code": None, "close_reason": None,
            "messages_meta": {"count": 0, "contentLength": 0, "timestamp_last": None},
            "trimmed_messages": 0, **changes}


def message(message_id, size=1, **changes):
    return {"id": message_id, "type": "text", "from_client": True, "timestamp": 2.0,
            "dropped": False, "injected": False,
            "body": {"available": True, "size": size, "reason": None}, **changes}


def message_page(data=b"x", *, offset=0, total=None):
    total = len(data) if total is None else total
    return {"available": True, "offset": offset, "total_size": total, "size": len(data),
            "data_base64": base64.b64encode(data).decode(), "end": offset + len(data) == total, "reason": None}


def websocket_client(messages=None):
    api = client()
    session = websocket_session()
    row = flow(state="websocket_open", status=101, websocket=session)
    api.traffic_flows.return_value = {"flows": [row], "scope": {}}
    api.traffic_flow.return_value = row
    api.traffic_websocket_messages.return_value = {"websocket": session, "messages": messages or []}
    api.traffic_websocket_message_body.return_value = message_page()
    return api


def test_websocket_rendering_preserves_disposition_close_and_trimmed_history():
    api = websocket_client([message(7, 4, type="binary", from_client=False, dropped=True)])
    api.traffic_flow.return_value["error"] = "inspection_error"
    session = api.traffic_websocket_messages.return_value["websocket"]
    session.update(state="error", timestamp_end=5.0, close_code=1006,
                   close_reason="\x1b]52;c;secret\x07\n[bold]", trimmed_messages=3,
                   messages_meta={"count": 1, "contentLength": 4, "timestamp_last": 2.0})
    api.traffic_websocket_message_body.return_value = message_page(b"\xff\x1b\r\n")
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        assert "w opens transcript" in view.detail_text()
        view.toggle_websocket()
        await view.refresh()

    asyncio.run(run())
    assert "> 7 server→client binary 4 bytes @2.0 dropped" in view.rows_text()
    text = view.detail_text()
    assert "error: inspection_error" in text
    assert "state: error" in text and "timestamp_end: 5.0" in text
    assert "closed_by_client: None" in text and "close_code: 1006" in text
    assert "Retained: 1 messages / 4 bytes; trimmed from history: 3" in text
    assert "dropped: True" in text and "injected: False" in text
    assert "not a delivery receipt" in text
    assert "Message bytes [0:4) of 4 (decompressed/unmasked bytes" in text
    assert r"\xff\x1b\x0d" in text and "\x1b" not in text and "\r" not in text
    assert r"close_reason: \x1b]52;c;secret\x07\x0a[bold]" in text


def test_websocket_pages_are_fetched_once_and_keep_selection_when_messages_arrive():
    size = BODY_PREVIEW_BYTES * 2 + 3
    api = websocket_client([message(7, size)])
    payload = b"a" * BODY_PREVIEW_BYTES + b"b" * BODY_PREVIEW_BYTES + b"end"
    api.traffic_websocket_message_body.side_effect = lambda flow_id, message_id, offset: message_page(
        payload[offset:offset + BODY_PREVIEW_BYTES], offset=offset, total=size,
    )
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        view.toggle_websocket()
        await view.refresh()
        assert f"[0:{BODY_PREVIEW_BYTES}) of {size}" in view.detail_text()
        await view.refresh()
        assert api.traffic_websocket_message_body.call_count == 1
        api.traffic_websocket_messages.return_value["messages"].append(message(9))
        await view.refresh()
        assert view.transcript.selected == 7
        assert api.traffic_websocket_message_body.call_count == 1
        view.transcript.page(1)
        assert view.transcript.body == ""
        await view.refresh()
        assert f"[{BODY_PREVIEW_BYTES}:{BODY_PREVIEW_BYTES * 2}) of {size}" in view.detail_text()
        view.transcript.page(1)
        await view.refresh()
        assert view.transcript.body.endswith("end")
        assert f"[{BODY_PREVIEW_BYTES * 2}:{size})" in view.detail_text()
        view.transcript.page(-1)
        await view.refresh()
        assert view.transcript.body.endswith("b" * BODY_PREVIEW_BYTES)

    asyncio.run(run())
    assert [call.args for call in api.traffic_websocket_message_body.call_args_list] == [
        ("one", 7, 0), ("one", 7, BODY_PREVIEW_BYTES), ("one", 7, BODY_PREVIEW_BYTES * 2),
        ("one", 7, BODY_PREVIEW_BYTES),
    ]


def test_filter_refresh_preserves_visible_websocket_selection_and_cached_page():
    api = websocket_client([message(7)])
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        view.toggle_websocket()
        await view.refresh()
        previous_page = view.transcript.body
        api.reset_mock()
        view.set_filter("  ~b x  ")
        api.traffic_flows.return_value["scope"] = {"user_filter": "  ~b x  ", "effective_filter": "(~b x)"}
        await view.refresh()
        assert [call[0] for call in api.method_calls] == [
            "set_traffic_filter", "traffic_flows", "traffic_flow", "traffic_websocket_messages",
        ]
        assert view.websocket_mode and view.selected == "one" and view.transcript.selected == 7
        assert view.transcript.body == previous_page
        api.traffic_websocket_message_body.assert_not_called()
        api.set_traffic_scope.assert_not_called()
        # An accepted expression hiding the current row releases its client projection.
        api.traffic_flows.return_value = {"flows": [], "scope": {"user_filter": "~b missing", "effective_filter": "(~b missing)"}}
        view.set_filter("~b missing")
        await view.refresh()
        assert view.selected is None and not view.websocket_mode
        assert not view.transcript.messages and not view.transcript.body

    asyncio.run(run())


def test_trimmed_selection_and_changed_flow_clear_old_pages_and_http_controls_work():
    api = websocket_client([message(1), message(2)])
    api.traffic_websocket_message_body.side_effect = lambda flow_id, message_id, offset: message_page(str(message_id).encode())
    api.traffic_body.return_value = {"available": True, "data_base64": "aHR0cA=="}
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        view.toggle_websocket()
        await view.refresh()
        view.select(1)
        assert view.transcript.selected == 2 and view.transcript.body == ""
        await view.refresh()
        assert view.transcript.body.endswith("2")
        api.traffic_websocket_messages.return_value["messages"] = [message(3)]
        api.traffic_websocket_messages.return_value["websocket"]["trimmed_messages"] = 2
        await view.refresh()
        assert view.transcript.selected == 3 and view.transcript.body.endswith("3")
        view.request_body("request")
        assert not view.websocket_mode
        await view.refresh()
        assert view.body.endswith("http") and "encoded bytes" in view.detail_text()
        assert view.selected == "one"
        view.toggle_websocket()
        await view.refresh()
        assert view.transcript.selected == 3
        view.snapshot({"flows": [flow("other")], "scope": {}})
        assert not view.websocket_mode and view.selected == "other"
        assert view.transcript.messages == [] and view.transcript.body == ""

    asyncio.run(run())
    api.traffic_body.assert_called_once_with("one", "request")
    assert api.traffic_websocket_message_body.call_count == 3


def test_missing_page_and_storage_error_remain_explicit_and_recover_on_request():
    api = websocket_client([message(5)])
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        view.toggle_websocket()
        api.traffic_websocket_message_body.side_effect = APIError("sensitive payload\x1b", 404)
        await view.refresh()
        assert "APIError 404" in view.notice and "sensitive" not in view.notice
        assert view.transcript.body == ""
        await view.refresh()
        assert api.traffic_websocket_message_body.call_count == 1
        api.traffic_websocket_message_body.side_effect = None
        api.traffic_websocket_message_body.return_value = {
            "available": False, "offset": 0, "total_size": 1, "size": 0,
            "data_base64": None, "end": False, "reason": "storage_error",
        }
        view.transcript.page(-1)
        await view.refresh()
        assert "absent: storage_error" in view.detail_text()
        api.traffic_websocket_message_body.return_value = message_page()
        view.transcript.page(-1)
        await view.refresh()
        assert view.transcript.body.endswith("x")
        api.traffic_websocket_messages.return_value["messages"] = []
        await view.refresh()
        assert view.transcript.selected is None and view.transcript.body == ""
        assert "No retained WebSocket messages" in view.rows_text()

    asyncio.run(run())


def test_websocket_empty_bytes_and_invalid_page_contract():
    from safeyolo.traffic_inspector import websocket_page

    text = websocket_page(message_page(b""), 0)
    assert "bytes [0:0) of 0" in text and "present, empty body" in text
    for changes in ({"offset": 1}, {"size": 2}, {"end": False}, {"data_base64": "!"}):
        value = {**message_page(), **changes}
        with pytest.raises(ValueError):
            websocket_page(value, 0)
    with pytest.raises(ValueError, match="bounds"):
        websocket_page(message_page(b"x" * (BODY_PREVIEW_BYTES + 1)), 0)


def test_headless_application_navigates_websocket_pages_and_returns_to_http():
    api = websocket_client([message(1), message(2, BODY_PREVIEW_BYTES + 1)])
    api.traffic_websocket_message_body.side_effect = lambda flow_id, message_id, offset: message_page(
        b"x" if message_id == 1 or offset else b"a" * BODY_PREVIEW_BYTES,
        offset=offset, total=1 if message_id == 1 else BODY_PREVIEW_BYTES + 1,
    )
    view = TrafficInspector(api)

    async def until(predicate):
        while not predicate():
            await asyncio.sleep(0.01)

    async def run():
        with create_pipe_input() as keyboard, create_app_session(input=keyboard, output=DummyOutput()):
            app = view.application()
            app.ttimeoutlen = 0.01

            async def operator():
                await until(lambda: view.detail is not None)
                keyboard.send_text("w")
                await until(lambda: bool(view.transcript.body))
                keyboard.send_text("\x1b[B")
                await until(lambda: view.transcript.selected == 2 and bool(view.transcript.body))
                keyboard.send_text("]")
                await until(lambda: view.transcript.offset == BODY_PREVIEW_BYTES and bool(view.transcript.body))
                assert f"[{BODY_PREVIEW_BYTES}:{BODY_PREVIEW_BYTES + 1})" in view.detail_text()
                keyboard.send_text("\t\x1b[A")
                await asyncio.sleep(0.04)
                assert view.transcript.selected == 2  # detail scrolling does not select another message
                keyboard.send_text("[w")
                await until(lambda: not view.websocket_mode)
                assert view.selected == "one" and "HTTP" not in view.help_text()
                keyboard.send_text("q")

            app.pre_run_callables.append(lambda: app.create_background_task(operator()))
            await asyncio.wait_for(app.run_async(), timeout=3)

    asyncio.run(run())
    assert api.traffic_websocket_message_body.call_args_list[0].args == ("one", 1, 0)
    assert ("one", 2, BODY_PREVIEW_BYTES) in [call.args for call in api.traffic_websocket_message_body.call_args_list]
    api.traffic_body.assert_not_called()
    api.set_traffic_scope.assert_not_called()


def test_websocket_api_helpers_quote_identifiers_and_validate_offsets():
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    with patch.object(AdminAPI, "_request", autospec=True, spec_set=True) as request:
        api.traffic_websocket_messages("one/two?#")
        request.assert_called_with(api, "GET", "/admin/traffic/flows/one%2Ftwo%3F%23/websocket/messages")
        api.traffic_websocket_message_body("one/two", 7)
        request.assert_called_with(api, "GET", "/admin/traffic/flows/one%2Ftwo/websocket/messages/7/body?offset=0")
        api.traffic_websocket_message_body("one", "7/evil?", BODY_PREVIEW_BYTES)
        request.assert_called_with(api, "GET", "/admin/traffic/flows/one/websocket/messages/7%2Fevil%3F/body?offset=65536")
        request.reset_mock()
        for offset in (-1, 1.5, True, "0"):
            with pytest.raises(ValueError, match="offset"):
                api.traffic_websocket_message_body("one", 7, offset)
        request.assert_not_called()


def test_inflight_page_cannot_replace_new_message_selection():
    import threading

    api = websocket_client([message(1), message(2)])
    entered, release = threading.Event(), threading.Event()

    def read_page(flow_id, message_id, offset):
        if message_id == 1:
            entered.set()
            assert release.wait(timeout=2)
        return message_page(str(message_id).encode())

    api.traffic_websocket_message_body.side_effect = read_page
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        view.toggle_websocket()
        refresh = asyncio.create_task(view.refresh())
        try:
            while not entered.is_set():
                await asyncio.sleep(0.01)
            view.select(1)
            assert view.transcript.selected == 2 and view.transcript.body == ""
        finally:
            release.set()
            await refresh
        assert view.transcript.body == ""
        await view.refresh()
        assert view.transcript.body.endswith("2")

    asyncio.run(asyncio.wait_for(run(), timeout=3))
    assert [call.args for call in api.traffic_websocket_message_body.call_args_list] == [
        ("one", 1, 0), ("one", 2, 0),
    ]
