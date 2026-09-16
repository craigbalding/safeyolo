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
