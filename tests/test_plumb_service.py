"""Tests for core/plumb_service.py — the host-mediated agent-to-agent mailbox.

These exercise PlumbService directly (no mitmproxy), covering the state
machine, attribution, secret-scanning, async long-poll (wake + timeout), the
trusted/untrusted field split, and SQLite rehydrate-across-restart.
"""

import asyncio

import pytest

from safeyolo.core import plumb_service as ps


@pytest.fixture
def svc(tmp_path, monkeypatch):
    """Fresh PlumbService rooted at a temp data dir, with the audit sink
    stubbed out (write_event's async writer isn't configured in unit tests)."""
    monkeypatch.setenv("SAFEYOLO_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(ps, "write_event", lambda *a, **k: None)
    return ps.PlumbService(data_dir=str(tmp_path))


def _request_chat(svc, requester="web", others=("cody",), topic="topic", note="note", ttl=3600):
    return asyncio.run(svc.request_chat(requester, list(others), topic, note, ttl))


def _approved_conv(svc, requester="web", others=("cody",), ttl=3600):
    r = _request_chat(svc, requester, others, ttl=ttl)
    grant = asyncio.run(svc.approve_request(r["request_id"]))
    return grant["conversation_id"]


class TestRequestApprove:
    def test_request_chat_returns_pending(self, svc):
        r = _request_chat(svc)
        assert r["status"] == 202 and r["state"] == "pending"
        assert set(r["participants"]) == {"web", "cody"}

    def test_empty_targets_rejected(self, svc):
        # an agent cannot request a one-person "chat" (only itself)
        assert asyncio.run(svc.request_chat("web", [], "t", "n", 3600))["status"] == 400
        assert asyncio.run(svc.request_chat("web", ["web"], "t", "n", 3600))["status"] == 400

    def test_invalid_participant_name_rejected(self, svc):
        for bad in ("Cody", "has space", "under_score", ""):
            assert asyncio.run(svc.request_chat("web", [bad], "t", "n", 3600))["status"] == 400

    def test_over_limit_rejected_not_truncated(self, svc):
        svc._max_participants = 4
        # 'zzz' sorts last — the old sort+truncate could drop the requester;
        # now an over-limit set is rejected outright.
        res = asyncio.run(svc.request_chat("zzz", ["a", "b", "c", "d"], "t", "n", 3600))
        assert res["status"] == 400

    def test_max_participants_configurable(self, tmp_path):
        # the limit is an instance value (from config), not a hidden constant
        svc = ps.PlumbService(data_dir=str(tmp_path), max_participants=3)
        assert svc._max_participants == 3
        ok = asyncio.run(svc.request_chat("web", ["a", "b"], "t", "n", 3600))
        assert ok["status"] == 202                      # 3 incl. requester — allowed
        over = asyncio.run(svc.request_chat("web", ["a", "b", "c"], "t", "n", 3600))
        assert over["status"] == 400                    # 4 > 3 — rejected

    def test_requester_always_present(self, svc):
        # high-sorting requester name must still be in the member set
        r = _request_chat(svc, requester="zzz", others=("a", "b"))
        assert "zzz" in r["participants"]

    def test_untrusted_prose_is_sanitized_without_truncation(self, svc):
        long_topic = "line1\nline2\r[red]x" + ("z" * 1000)
        r = _request_chat(svc, topic=long_topic)
        topic = svc._pending[r["request_id"]]["topic"]
        assert "\n" not in topic and "\r" not in topic
        assert topic.endswith("z" * 1000)

    def test_requested_ttl_is_not_max_clamped(self, svc):
        r = _request_chat(svc, ttl=10**9)
        assert svc._pending[r["request_id"]]["ttl_seconds"] == 10**9

    def test_approve_creates_grant(self, svc):
        r = _request_chat(svc)
        g = asyncio.run(svc.approve_request(r["request_id"]))
        assert g["status"] == 200
        assert g["conversation_id"] in svc._convos
        assert set(g["participants"]) == {"web", "cody"}

    def test_operator_ttl_is_not_max_clamped(self, svc):
        r = _request_chat(svc, ttl=60)
        g = asyncio.run(svc.approve_request(r["request_id"], operator_ttl=10**9))
        assert g["expires_at"] - g["created_at"] >= (10**9 - 1)

    def test_list_pending_excludes_resolved(self, svc):
        r = _request_chat(svc)
        assert len(asyncio.run(svc.list_pending())["pending"]) == 1
        asyncio.run(svc.approve_request(r["request_id"]))
        assert asyncio.run(svc.list_pending())["pending"] == []

    def test_approve_unknown_request_404(self, svc):
        g = asyncio.run(svc.approve_request("req_nope"))
        assert g["status"] == 404

    def test_deny_marks_denied(self, svc):
        r = _request_chat(svc)
        d = asyncio.run(svc.deny_request(r["request_id"]))
        assert d["status"] == 200
        assert svc._pending[r["request_id"]]["status"] == "denied"


class TestMessaging:
    def test_non_member_cannot_post(self, svc):
        conv = _approved_conv(svc)
        res = asyncio.run(svc.post_message("intruder", conv, "hi"))
        assert res["status"] == 403

    def test_post_then_read_attributes_sender(self, svc):
        conv = _approved_conv(svc)
        asyncio.run(svc.post_message("web", conv, "review the UI?"))
        got = asyncio.run(svc.read_messages("cody", conv, None, 0))
        assert len(got["messages"]) == 1
        # sender comes from attribution, never the body
        assert got["messages"][0]["from_agent"] == "web"

    def test_secret_is_blocked(self, svc):
        conv = _approved_conv(svc)
        res = asyncio.run(svc.post_message("web", conv, "key sk-" + "a" * 48))
        assert res["status"] == 403
        assert "openai-api-key" in res["detected_classes"]

    def test_oversized_rejected(self, svc):
        svc._max_message_bytes = 8
        conv = _approved_conv(svc)
        res = asyncio.run(svc.post_message("web", conv, "x" * 9))
        assert res["status"] == 413

    def test_message_size_cap_can_be_disabled(self, tmp_path):
        svc = ps.PlumbService(data_dir=str(tmp_path), max_message_bytes=0)
        conv = _approved_conv(svc)
        res = asyncio.run(svc.post_message("web", conv, "x" * 100))
        assert res["status"] == 200

    def test_messages_are_not_capped_per_conversation(self, svc):
        conv = _approved_conv(svc)
        for i in range(20):
            assert asyncio.run(svc.post_message("web", conv, f"msg {i}"))["status"] == 200
        got = asyncio.run(svc.read_messages("cody", conv, None, 0))
        assert [m["body"] for m in got["messages"]] == [f"msg {i}" for i in range(20)]

    def test_read_messages_is_paginated(self, svc):
        conv = _approved_conv(svc)
        for i in range(5):
            assert asyncio.run(svc.post_message("web", conv, f"msg {i}"))["status"] == 200

        first = asyncio.run(svc.read_messages("cody", conv, None, 0, limit=2))
        assert [m["body"] for m in first["messages"]] == ["msg 0", "msg 1"]
        assert first["has_more"] is True
        assert first["next_after"] == first["messages"][-1]["id"]

        second = asyncio.run(
            svc.read_messages("cody", conv, first["next_after"], 0, limit=2)
        )
        assert [m["body"] for m in second["messages"]] == ["msg 2", "msg 3"]
        assert second["has_more"] is True

        third = asyncio.run(
            svc.read_messages("cody", conv, second["next_after"], 0, limit=2)
        )
        assert [m["body"] for m in third["messages"]] == ["msg 4"]
        assert third["has_more"] is False

    def test_read_limit_is_clamped_to_service_page_limit(self, tmp_path):
        svc = ps.PlumbService(data_dir=str(tmp_path), message_page_limit=3)
        conv = _approved_conv(svc)
        for i in range(5):
            asyncio.run(svc.post_message("web", conv, f"msg {i}"))
        got = asyncio.run(svc.read_messages("cody", conv, None, 0, limit=99))
        assert len(got["messages"]) == 3
        assert got["limit"] == 3
        assert got["has_more"] is True


class TestLongPoll:
    def test_longpoll_wakes_on_new_message(self, svc):
        conv = _approved_conv(svc)
        first = asyncio.run(svc.post_message("web", conv, "first"))
        last = first["id"]

        async def scenario():
            async def delayed():
                await asyncio.sleep(0.2)
                await svc.post_message("cody", conv, "reply")

            waiter = asyncio.create_task(svc.read_messages("web", conv, last, 5))
            poster = asyncio.create_task(delayed())
            res = await asyncio.wait_for(waiter, timeout=3)
            await poster
            return res

        res = asyncio.run(scenario())
        assert any(m["from_agent"] == "cody" for m in res["messages"])

    def test_longpoll_times_out_empty(self, svc):
        conv = _approved_conv(svc)
        only = asyncio.run(svc.post_message("web", conv, "only"))
        last = only["id"]
        res = asyncio.run(asyncio.wait_for(svc.read_messages("web", conv, last, 1), 3))
        assert res["messages"] == []


class TestPersistence:
    def test_grant_and_messages_rehydrate(self, svc, tmp_path):
        conv = _approved_conv(svc)
        asyncio.run(svc.post_message("web", conv, "persisted"))
        # a fresh service over the same data dir sees the grant + message
        svc2 = ps.PlumbService(data_dir=str(tmp_path))
        assert conv in svc2._convos
        got = asyncio.run(svc2.read_messages("cody", conv, None, 0))
        assert [m["body"] for m in got["messages"]] == ["persisted"]


class TestScanner:
    def test_secret_rules_load(self):
        # In CI (deps present) this is non-empty; a zero here would mean the
        # scanner is a silent no-op — which _load_secret_rules now logs loudly.
        assert isinstance(ps._load_secret_rules(), list)
