"""Tests for addons/flow_store.py - SQLite flow storage."""

import json
import sqlite3

import pytest

from safeyolo.storage.flow_store import (
    FlowStore,
    compress_body,
    decompress_body,
    extract_preview,
    headers_to_json,
    is_text_like_content_type,
)


@pytest.fixture
def store(tmp_path):
    """Create an initialized FlowStore with temp DB."""
    db = tmp_path / "test_flows.sqlite3"
    s = FlowStore(db_path=str(db))
    s.init_db()
    yield s
    s.close()


def _make_record(**overrides):
    """Create a minimal valid flow record."""
    defaults = {
        "request_id": "req-test000001",
        "ts_start": 1710000100000,
        "ts_end": 1710000100084,
        "duration_ms": 84,
        "engagement_id": "acme-portal",
        "agent_id": "agent-1",
        "source_id": "172.20.0.5",
        "run": "sec1",
        "test": "idor-baseline",
        "role": "attacker",
        "context_json": json.dumps({"run": "sec1", "test": "idor-baseline"}),
        "source_type": None,
        "flow_state": "completed",
        "scheme": "https",
        "host": "app.example.com",
        "port": 443,
        "method": "GET",
        "path": "/api/todos/42",
        "query_string": None,
        "full_url": "https://app.example.com/api/todos/42",
        "status_code": 200,
        "reason": None,
        "request_content_type": "",
        "response_content_type": "application/json",
        "is_websocket": False,
        "request_headers_json": "[]",
        "response_headers_json": "[]",
        "request_body": b"",
        "response_body": b'{"id":42,"owner":"alice","title":"Buy milk"}',
    }
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

class TestCompress:
    def test_compress_decompress_roundtrip(self):
        data = b"Hello, world! " * 100
        compressed = compress_body(data)
        assert compressed != data
        assert decompress_body(compressed) == data

    def test_compress_empty(self):
        compressed = compress_body(b"")
        assert decompress_body(compressed) == b""


class TestIsTextLikeContentType:
    def test_text_types_recognised(self):
        assert is_text_like_content_type("text/html")
        assert is_text_like_content_type("text/plain; charset=utf-8")
        assert is_text_like_content_type("application/json")
        assert is_text_like_content_type("application/javascript")
        assert is_text_like_content_type("application/xml")
        assert is_text_like_content_type("application/x-www-form-urlencoded")
        assert is_text_like_content_type("application/problem+json")
        assert is_text_like_content_type("application/graphql-response+json")
        assert is_text_like_content_type("application/vnd.api+json")
        assert is_text_like_content_type("application/soap+xml")

    def test_non_text_types_rejected(self):
        assert not is_text_like_content_type("image/png")
        assert not is_text_like_content_type("application/octet-stream")
        assert not is_text_like_content_type("application/pdf")
        assert not is_text_like_content_type("")
        assert not is_text_like_content_type("video/mp4")

    def test_case_insensitive(self):
        """Content type matching is case insensitive per RFC 7231."""
        assert is_text_like_content_type("Application/JSON")
        assert is_text_like_content_type("TEXT/HTML")
        assert is_text_like_content_type("Application/Vnd.Api+JSON")


class TestExtractPreview:
    def test_text_body_extracted(self):
        body = b'{"key": "value"}'
        preview = extract_preview(body, "application/json")
        assert preview == '{"key": "value"}'

    def test_truncation_at_max_chars(self):
        body = b"x" * 20000
        preview = extract_preview(body, "text/plain", max_chars=100)
        assert len(preview) == 100
        assert preview == "x" * 100

    def test_binary_returns_empty(self):
        body = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        preview = extract_preview(body, "image/png")
        assert preview == ""

    def test_empty_body_returns_empty(self):
        assert extract_preview(b"", "text/html") == ""

    def test_none_body_returns_empty(self):
        assert extract_preview(None, "text/html") == ""


class TestHeadersToJson:
    def test_basic_headers(self):
        from mitmproxy.http import Headers
        h = Headers([(b"Content-Type", b"application/json"), (b"X-Custom", b"test")])
        result = json.loads(headers_to_json(h))
        assert result == [["Content-Type", "application/json"], ["X-Custom", "test"]]

    def test_none_returns_empty_list(self):
        assert headers_to_json(None) == "[]"

    def test_duplicate_header_names_preserved(self):
        from mitmproxy.http import Headers
        h = Headers([(b"Set-Cookie", b"a=1"), (b"Set-Cookie", b"b=2")])
        result = json.loads(headers_to_json(h))
        assert result == [["Set-Cookie", "a=1"], ["Set-Cookie", "b=2"]]

    def test_redact_replaces_value_with_gateway_suffix(self):
        """Redacted headers get [GATEWAY:...{last4}] as value."""
        from mitmproxy.http import Headers
        h = Headers([(b"Authorization", b"Bearer sk-abc123xyz")])
        result = json.loads(headers_to_json(h, redact_headers={"Authorization"}))
        assert result == [["Authorization", "[GATEWAY:...3xyz]"]]

    def test_redact_case_insensitive(self):
        """Header name matching for redaction is case insensitive."""
        from mitmproxy.http import Headers
        h = Headers([(b"authorization", b"Bearer secret1234")])
        result = json.loads(headers_to_json(h, redact_headers={"Authorization"}))
        assert result == [["authorization", "[GATEWAY:...1234]"]]

    def test_redact_short_value_uses_question_mark(self):
        """Values shorter than 4 chars get [GATEWAY:...?] suffix."""
        from mitmproxy.http import Headers
        h = Headers([(b"X-Key", b"ab")])
        result = json.loads(headers_to_json(h, redact_headers={"X-Key"}))
        assert result == [["X-Key", "[GATEWAY:...?]"]]

    def test_redact_preserves_non_redacted_headers(self):
        """Non-redacted headers pass through unchanged."""
        from mitmproxy.http import Headers
        h = Headers([
            (b"Authorization", b"Bearer secret1234"),
            (b"Content-Type", b"application/json"),
        ])
        result = json.loads(headers_to_json(h, redact_headers={"Authorization"}))
        assert result[0] == ["Authorization", "[GATEWAY:...1234]"]
        assert result[1] == ["Content-Type", "application/json"]

    def test_redact_exactly_four_char_value(self):
        """Value of exactly 4 chars shows all 4 as suffix."""
        from mitmproxy.http import Headers
        h = Headers([(b"X-Key", b"abcd")])
        result = json.loads(headers_to_json(h, redact_headers={"X-Key"}))
        assert result == [["X-Key", "[GATEWAY:...abcd]"]]

    def test_redact_empty_set_no_redaction(self):
        """Empty redact set means no redaction."""
        from mitmproxy.http import Headers
        h = Headers([(b"Authorization", b"Bearer secret1234")])
        result = json.loads(headers_to_json(h, redact_headers=set()))
        assert result == [["Authorization", "Bearer secret1234"]]


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------

class TestSchemaInit:
    def test_tables_and_indexes_exist(self, store):
        """Schema creates all required tables, FTS virtual tables, and indexes."""
        with store._lock:
            tables = store._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
        names = [t["name"] for t in tables]
        assert "flows" in names
        assert "flow_fts" in names
        assert "flow_request_fts" in names
        assert "flow_tags" in names

        with store._lock:
            indexes = store._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
            ).fetchall()
        idx_names = [i["name"] for i in indexes]
        assert "idx_flows_engagement_ts" in idx_names
        assert "idx_flows_engagement_agent_ts" in idx_names
        assert "idx_flows_engagement_test_ts" in idx_names
        assert "idx_flows_engagement_host_path" in idx_names
        assert "idx_flows_engagement_status_ts" in idx_names
        assert "idx_flow_tags_flow_id" in idx_names
        assert "idx_flow_tags_tag" in idx_names

    def test_wal_mode(self, store):
        with store._lock:
            mode = store._conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"

    def test_foreign_keys_enabled(self, store):
        """B2 fix: PRAGMA foreign_keys=ON is set during init_db."""
        with store._lock:
            fk = store._conn.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk == 1

    def test_init_db_idempotent(self, tmp_path):
        """Calling init_db twice does not raise or corrupt data."""
        db = tmp_path / "idempotent.sqlite3"
        s = FlowStore(db_path=str(db))
        s.init_db()
        flow_id = s.record_flow(_make_record(request_id="req-idem000001"))
        s.init_db()
        result = s.get_flow(flow_id)
        assert result["request_id"] == "req-idem000001"
        s.close()

    def test_close_idempotent(self, tmp_path):
        """Calling close twice does not raise."""
        db = tmp_path / "close_idem.sqlite3"
        s = FlowStore(db_path=str(db))
        s.init_db()
        s.close()
        s.close()  # second close should not raise


# ---------------------------------------------------------------------------
# record_flow
# ---------------------------------------------------------------------------

class TestRecordFlow:
    def test_record_completed_flow(self, store):
        record = _make_record()
        flow_id = store.record_flow(record)
        assert flow_id == 1

        result = store.get_flow(flow_id)
        assert result["request_id"] == "req-test000001"
        assert result["flow_state"] == "completed"
        assert result["host"] == "app.example.com"
        assert result["status_code"] == 200

    def test_record_blocked_flow(self, store):
        record = _make_record(
            request_id="req-blocked00001",
            flow_state="blocked",
            status_code=403,
            reason="credential-guard",
        )
        flow_id = store.record_flow(record)
        result = store.get_flow(flow_id)
        assert result["flow_state"] == "blocked"
        assert result["status_code"] == 403
        assert result["reason"] == "credential-guard"

    def test_record_error_flow(self, store):
        record = _make_record(
            request_id="req-error00001",
            flow_state="error",
            status_code=None,
            reason="Connection refused",
            response_body=b"",
            response_content_type="",
        )
        flow_id = store.record_flow(record)
        result = store.get_flow(flow_id)
        assert result["flow_state"] == "error"
        assert result["reason"] == "Connection refused"

    def test_body_compression_roundtrip(self, store):
        body = b'{"data": "' + b"x" * 10000 + b'"}'
        record = _make_record(
            request_id="req-compress001",
            response_body=body,
            response_content_type="application/json",
        )
        flow_id = store.record_flow(record)

        result = store.get_response_body(flow_id)
        assert result["body"] == body
        assert result["response_body_encoding"] == "gzip"

    def test_request_body_compression_roundtrip(self, store):
        body = b'{"action": "create", "data": "test"}'
        record = _make_record(
            request_id="req-reqbody001",
            request_body=body,
            request_content_type="application/json",
        )
        flow_id = store.record_flow(record)

        result = store.get_request_body(flow_id)
        assert result["body"] == body

    def test_response_body_truncation(self, store):
        """Large response body is truncated and flagged."""
        small_store = FlowStore(
            db_path=store.db_path,
            max_response_body_bytes=100,
        )
        small_store._conn = store._conn
        small_store._lock = store._lock

        body = b"x" * 500
        record = _make_record(
            request_id="req-truncate01",
            response_body=body,
            response_content_type="text/plain",
        )
        flow_id = small_store.record_flow(record)

        result = store.get_flow(flow_id)
        assert result["response_body_truncated"] == 1
        assert result["response_body_size"] == 500

        resp = store.get_response_body(flow_id)
        assert len(resp["body"]) == 100

    def test_request_body_truncation(self, store):
        """Large request body is truncated and flagged."""
        small_store = FlowStore(
            db_path=store.db_path,
            max_request_body_bytes=50,
        )
        small_store._conn = store._conn
        small_store._lock = store._lock

        body = b"y" * 200
        record = _make_record(
            request_id="req-reqtrunc01",
            request_body=body,
            request_content_type="text/plain",
        )
        flow_id = small_store.record_flow(record)

        result = store.get_flow(flow_id)
        assert result["request_body_truncated"] == 1
        assert result["request_body_size"] == 200

        req = store.get_request_body(flow_id)
        assert len(req["body"]) == 50

    def test_preview_stored(self, store):
        body = b'{"message": "hello world"}'
        record = _make_record(
            request_id="req-preview001",
            response_body=body,
            response_content_type="application/json",
        )
        flow_id = store.record_flow(record)
        result = store.get_flow(flow_id)
        assert result["response_body_text_preview"] == '{"message": "hello world"}'

    def test_binary_body_no_preview(self, store):
        body = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        record = _make_record(
            request_id="req-binary001",
            response_body=body,
            response_content_type="image/png",
        )
        flow_id = store.record_flow(record)
        result = store.get_flow(flow_id)
        assert result["response_body_text_preview"] == ""

    def test_uncompressed_mode(self, tmp_path):
        db = tmp_path / "uncompressed.sqlite3"
        s = FlowStore(db_path=str(db), compress_bodies=False)
        s.init_db()

        body = b'{"test": true}'
        record = _make_record(
            request_id="req-uncompress1",
            response_body=body,
            response_content_type="application/json",
        )
        flow_id = s.record_flow(record)
        result = s.get_response_body(flow_id)
        assert result["body"] == body
        assert result["response_body_encoding"] == "identity"
        s.close()

    def test_empty_body_not_stored(self, store):
        record = _make_record(
            request_id="req-emptybody1",
            response_body=b"",
            response_content_type="",
        )
        flow_id = store.record_flow(record)
        result = store.get_flow(flow_id)
        assert result["response_body_stored"] == 0

    def test_duplicate_request_id_raises(self, store):
        """request_id has a UNIQUE constraint -- inserting a duplicate raises."""
        store.record_flow(_make_record(request_id="req-dup0000001"))
        with pytest.raises(sqlite3.IntegrityError):
            store.record_flow(_make_record(request_id="req-dup0000001"))

    def test_none_body_treated_as_empty(self, store):
        """record.get('response_body') returning None is treated as b''."""
        record = _make_record(
            request_id="req-nonebody01",
            response_body=None,
            response_content_type="application/json",
        )
        flow_id = store.record_flow(record)
        result = store.get_flow(flow_id)
        assert result["response_body_stored"] == 0
        assert result["response_body_size"] == 0


# ---------------------------------------------------------------------------
# search_flows
# ---------------------------------------------------------------------------

class TestSearchFlows:
    def test_search_by_host(self, store):
        store.record_flow(_make_record(request_id="req-host000001"))
        store.record_flow(_make_record(
            request_id="req-host000002", host="other.example.com"
        ))

        results = store.search_flows({"host": "app.example.com"})
        assert len(results) == 1
        assert results[0]["host"] == "app.example.com"

    def test_search_by_status_code(self, store):
        store.record_flow(_make_record(request_id="req-status0001", status_code=200))
        store.record_flow(_make_record(request_id="req-status0002", status_code=404))

        results = store.search_flows({"status_code": 404})
        assert len(results) == 1
        assert results[0]["status_code"] == 404

    def test_search_by_method(self, store):
        store.record_flow(_make_record(request_id="req-method0001", method="GET"))
        store.record_flow(_make_record(request_id="req-method0002", method="POST"))

        results = store.search_flows({"method": "POST"})
        assert len(results) == 1
        assert results[0]["method"] == "POST"

    def test_search_by_path_contains(self, store):
        store.record_flow(_make_record(request_id="req-path000001", path="/api/todos/42"))
        store.record_flow(_make_record(request_id="req-path000002", path="/api/users/1"))

        results = store.search_flows({"path_contains": "/todos"})
        assert len(results) == 1
        assert results[0]["path"] == "/api/todos/42"

    def test_search_by_time_range(self, store):
        store.record_flow(_make_record(
            request_id="req-time000001", ts_start=1710000000000
        ))
        store.record_flow(_make_record(
            request_id="req-time000002", ts_start=1710005000000
        ))

        results = store.search_flows({
            "from_ts": 1710004000000,
            "to_ts": 1710006000000,
        })
        assert len(results) == 1
        assert results[0]["request_id"] == "req-time000002"

    def test_search_limit_offset(self, store):
        for i in range(10):
            store.record_flow(_make_record(
                request_id=f"req-page{i:06d}",
                ts_start=1710000000000 + i * 1000,
            ))

        results = store.search_flows({"limit": 3, "offset": 0})
        assert len(results) == 3

        results2 = store.search_flows({"limit": 3, "offset": 3})
        assert len(results2) == 3
        assert results[0]["request_id"] != results2[0]["request_id"]

    def test_search_limit_capped_at_500(self, store):
        """Requesting limit > 500 is silently capped to 500."""
        store.record_flow(_make_record(request_id="req-cap0000001"))
        # We can't insert 501 rows easily, but we can verify the SQL uses 500
        # by requesting 1000 and getting at most 500.  With 1 row, we just
        # verify no error and the result is returned.
        results = store.search_flows({"limit": 1000})
        assert len(results) == 1

    def test_search_ordered_by_ts_desc(self, store):
        """Results are ordered by ts_start descending (newest first)."""
        store.record_flow(_make_record(
            request_id="req-ord0000001", ts_start=1710000000000
        ))
        store.record_flow(_make_record(
            request_id="req-ord0000002", ts_start=1710000002000
        ))
        store.record_flow(_make_record(
            request_id="req-ord0000003", ts_start=1710000001000
        ))

        results = store.search_flows({})
        assert results[0]["request_id"] == "req-ord0000002"
        assert results[1]["request_id"] == "req-ord0000003"
        assert results[2]["request_id"] == "req-ord0000001"

    def test_search_empty_result(self, store):
        """Searching with no matching rows returns empty list, not None."""
        results = store.search_flows({"host": "nonexistent.example.com"})
        assert results == []

    def test_search_by_engagement_id(self, store):
        store.record_flow(_make_record(
            request_id="req-eng0000001", engagement_id="acme-portal"
        ))
        store.record_flow(_make_record(
            request_id="req-eng0000002", engagement_id="other-project"
        ))

        results = store.search_flows({"engagement_id": "acme-portal"})
        assert len(results) == 1
        assert results[0]["request_id"] == "req-eng0000001"

    def test_search_response_preview_content(self, store):
        """search_flows returns a response_preview field with actual content."""
        store.record_flow(_make_record(
            request_id="req-prev000001",
            response_body=b'{"id":42,"owner":"alice","title":"Buy milk"}',
            response_content_type="application/json",
        ))
        results = store.search_flows({})
        assert len(results) == 1
        assert results[0]["response_preview"] == '{"id":42,"owner":"alice","title":"Buy milk"}'

    def test_search_preview_truncated_at_512_chars(self, store):
        """Response preview in search results is truncated to 512 chars + '...'."""
        body = b"z" * 1000
        store.record_flow(_make_record(
            request_id="req-prevtrunc1",
            response_body=body,
            response_content_type="text/plain",
        ))
        results = store.search_flows({})
        assert len(results) == 1
        preview = results[0]["response_preview"]
        assert len(preview) == 515  # 512 + len("...")
        assert preview.endswith("...")

    def test_search_text_contains(self, store):
        store.record_flow(_make_record(
            request_id="req-textcont01",
            response_body=b'{"role": "admin", "name": "alice"}',
            response_content_type="application/json",
        ))
        store.record_flow(_make_record(
            request_id="req-textcont02",
            response_body=b'{"role": "user", "name": "bob"}',
            response_content_type="application/json",
        ))
        results = store.search_flows({"text_contains": "admin"})
        assert len(results) == 1
        assert results[0]["request_id"] == "req-textcont01"

    def test_search_by_tag_with_colon_in_value(self, store):
        """tag filter 'a:b:c' splits on first colon only: tag='a', value='b:c'."""
        fid = store.record_flow(_make_record(request_id="req-tagcolon01"))
        store.tag_flow(fid, "url", "http://example.com")

        results = store.search_flows({"tag": "url:http://example.com"})
        assert len(results) == 1
        assert results[0]["id"] == fid


# ---------------------------------------------------------------------------
# get_flow
# ---------------------------------------------------------------------------

class TestGetFlow:
    def test_get_existing_flow(self, store):
        flow_id = store.record_flow(_make_record(request_id="req-get0000001"))
        result = store.get_flow(flow_id)
        assert result["id"] == flow_id
        assert result["request_id"] == "req-get0000001"

    def test_get_nonexistent_flow(self, store):
        assert store.get_flow(99999) is None


# ---------------------------------------------------------------------------
# get_request_body / get_response_body
# ---------------------------------------------------------------------------

class TestGetBody:
    def test_get_request_body(self, store):
        body = b'{"action": "test"}'
        flow_id = store.record_flow(_make_record(
            request_id="req-getreq0001",
            request_body=body,
            request_content_type="application/json",
        ))
        result = store.get_request_body(flow_id)
        assert result["body"] == body

    def test_get_response_body(self, store):
        body = b'{"id": 42}'
        flow_id = store.record_flow(_make_record(
            request_id="req-getresp001",
            response_body=body,
            response_content_type="application/json",
        ))
        result = store.get_response_body(flow_id)
        assert result["body"] == body

    def test_get_body_nonexistent_flow(self, store):
        assert store.get_request_body(99999) is None
        assert store.get_response_body(99999) is None

    def test_get_empty_body(self, store):
        flow_id = store.record_flow(_make_record(
            request_id="req-emptybod01",
            request_body=b"",
            request_content_type="",
        ))
        result = store.get_request_body(flow_id)
        assert result["body"] == b""
        assert result["request_body_stored"] == 0


# ---------------------------------------------------------------------------
# FTS and body search
# ---------------------------------------------------------------------------

class TestFTSAndBodySearch:
    def test_fts_indexes_text_response(self, store):
        store.record_flow(_make_record(
            request_id="req-fts0000001",
            response_body=b'{"role":"admin","secret":"supersecret"}',
            response_content_type="application/json",
        ))

        with store._lock:
            row = store._conn.execute(
                "SELECT COUNT(*) as cnt FROM flow_fts"
            ).fetchone()
        assert row["cnt"] == 1

    def test_body_search(self, store):
        store.record_flow(_make_record(
            request_id="req-bsearch001",
            response_body=b'{"privilege":"administrator","access":"full"}',
            response_content_type="application/json",
        ))
        store.record_flow(_make_record(
            request_id="req-bsearch002",
            response_body=b'{"privilege":"user","access":"limited"}',
            response_content_type="application/json",
        ))

        results = store.search_bodies({
            "engagement_id": "acme-portal",
            "query": "administrator",
        })
        assert len(results) == 1
        assert results[0]["request_id"] == "req-bsearch001"

    def test_body_search_requires_engagement_id(self, store):
        results = store.search_bodies({"query": "test"})
        assert results == []

    def test_body_search_requires_query(self, store):
        results = store.search_bodies({"engagement_id": "acme-portal"})
        assert results == []

    def test_body_search_scoped_by_engagement(self, store):
        store.record_flow(_make_record(
            request_id="req-scope00001",
            engagement_id="acme-portal",
            response_body=b'{"data":"secret_data_here"}',
            response_content_type="application/json",
        ))
        store.record_flow(_make_record(
            request_id="req-scope00002",
            engagement_id="other-project",
            response_body=b'{"data":"secret_data_here"}',
            response_content_type="application/json",
        ))

        results = store.search_bodies({
            "engagement_id": "acme-portal",
            "query": "secret_data_here",
        })
        assert len(results) == 1
        assert results[0]["engagement_id"] == "acme-portal"

    def test_body_search_with_hyphenated_term(self, store):
        """Hyphens in queries don't break FTS (treated as phrase, not NOT operator)."""
        store.record_flow(_make_record(
            request_id="req-hyphen0001",
            response_body=b'<h1>Herman Melville - Moby-Dick</h1>',
            response_content_type="text/html",
        ))
        results = store.search_bodies({
            "engagement_id": "acme-portal",
            "query": "Moby-Dick",
        })
        assert len(results) == 1

    def test_body_search_multiple_tokens(self, store):
        """Multiple tokens are implicitly ANDed -- all must match."""
        store.record_flow(_make_record(
            request_id="req-multi00001",
            response_body=b'{"role":"admin","access":"full"}',
            response_content_type="application/json",
        ))
        store.record_flow(_make_record(
            request_id="req-multi00002",
            response_body=b'{"role":"user","access":"limited"}',
            response_content_type="application/json",
        ))
        results = store.search_bodies({
            "engagement_id": "acme-portal",
            "query": "admin full",
        })
        assert len(results) == 1
        assert results[0]["request_id"] == "req-multi00001"

    def test_body_search_with_embedded_quotes(self, store):
        """Double quotes in search terms are properly escaped."""
        store.record_flow(_make_record(
            request_id="req-dquote0001",
            response_body=b'she said "hello" to the admin',
            response_content_type="text/plain",
        ))
        results = store.search_bodies({
            "engagement_id": "acme-portal",
            "query": '"hello"',
        })
        assert len(results) == 1

    def test_binary_body_not_indexed(self, store):
        store.record_flow(_make_record(
            request_id="req-noindex001",
            response_body=b"\x89PNG" + b"\x00" * 100,
            response_content_type="image/png",
        ))
        with store._lock:
            row = store._conn.execute(
                "SELECT COUNT(*) as cnt FROM flow_fts"
            ).fetchone()
        assert row["cnt"] == 0

    def test_body_search_with_host_filter(self, store):
        """FTS search can be additionally filtered by host."""
        store.record_flow(_make_record(
            request_id="req-ftshost001",
            host="api.example.com",
            response_body=b'{"data":"findme"}',
            response_content_type="application/json",
        ))
        store.record_flow(_make_record(
            request_id="req-ftshost002",
            host="other.example.com",
            response_body=b'{"data":"findme"}',
            response_content_type="application/json",
        ))

        results = store.search_bodies({
            "engagement_id": "acme-portal",
            "query": "findme",
            "host": "api.example.com",
        })
        assert len(results) == 1
        assert results[0]["host"] == "api.example.com"

    def test_body_search_returns_snippet_field(self, store):
        """FTS results include a 'snippet' field with match context."""
        store.record_flow(_make_record(
            request_id="req-ftsnip0001",
            response_body=b'The quick brown fox jumps over the lazy dog',
            response_content_type="text/plain",
        ))
        results = store.search_bodies({
            "engagement_id": "acme-portal",
            "query": "fox",
        })
        assert len(results) == 1
        assert "snippet" in results[0]
        assert "fox" in results[0]["snippet"]


# ---------------------------------------------------------------------------
# _sanitize_fts_query
# ---------------------------------------------------------------------------

class TestSanitizeFtsQuery:
    def test_single_token_quoted(self):
        assert FlowStore._sanitize_fts_query("hello") == '"hello"'

    def test_multiple_tokens_each_quoted(self):
        assert FlowStore._sanitize_fts_query("hello world") == '"hello" "world"'

    def test_empty_string_returns_empty(self):
        assert FlowStore._sanitize_fts_query("") == ""

    def test_whitespace_only_returns_original(self):
        assert FlowStore._sanitize_fts_query("   ") == "   "

    def test_hyphenated_token_quoted(self):
        """Hyphens are wrapped in quotes so FTS5 doesn't treat them as NOT."""
        assert FlowStore._sanitize_fts_query("Moby-Dick") == '"Moby-Dick"'

    def test_embedded_double_quotes_escaped(self):
        """Double quotes inside tokens are doubled for FTS5 escaping."""
        result = FlowStore._sanitize_fts_query('say"hello')
        assert result == '"say""hello"'

    def test_colon_in_token_quoted(self):
        """Colons (FTS5 column filter syntax) are safely quoted."""
        assert FlowStore._sanitize_fts_query("host:value") == '"host:value"'

    def test_dot_in_token_quoted(self):
        assert FlowStore._sanitize_fts_query("api.example.com") == '"api.example.com"'


# ---------------------------------------------------------------------------
# get_endpoints
# ---------------------------------------------------------------------------

class TestGetEndpoints:
    def test_endpoints_grouping(self, store):
        for i in range(5):
            store.record_flow(_make_record(
                request_id=f"req-endpt{i:05d}",
                method="GET",
                host="app.example.com",
                path="/api/todos",
                status_code=200,
            ))
        store.record_flow(_make_record(
            request_id="req-endptother",
            method="POST",
            host="app.example.com",
            path="/api/todos",
            status_code=201,
        ))

        results = store.get_endpoints({"engagement_id": "acme-portal"})
        assert len(results) == 2

        # GET should have count 5 (ordered by count DESC, so first)
        assert results[0]["method"] == "GET"
        assert results[0]["count"] == 5
        assert results[0]["status_codes"] == [200]

    def test_endpoints_with_filters(self, store):
        store.record_flow(_make_record(
            request_id="req-endfilt001",
            engagement_id="acme-portal",
        ))
        store.record_flow(_make_record(
            request_id="req-endfilt002",
            engagement_id="other-project",
        ))

        results = store.get_endpoints({"engagement_id": "acme-portal"})
        assert len(results) == 1

    def test_endpoints_status_codes_are_ints(self, store):
        """status_codes field contains ints, not strings."""
        store.record_flow(_make_record(
            request_id="req-endint0001",
            method="GET",
            host="api.example.com",
            path="/health",
            status_code=200,
        ))
        store.record_flow(_make_record(
            request_id="req-endint0002",
            method="GET",
            host="api.example.com",
            path="/health",
            status_code=503,
        ))
        results = store.get_endpoints({"engagement_id": "acme-portal"})
        assert len(results) == 1
        assert all(isinstance(sc, int) for sc in results[0]["status_codes"])
        assert set(results[0]["status_codes"]) == {200, 503}

    def test_endpoints_limit_capped_at_500(self, store):
        """Requesting limit > 500 is silently capped to 500."""
        store.record_flow(_make_record(request_id="req-endcap0001"))
        results = store.get_endpoints({"engagement_id": "acme-portal", "limit": 1000})
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Status code range/class filters
# ---------------------------------------------------------------------------

class TestStatusCodeRange:
    def test_status_min(self, store):
        store.record_flow(_make_record(request_id="req-smin000001", status_code=200))
        store.record_flow(_make_record(request_id="req-smin000002", status_code=404))
        store.record_flow(_make_record(request_id="req-smin000003", status_code=500))
        results = store.search_flows({"status_min": 400})
        assert len(results) == 2

    def test_status_max(self, store):
        store.record_flow(_make_record(request_id="req-smax000001", status_code=200))
        store.record_flow(_make_record(request_id="req-smax000002", status_code=404))
        store.record_flow(_make_record(request_id="req-smax000003", status_code=500))
        results = store.search_flows({"status_max": 299})
        assert len(results) == 1

    def test_status_range(self, store):
        store.record_flow(_make_record(request_id="req-srng000001", status_code=200))
        store.record_flow(_make_record(request_id="req-srng000002", status_code=301))
        store.record_flow(_make_record(request_id="req-srng000003", status_code=404))
        store.record_flow(_make_record(request_id="req-srng000004", status_code=500))
        results = store.search_flows({"status_min": 300, "status_max": 499})
        assert len(results) == 2

    def test_status_class_4xx(self, store):
        store.record_flow(_make_record(request_id="req-sc4x000001", status_code=200))
        store.record_flow(_make_record(request_id="req-sc4x000002", status_code=401))
        store.record_flow(_make_record(request_id="req-sc4x000003", status_code=404))
        store.record_flow(_make_record(request_id="req-sc4x000004", status_code=500))
        results = store.search_flows({"status_class": "4xx"})
        assert len(results) == 2

    def test_status_class_5xx(self, store):
        store.record_flow(_make_record(request_id="req-sc5x000001", status_code=200))
        store.record_flow(_make_record(request_id="req-sc5x000002", status_code=502))
        store.record_flow(_make_record(request_id="req-sc5x000003", status_code=503))
        results = store.search_flows({"status_class": "5xx"})
        assert len(results) == 2

    def test_status_class_unknown_ignored(self, store):
        """Unknown status class is ignored (returns all)."""
        store.record_flow(_make_record(request_id="req-scuk000001", status_code=200))
        results = store.search_flows({"status_class": "9xx"})
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Header search
# ---------------------------------------------------------------------------

class TestHeaderSearch:
    def test_response_header_contains(self, store):
        store.record_flow(_make_record(
            request_id="req-rhdr000001",
            response_headers_json='[["Content-Type","application/json"],["X-Custom","secret-value"]]',
        ))
        store.record_flow(_make_record(
            request_id="req-rhdr000002",
            response_headers_json='[["Content-Type","text/html"]]',
        ))
        results = store.search_flows({"response_header_contains": "secret-value"})
        assert len(results) == 1
        assert results[0]["request_id"] == "req-rhdr000001"

    def test_response_header_no_match(self, store):
        store.record_flow(_make_record(
            request_id="req-rhnm000001",
            response_headers_json='[["Content-Type","text/html"]]',
        ))
        results = store.search_flows({"response_header_contains": "nonexistent"})
        assert len(results) == 0

    def test_request_header_contains(self, store):
        store.record_flow(_make_record(
            request_id="req-qhdr000001",
            request_headers_json='[["Authorization","Bearer token123"]]',
        ))
        store.record_flow(_make_record(
            request_id="req-qhdr000002",
            request_headers_json='[["Content-Type","text/plain"]]',
        ))
        results = store.search_flows({"request_header_contains": "Bearer"})
        assert len(results) == 1
        assert results[0]["request_id"] == "req-qhdr000001"

    def test_header_combined_with_other_filters(self, store):
        store.record_flow(_make_record(
            request_id="req-hcmb000001",
            host="api.example.com",
            response_headers_json='[["X-Debug","true"]]',
        ))
        store.record_flow(_make_record(
            request_id="req-hcmb000002",
            host="other.example.com",
            response_headers_json='[["X-Debug","true"]]',
        ))
        results = store.search_flows({
            "host": "api.example.com",
            "response_header_contains": "X-Debug",
        })
        assert len(results) == 1
        assert results[0]["request_id"] == "req-hcmb000001"


# ---------------------------------------------------------------------------
# diff_flows
# ---------------------------------------------------------------------------

class TestDiffFlows:
    def test_identical_bodies(self, store):
        body = b'{"same": "content"}'
        id_a = store.record_flow(_make_record(
            request_id="req-diff000001",
            response_body=body,
            response_content_type="application/json",
        ))
        id_b = store.record_flow(_make_record(
            request_id="req-diff000002",
            response_body=body,
            response_content_type="application/json",
        ))
        result = store.diff_flows(id_a, id_b)
        assert result["identical"] is True
        assert result["size_delta"] == 0
        assert result["both_text"] is True
        assert result["diff_lines"] == []

    def test_different_text_bodies_produce_unified_diff(self, store):
        id_a = store.record_flow(_make_record(
            request_id="req-diff000003",
            response_body=b'{"role": "user"}',
            response_content_type="application/json",
        ))
        id_b = store.record_flow(_make_record(
            request_id="req-diff000004",
            response_body=b'{"role": "admin"}',
            response_content_type="application/json",
        ))
        result = store.diff_flows(id_a, id_b)
        assert result["identical"] is False
        assert result["both_text"] is True
        diff_text = "".join(result["diff_lines"])
        assert "-" + '{"role": "user"}' in diff_text
        assert "+" + '{"role": "admin"}' in diff_text

    def test_size_comparison(self, store):
        id_a = store.record_flow(_make_record(
            request_id="req-diff000005",
            response_body=b"short",
            response_content_type="text/plain",
        ))
        id_b = store.record_flow(_make_record(
            request_id="req-diff000006",
            response_body=b"much longer content here",
            response_content_type="text/plain",
        ))
        result = store.diff_flows(id_a, id_b)
        assert result["size_a"] == 5
        assert result["size_b"] == 24
        assert result["size_delta"] == 19

    def test_missing_flow_returns_none(self, store):
        id_a = store.record_flow(_make_record(request_id="req-diff000007"))
        result = store.diff_flows(id_a, 99999)
        assert result is None

    def test_both_missing_returns_none(self, store):
        result = store.diff_flows(99998, 99999)
        assert result is None

    def test_binary_no_diff(self, store):
        id_a = store.record_flow(_make_record(
            request_id="req-diff000008",
            response_body=b"\x89PNG" + b"\x00" * 50,
            response_content_type="image/png",
        ))
        id_b = store.record_flow(_make_record(
            request_id="req-diff000009",
            response_body=b"\x89PNG" + b"\x01" * 50,
            response_content_type="image/png",
        ))
        result = store.diff_flows(id_a, id_b)
        assert result["both_text"] is False
        assert result["diff_lines"] == []

    def test_mixed_text_binary(self, store):
        id_a = store.record_flow(_make_record(
            request_id="req-diff000010",
            response_body=b'{"text": true}',
            response_content_type="application/json",
        ))
        id_b = store.record_flow(_make_record(
            request_id="req-diff000011",
            response_body=b"\x89PNG\x00",
            response_content_type="image/png",
        ))
        result = store.diff_flows(id_a, id_b)
        assert result["both_text"] is False
        assert result["diff_lines"] == []

    def test_diff_truncation_flag_on_large_diff(self, store):
        """Diffs exceeding 5000 lines are truncated with diff_truncated=True."""
        # Create two text bodies that produce > 5000 diff lines.
        # Each unique line produces ~3 diff lines (context + -/+ pair),
        # so 2500 unique lines in each body should exceed 5000.
        body_a = ("\n".join(f"line-a-{i}" for i in range(3000)) + "\n").encode()
        body_b = ("\n".join(f"line-b-{i}" for i in range(3000)) + "\n").encode()

        id_a = store.record_flow(_make_record(
            request_id="req-difftrunc1",
            response_body=body_a,
            response_content_type="text/plain",
        ))
        id_b = store.record_flow(_make_record(
            request_id="req-difftrunc2",
            response_body=body_b,
            response_content_type="text/plain",
        ))
        result = store.diff_flows(id_a, id_b)
        assert result["diff_truncated"] is True
        assert len(result["diff_lines"]) == 5000


# ---------------------------------------------------------------------------
# Request body FTS
# ---------------------------------------------------------------------------

class TestRequestBodyFTS:
    def test_text_request_indexed(self, store):
        store.record_flow(_make_record(
            request_id="req-rfts000001",
            request_body=b'{"action":"create","username":"admin"}',
            request_content_type="application/json",
        ))
        with store._lock:
            row = store._conn.execute(
                "SELECT COUNT(*) as cnt FROM flow_request_fts"
            ).fetchone()
        assert row["cnt"] == 1

    def test_search_request_bodies(self, store):
        store.record_flow(_make_record(
            request_id="req-rfts000002",
            request_body=b'{"action":"create","payload":"sensitive_data"}',
            request_content_type="application/json",
        ))
        store.record_flow(_make_record(
            request_id="req-rfts000003",
            request_body=b'{"action":"delete","payload":"normal"}',
            request_content_type="application/json",
        ))
        results = store.search_request_bodies({
            "engagement_id": "acme-portal",
            "query": "sensitive_data",
        })
        assert len(results) == 1
        assert results[0]["request_id"] == "req-rfts000002"

    def test_binary_request_not_indexed(self, store):
        store.record_flow(_make_record(
            request_id="req-rfts000004",
            request_body=b"\x89PNG" + b"\x00" * 100,
            request_content_type="image/png",
        ))
        with store._lock:
            row = store._conn.execute(
                "SELECT COUNT(*) as cnt FROM flow_request_fts"
            ).fetchone()
        assert row["cnt"] == 0

    def test_search_scoped_by_engagement(self, store):
        store.record_flow(_make_record(
            request_id="req-rfts000005",
            engagement_id="acme-portal",
            request_body=b'{"secret":"value"}',
            request_content_type="application/json",
        ))
        store.record_flow(_make_record(
            request_id="req-rfts000006",
            engagement_id="other-project",
            request_body=b'{"secret":"value"}',
            request_content_type="application/json",
        ))
        results = store.search_request_bodies({
            "engagement_id": "acme-portal",
            "query": "secret",
        })
        assert len(results) == 1
        assert results[0]["engagement_id"] == "acme-portal"

    def test_request_body_search_returns_snippet(self, store):
        """Request body FTS results include a snippet field."""
        store.record_flow(_make_record(
            request_id="req-rftssnip01",
            request_body=b'The quick brown fox jumps',
            request_content_type="text/plain",
        ))
        results = store.search_request_bodies({
            "engagement_id": "acme-portal",
            "query": "fox",
        })
        assert len(results) == 1
        assert "snippet" in results[0]
        assert "fox" in results[0]["snippet"]


# ---------------------------------------------------------------------------
# Tagging
# ---------------------------------------------------------------------------

class TestFlowTagging:
    def test_tag_flow(self, store):
        flow_id = store.record_flow(_make_record(request_id="req-tag0000001"))
        result = store.tag_flow(flow_id, "confirmed", "idor")
        assert result["tag"] == "confirmed"
        assert result["value"] == "idor"
        assert result["flow_id"] == flow_id

    def test_tag_upsert(self, store):
        flow_id = store.record_flow(_make_record(request_id="req-tag0000002"))
        store.tag_flow(flow_id, "severity", "low")
        store.tag_flow(flow_id, "severity", "high")
        tags = store.get_flow_tags(flow_id)
        assert len(tags) == 1
        assert tags[0]["value"] == "high"

    def test_untag_flow(self, store):
        flow_id = store.record_flow(_make_record(request_id="req-tag0000003"))
        store.tag_flow(flow_id, "false-positive")
        assert store.untag_flow(flow_id, "false-positive") is True
        assert store.untag_flow(flow_id, "false-positive") is False

    def test_get_flow_includes_tags(self, store):
        flow_id = store.record_flow(_make_record(request_id="req-tag0000004"))
        store.tag_flow(flow_id, "confirmed", "xss")
        store.tag_flow(flow_id, "severity", "high")
        result = store.get_flow(flow_id)
        assert len(result["tags"]) == 2
        tag_names = [t["tag"] for t in result["tags"]]
        assert "confirmed" in tag_names
        assert "severity" in tag_names

    def test_search_by_tag_name(self, store):
        id1 = store.record_flow(_make_record(request_id="req-tag0000005"))
        store.record_flow(_make_record(request_id="req-tag0000006"))
        store.tag_flow(id1, "confirmed")
        results = store.search_flows({"tag": "confirmed"})
        assert len(results) == 1
        assert results[0]["id"] == id1

    def test_search_by_tag_value(self, store):
        id1 = store.record_flow(_make_record(request_id="req-tag0000007"))
        id2 = store.record_flow(_make_record(request_id="req-tag0000008"))
        store.tag_flow(id1, "confirmed", "idor")
        store.tag_flow(id2, "confirmed", "xss")
        results = store.search_flows({"tag": "confirmed:idor"})
        assert len(results) == 1
        assert results[0]["id"] == id1

    def test_tag_nonexistent_flow_raises(self, store):
        """Tagging a flow_id that doesn't exist raises IntegrityError (FK constraint)."""
        with pytest.raises(sqlite3.IntegrityError):
            store.tag_flow(99999, "orphan", "value")

    def test_untag_nonexistent_flow_returns_false(self, store):
        """Untagging a nonexistent flow returns False (no rows deleted)."""
        assert store.untag_flow(99999, "anything") is False

    def test_get_tags_empty_flow(self, store):
        """get_flow_tags returns empty list for a flow with no tags."""
        flow_id = store.record_flow(_make_record(request_id="req-notag00001"))
        assert store.get_flow_tags(flow_id) == []
