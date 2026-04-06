"""
flow_store.py - SQLite storage for HTTP flow recording

Pure Python module (not a mitmproxy addon). Stores one row per completed
HTTP transaction with metadata, headers, and compressed request/response bodies.
Supports full-text search over text-like response bodies via FTS5.

Used by flow_recorder.py (the mitmproxy addon) and queried via agent_api.py.
"""

import difflib
import gzip
import json
import logging
import re
import sqlite3
import threading
import time

log = logging.getLogger("safeyolo.flow-store")

# Text-like content types for preview extraction and FTS indexing
_TEXT_LIKE_TYPES = re.compile(
    r"^("
    r"text/.*"
    r"|application/json"
    r"|application/javascript"
    r"|application/xml"
    r"|application/x-www-form-urlencoded"
    r"|application/problem\+json"
    r"|application/graphql-response\+json"
    r"|application/[a-zA-Z0-9._-]+\+json"
    r"|application/[a-zA-Z0-9._-]+\+xml"
    r")$",
    re.IGNORECASE,
)

_CREATE_FLOWS_TABLE = """
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL UNIQUE,

    ts_start INTEGER NOT NULL,
    ts_end INTEGER,
    duration_ms INTEGER,

    engagement_id TEXT NOT NULL,
    agent_id TEXT,
    source_id TEXT,

    run TEXT,
    test TEXT,
    role TEXT,
    context_json TEXT,

    source_type TEXT,
    flow_state TEXT NOT NULL,

    scheme TEXT,
    host TEXT NOT NULL,
    port INTEGER,
    method TEXT,
    path TEXT,
    query_string TEXT,
    full_url TEXT,

    status_code INTEGER,
    reason TEXT,

    request_content_type TEXT,
    response_content_type TEXT,
    is_websocket INTEGER NOT NULL DEFAULT 0,

    request_headers_json TEXT,
    response_headers_json TEXT,

    request_body_encoding TEXT,
    response_body_encoding TEXT,

    request_body_blob BLOB,
    response_body_blob BLOB,

    request_body_text_preview TEXT,
    response_body_text_preview TEXT,
    response_body_text_index TEXT,
    request_body_text_index TEXT,

    request_body_size INTEGER NOT NULL DEFAULT 0,
    response_body_size INTEGER NOT NULL DEFAULT 0,

    request_body_stored INTEGER NOT NULL DEFAULT 0,
    response_body_stored INTEGER NOT NULL DEFAULT 0,

    request_body_truncated INTEGER NOT NULL DEFAULT 0,
    response_body_truncated INTEGER NOT NULL DEFAULT 0
);
"""

_CREATE_FTS_TABLE = """
CREATE VIRTUAL TABLE IF NOT EXISTS flow_fts USING fts5(
    flow_id UNINDEXED,
    engagement_id UNINDEXED,
    agent_id UNINDEXED,
    host UNINDEXED,
    path UNINDEXED,
    run UNINDEXED,
    test UNINDEXED,
    response_body_text,
    tokenize = 'unicode61'
);
"""

_CREATE_REQUEST_FTS_TABLE = """
CREATE VIRTUAL TABLE IF NOT EXISTS flow_request_fts USING fts5(
    flow_id UNINDEXED,
    engagement_id UNINDEXED,
    agent_id UNINDEXED,
    host UNINDEXED,
    path UNINDEXED,
    run UNINDEXED,
    test UNINDEXED,
    request_body_text,
    tokenize = 'unicode61'
);
"""

_CREATE_FLOW_TAGS_TABLE = """
CREATE TABLE IF NOT EXISTS flow_tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    value TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    FOREIGN KEY (flow_id) REFERENCES flows(id),
    UNIQUE(flow_id, tag)
);
"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_flows_engagement_ts ON flows (engagement_id, ts_start DESC);",
    "CREATE INDEX IF NOT EXISTS idx_flows_engagement_agent_ts ON flows (engagement_id, agent_id, ts_start DESC);",
    "CREATE INDEX IF NOT EXISTS idx_flows_engagement_test_ts ON flows (engagement_id, test, ts_start DESC);",
    "CREATE INDEX IF NOT EXISTS idx_flows_engagement_host_path ON flows (engagement_id, host, path);",
    "CREATE INDEX IF NOT EXISTS idx_flows_engagement_status_ts ON flows (engagement_id, status_code, ts_start DESC);",
]


def compress_body(data: bytes) -> bytes:
    """Gzip compress body data."""
    return gzip.compress(data)


def decompress_body(data: bytes) -> bytes:
    """Gzip decompress body data."""
    return gzip.decompress(data)


def is_text_like_content_type(ct: str) -> bool:
    """Check if content type is text-like (suitable for preview/FTS)."""
    if not ct:
        return False
    # Strip parameters (e.g., charset=utf-8)
    base = ct.split(";")[0].strip()
    return bool(_TEXT_LIKE_TYPES.match(base))


def extract_preview(body: bytes, content_type: str, max_chars: int = 8192) -> str:
    """Extract text preview from body if content type is text-like.

    Returns empty string for binary content types.
    """
    if not body or not is_text_like_content_type(content_type):
        return ""
    text = body.decode("utf-8", errors="replace")
    if len(text) > max_chars:
        return text[:max_chars]
    return text


def headers_to_json(headers, redact_headers: set[str] | None = None) -> str:
    """Convert mitmproxy Headers to JSON string.

    Preserves duplicate header names as list of [name, value] pairs.
    Headers named in redact_headers have their values replaced with
    [GATEWAY:...{last4chars}] (or [GATEWAY:...?] for values shorter than 4 chars).
    """
    if headers is None:
        return "[]"
    redact_lower = {h.lower() for h in redact_headers} if redact_headers else set()
    pairs = [[name, value] for name, value in headers.fields]
    # Headers.fields returns (bytes, bytes) tuples
    decoded = []
    for name, value in pairs:
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="replace")
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        if name.lower() in redact_lower:
            suffix = value[-4:] if len(value) >= 4 else "?"
            value = f"[GATEWAY:...{suffix}]"
        decoded.append([name, value])
    return json.dumps(decoded)


class FlowStore:
    """SQLite-backed storage for HTTP flow records."""

    def __init__(
        self,
        db_path: str,
        max_request_body_bytes: int = 1_048_576,
        max_response_body_bytes: int = 4_194_304,
        preview_text_chars: int = 8192,
        compress_bodies: bool = True,
    ):
        self.db_path = db_path
        self.max_request_body_bytes = max_request_body_bytes
        self.max_response_body_bytes = max_response_body_bytes
        self.preview_text_chars = preview_text_chars
        self.compress_bodies = compress_bodies
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    def init_db(self) -> None:
        """Initialize database schema, indexes, and FTS table."""
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute("PRAGMA temp_store=MEMORY;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._conn.execute(_CREATE_FLOWS_TABLE)
        self._conn.execute(_CREATE_FTS_TABLE)
        self._conn.execute(_CREATE_REQUEST_FTS_TABLE)
        self._conn.execute(_CREATE_FLOW_TAGS_TABLE)
        for idx_sql in _CREATE_INDEXES:
            self._conn.execute(idx_sql)
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_flow_tags_flow_id ON flow_tags (flow_id);"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_flow_tags_tag ON flow_tags (tag, value);"
        )
        self._conn.commit()

    def record_flow(self, record: dict) -> int:
        """Insert a flow record and update FTS index.

        Args:
            record: Dict with flow data fields matching the flows table columns.

        Returns:
            The inserted row ID.
        """
        # Process request body
        req_body_raw = record.get("request_body") or b""
        req_ct = record.get("request_content_type", "")
        req_size = len(req_body_raw)
        req_truncated = 0
        if req_size > self.max_request_body_bytes:
            req_body_raw = req_body_raw[:self.max_request_body_bytes]
            req_truncated = 1
        req_preview = extract_preview(req_body_raw, req_ct, self.preview_text_chars)
        req_text_index = ""
        if is_text_like_content_type(req_ct) and req_body_raw:
            req_text_index = req_body_raw.decode("utf-8", errors="replace")
        req_blob = None
        req_encoding = None
        req_stored = 0
        if req_body_raw:
            req_stored = 1
            if self.compress_bodies:
                req_blob = compress_body(req_body_raw)
                req_encoding = "gzip"
            else:
                req_blob = req_body_raw
                req_encoding = "identity"

        # Process response body
        resp_body_raw = record.get("response_body") or b""
        resp_ct = record.get("response_content_type", "")
        resp_size = len(resp_body_raw)
        resp_truncated = 0
        if resp_size > self.max_response_body_bytes:
            resp_body_raw = resp_body_raw[:self.max_response_body_bytes]
            resp_truncated = 1
        resp_preview = extract_preview(resp_body_raw, resp_ct, self.preview_text_chars)
        resp_text_index = ""
        if is_text_like_content_type(resp_ct) and resp_body_raw:
            resp_text_index = resp_body_raw.decode("utf-8", errors="replace")
        resp_blob = None
        resp_encoding = None
        resp_stored = 0
        if resp_body_raw:
            resp_stored = 1
            if self.compress_bodies:
                resp_blob = compress_body(resp_body_raw)
                resp_encoding = "gzip"
            else:
                resp_blob = resp_body_raw
                resp_encoding = "identity"

        sql = """
        INSERT INTO flows (
            request_id, ts_start, ts_end, duration_ms,
            engagement_id, agent_id, source_id,
            run, test, role, context_json,
            source_type, flow_state,
            scheme, host, port, method, path, query_string, full_url,
            status_code, reason,
            request_content_type, response_content_type, is_websocket,
            request_headers_json, response_headers_json,
            request_body_encoding, response_body_encoding,
            request_body_blob, response_body_blob,
            request_body_text_preview, response_body_text_preview,
            response_body_text_index, request_body_text_index,
            request_body_size, response_body_size,
            request_body_stored, response_body_stored,
            request_body_truncated, response_body_truncated
        ) VALUES (
            ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?,
            ?, ?, ?, ?, ?, ?, ?,
            ?, ?,
            ?, ?, ?,
            ?, ?,
            ?, ?,
            ?, ?,
            ?, ?,
            ?, ?,
            ?, ?,
            ?, ?,
            ?, ?
        )
        """
        params = (
            record.get("request_id"),
            record.get("ts_start"),
            record.get("ts_end"),
            record.get("duration_ms"),
            record.get("engagement_id"),
            record.get("agent_id"),
            record.get("source_id"),
            record.get("run"),
            record.get("test"),
            record.get("role"),
            record.get("context_json"),
            record.get("source_type"),
            record.get("flow_state"),
            record.get("scheme"),
            record.get("host"),
            record.get("port"),
            record.get("method"),
            record.get("path"),
            record.get("query_string"),
            record.get("full_url"),
            record.get("status_code"),
            record.get("reason"),
            req_ct,
            resp_ct,
            1 if record.get("is_websocket") else 0,
            record.get("request_headers_json"),
            record.get("response_headers_json"),
            req_encoding,
            resp_encoding,
            req_blob,
            resp_blob,
            req_preview,
            resp_preview,
            resp_text_index,
            req_text_index,
            req_size,
            resp_size,
            req_stored,
            resp_stored,
            req_truncated,
            resp_truncated,
        )

        with self._lock:
            cursor = self._conn.execute(sql, params)
            flow_id = cursor.lastrowid
            self._conn.commit()

        # FTS insert (separate try/except so failure doesn't break recording)
        if resp_text_index:
            try:
                with self._lock:
                    self._conn.execute(
                        """INSERT INTO flow_fts (
                            flow_id, engagement_id, agent_id, host, path, run, test,
                            response_body_text
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            flow_id,
                            record.get("engagement_id"),
                            record.get("agent_id"),
                            record.get("host"),
                            record.get("path"),
                            record.get("run"),
                            record.get("test"),
                            resp_text_index,
                        ),
                    )
                    self._conn.commit()
            except Exception as exc:
                log.warning(f"FTS insert failed for flow {flow_id}: {exc}")

        # Request body FTS insert
        if req_text_index:
            try:
                with self._lock:
                    self._conn.execute(
                        """INSERT INTO flow_request_fts (
                            flow_id, engagement_id, agent_id, host, path, run, test,
                            request_body_text
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            flow_id,
                            record.get("engagement_id"),
                            record.get("agent_id"),
                            record.get("host"),
                            record.get("path"),
                            record.get("run"),
                            record.get("test"),
                            req_text_index,
                        ),
                    )
                    self._conn.commit()
            except Exception as exc:
                log.warning(f"Request FTS insert failed for flow {flow_id}: {exc}")

        return flow_id

    def search_flows(self, filters: dict) -> list[dict]:
        """Search flows by filter criteria. Returns summaries (no body blobs)."""
        conditions = []
        params = []

        _filter_map = {
            "engagement_id": ("engagement_id = ?", None),
            "agent_id": ("agent_id = ?", None),
            "run": ("run = ?", None),
            "test": ("test = ?", None),
            "host": ("host = ?", None),
            "method": ("method = ?", None),
            "status_code": ("status_code = ?", None),
            "flow_state": ("flow_state = ?", None),
        }

        for key, (clause, _) in _filter_map.items():
            if key in filters and filters[key] is not None:
                conditions.append(clause)
                params.append(filters[key])

        if "path_contains" in filters and filters["path_contains"]:
            conditions.append("path LIKE ?")
            params.append(f"%{filters['path_contains']}%")

        if "text_contains" in filters and filters["text_contains"]:
            conditions.append(
                "(response_body_text_preview LIKE ? OR request_body_text_preview LIKE ?)"
            )
            params.append(f"%{filters['text_contains']}%")
            params.append(f"%{filters['text_contains']}%")

        if "status_min" in filters and filters["status_min"] is not None:
            conditions.append("status_code >= ?")
            params.append(filters["status_min"])

        if "status_max" in filters and filters["status_max"] is not None:
            conditions.append("status_code <= ?")
            params.append(filters["status_max"])

        if "status_class" in filters and filters["status_class"]:
            sc = filters["status_class"]
            _class_ranges = {
                "2xx": (200, 299),
                "3xx": (300, 399),
                "4xx": (400, 499),
                "5xx": (500, 599),
            }
            if sc in _class_ranges:
                lo, hi = _class_ranges[sc]
                conditions.append("status_code >= ?")
                params.append(lo)
                conditions.append("status_code <= ?")
                params.append(hi)

        if "response_header_contains" in filters and filters["response_header_contains"]:
            conditions.append("response_headers_json LIKE ?")
            params.append(f"%{filters['response_header_contains']}%")

        if "request_header_contains" in filters and filters["request_header_contains"]:
            conditions.append("request_headers_json LIKE ?")
            params.append(f"%{filters['request_header_contains']}%")

        if "tag" in filters and filters["tag"]:
            tag_filter = filters["tag"]
            if ":" in tag_filter:
                tag_name, tag_value = tag_filter.split(":", 1)
                conditions.append(
                    "id IN (SELECT flow_id FROM flow_tags WHERE tag = ? AND value = ?)"
                )
                params.append(tag_name)
                params.append(tag_value)
            else:
                conditions.append(
                    "id IN (SELECT flow_id FROM flow_tags WHERE tag = ?)"
                )
                params.append(tag_filter)

        if "from_ts" in filters and filters["from_ts"] is not None:
            conditions.append("ts_start >= ?")
            params.append(filters["from_ts"])

        if "to_ts" in filters and filters["to_ts"] is not None:
            conditions.append("ts_start <= ?")
            params.append(filters["to_ts"])

        where = " AND ".join(conditions) if conditions else "1=1"
        limit = min(filters.get("limit", 50), 500)
        offset = filters.get("offset", 0)

        sql = f"""
        SELECT id, request_id, ts_start, ts_end, duration_ms,
               engagement_id, agent_id, source_id,
               run, test, role,
               flow_state, method, host, path, query_string, full_url,
               status_code, reason,
               request_content_type, response_content_type, is_websocket,
               request_body_size, response_body_size,
               request_body_truncated, response_body_truncated,
               response_body_text_preview
        FROM flows
        WHERE {where}
        ORDER BY ts_start DESC
        LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()

        results = []
        for row in rows:
            d = dict(row)
            # Include a short response preview snippet
            preview = d.pop("response_body_text_preview", "") or ""
            if len(preview) > 512:
                preview = preview[:512] + "..."
            d["response_preview"] = preview
            results.append(d)
        return results

    def get_flow(self, flow_id: int) -> dict | None:
        """Get full flow metadata, headers, previews, flags (no blobs)."""
        sql = """
        SELECT id, request_id, ts_start, ts_end, duration_ms,
               engagement_id, agent_id, source_id,
               run, test, role, context_json,
               source_type, flow_state,
               scheme, host, port, method, path, query_string, full_url,
               status_code, reason,
               request_content_type, response_content_type, is_websocket,
               request_headers_json, response_headers_json,
               request_body_text_preview, response_body_text_preview,
               request_body_size, response_body_size,
               request_body_stored, response_body_stored,
               request_body_truncated, response_body_truncated
        FROM flows WHERE id = ?
        """
        with self._lock:
            row = self._conn.execute(sql, (flow_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["tags"] = self.get_flow_tags(flow_id)
        return d

    def get_request_body(self, flow_id: int) -> dict | None:
        """Get and decompress request body for a flow."""
        sql = """
        SELECT request_body_blob, request_body_encoding,
               request_content_type, request_body_size,
               request_body_stored, request_body_truncated
        FROM flows WHERE id = ?
        """
        with self._lock:
            row = self._conn.execute(sql, (flow_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        blob = d.pop("request_body_blob")
        if blob and d.get("request_body_encoding") == "gzip":
            d["body"] = decompress_body(blob)
        elif blob:
            d["body"] = bytes(blob)
        else:
            d["body"] = b""
        return d

    def get_response_body(self, flow_id: int) -> dict | None:
        """Get and decompress response body for a flow."""
        sql = """
        SELECT response_body_blob, response_body_encoding,
               response_content_type, response_body_size,
               response_body_stored, response_body_truncated
        FROM flows WHERE id = ?
        """
        with self._lock:
            row = self._conn.execute(sql, (flow_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        blob = d.pop("response_body_blob")
        if blob and d.get("response_body_encoding") == "gzip":
            d["body"] = decompress_body(blob)
        elif blob:
            d["body"] = bytes(blob)
        else:
            d["body"] = b""
        return d

    def get_endpoints(self, filters: dict) -> list[dict]:
        """Group flows by method+host+path with counts and status codes."""
        conditions = []
        params = []

        if "engagement_id" in filters and filters["engagement_id"]:
            conditions.append("engagement_id = ?")
            params.append(filters["engagement_id"])
        if "agent_id" in filters and filters["agent_id"]:
            conditions.append("agent_id = ?")
            params.append(filters["agent_id"])
        if "run" in filters and filters["run"]:
            conditions.append("run = ?")
            params.append(filters["run"])
        if "test" in filters and filters["test"]:
            conditions.append("test = ?")
            params.append(filters["test"])

        where = " AND ".join(conditions) if conditions else "1=1"
        limit = min(filters.get("limit", 100), 500)
        offset = filters.get("offset", 0)

        sql = f"""
        SELECT method, host, path,
               COUNT(*) as count,
               MAX(ts_start) as last_seen,
               GROUP_CONCAT(DISTINCT status_code) as status_codes
        FROM flows
        WHERE {where}
        GROUP BY method, host, path
        ORDER BY count DESC
        LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()

        results = []
        for row in rows:
            d = dict(row)
            # Convert status_codes from comma-separated string to list of ints
            sc_str = d.pop("status_codes", "") or ""
            d["status_codes"] = [int(s) for s in sc_str.split(",") if s]
            results.append(d)
        return results

    @staticmethod
    def _sanitize_fts_query(query: str) -> str:
        """Sanitize a user query for FTS5 MATCH.

        Escapes each whitespace-delimited token by doubling any internal
        double-quotes and wrapping in double-quotes. This prevents FTS5
        from interpreting special characters (hyphens, dots, colons, etc.)
        as operators.

        Tokens are implicitly ANDed — all must match, in any order.

        Ref: https://www.sqlite.org/fts5.html (string quoting rules)
        """
        tokens = query.split()
        if not tokens:
            return query
        return " ".join(f'"{t.replace(chr(34), chr(34)+chr(34))}"' for t in tokens)

    def search_bodies(self, filters: dict) -> list[dict]:
        """Full-text search over response bodies via FTS5.

        Always scoped by engagement_id.
        """
        query = filters.get("query", "")
        if not query:
            return []

        engagement_id = filters.get("engagement_id")
        if not engagement_id:
            return []

        query = self._sanitize_fts_query(query)

        # Build FTS WHERE conditions for the non-FTS filter columns
        fts_conditions = ["fts.engagement_id = ?"]
        params: list = [engagement_id]

        if filters.get("agent_id"):
            fts_conditions.append("fts.agent_id = ?")
            params.append(filters["agent_id"])
        if filters.get("test"):
            fts_conditions.append("fts.test = ?")
            params.append(filters["test"])
        if filters.get("host"):
            fts_conditions.append("fts.host = ?")
            params.append(filters["host"])
        if filters.get("run"):
            fts_conditions.append("fts.run = ?")
            params.append(filters["run"])
        if filters.get("path"):
            fts_conditions.append("fts.path = ?")
            params.append(filters["path"])

        fts_where = " AND ".join(fts_conditions)
        limit = min(filters.get("limit", 50), 500)
        offset = filters.get("offset", 0)

        # Use FTS5 MATCH for the query text
        params.append(query)

        sql = f"""
        SELECT f.id, f.request_id, f.ts_start, f.duration_ms,
               f.engagement_id, f.agent_id,
               f.run, f.test,
               f.method, f.host, f.path,
               f.status_code, f.flow_state,
               snippet(flow_fts, 7, '<mark>', '</mark>', '...', 64) as snippet
        FROM flow_fts fts
        JOIN flows f ON f.id = fts.flow_id
        WHERE {fts_where}
          AND fts.response_body_text MATCH ?
        ORDER BY f.ts_start DESC
        LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()

        return [dict(row) for row in rows]

    def diff_flows(self, id_a: int, id_b: int) -> dict | None:
        """Compare response bodies of two flows.

        Returns diff info including sizes, unified diff for text bodies.
        Returns None if either flow is missing.
        """
        body_a = self.get_response_body(id_a)
        body_b = self.get_response_body(id_b)
        if body_a is None or body_b is None:
            return None

        raw_a = body_a.get("body", b"")
        raw_b = body_b.get("body", b"")
        size_a = len(raw_a)
        size_b = len(raw_b)

        ct_a = body_a.get("response_content_type", "")
        ct_b = body_b.get("response_content_type", "")
        text_a = is_text_like_content_type(ct_a)
        text_b = is_text_like_content_type(ct_b)
        both_text = text_a and text_b

        result = {
            "identical": raw_a == raw_b,
            "size_a": size_a,
            "size_b": size_b,
            "size_delta": size_b - size_a,
            "both_text": both_text,
            "body_text_a": None,
            "body_text_b": None,
            "diff_lines": [],
            "diff_truncated": False,
        }

        if both_text:
            max_chars = 100_000
            text_a_str = raw_a.decode("utf-8", errors="replace")[:max_chars]
            text_b_str = raw_b.decode("utf-8", errors="replace")[:max_chars]
            result["body_text_a"] = text_a_str
            result["body_text_b"] = text_b_str
            diff = list(difflib.unified_diff(
                text_a_str.splitlines(keepends=True),
                text_b_str.splitlines(keepends=True),
                fromfile=f"flow/{id_a}",
                tofile=f"flow/{id_b}",
            ))
            max_lines = 5000
            if len(diff) > max_lines:
                diff = diff[:max_lines]
                result["diff_truncated"] = True
            result["diff_lines"] = diff

        return result

    def search_request_bodies(self, filters: dict) -> list[dict]:
        """Full-text search over request bodies via FTS5.

        Always scoped by engagement_id.
        """
        query = filters.get("query", "")
        if not query:
            return []

        engagement_id = filters.get("engagement_id")
        if not engagement_id:
            return []

        query = self._sanitize_fts_query(query)

        fts_conditions = ["fts.engagement_id = ?"]
        params: list = [engagement_id]

        if filters.get("agent_id"):
            fts_conditions.append("fts.agent_id = ?")
            params.append(filters["agent_id"])
        if filters.get("test"):
            fts_conditions.append("fts.test = ?")
            params.append(filters["test"])
        if filters.get("host"):
            fts_conditions.append("fts.host = ?")
            params.append(filters["host"])
        if filters.get("run"):
            fts_conditions.append("fts.run = ?")
            params.append(filters["run"])
        if filters.get("path"):
            fts_conditions.append("fts.path = ?")
            params.append(filters["path"])

        fts_where = " AND ".join(fts_conditions)
        limit = min(filters.get("limit", 50), 500)
        offset = filters.get("offset", 0)

        params.append(query)

        sql = f"""
        SELECT f.id, f.request_id, f.ts_start, f.duration_ms,
               f.engagement_id, f.agent_id,
               f.run, f.test,
               f.method, f.host, f.path,
               f.status_code, f.flow_state,
               snippet(flow_request_fts, 7, '<mark>', '</mark>', '...', 64) as snippet
        FROM flow_request_fts fts
        JOIN flows f ON f.id = fts.flow_id
        WHERE {fts_where}
          AND fts.request_body_text MATCH ?
        ORDER BY f.ts_start DESC
        LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()

        return [dict(row) for row in rows]

    def tag_flow(self, flow_id: int, tag: str, value: str = "") -> dict:
        """Add or update a tag on a flow. Returns the tag dict."""
        created_at = int(time.time() * 1000)
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO flow_tags (flow_id, tag, value, created_at)
                   VALUES (?, ?, ?, ?)""",
                (flow_id, tag, value, created_at),
            )
            self._conn.commit()
        return {"flow_id": flow_id, "tag": tag, "value": value, "created_at": created_at}

    def untag_flow(self, flow_id: int, tag: str) -> bool:
        """Remove a tag from a flow. Returns True if a tag was deleted."""
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM flow_tags WHERE flow_id = ? AND tag = ?",
                (flow_id, tag),
            )
            self._conn.commit()
        return cursor.rowcount > 0

    def get_flow_tags(self, flow_id: int) -> list[dict]:
        """Get all tags for a flow."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT tag, value, created_at FROM flow_tags WHERE flow_id = ? ORDER BY tag",
                (flow_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
