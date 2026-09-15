"""Actual FlowStore tags and diff, with compact hashes for large body results."""

import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(ROOT / "cli/src"))
from safeyolo.storage.flow_store import FlowStore  # noqa: E402


def record(store, name, body=b"", ct="text/plain"):
    return store.record_flow(
        {
            "request_id": name,
            "ts_start": 1,
            "engagement_id": "owned",
            "agent_id": "alice",
            "host": "owned.invalid",
            "flow_state": "completed",
            "response_content_type": ct,
            "response_body": body,
        }
    )


def summary(value):
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    if value is None:
        return {"sha256": hashlib.sha256(raw).hexdigest(), "missing": True}
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "identical": value["identical"],
        "size_a": value["size_a"],
        "size_b": value["size_b"],
        "chars_a": len(value["body_text_a"])
        if value["body_text_a"] is not None
        else None,
        "chars_b": len(value["body_text_b"])
        if value["body_text_b"] is not None
        else None,
        "line_count": len(value["diff_lines"]),
        "truncated": value["diff_truncated"],
    }


def body(recipe):
    if "hex" in recipe:
        return bytes.fromhex(recipe["hex"])
    if recipe["kind"] == "prefix":
        return (recipe["character"] * 100_000 + recipe["tail"]).encode()
    return "".join(
        f"{recipe['prefix']}{index}\n" for index in range(recipe["lines"])
    ).encode()


def diff_cases():
    cases = []

    def add(name, a, b, **kwargs):
        cases.append(
            {"name": name, "a": {"hex": a.hex()}, "b": {"hex": b.hex()}, **kwargs}
        )

    add("same", b"one\ntwo\n", b"one\ntwo\n")
    add("empty", b"", b"")
    add("insert_empty", b"", b"added")
    add("delete_empty", b"gone", b"")
    add("no_final_newline", b"one\ntwo", b"one\nthree")
    add("earliest_longest", b"a\nb\n", b"a\nc\na\nb\n")
    add("binary", b"\x00\xff", b"\xff\x00", ct_a="image/png", ct_b="image/png")
    add("mixed", b"text", b"other", ct_b="image/png")
    add("invalid_utf8", bytes(range(256)), bytes(range(1, 256)) + b"x")
    add(
        "all_splitlines",
        "a\rb\nc\r\nd\ve\ff\x1cg\x1dh\x1ei\x85j\u2028k\u2029z".encode(),
        "a\rb\nc\r\nd\ve\ff\x1cg\x1dh\x1ei\x85j\u2028changed\u2029z".encode(),
    )
    add("unit_separator_not_linebreak", b"a\x1fb\n", b"a\x1fc\n")
    add("autojunk_199", b"a\n" * 198 + b"x\n", b"b\n" + b"a\n" * 198)
    add("autojunk_200", b"a\n" * 199 + b"x\n", b"b\n" + b"a\n" * 199)
    for gap in [5, 6, 7, 8]:
        add(
            f"context_gap_{gap}",
            b"before\nold\n" + b"same\n" * gap + b"old\nafter\n",
            b"before\nnew\n" + b"same\n" * gap + b"new\nafter\n",
        )
    cases.extend(
        [
            {
                "name": "exact_5000",
                "a": {"kind": "lines", "prefix": "left", "lines": 2498},
                "b": {"kind": "lines", "prefix": "right", "lines": 2499},
            },
            {
                "name": "over_5000",
                "a": {"kind": "lines", "prefix": "left", "lines": 2499},
                "b": {"kind": "lines", "prefix": "right", "lines": 2499},
            },
            {
                "name": "unicode_prefix_only",
                "a": {"kind": "prefix", "character": "😀", "tail": "a"},
                "b": {"kind": "prefix", "character": "😀", "tail": "b"},
            },
            {
                "name": "ascii_prefix_only",
                "a": {"kind": "prefix", "character": "x", "tail": "a"},
                "b": {"kind": "prefix", "character": "x", "tail": "b"},
            },
        ]
    )
    add("retained_byte_sizes", b"abcdefgh", b"abcdefXYZ", limit=3)
    add("missing_a", b"x", b"y", missing="a")
    add("missing_b", b"x", b"y", missing="b")
    add("missing_a_bad_b", b"x", b"y", missing="a", corrupt="b")
    add("bad_a_missing_b", b"x", b"y", missing="b", corrupt="a")
    # Deterministic short/repeated/adversarial line sequences exercise the actual
    # matcher independently of Rust's implementation, without another algorithm.
    state = 0x12345678

    def next_value():
        nonlocal state
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        return state

    for index in range(120):
        a = [f"{next_value() % 7}\n" for _ in range(next_value() % 45)]
        b = [f"{next_value() % 7}\n" for _ in range(next_value() % 45)]
        add(f"sequence_{index}", "".join(a).encode(), "".join(b).encode())
    return cases


def run():
    result = {"tags": [], "diff": []}
    with tempfile.TemporaryDirectory(prefix="flow-details-source-") as directory:
        store = FlowStore(str(Path(directory) / "tags.db"))
        store.init_db()
        record(store, "tagged")
        inputs = [
            ("plain", "label", "old"),
            ("upsert", "label", "new"),
            ("unicode", "é", "☃"),
            ("colon", "url", "https://owned.invalid/x:y"),
            ("empty", "", ""),
            ("boolean", True, False),
            ("integer", 3, 4),
            ("float", 3.0, 1e-6),
            ("negative_zero", -0.0, -0.0),
            ("infinity", float("inf"), -float("inf")),
            ("nan", "nan", float("nan")),
            ("null_tag", None, "v"),
            ("null_value", "v", None),
            ("array", [], "v"),
            ("object", "v", {}),
            ("huge", 10**100, "v"),
            ("missing", "missing", "v"),
        ]
        for index, (name, tag, value) in enumerate(inputs):
            flow_id = 9 if name == "missing" else 1
            now = (1000 + index) * 1000
            row = {
                "name": name,
                "id": flow_id,
                "tag_json": json.dumps(tag),
                "value_json": json.dumps(value),
                "now": now,
            }
            try:
                with patch("time.time", return_value=now / 1000):
                    immediate = store.tag_flow(flow_id, tag, value)
                row["immediate_json"] = json.dumps(immediate)
            except (sqlite3.Error, OverflowError) as error:
                row["error"] = type(error).__name__
            row["tags"] = store.get_flow_tags(1)
            result["tags"].append(row)
        for index, tag in enumerate(
            [3.0, 3, True, "absent", None, float("nan"), [], "label", "label"]
        ):
            row = {
                "name": f"delete_{index}",
                "delete": True,
                "id": 1,
                "tag_json": json.dumps(tag),
            }
            try:
                row["deleted"] = store.untag_flow(1, tag)
            except sqlite3.Error as error:
                row["error"] = type(error).__name__
            row["tags"] = store.get_flow_tags(1)
            result["tags"].append(row)
        store.close()
        for index, case in enumerate(diff_cases()):
            store = FlowStore(
                str(Path(directory) / f"diff{index}.db"),
                max_response_body_bytes=case.get("limit", 4_194_304),
            )
            store.init_db()
            record(store, "a", body(case["a"]), case.get("ct_a", "text/plain"))
            record(store, "b", body(case["b"]), case.get("ct_b", "text/plain"))
            if "corrupt" in case:
                store._conn.execute(
                    "UPDATE flows SET response_body_blob=?,response_body_encoding='gzip' WHERE id=?",
                    (b"not gzip", 1 if case["corrupt"] == "a" else 2),
                )
                store._conn.commit()
            try:
                value = store.diff_flows(
                    9 if case.get("missing") == "a" else 1,
                    9 if case.get("missing") == "b" else 2,
                )
                case["summary"] = summary(value)
            except (OSError, EOFError) as error:
                case["error"] = type(error).__name__
            result["diff"].append(case)
            store.close()
        path = str(Path(directory) / "partial.db")
        store = FlowStore(path)
        store.init_db()
        record(store, "owned", b"response")
        store.close()
        external = sqlite3.connect(path)
        external.executescript(
            "DROP TABLE flow_fts; DROP TABLE flow_request_fts; CREATE TABLE marker(value); CREATE INDEX flow_request_fts ON marker(value); PRAGMA user_version=1;"
        )
        store = FlowStore(path)
        try:
            store.init_db()
        except sqlite3.OperationalError as error:
            result["pending"] = {"error": type(error).__name__}
        result["pending"]["before"] = external.execute(
            "PRAGMA user_version"
        ).fetchone()[0]
        with patch("time.time", return_value=4):
            store.tag_flow(1, "ready", "yes")
        result["pending"]["after"] = external.execute("PRAGMA user_version").fetchone()[
            0
        ]
        result["pending"]["tags"] = store.get_flow_tags(1)
        external.close()
        store.close()
    return result


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=True, allow_nan=False))
