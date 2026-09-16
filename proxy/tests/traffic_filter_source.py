"""Pure installed flowfilter observations over synthetic HTTP/WS values.

No proxy, listener, process sampler, API or operational files are used. The
module-owned case flag is restored after each row; process environment is not
changed. Run normally for deterministic JSON stdout, or --check to compare the
adjacent frozen JSON. Payload recipes keep the beyond-page witness compact.
"""

import argparse
import gzip
import hashlib
import importlib.metadata
import importlib.util
import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pyparsing
from mitmproxy import connection, exceptions, flow, flowfilter, http, websocket
from mitmproxy.net import encoding

ROOT = Path(__file__).resolve().parents[2]
SCOPE_PATH = ROOT / "cli/src/safeyolo/mitm_addons/traffic_scope.py"
SCOPE_SPEC = importlib.util.spec_from_file_location("owned_traffic_filter_scope", SCOPE_PATH)
assert SCOPE_SPEC and SCOPE_SPEC.loader
SCOPE_MODULE = importlib.util.module_from_spec(SCOPE_SPEC)
SCOPE_SPEC.loader.exec_module(SCOPE_MODULE)


def body(recipe):
    if recipe is None:
        return None
    content = bytes.fromhex(recipe["hex"]) if "hex" in recipe else recipe.get("text", "").encode()
    content = content * recipe.get("repeat", 1) + recipe.get("suffix_text", "").encode()
    return gzip.compress(content, mtime=0) if recipe.get("gzip", False) else content


def case(
    name,
    expressions,
    *,
    request=None,
    response=None,
    metadata=None,
    messages=None,
    error=False,
    case_sensitive=False,
    scope="shared",
):
    request = {
        "method": "GET",
        "url": "http://owned.invalid/foo",
        "headers": [],
        "body": None,
    } | (request or {})
    if response is not None:
        response = {"status": 200, "headers": [], "body": None} | response
    return {
        "name": name,
        "scope": scope,
        "case_sensitive": case_sensitive,
        "flow": {
            "request": request,
            "response": response,
            "metadata": metadata or {},
            "websocket": messages,
            "error": error,
        },
        "expressions": expressions,
    }


CASES = [
    case(
        "pending_method_url",
        [
            "~all",
            "~http",
            "~websocket",
            "~q",
            "~s",
            "~e",
            "~m get",
            "owned.invalid",
            "~u absent",
        ],
    ),
    case(
        "response_status_error",
        ["~q", "~s", "~e", "~c 418", "~c 200", "~c 1267650600228229401496703205376"],
        response={"status": 418},
        error=True,
    ),
    case(
        "implicit_and_and_precedence",
        [
            "~m GET ~u owned",
            "(~m GET ~u owned)",
            "~m GET ~u owned | ~c 404",
            "~m GET | ~m POST ~c 404",
            "~m GET | (~m POST & ~c 404)",
            "!~m POST & ~c 200 | ~c 404",
            "~m^GET",
            "~m ^GET",
        ],
        response={},
    ),
    case(
        "bare_operator_punctuation",
        [
            "foo|absent",
            "~u foo|absent",
            "~u foo!bar",
            "~u bar&tail",
            "~u absent | ~m GET",
        ],
        request={"url": "http://owned.invalid/foo!bar&tail"},
    ),
    case(
        "quoted_unescape",
        [
            r'~b "\d+"',
            r'~b "\\d+"',
            r"~b \d+",
            r'~b "\x41"',
            r'~b "\x42"',
            r'~b "\101"',
            r'~b "a\nb"',
            "~b 'a\nb'",
            r'~b "a\tb"',
        ],
        request={"body": {"text": "123 A B a\nb a\tb"}},
    ),
    case(
        "invalid_syntax",
        ["", " ", "~m", "~unknown", "(~all", "~c -1", "~u [", '~u "unterminated'],
    ),
    case(
        "binary_regex_categories",
        [r"~b .", r"~b ^.$", r"~b \w", r"~b \xff", '~b "(?u)."', r"~b \u00ff"],
        request={"body": {"hex": "ff"}},
    ),
    case(
        "unicode_pattern_bytes_and_text",
        ["~b É", "~b é", "~meta é", '~b "(?i:é)"', '~b "(?-i:É)"'],
        request={"body": {"text": "É"}},
        metadata={"note": "É"},
    ),
    case(
        "ordered_header_lines",
        [
            r'~hq "^X-Dup: one\r\nx-dup: two\r\n"',
            r'~hq "two\r\n$"',
            r'~hq "Raw: \\xff\r\n$"',
            "~hq ÿ",
            r"~hq \xff",
            "~hs reply",
            "~h reply",
        ],
        request={"headers": [["X-Dup", "one"], ["x-dup", "two"], ["Raw", "ÿ"]]},
        response={"headers": [["Reply", "yes"]]},
    ),
    case(
        "case_sensitive_mode",
        [
            "~m get",
            "~m GET",
            "~u OWNED",
            "~hq x-case",
            "~hq X-Case",
            "~b body",
            "~meta alice",
        ],
        request={"headers": [["X-Case", "Owned"]], "body": {"text": "Body"}},
        metadata={"agent": "Alice"},
        case_sensitive=True,
    ),
    case(
        "content_type_fields_and_assets",
        [
            "~t image",
            "~tq image",
            "~ts image",
            "~ts text/css",
            "~a",
            '~t "plain, image"',
        ],
        request={"headers": [["Content-Type", "text/plain"], ["content-type", "image/png"]]},
        response={
            "headers": [
                ["Content-Type", "application/json"],
                ["CONTENT-TYPE", "text/css"],
            ]
        },
    ),
    case(
        "asset_case_is_independent",
        ["~a", "~ts image", "~t IMAGE"],
        response={"headers": [["Content-Type", "IMAGE/PNG"]]},
    ),
    case(
        "metadata_python_values",
        [
            r'~meta "^flag: True$"',
            r'~meta "^none: None$"',
            r'~meta "^items: \\[1, .x.\\]$"',
            r'~meta "^mapping: .*b.*False.*a.*2"',
            r'~meta "^embedded: yes$"',
        ],
        metadata={
            "flag": True,
            "none": None,
            "items": [1, "x"],
            "mapping": {"b": False, "a": 2},
            "note": "first\nembedded: yes\nlast",
        },
    ),
    case(
        "decoded_gzip_both_sides",
        [
            "~b request_inside",
            "~bq request_inside",
            "~bs request_inside",
            "~bs response_inside",
            '~b "request.*response"',
        ],
        request={
            "headers": [["Content-Encoding", "gzip"]],
            "body": {"text": "request_inside", "gzip": True},
        },
        response={
            "headers": [["Content-Encoding", "gzip"]],
            "body": {"text": "response_inside", "gzip": True},
        },
    ),
    case(
        "malformed_value_falls_back_raw",
        ["~b RAW_MARKER", "~bq RAW_MARKER", "~bs response"],
        request={
            "headers": [["Content-Encoding", "gzip"]],
            "body": {"text": "RAW_MARKER"},
        },
        response={"body": {"text": "response"}},
    ),
    case(
        "codec_type_error_and_short_circuit",
        [
            "~b response",
            "~bq marker",
            "~bs response",
            "~all | ~b marker",
            "~all & ~b marker",
            "!~b marker",
        ],
        request={
            "headers": [["Content-Encoding", "rot_13"]],
            "body": {"text": "marker"},
        },
        response={"body": {"text": "response"}},
    ),
    case("absent_bodies", ["~b ^$", "~bq ^$", "~bs ^$", "~s"], response={}),
    case(
        "empty_present_bodies",
        ["~b ^$", "~bq ^$", "~bs ^$", "~b missing"],
        request={"body": {"text": ""}},
        response={"body": {"text": ""}},
    ),
    case(
        "websocket_messages_are_separate",
        [
            "~http",
            "~websocket",
            "~b left",
            "~bq left",
            "~bs left",
            "~bs right",
            "~b leftright",
            r"~bq \xff",
        ],
        response={"status": 101},
        messages=[
            {
                "type": "text",
                "from_client": True,
                "body": {"text": "left"},
                "dropped": True,
            },
            {
                "type": "binary",
                "from_client": True,
                "body": {"hex": "ff00"},
                "dropped": False,
            },
            {
                "type": "text",
                "from_client": False,
                "body": {"text": "right"},
                "dropped": False,
            },
        ],
    ),
    case(
        "websocket_beyond_page",
        ["~b NEEDLE", "~bq NEEDLE", "~bs NEEDLE", "~b xxNEEDLE"],
        response={"status": 101},
        messages=[
            {
                "type": "binary",
                "from_client": False,
                "body": {"text": "x", "repeat": 65534, "suffix_text": "NEEDLE"},
                "dropped": True,
            },
        ],
    ),
    case(
        "websocket_empty_transcript",
        ["~websocket", "~b ^$", "~q", "~s"],
        response={"status": 101},
        messages=[],
    ),
    case(
        "pretty_url_uses_presented_host",
        ["~u presented.invalid", "~u dial.invalid", "~u :80"],
        request={
            "url": "http://dial.invalid:80/path",
            "headers": [["Host", "presented.invalid:80"]],
        },
        scope="source_projection",
    ),
    case(
        "regex_backreference_lookaround",
        [
            r'~b "(ab)\\1"',
            '~b "(?<=ab)ab"',
            '~b "(?s:a.b)"',
            '~b "(?-s:a.b)"',
            r'~b "\\Aabab.*end\\Z"',
        ],
        request={"body": {"text": "abab a\nb end"}},
        scope="regex_compatibility",
    ),
]


def make_flow(recipe):
    client = connection.Client(peername=("192.0.2.1", 1234), sockname=("192.0.2.2", 8080))
    server = connection.Server(address=("owned.invalid", 80))
    owned = http.HTTPFlow(client, server)
    request = recipe["request"]
    owned.request = http.Request.make(request["method"], request["url"])
    owned.request.raw_content = body(request["body"])
    owned.request.headers = http.Headers(
        [(name.encode("latin1"), value.encode("latin1")) for name, value in request["headers"]]
    )
    if response := recipe["response"]:
        owned.response = http.Response.make(response["status"])
        owned.response.raw_content = body(response["body"])
        owned.response.headers = http.Headers(
            [(name.encode("latin1"), value.encode("latin1")) for name, value in response["headers"]]
        )
    owned.metadata = recipe["metadata"].copy()
    if recipe["error"]:
        owned.error = flow.Error("owned filter fixture error", timestamp=1.0)
    if recipe["websocket"] is not None:
        owned.websocket = websocket.WebSocketData(
            messages=[
                websocket.WebSocketMessage(
                    1 if message["type"] == "text" else 2,
                    message["from_client"],
                    body(message["body"]),
                    timestamp=float(index + 1),
                    dropped=message["dropped"],
                )
                for index, message in enumerate(recipe["websocket"])
            ]
        )
    return owned


def tree(node):
    result = {"type": type(node).__name__}
    if isinstance(node, (flowfilter.FAnd, flowfilter.FOr)):
        result["children"] = [tree(child) for child in node.lst]
    elif isinstance(node, flowfilter.FNot):
        result["child"] = tree(node.itm)
    elif hasattr(node, "expr"):
        result["expr"] = node.expr
    elif hasattr(node, "num"):
        result["num"] = node.num
    return result


def evaluate(expression, owned):
    result = {
        "expression": expression,
        "parse_error": None,
        "error_type": None,
        "matched": None,
        "tree": None,
    }
    try:
        parsed = flowfilter.parse(expression)
    except ValueError as error:
        result["parse_error"] = type(error).__name__
        return result
    result["tree"] = tree(parsed)
    try:
        result["matched"] = bool(parsed(owned))
    except (ValueError, TypeError) as error:
        # These finite specimens deliberately expose the source evaluation
        # boundary; an unexpected exception is not converted to a result.
        result["error_type"] = type(error).__name__
    return result


def observe(spec):
    owned = make_flow(spec["flow"])
    with patch.object(flowfilter, "maybe_ignore_case", 0 if spec["case_sensitive"] else re.IGNORECASE):
        results = [evaluate(expression, owned) for expression in spec["expressions"]]
    return {
        "input": spec,
        "projection": {
            "pretty_url": owned.request.pretty_url,
            "request_method_hex": owned.request.data.method.hex(),
            "request_headers_hex": bytes(owned.request.headers).hex(),
            "response_headers_hex": None if owned.response is None else bytes(owned.response.headers).hex(),
            "metadata_text": "\n".join(f"{key}: {value}" for key, value in owned.metadata.items()),
        },
        "results": results,
    }


def assert_contract(rows):
    observed = {(row["input"]["name"], result["expression"]): result for row in rows for result in row["results"]}
    # Selected independent expectations make accidental fixture construction
    # changes fail before a new JSON result can be accepted.
    expectations = [
        (
            "response_status_error",
            "~c 1267650600228229401496703205376",
            False,
            None,
            None,
        ),
        ("implicit_and_and_precedence", "~m GET ~u owned", True, None, None),
        ("implicit_and_and_precedence", "(~m GET ~u owned)", None, "ValueError", None),
        ("implicit_and_and_precedence", "~m GET | ~m POST ~c 404", False, None, None),
        ("quoted_unescape", r'~b "\d+"', False, None, None),
        ("quoted_unescape", r'~b "\\d+"', True, None, None),
        ("quoted_unescape", r'~b "\x42"', True, None, None),
        ("binary_regex_categories", r"~b \w", False, None, None),
        ("binary_regex_categories", r"~b \xff", True, None, None),
        ("ordered_header_lines", r'~hq "Raw: \\xff\r\n$"', True, None, None),
        ("unicode_pattern_bytes_and_text", "~b é", False, None, None),
        ("unicode_pattern_bytes_and_text", "~meta é", True, None, None),
        ("case_sensitive_mode", "~m get", False, None, None),
        ("asset_case_is_independent", "~a", False, None, None),
        ("decoded_gzip_both_sides", "~bs response_inside", True, None, None),
        ("malformed_value_falls_back_raw", "~bq RAW_MARKER", True, None, None),
        ("codec_type_error_and_short_circuit", "~b response", None, None, "TypeError"),
        ("codec_type_error_and_short_circuit", "~all | ~b marker", True, None, None),
        ("absent_bodies", "~b ^$", False, None, None),
        ("empty_present_bodies", "~b ^$", True, None, None),
        ("websocket_messages_are_separate", "~bq left", True, None, None),
        ("websocket_messages_are_separate", "~b leftright", False, None, None),
        ("websocket_beyond_page", "~bs NEEDLE", True, None, None),
        ("websocket_beyond_page", "~bq NEEDLE", False, None, None),
    ]
    for name, expression, matched, parse_error, error_type in expectations:
        result = observed[name, expression]
        assert (result["matched"], result["parse_error"], result["error_type"]) == (
            matched,
            parse_error,
            error_type,
        ), (name, expression, result)
    grouped = observed["implicit_and_and_precedence", "~m GET | ~m POST ~c 404"]["tree"]
    assert grouped["type"] == "FAnd"
    assert [child["type"] for child in grouped["children"]] == ["FOr", "FCode"]


class OwnedOptions:
    """Only the selected setter's option publication; no addon dispatcher."""

    def __init__(self):
        self.view_filter = ""
        self.updates = []

    def update(self, *, view_filter):
        self.view_filter = view_filter
        self.updates.append(view_filter)


def scope_setters():
    rows = []
    for agent in [None, "alice"]:
        options = OwnedOptions()
        addon = SCOPE_MODULE.TrafficScope()
        context = SimpleNamespace(options=options)
        spec = case("owned_scope_flow", [], metadata={"agent": "alice"})
        owned = make_flow(spec["flow"])
        values = [
            "  ~m GET  ",
            "~m GET ~u owned",
            "~m GET & ~u owned",
            "~all",
            "~q",
            "~s",
            "~websocket",
            "(~all )",
            "(~q )",
            "(~s )",
            "(~websocket )",
            "~all & ~m GET",
            "",
        ]
        steps = []
        with (
            patch.object(SCOPE_MODULE, "ctx", context),
            patch.object(flowfilter, "maybe_ignore_case", re.IGNORECASE),
        ):
            addon.set_scope(agent=agent)
            for value in values:
                before = addon.get_stats()
                publications = len(options.updates)
                error_type = None
                try:
                    addon.set_user_filter(value)
                except exceptions.OptionsError as error:
                    error_type = type(error).__name__
                stats = addon.get_stats()
                effective = stats["effective_filter"]
                evaluated = evaluate(effective, owned) if effective else None
                if value in {"~m GET ~u owned", "~all", "~q", "~s", "~websocket"}:
                    assert error_type == "OptionsError"
                    assert stats == before
                    assert len(options.updates) == publications
                else:
                    assert error_type is None
                    assert stats["user_filter"] == value
                assert options.view_filter == effective
                assert evaluated is None or evaluated["parse_error"] is None
                if evaluated is not None and error_type is None:
                    assert evaluated["matched"] is (value not in {"(~s )", "(~websocket )"})
                steps.append(
                    {
                        "value": value,
                        "error_type": error_type,
                        "stats": stats,
                        "published": options.updates[publications:],
                        "effective_evaluation": evaluated,
                    }
                )
        rows.append(
            {
                "input": {"agent": agent, "values": values, "flow": spec["flow"]},
                "steps": steps,
            }
        )
    return rows


def document():
    original_case_mode = flowfilter.maybe_ignore_case
    rows = [observe(spec) for spec in CASES]
    assert flowfilter.maybe_ignore_case == original_case_mode
    assert_contract(rows)
    modules = {
        "mitmproxy/flowfilter.py": flowfilter,
        "mitmproxy/http.py": http,
        "mitmproxy/websocket.py": websocket,
        "mitmproxy/flow.py": flow,
        "mitmproxy/connection.py": connection,
        "mitmproxy/net/encoding.py": encoding,
        "pyparsing/core.py": pyparsing.core,
        "stdlib/re/__init__.py": re,
        "stdlib/gzip.py": gzip,
        "cli/src/safeyolo/mitm_addons/traffic_scope.py": SCOPE_MODULE,
    }
    return {
        "schema": 1,
        "source_sha256": {
            name: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest() for name, module in modules.items()
        },
        "versions": {
            "python": sys.version.split()[0],
            "mitmproxy": importlib.metadata.version("mitmproxy"),
            "pyparsing": importlib.metadata.version("pyparsing"),
        },
        "quoted_unquote_pattern": pyparsing.QuotedString('"', esc_char="\\").unquote_scan_re.pattern,
        "rows": rows,
        "scope_rows": scope_setters(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    options = parser.parse_args()
    observed = document()
    text = json.dumps(observed, indent=2, ensure_ascii=True) + "\n"
    if options.check:
        expected = Path(__file__).with_suffix(".json").read_text()
        if text != expected:
            raise SystemExit("traffic filter fixture differs")
        count = sum(len(row["results"]) for row in observed["rows"])
        scope_steps = sum(len(row["steps"]) for row in observed["scope_rows"])
        print(
            f"matched {len(observed['rows'])} workflows / {count} filter observations; "
            f"{len(observed['scope_rows'])} scope workflows / {scope_steps} setter steps"
        )
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
