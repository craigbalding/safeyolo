"""Observe installed flow-dump save/load behavior using owned synthetic flows.

Run with the repository's mitmproxy 12.2.3 Python environment. ``--write``
regenerates the adjacent JSON; ``--check`` compares it with fresh observations.
The script uses BytesIO and temporary files. It does not start a proxy or
exercise startup, streaming-save, web-import, or addon lifecycle dispatch.
"""

import argparse
import copy
import hashlib
import importlib.metadata
import io
import json
import logging
import sys
import tempfile
import zlib
from pathlib import Path

from mitmproxy import connection, exceptions, flow, http, tcp, version, websocket
from mitmproxy.addons import save, view
from mitmproxy.coretypes import serializable
from mitmproxy.io import compat, tnetstring
from mitmproxy.io import har as har_io
from mitmproxy.io import io as flow_io

SOURCE_MODULES = {
    "mitmproxy/addons/save.py": save,
    "mitmproxy/addons/view.py": view,
    "mitmproxy/connection.py": connection,
    "mitmproxy/coretypes/serializable.py": serializable,
    "mitmproxy/flow.py": flow,
    "mitmproxy/http.py": http,
    "mitmproxy/io/compat.py": compat,
    "mitmproxy/io/har.py": har_io,
    "mitmproxy/io/io.py": flow_io,
    "mitmproxy/io/tnetstring.py": tnetstring,
    "mitmproxy/tcp.py": tcp,
    "mitmproxy/version.py": version,
    "mitmproxy/websocket.py": websocket,
}


def json_state(value):
    """Preserve bytes versus text; typed netstrings merge tuple/list identity."""
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, dict):
        return {key: json_state(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_state(item) for item in value]
    return value


def fixed_flow(name, *, opaque=False):
    client = connection.Client(
        id=f"client-{name}",
        peername=("192.0.2.10", 1234),
        sockname=("192.0.2.20", 8080),
        timestamp_start=1.0,
    )
    server = connection.Server(
        id=f"server-{name}",
        address=("source.fixture.invalid", 8081),
        peername=("198.51.100.20", 8081),
        timestamp_start=2.0,
        timestamp_tcp_setup=3.0,
    )
    owned = tcp.TCPFlow(client, server) if opaque else http.HTTPFlow(client, server)
    owned.id = f"flow-{name}"
    owned.timestamp_created = 4.0
    if not opaque:
        owned.request = http.Request.make("POST", "http://source.fixture.invalid:8081/a?q=1&q=2", b"")
        owned.request.headers = http.Headers([(b"X-Dup", b"one"), (b"x-dup", b"\xff")])
        owned.request.raw_content = b"\x00\xffrequest"
        owned.request.timestamp_start = 5.0
        owned.request.timestamp_end = 6.0
        owned.response = http.Response.make(299, b"reply", [(b"X-Reply", b"two")])
        owned.response.data.reason = b"Synthetic \xff"
        owned.response.timestamp_start = 7.0
        owned.response.timestamp_end = 8.0
    return owned


def owned_flows():
    rich = fixed_flow("rich")
    rich.request.trailers = http.Headers([(b"X-Trailer", b"\x80")])
    rich.response.trailers = http.Headers([])
    rich.metadata = {"text": "café", "bytes": b"\xff", "nested": [None, True, 7, 1.5]}
    rich.comment = "owned note"
    rich.marked = ":star:"
    rich.is_replay = "request"
    rich.intercepted = True
    rich.live = True  # live connection state is deliberately not serialized.
    rich.backup()
    rich.comment = "changed note"

    empty = fixed_flow("empty")
    empty.request.raw_content = b""
    empty.response.raw_content = b""
    missing = fixed_flow("missing")
    missing.request.raw_content = None
    missing.request.timestamp_end = None
    missing.response.raw_content = None
    missing.response.timestamp_end = None
    failed = fixed_flow("failed")
    failed.response = None
    failed.error = flow.Error("owned failure", timestamp=9.0)

    ws = fixed_flow("websocket")
    ws.response.status_code = 101
    ws.websocket = websocket.WebSocketData()
    ws.websocket.messages = [
        websocket.WebSocketMessage(1, True, b"outgoing", 10.0),
        websocket.WebSocketMessage(2, False, b"\xff\x00", 11.0, dropped=True),
        websocket.WebSocketMessage(1, False, b"\xff", 12.0, injected=True),
    ]
    ws.websocket.closed_by_client = False
    ws.websocket.close_code = 1001
    ws.websocket.close_reason = "owned close"
    ws.websocket.timestamp_end = 13.0
    opaque = fixed_flow("tcp", opaque=True)
    opaque.messages = [tcp.TCPMessage(False, b"server first", 10.0), tcp.TCPMessage(True, b"\x00\xff", 11.0)]
    return {"rich": rich, "empty": empty, "missing": missing, "failed": failed, "websocket": ws, "tcp": opaque}


def dump_bytes(flows):
    output = io.BytesIO()
    writer = flow_io.FlowWriter(output)
    for item in flows:
        writer.add(item)
    return output.getvalue()


def read_observation(data):
    states = []
    try:
        for item in flow_io.FlowReader(io.BytesIO(data)).stream():
            states.append(json_state(item.get_state()))
    except exceptions.FlowReadException as error:
        return {"states": states, "error": {"type": type(error).__name__, "message": str(error)}}
    return {"states": states, "error": None}


def scalar_controls():
    cases = [
        ("null", None, b"0:~"),
        ("empty_bytes", b"", b"0:,"),
        ("empty_text", "", b"0:;"),
        ("binary", b"\xff", b"1:\xff,"),
        ("unicode", "é", b"2:\xc3\xa9;"),
        ("integer", -7, b"2:-7#"),
        ("float", 1.5, b"3:1.5^"),
        ("boolean", True, b"4:true!"),
        ("sequence", [None, b""], b"6:0:~0:,]"),
    ]
    result = []
    for name, value, expected in cases:
        encoded = tnetstring.dumps(value)
        assert encoded == expected
        assert tnetstring.loads(encoded) == value
        result.append({"name": name, "value": json_state(value), "wire_hex": encoded.hex()})
    return result


def error_controls(owned, encoded):
    state = owned.get_state()
    future = copy.deepcopy(state)
    future["version"] = version.FLOW_FORMAT_VERSION + 1
    unknown = copy.deepcopy(state)
    unknown["type"] = "owned-unknown"
    cases = {
        "empty_file": b"",
        "non_mapping_record": tnetstring.dumps([1]),
        "truncated_record": encoded[:-1],
        "future_version": tnetstring.dumps(future),
        "unknown_type": tnetstring.dumps(unknown),
        "valid_then_corrupt": encoded + b"invalid",
    }
    result = {name: read_observation(data) for name, data in cases.items()}
    assert result["empty_file"] == {"states": [], "error": None}
    for name in ("non_mapping_record", "truncated_record", "future_version", "unknown_type"):
        assert result[name]["states"] == []
        assert result[name]["error"]["type"] == "FlowReadException"
    assert result["valid_then_corrupt"]["states"] == [json_state(state)]
    assert result["valid_then_corrupt"]["error"]["type"] == "FlowReadException"
    return {name: {"wire_hex": cases[name].hex(), **item} for name, item in result.items()}


def file_workflows(flows, encoded):
    with tempfile.TemporaryDirectory(prefix="safeyolo-dump-source-") as directory:
        path = Path(directory) / "flows.dump"
        saver = save.Save()
        saver.save([flows["rich"]], str(path))
        assert path.read_bytes() == encoded["rich"]
        saver.save([flows["empty"]], "+" + str(path))
        assert path.read_bytes() == encoded["rich"] + encoded["empty"]
        saver.save([flows["failed"]], str(path))
        assert path.read_bytes() == encoded["failed"]
        missing_parent = Path(directory) / "missing" / "flows.dump"
        try:
            saver.save([flows["rich"]], str(missing_parent))
        except exceptions.CommandError:
            pass
        else:
            raise AssertionError("save.file unexpectedly created a missing parent")
        assert not missing_parent.parent.exists()
        suffix = Path(directory) / "flows.har"
        saver.save([flows["rich"]], str(suffix))
        assert suffix.read_bytes() == encoded["rich"]

        path.write_bytes(encoded["rich"])
        inspector = view.View()
        inspector.add([flows["empty"]])
        inspector.load_file(str(path))
        inspector.load_file(str(path))
        assert len(inspector) == 3
        ids = {item.id for item in inspector}
        assert len(ids) == 3 and flows["rich"].id not in ids
        for item in inspector:
            if item.id != flows["empty"].id:
                state = item.get_state()
                state["id"] = flows["rich"].id
                assert json_state(state) == json_state(flows["rich"].get_state())
                assert item.live is False
        path.write_bytes(encoded["failed"] + b"invalid")
        inspector.load_file(str(path))
        assert len(inspector) == 4
    return {
        "overwrite_ids": [flows["failed"].id],
        "append_ids": [flows["rich"].id, flows["empty"].id],
        "missing_parent_created": False,
        "har_suffix_writes_dump": True,
        "repeat_load_count_including_existing": 3,
        "loaded_ids_are_fresh_and_unique": True,
        "loaded_state_preserved_except_id": True,
        "loaded_live": False,
        "count_after_valid_then_corrupt_load": 4,
    }


def owned_har_entry():
    """Construct importer input independently of the source HAR exporter."""
    return {
        "startedDateTime": "1970-01-01T00:00:10+00:00",
        "time": 2500,
        "serverIPAddress": "198.51.100.40",
        "timings": {"connect": 100, "send": 200, "wait": 300, "receive": 1900},
        "request": {
            "method": "POST",
            "url": "http://source.fixture.invalid:8081/import?q=one&q=two",
            "httpVersion": "HTTP/1.0",
            "headers": [
                {"name": "X-Dup", "value": "one"},
                ["x-dup", "two"],
                {"name": "Content-Type", "value": "text/plain; charset=iso-8859-1"},
            ],
            "postData": {"mimeType": "text/plain; charset=iso-8859-1", "text": "café"},
        },
        "response": {
            "status": 299,
            "statusText": "Owned custom reason",
            "httpVersion": "http/2.0",
            "headers": [
                {"name": "Content-Encoding", "value": "gzip"},
                {"name": "Content-Type", "value": "application/octet-stream"},
            ],
            "content": {"encoding": "base64", "text": "AP8="},
        },
        "_webSocketMessages": [{"type": "send", "time": 11.0, "opcode": 1, "data": "owned message"}],
    }


def har_loaded_state(owned):
    """Omit generated IDs and creation time; keep reconstructed socket facts."""
    state = owned.get_state()
    del state["id"]
    del state["timestamp_created"]
    del state["client_conn"]["id"]
    del state["server_conn"]["id"]
    return {"state": json_state(state), "live": owned.live}


def read_har_observation(data):
    states = []
    try:
        for owned in flow_io.FlowReader(io.BytesIO(data)).stream():
            states.append(har_loaded_state(owned))
    except exceptions.FlowReadException as error:
        return {"flows": states, "error": {"type": type(error).__name__, "message": str(error)}}
    return {"flows": states, "error": None}


def assert_har_reader_state(observation):
    assert observation["error"] is None and len(observation["flows"]) == 1
    loaded = observation["flows"][0]
    assert loaded["live"] is False
    state = loaded["state"]
    assert state["request"]["content"] == {"bytes_hex": "636166e9"}
    assert state["response"]["content"] == {"bytes_hex": "00ff"}
    assert state["request"]["http_version"] == {"bytes_hex": b"HTTP/1.1".hex()}
    assert state["response"]["http_version"] == {"bytes_hex": b"HTTP/2".hex()}
    assert state["response"]["reason"] == {"bytes_hex": ""}
    assert state["websocket"] is None
    assert state["request"]["port"] == 8081
    assert state["server_conn"]["address"] == ["198.51.100.40", 80]
    assert state["server_conn"]["peername"] is None
    assert state["server_conn"]["timestamp_tcp_setup"] is None
    assert state["client_conn"]["peername"] == ["127.0.0.1", 0]
    assert state["client_conn"]["sockname"] == ["127.0.0.1", 0]
    for name in ("request", "response", "client_conn"):
        assert state[name]["timestamp_start"] == 10.0
        assert state[name]["timestamp_end"] == 12.5
    response_headers = state["response"]["headers"]
    assert not any(bytes.fromhex(pair[0]["bytes_hex"]).lower() == b"content-encoding" for pair in response_headers)


def har_reader_controls():
    entry = owned_har_entry()
    document = {"log": {"version": "1.2", "entries": [entry]}}
    encoded = json.dumps(document, ensure_ascii=True).encode()
    cases = {
        "json": encoded,
        "utf8_bom": b"\xef\xbb\xbf" + encoded,
        "leading_whitespace": b" \n" + encoded,
        "zlib_is_not_autodetected": zlib.compress(encoded, 9),
        "malformed_json": b'{"log":',
        "empty_entries": b'{"log":{"entries":[]}}',
        "valid_then_invalid_entry": json.dumps({"log": {"entries": [entry, {}]}}).encode(),
    }
    result = {name: read_har_observation(data) for name, data in cases.items()}
    assert_har_reader_state(result["json"])
    assert result["utf8_bom"] == result["json"]
    for name in ("leading_whitespace", "zlib_is_not_autodetected", "malformed_json"):
        assert result[name]["flows"] == []
        assert result[name]["error"]["type"] == "FlowReadException"
    assert result["empty_entries"] == {"flows": [], "error": None}
    assert result["valid_then_invalid_entry"]["flows"] == result["json"]["flows"]
    assert result["valid_then_invalid_entry"]["error"]["type"] == "FlowReadException"
    first = next(flow_io.FlowReader(io.BytesIO(encoded)).stream())
    second = next(flow_io.FlowReader(io.BytesIO(encoded)).stream())
    assert first.id != second.id
    assert first.client_conn.id != second.client_conn.id
    assert first.server_conn.id != second.server_conn.id
    return {
        "normalization": "omit generated flow/client/server IDs and flow creation time only",
        "repeated_reads_have_fresh_ids": True,
        "cases": {name: {"wire_hex": cases[name].hex(), **observation} for name, observation in result.items()},
    }


def observe():
    flows = owned_flows()
    encoded = {name: dump_bytes([item]) for name, item in flows.items()}
    records = []
    for name, item in flows.items():
        state = json_state(item.get_state())
        read = read_observation(encoded[name])
        assert read == {"states": [state], "error": None}
        records.append({"name": name, "state": state, "wire_hex": encoded[name].hex()})
    rich = flows["rich"].get_state()
    assert rich["backup"]["comment"] == "owned note"
    assert rich["comment"] == "changed note" and "live" not in rich
    ws = flows["websocket"].get_state()["websocket"]["messages"]
    assert ws[1] == (2, False, b"\xff\x00", 11.0, True, False)
    assert ws[2] == (1, False, b"\xff", 12.0, False, True)
    combined = read_observation(b"".join(encoded.values()))
    assert [state["id"] for state in combined["states"]] == [item.id for item in flows.values()]
    assert combined["error"] is None
    return {
        "schema_version": 1,
        "python_version": sys.version.split()[0],
        "mitmproxy_version": importlib.metadata.version("mitmproxy"),
        "flow_format_version": version.FLOW_FORMAT_VERSION,
        "source_sha256": {
            name: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
            for name, module in SOURCE_MODULES.items()
        },
        "scalar_controls": scalar_controls(),
        "records": records,
        "concatenated_ids": [state["id"] for state in combined["states"]],
        "read_errors": error_controls(flows["failed"], encoded["failed"]),
        "file_workflows": file_workflows(flows, encoded),
        "har_reader": har_reader_controls(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--write", action="store_true")
    modes.add_argument("--check", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.CRITICAL)
    document = observe()
    target = Path(__file__).with_suffix(".json")
    if args.check:
        if json.loads(target.read_text()) != document:
            raise SystemExit("flow-dump source observations differ")
        print(
            f"matched {len(document['records'])} flow records, save/load controls, "
            f"and {len(document['har_reader']['cases'])} HAR-reader controls"
        )
    elif args.write:
        target.write_text(json.dumps(document, indent=2, ensure_ascii=True) + "\n")
    else:
        json.dump(document, sys.stdout, indent=2, ensure_ascii=True)
        print()


if __name__ == "__main__":
    main()
