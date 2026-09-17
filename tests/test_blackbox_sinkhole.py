"""Regression tests for the blackbox sinkhole server."""

import http.client
import importlib.util
import socket
import sys
import threading
import time
from pathlib import Path
from unittest.mock import Mock, patch

from tests.blackbox.sinkhole.models import CapturedRequest


def _load_sinkhole_server():
    sinkhole_dir = Path(__file__).parent / "blackbox" / "sinkhole"
    sys.path.insert(0, str(sinkhole_dir))
    spec = importlib.util.spec_from_file_location("blackbox_sinkhole_server", sinkhole_dir / "server.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _send_raw_request(port, request, *, shutdown_write=False):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
        client.sendall(request)
        if shutdown_write:
            client.shutdown(socket.SHUT_WR)
        response = b""
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            response += chunk
        return response


def test_sinkhole_bind_does_not_perform_reverse_dns():
    server_module = _load_sinkhole_server()

    with patch("socket.getfqdn", side_effect=AssertionError("reverse DNS lookup attempted"), autospec=True,):
        server = server_module.NoReverseDNSThreadingHTTPServer(
            ("127.0.0.1", 0), server_module.ControlAPIHandler
        )
    try:
        assert server.server_address[0] == "127.0.0.1"
        assert server.server_name == "127.0.0.1"
        assert server.server_port == server.server_address[1]
    finally:
        server.server_close()


def test_sinkhole_observer_preserves_exact_body_bytes():
    payload = b"prefix\x00\xff\xfe\n\xe2\x28\xa1"
    captured = CapturedRequest(
        timestamp=1.0,
        host="binary.test",
        method="POST",
        path="/upload",
        headers={},
        body=payload,
        client_ip="127.0.0.1",
    )

    wire = captured.to_dict()

    assert wire["body"] == payload.decode("utf-8", errors="replace")
    assert wire["body_hex"] == payload.hex()
    assert wire["header_items"] == []


def test_sinkhole_client_decodes_exact_body_bytes_from_control_api():
    from tests.blackbox.host.sinkhole_client import SinkholeClient

    payload = b"\x00\xffnot-utf8\xe2\x28\xa1"
    response = Mock()
    response.json.return_value = {
        "requests": [
            {
                "timestamp": 1.0,
                "host": "binary.test",
                "method": "POST",
                "path": "/upload",
                "headers": {},
                "body": payload.decode("utf-8", errors="replace"),
                "body_hex": payload.hex(),
                "client_ip": "127.0.0.1",
            }
        ]
    }
    client = SinkholeClient("http://sinkhole.invalid:9999")
    try:
        with patch.object(client._client, "get", return_value=response):
            requests = client.get_requests()
    finally:
        client.close()

    assert len(requests) == 1
    assert requests[0].body_bytes == payload
    assert requests[0].header_items is None
    assert requests[0].body_complete is None
    assert requests[0].connection_accepted is None


def test_sinkhole_fixture_preserves_signed_target_and_query_order():
    server_module = _load_sinkhole_server()
    server_module.clear_requests()
    server = server_module.NoReverseDNSThreadingHTTPServer(
        ("127.0.0.1", 0), server_module.SinkholeHandler
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = "/signed;v=1?z=last&scope=read&scope=write%2Fitems&signature=abc%2B%2F%3D"
    client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        client.request("GET", target, headers={"Host": "signed.test"})
        response = client.getresponse()
        assert response.status == 200
        response.read()
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    requests = server_module.get_requests(host="signed.test")
    assert len(requests) == 1
    wire = requests[0].to_dict()
    assert wire["raw_target"] == target
    assert wire["raw_query"] == target.split("?", 1)[1]
    assert wire["path"] == "/signed"
    assert list(wire["query_params"]) == ["z", "scope", "signature"]
    assert wire["query_params"]["scope"] == ["read", "write/items"]


def test_sinkhole_fixture_preserves_ordered_duplicate_headers_and_reversal():
    server_module = _load_sinkhole_server()
    server_module.clear_requests()
    server = server_module.NoReverseDNSThreadingHTTPServer(
        ("127.0.0.1", 0), server_module.SinkholeHandler
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    header_orders = [
        [
            ("Host", "signed.test"),
            ("X-Duplicate", "first"),
            ("X-Middle", "middle"),
            ("x-duplicate", "second"),
        ],
        [
            ("Host", "signed.test"),
            ("x-duplicate", "second"),
            ("X-Middle", "middle"),
            ("X-Duplicate", "first"),
        ],
    ]
    target = "/signed?scope=read&scope=write%2Fitems"
    responses = []
    try:
        for header_lines in header_orders:
            request = (
                f"GET {target} HTTP/1.1\r\n"
                + "".join(f"{name}: {value}\r\n" for name, value in header_lines)
                + "Connection: close\r\n"
                + "\r\n"
            ).encode("ascii")
            with socket.create_connection(("127.0.0.1", server.server_port), timeout=5) as client:
                client.sendall(request)
                response = b""
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                responses.append(response)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert all(b"HTTP/1.0 200 OK" in response for response in responses)
    requests = server_module.get_requests(host="signed.test")
    assert len(requests) == 2
    assert requests[0].to_dict()["header_items"] == [
        ("Host", "signed.test"),
        ("X-Duplicate", "first"),
        ("X-Middle", "middle"),
        ("x-duplicate", "second"),
        ("Connection", "close"),
    ]
    assert requests[1].to_dict()["header_items"] == [
        ("Host", "signed.test"),
        ("x-duplicate", "second"),
        ("X-Middle", "middle"),
        ("X-Duplicate", "first"),
        ("Connection", "close"),
    ]


def test_sinkhole_fixture_distinguishes_partial_and_chunked_body_receipt():
    server_module = _load_sinkhole_server()
    server_module.clear_requests()
    server = server_module.NoReverseDNSThreadingHTTPServer(
        ("127.0.0.1", 0), server_module.SinkholeHandler
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    fixed_partial = (
        b"POST /partial-fixed HTTP/1.1\r\n"
        b"Host: partial.test\r\n"
        b"Content-Length: 10\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"abc"
    )
    chunked_complete = (
        b"POST /chunked-complete HTTP/1.1\r\n"
        b"Host: partial.test\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n"
    )
    chunked_partial = (
        b"POST /chunked-partial HTTP/1.1\r\n"
        b"Host: partial.test\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"3\r\nabc\r\n4\r\nde"
    )
    try:
        _send_raw_request(server.server_port, fixed_partial, shutdown_write=True)
        _send_raw_request(server.server_port, chunked_complete)
        _send_raw_request(server.server_port, chunked_partial, shutdown_write=True)
        # An accepted socket that closes before sending a request must not
        # become a fabricated empty request in the observer.
        with socket.create_connection(("127.0.0.1", server.server_port), timeout=5):
            pass
        time.sleep(0.05)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    requests = server_module.get_requests(host="partial.test")
    assert len(requests) == 3
    fixed, complete, partial = requests
    assert fixed.body == b"abc"
    assert fixed.body_expected_bytes == 10
    assert fixed.body_received_bytes == 3
    assert fixed.body_complete is False
    assert fixed.connection_accepted is True
    assert fixed.connection_closed is True
    assert complete.body == b"abcdefg"
    assert complete.body_expected_bytes is None
    assert complete.body_received_bytes == 7
    assert complete.body_complete is True
    assert complete.connection_accepted is True
    assert complete.connection_closed is False
    assert partial.body == b"abcde"
    assert partial.body_expected_bytes is None
    assert partial.body_received_bytes == 5
    assert partial.body_complete is False
    assert partial.connection_accepted is True
    assert partial.connection_closed is True


def test_sinkhole_fixture_preserves_double_slash_target_from_raw_request_line():
    server_module = _load_sinkhole_server()
    server_module.clear_requests()
    server = server_module.NoReverseDNSThreadingHTTPServer(
        ("127.0.0.1", 0), server_module.SinkholeHandler
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = "//signed/path?scope=read&scope=write%2Fitems&signature=abc%2B%2F%3D"
    request = (
        f"GET {target} HTTP/1.1\r\n"
        "Host: signed.test\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    try:
        with socket.create_connection(("127.0.0.1", server.server_port), timeout=5) as client:
            client.sendall(request)
            response = b""
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                response += chunk
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert b"HTTP/1.0 200 OK" in response
    requests = server_module.get_requests(host="signed.test")
    assert len(requests) == 1
    wire = requests[0].to_dict()
    assert wire["raw_target"] == target
    assert wire["raw_query"] == target.split("?", 1)[1]
    assert wire["path"] == "/signed/path"
    assert wire["query_params"]["scope"] == ["read", "write/items"]


def test_sinkhole_client_exposes_raw_target_and_query_from_control_api():
    from tests.blackbox.host.sinkhole_client import SinkholeClient

    target = "/signed?scope=read&scope=write%2Fitems&signature=abc%2B%2F%3D"
    response = Mock()
    response.json.return_value = {
        "requests": [
            {
                "timestamp": 1.0,
                "host": "signed.test",
                "method": "GET",
                "path": "/signed",
                "headers": {},
                "body": "",
                "body_hex": "",
                "raw_target": target,
                "raw_query": target.split("?", 1)[1],
                "header_items": [
                    ["Host", "signed.test"],
                    ["X-Signature", "first"],
                    ["X-Signature", "second"],
                ],
                "body_expected_bytes": 0,
                "body_received_bytes": 0,
                "body_complete": True,
                "connection_accepted": True,
                "connection_closed": False,
                "client_ip": "127.0.0.1",
                "query_params": {
                    "scope": ["read", "write/items"],
                    "signature": ["abc+/="],
                },
            }
        ]
    }
    client = SinkholeClient("http://sinkhole.invalid:9999")
    try:
        with patch.object(client._client, "get", return_value=response):
            requests = client.get_requests()
    finally:
        client.close()

    assert requests[0].raw_target == target
    assert requests[0].raw_query == "scope=read&scope=write%2Fitems&signature=abc%2B%2F%3D"
    assert requests[0].header_items == [
        ("Host", "signed.test"),
        ("X-Signature", "first"),
        ("X-Signature", "second"),
    ]
    assert requests[0].body_expected_bytes == 0
    assert requests[0].body_received_bytes == 0
    assert requests[0].body_complete is True
    assert requests[0].connection_accepted is True
    assert requests[0].connection_closed is False
