"""Regression tests for the blackbox sinkhole server."""

import http.client
import importlib.util
import socket
import sys
import threading
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
