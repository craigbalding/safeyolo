"""Regression tests for the blackbox sinkhole server."""

import importlib.util
import sys
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
