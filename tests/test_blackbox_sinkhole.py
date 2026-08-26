"""Regression tests for the blackbox sinkhole server."""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch


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
