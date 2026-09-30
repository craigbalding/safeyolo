"""Host checks against the installed native process shared with the guest lane."""

import http.client
import json
import os
import socket
from pathlib import Path

from installed_host_smoke import _agent_map, _probe_agent_health


def _request(
    socket_path: str, target: str, host: str, *, test_context: str
) -> tuple[int, bytes, str | None]:
    connection = http.client.HTTPConnection("fixture", timeout=5)
    connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.sock.settimeout(5)
    try:
        connection.sock.connect(socket_path)
        connection.request("GET", target, headers={
            "Host": host,
            "Connection": "close",
            "X-SafeYolo-Test-Context": test_context,
        })
        response = connection.getresponse()
        return response.status, response.read(), response.getheader("X-Blocked-By")
    finally:
        connection.close()


class TestInstalledNative:
    """The installed native listener serves real host requests during the guest run.

    Why: An isolation pass cannot name a native proxy if its host requests ran
    through a different process or never reached an origin.
    """

    def test_controlled_origin_and_protected_admin(self, sinkhole, clear_sinkhole):
        """The selected agent reaches an owned origin and cannot proxy to admin.

        What: Send one ordinary request to the controlled sinkhole, then one
        to the protected management listener through the same agent socket.
        Why: A response alone cannot show origin delivery or admin containment.
        """
        config_dir = Path(os.environ["SAFEYOLO_CONFIG_DIR"])
        agent = os.environ.get("SAFEYOLO_TEST_AGENT", "bbtest")
        test_context = f"run=installed-native;agent={agent}"
        listeners = {item["agent_id"]: item for item in _agent_map(config_dir)}
        listener = listeners[agent]
        assert _probe_agent_health(listener, config_dir)["status"] == 200

        marker = "/installed-native-origin-marker"
        target = f"http://httpbin.org{marker}"
        status, body, blocked_by = _request(
            listener["path"], target, "httpbin.org", test_context=test_context
        )
        assert (status, blocked_by) == (200, None)
        assert body == json.dumps({
            "received": True,
            "host": "httpbin.org",
            "method": "GET",
            "path": marker,
            "has_auth": False,
        }).encode()
        delivered = sinkhole.get_requests(host="httpbin.org")
        assert len(delivered) == 1
        assert delivered[0].path == marker

        native = json.loads((config_dir / "data" / "native.json").read_text())
        admin_port = native["admin_port"]
        denied, _, blocked_by = _request(
            listener["path"], f"http://127.0.0.1:{admin_port}/admin/instance",
            f"127.0.0.1:{admin_port}",
            test_context=test_context,
        )
        assert (denied, blocked_by) == (403, "admin-shield")
        assert len(sinkhole.get_requests(host="httpbin.org")) == 1
