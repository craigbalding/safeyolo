"""Exercise outbound policy and the inner container's actual network boundary."""

import json
import os
import socket
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

phase = os.environ.get("PROBE_PHASE", "build")
headers = {"X-SafeYolo-Trace": "1", "X-SafeYolo-Test-Context": f"run=nested-docker;step={phase}"}
with urlopen(Request("https://example.com", headers=headers), timeout=20) as response:
    assert response.status == 200, response.status
    print(json.dumps({"phase": phase, "destination": "example.com", "status": response.status,
                      "request_id": response.headers.get("X-SafeYolo-Request-Id")}))

try:
    # An HTTP URL exposes the proxy's denial response directly. urllib wraps
    # a refused HTTPS CONNECT in URLError and hides its response headers.
    with urlopen(Request("http://denied.invalid", headers=headers), timeout=20):
        raise AssertionError("denied destination was reachable")
except HTTPError as error:
    assert error.code == 403 and error.headers.get("X-Blocked-By"), error.code
    print(json.dumps({"phase": phase, "destination": "denied.invalid", "status": error.code,
                      "blocked_by": error.headers["X-Blocked-By"],
                      "request_id": error.headers.get("X-SafeYolo-Request-Id")}))

if phase in {"application", "privileged"}:
    interfaces = [line.split(":")[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()[2:]]
    assert interfaces == ["lo"], interfaces
    print(json.dumps({"interfaces": interfaces, "network_mode": "host"}))
    print(json.dumps({"uid": os.getuid(), "process_status": Path("/proc/self/status").read_text()}))
    assert not Path(os.environ["PROBE_HOST_FILE"]).exists(), "unshared host file was visible"
    print(json.dumps({"unshared_host_file": "absent"}))
    for label, address in (("direct_external", ("1.1.1.1", 443)),
                           ("unapproved_host", (os.environ["PROBE_HOST"], int(os.environ["PROBE_HOST_PORT"])))):
        try:
            with socket.create_connection(address, timeout=2):
                raise AssertionError(f"{label} was reachable")
        except OSError as error:
            print(json.dumps({"attempt": label, "address": address, "error": type(error).__name__}))
