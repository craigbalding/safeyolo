"""Exercise the fixture's two operator-selected HTTP policy destinations."""

import json
from urllib.error import HTTPError
from urllib.request import urlopen

with urlopen("https://example.com", timeout=20) as response:
    assert response.status == 200, response.status
    print(json.dumps({"destination": "example.com", "status": response.status}))

try:
    with urlopen("https://denied.invalid", timeout=20):
        raise AssertionError("denied destination was reachable")
except HTTPError as error:
    assert error.code == 403 and error.headers.get("X-Blocked-By"), error.code
    print(json.dumps({"destination": "denied.invalid", "status": error.code,
                      "blocked_by": error.headers["X-Blocked-By"]}))
