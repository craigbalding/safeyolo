#!/usr/bin/env python3
"""Phase 4 test: HTTP request through localhost:8080 -> UDS -> host bridge."""
import http.client
import sys

try:
    conn = http.client.HTTPConnection("127.0.0.1", 8080, timeout=5)
    conn.request("GET", "/test")
    resp = conn.getresponse()
    body = resp.read().decode()
    print(f"status={resp.status} body={body.strip()}", flush=True)
    conn.close()
    if resp.status == 200 and "HELLO_PROXY" in body:
        sys.exit(0)
    sys.exit(1)
except Exception as exc:
    print(f"Error: {type(exc).__name__}: {exc}", flush=True)
    sys.exit(1)
