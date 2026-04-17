#!/usr/bin/env python3
"""Phase 5 test: verify container CANNOT reach external IPs."""
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(("1.1.1.1", 80))
    print("CONNECTED (bad!)", flush=True)
    s.close()
    sys.exit(1)  # should not succeed
except (TimeoutError, OSError) as exc:
    print(f"Blocked: {type(exc).__name__}: {exc}", flush=True)
    sys.exit(0)  # expected
