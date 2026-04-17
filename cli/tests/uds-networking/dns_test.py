#!/usr/bin/env python3
"""Phase 5 test: verify container CANNOT resolve DNS."""
import socket
import sys

try:
    socket.setdefaulttimeout(2)
    socket.getaddrinfo("google.com", 80)
    print("DNS resolved (bad!)", flush=True)
    sys.exit(1)
except (TimeoutError, OSError, socket.gaierror) as exc:
    print(f"DNS blocked: {type(exc).__name__}: {exc}", flush=True)
    sys.exit(0)
