#!/usr/bin/env python3
"""Phase 1 test: connect to host UDS from inside gVisor container."""
import socket
import sys

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect("/safeyolo/proxy.sock")
    s.sendall(b"HELLO_FROM_GVISOR")
    reply = s.recv(100)
    print(f"Reply: {reply.decode()}", flush=True)
    s.close()
    if b"ECHO:HELLO_FROM_GVISOR" in reply:
        sys.exit(0)
    sys.exit(1)
except Exception as exc:
    print(f"Error: {type(exc).__name__}: {exc}", flush=True)
    sys.exit(1)
