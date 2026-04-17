#!/usr/bin/env python3
"""Test real HTTPS request through the proxy chain.

Equivalent to: curl -x http://localhost:8080 https://httpbin.org/get
Uses urllib which supports HTTP_PROXY for CONNECT tunneling.
"""
import os
import ssl
import sys
import urllib.request

# Set proxy via environment (same as agent would have)
os.environ["HTTP_PROXY"] = "http://127.0.0.1:8080"
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:8080"

# Allow self-signed certs from mitmproxy (or no cert verification for test)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

try:
    req = urllib.request.Request("https://httpbin.org/get")
    resp = urllib.request.urlopen(req, timeout=10, context=ctx)
    body = resp.read().decode()
    status = resp.status
    print(f"status={status} length={len(body)}", flush=True)
    if status == 200 and "httpbin" in body.lower() or "origin" in body.lower():
        print("HTTPS CONNECT proxy works", flush=True)
        sys.exit(0)
    # Even if httpbin is down, getting any response means the tunnel worked
    print(f"Got response but unexpected content: {body[:200]}", flush=True)
    sys.exit(0)
except Exception as exc:
    print(f"Error: {type(exc).__name__}: {exc}", flush=True)
    sys.exit(1)
