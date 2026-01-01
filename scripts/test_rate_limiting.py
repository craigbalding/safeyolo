#!/usr/bin/env python3
"""
test_rate_limiting.py - Integration test for rate limiting

Verifies that rate limiting is working by:
1. Checking rate limiter stats via admin API
2. Making rapid requests to a test domain
3. Verifying that rate limiting warnings/blocks occur

Run from within SafeYolo container:
    python /app/scripts/test_rate_limiting.py

Or from host:
    docker exec safeyolo python /app/scripts/test_rate_limiting.py
"""

import json
import ssl
import time
import urllib.request
import urllib.error
import sys

# Path to mitmproxy CA cert (inside container)
CA_CERT_PATH = "/certs/mitmproxy-ca-cert.pem"


def get_ssl_context() -> ssl.SSLContext:
    """Create SSL context that trusts mitmproxy CA."""
    ctx = ssl.create_default_context()
    try:
        ctx.load_verify_locations(CA_CERT_PATH)
    except Exception as e:
        print(f"WARN: Could not load CA cert from {CA_CERT_PATH}: {e}")
        print("      Falling back to unverified SSL (for testing only)")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def get_stats() -> dict:
    """Fetch stats from admin API."""
    try:
        with urllib.request.urlopen("http://localhost:9090/stats", timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        print(f"ERROR: Cannot connect to admin API: {type(e).__name__}: {e}")
        return {}


def make_request(url: str, proxy: str = "http://localhost:8080") -> tuple[int, str]:
    """Make a request through the proxy. Returns (status_code, error_or_empty)."""
    proxy_handler = urllib.request.ProxyHandler({
        'http': proxy,
        'https': proxy,
    })
    https_handler = urllib.request.HTTPSHandler(context=get_ssl_context())
    opener = urllib.request.build_opener(proxy_handler, https_handler)

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "rate-limit-test"})
        with opener.open(req, timeout=10) as resp:
            return resp.status, ""
    except urllib.error.HTTPError as e:
        return e.code, str(e)
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"


def main():
    print("=" * 60)
    print("SafeYolo Rate Limiter Integration Test")
    print("=" * 60)

    # 1. Check if rate limiter is discovered by admin API
    print("\n[1] Checking admin API stats...")
    stats = get_stats()
    if not stats:
        print("FAIL: Cannot get stats from admin API")
        sys.exit(1)

    print(f"    Proxy: {stats.get('proxy', 'unknown')}")
    print(f"    Discovered addons: {list(stats.keys())}")

    if "rate-limiter" not in stats:
        print("FAIL: rate-limiter addon not discovered!")
        print("    Check that rate_limiter.py is loaded in start-safeyolo.sh")
        sys.exit(1)

    rl_stats = stats["rate-limiter"]
    print(f"\n    Rate limiter config:")
    print(f"      enabled: {rl_stats.get('enabled')}")
    print(f"      default_rps: {rl_stats.get('default_rps')}")
    print(f"      default_burst: {rl_stats.get('default_burst')}")
    print(f"      configured_domains: {rl_stats.get('configured_domains', [])}")
    print(f"      checks_total: {rl_stats.get('checks_total')}")
    print(f"      limited_total: {rl_stats.get('limited_total')}")

    # 2. Make rapid requests to test domain
    test_domain = "cloudsecurity.org"
    test_url = f"http://{test_domain}/"

    print(f"\n[2] Testing rate limiting against {test_domain}...")

    # Get initial stats
    initial_checks = rl_stats.get('checks_total', 0)
    initial_limited = rl_stats.get('limited_total', 0)

    # Make rapid requests
    num_requests = 10
    results = []
    for i in range(num_requests):
        status, err = make_request(test_url)
        results.append((status, err))
        print(f"    Request {i+1}: status={status}" + (f" error={err}" if err else ""))
        # No delay - we want rapid requests

    # 3. Check stats after
    print(f"\n[3] Checking stats after {num_requests} requests...")
    stats_after = get_stats()

    if "rate-limiter" not in stats_after:
        print("FAIL: rate-limiter stats unavailable after test")
        sys.exit(1)

    rl_after = stats_after["rate-limiter"]
    final_checks = rl_after.get('checks_total', 0)
    final_limited = rl_after.get('limited_total', 0)

    new_checks = final_checks - initial_checks
    new_limited = final_limited - initial_limited

    print(f"    New checks: {new_checks}")
    print(f"    New limited: {new_limited}")

    # 4. Analyze results
    print(f"\n[4] Analysis:")

    # Check if requests went through the proxy
    if new_checks == 0:
        print("    FAIL: No requests were checked by rate limiter!")
        print("    Possible causes:")
        print("      - Requests not going through proxy (check proxy settings)")
        print("      - rate_limiter addon not loaded correctly")
        print("      - Domain not matching in config")
        sys.exit(1)

    print(f"    OK: Rate limiter checked {new_checks} requests")

    # Check if rate limiting triggered
    if new_limited == 0:
        print("    WARN: No requests were rate-limited")
        print("    This could mean:")
        print("      - Burst capacity is too high for test")
        print("      - Domain has high rate limit configured")

        # Check config for test domain
        configured = rl_after.get('configured_domains', [])
        if test_domain not in configured and f"*.{test_domain}" not in configured:
            print(f"    NOTE: {test_domain} is not in configured domains, using default limits")
            print(f"          default_rps={rl_after.get('default_rps')}, default_burst={rl_after.get('default_burst')}")
    else:
        print(f"    OK: Rate limiter triggered {new_limited} times")

    # Check for 429 responses (if blocking is enabled)
    blocked_count = sum(1 for status, _ in results if status == 429)
    if blocked_count > 0:
        print(f"    OK: {blocked_count} requests were blocked with 429")
    else:
        print("    NOTE: No 429 responses (blocking may be disabled - warn-only mode)")

    print("\n" + "=" * 60)
    if new_checks > 0 and (new_limited > 0 or blocked_count > 0):
        print("PASS: Rate limiting is working!")
    elif new_checks > 0:
        print("PARTIAL: Requests go through limiter, but no limits triggered")
        print("         Increase request count or lower burst limit to verify blocking")
    else:
        print("FAIL: Rate limiting is not working")
    print("=" * 60)


if __name__ == "__main__":
    main()
