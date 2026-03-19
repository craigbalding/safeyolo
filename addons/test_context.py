"""
test_context.py - Link HTTP traffic to test activities

Activates for operator-declared test target hosts. Requires requests
to those hosts to include an X-Test-Context header linking the request
to a specific test run, agent, and test case. Logs request/response pairs
with full context for post-analysis.

Requests to non-target hosts pass through untouched.

Design:
- Active when target_hosts is non-empty in policy.yaml (no separate enable flag)
- Soft-reject (428) for missing/malformed context headers on target hosts
- Logs structured events for request and response with parsed context
- Body capture: first 4KB head + tail lines for truncated bodies

Usage:
    mitmdump -s addons/test_context.py --set test_context_block=true
"""

import logging
import re
import time

from base import SecurityAddon
from mitmproxy import http
from utils import matches_host_pattern, write_event

from pdp import get_policy_client

log = logging.getLogger("safeyolo.test-context")

CONTEXT_HEADER = "X-Test-Context"
REQUIRED_KEYS = {"run", "agent"}
_SAFE_VALUE = re.compile(r"^[a-zA-Z0-9_\-.:]+$")
_MAX_CONTEXT_PAIRS = 20


def _parse_context_header(value: str) -> dict | None:
    """Parse X-Test-Context header value into a dict.

    Format: semicolon-delimited key=value pairs.
    Example: "run=sec1;agent=idor;test=IDOR-003"

    Returns None if malformed or missing required keys.
    """
    if not value or not value.strip():
        return None

    result = {}
    for part in value.split(";")[:_MAX_CONTEXT_PAIRS]:
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            return None
        key, _, val = part.partition("=")
        key = key.strip()
        val = val.strip()
        if not key or not val:
            return None
        if not _SAFE_VALUE.match(key) or not _SAFE_VALUE.match(val):
            return None
        result[key] = val

    if not result:
        return None

    # Check required keys
    if not REQUIRED_KEYS.issubset(result.keys()):
        return None

    return result


def _capture_body(content: bytes, max_head: int = 4096, tail_lines: int = 5) -> str:
    """Capture body content with truncation for large bodies.

    Returns first max_head bytes as string, plus tail lines if truncated.
    """
    if not content:
        return ""

    total_size = len(content)
    text = content[:max_head].decode("utf-8", errors="replace")

    if total_size <= max_head:
        return text

    # Decode only the last 8KB for tail extraction (not the entire body)
    tail_chunk = content[-8192:]
    tail_text = tail_chunk.decode("utf-8", errors="replace")
    lines = tail_text.rstrip("\n").split("\n")
    tail = "\n".join(lines[-tail_lines:]) if len(lines) > tail_lines else ""

    result = text + f"\n...[truncated, {total_size} bytes total]...\n"
    if tail:
        result += tail

    return result


class TestContext(SecurityAddon):
    """Link test HTTP traffic to test activities via X-Test-Context header."""

    name = "test-context"

    def __init__(self):
        super().__init__()
        self._target_hosts: list[str] = []
        self._last_policy_hash: str = ""

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="test_context_block",
            typespec=bool,
            default=True,
            help="Block (428) requests to target hosts missing context header",
        )

    def _maybe_reload_config(self):
        """Reload target_hosts from PDP if policy changed."""
        try:
            client = get_policy_client()
            sensor_config = client.get_sensor_config()
            policy_hash = sensor_config.get("policy_hash", "")

            if policy_hash != self._last_policy_hash:
                pc_config = sensor_config.get("addons", {}).get("test_context", {})
                self._target_hosts = pc_config.get("target_hosts", [])
                self._last_policy_hash = policy_hash
                if self._target_hosts:
                    log.info(f"Loaded {len(self._target_hosts)} test target hosts")
        except RuntimeError:
            # PolicyClient not configured yet
            pass
        except Exception as exc:
            log.warning(f"Failed to reload test context config: {type(exc).__name__}: {exc}")

    def _is_target_host(self, host: str) -> bool:
        """Check if host matches any configured target host pattern."""
        for pattern in self._target_hosts:
            if matches_host_pattern(host, pattern):
                return True
        return False

    def request(self, flow: http.HTTPFlow):
        """Check requests to target hosts for context header.

        Active when target_hosts is non-empty in policy.yaml.
        No separate enable flag - add target hosts to activate, remove to deactivate.
        """
        if flow.response:
            return

        self._maybe_reload_config()

        if not self._target_hosts:
            return

        # Not a target host -> pass through
        if not self._is_target_host(flow.request.host):
            return

        self.stats.checks += 1

        # Parse context header
        header_value = flow.request.headers.get(CONTEXT_HEADER, "")
        context = _parse_context_header(header_value)

        if context is None:
            # Missing or malformed context
            reason = "missing_context" if not header_value else "malformed_context"

            if self.should_block():
                self.log_decision(
                    flow,
                    "block",
                    reason=reason,
                    host=flow.request.host,
                    path=flow.request.path,
                    method=flow.request.method,
                )
                body = {
                    "error": "Test context required",
                    "type": reason,
                    "destination": flow.request.host,
                    "action": "add_header",
                    "header": CONTEXT_HEADER,
                    "format": "run=<run_id>;agent=<agent_id>;test=<test_id>",
                    "example": f"{CONTEXT_HEADER}: run=sec1;agent=idor;test=IDOR-003",
                    "reflection": f"Add {CONTEXT_HEADER} header to link this request to your test activity.",
                }
                self.block(flow, 428, body)
            else:
                self.log_decision(
                    flow,
                    "warn",
                    reason=reason,
                    host=flow.request.host,
                    path=flow.request.path,
                    method=flow.request.method,
                )
                self.warn(flow)
            return

        # Valid context - store for response() and log, then strip before sending
        flow.metadata["ccapt_context"] = context
        flow.metadata["ccapt_request_time"] = time.time()
        del flow.request.headers[CONTEXT_HEADER]

        request_body = _capture_body(flow.request.content or b"")

        write_event(
            "security.test_context",
            request_id=flow.metadata.get("request_id"),
            addon=self.name,
            phase="request",
            method=flow.request.method,
            host=flow.request.host,
            path=flow.request.path,
            context=context,
            request_body_snippet=request_body[:512] if request_body else "",
        )

        self.stats.allowed += 1

    def response(self, flow: http.HTTPFlow):
        """Log response for requests that had valid context."""
        context = flow.metadata.get("ccapt_context")
        if context is None:
            return

        request_time = flow.metadata.get("ccapt_request_time", 0)
        duration_ms = int((time.time() - request_time) * 1000) if request_time else 0

        response_body = _capture_body(flow.response.content or b"") if flow.response else ""

        write_event(
            "security.test_context",
            request_id=flow.metadata.get("request_id"),
            addon=self.name,
            phase="response",
            method=flow.request.method,
            host=flow.request.host,
            path=flow.request.path,
            context=context,
            status_code=flow.response.status_code if flow.response else 0,
            response_body_snippet=response_body[:512] if response_body else "",
            duration_ms=duration_ms,
        )

    def get_stats(self) -> dict:
        """Return stats for admin API."""
        return {
            "active": len(self._target_hosts) > 0,
            "target_hosts": len(self._target_hosts),
            "checks_total": self.stats.checks,
            "allowed_total": self.stats.allowed,
            "blocked_total": self.stats.blocked,
            "warned_total": self.stats.warned,
        }


addons = [TestContext()]
