"""
client.py - PolicyClient interface for sensors

This module provides the abstraction between sensors and PDP.
Sensors use PolicyClient.evaluate() without knowing whether
PDP runs in-process or as a separate service.

Implementations:
- LocalPolicyClient: Direct call to pdp/core.py (default, fastest)
- HttpPolicyClient: HTTP call to FastAPI service (for split-process mode)

Design:
- Fail closed by default (timeout/error -> DENY)
- Sensors own failure mode logic
- Single httpx client reused with keep-alive
- Semaphore for backpressure (max_inflight)

Usage:
    from pdp.client import get_policy_client, PolicyClientConfig

    # Default: local (in-process)
    client = get_policy_client()
    decision = client.evaluate(http_event)

    # Remote: HTTP to PDP service
    client = get_policy_client(PolicyClientConfig(
        mode="http",
        endpoint="http://127.0.0.1:8080",
    ))
    decision = client.evaluate(http_event)
"""

import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Literal

from .schemas import (
    DecisionEventBlock,
    Effect,
    HttpEvent,
    ImmediateResponseBlock,
    PolicyDecision,
)

log = logging.getLogger("safeyolo.pdp.client")


class UnavailableMode(str, Enum):
    """What to do when PDP is unavailable."""
    DENY = "deny"   # Fail closed (default, recommended)
    ALLOW = "allow"  # Fail open (dangerous, dev only)
    # CACHED = "cached"  # Use cached decision (future)


@dataclass
class PolicyClientConfig:
    """Configuration for PolicyClient."""
    # Mode: "local" (in-process) or "http" (remote service)
    mode: Literal["local", "http"] = "local"

    # For local mode: paths to policy files
    baseline_path: Path | None = None
    budget_state_path: Path | None = None

    # For http mode: PDP service endpoint
    endpoint: str = "http://127.0.0.1:8080"
    timeout_ms: int = 500
    max_inflight: int = 256

    # Failure handling (applies to http mode)
    unavailable_mode: UnavailableMode = UnavailableMode.DENY

    # Retry settings (minimal for v1)
    retry_attempts: int = 0  # Default: no retries (avoid retry storms)


class PolicyClient(ABC):
    """Abstract interface for policy evaluation.

    Sensors depend on this interface, not concrete implementations.

    Main contract:
        evaluate(HttpEvent) -> PolicyDecision

    The evaluate() method is THE policy query path. All policy decisions
    should flow through it. Other methods (health_check, is_addon_enabled)
    are operational/compatibility helpers, not a second policy API.
    """

    @abstractmethod
    def evaluate(self, event: HttpEvent) -> PolicyDecision:
        """Evaluate an HTTP event and return policy decision.

        This is synchronous - sensors call this blocking.
        Implementations may be async internally.

        Args:
            event: The HTTP event to evaluate

        Returns:
            PolicyDecision with effect and metadata

        Note:
            Implementations must handle errors internally and return
            a valid PolicyDecision (typically DENY on error).
        """
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Check if PDP is healthy.

        Returns:
            True if PDP is operational
        """
        pass

    @abstractmethod
    def shutdown(self) -> None:
        """Graceful shutdown - cleanup resources."""
        pass

    @abstractmethod
    def is_addon_enabled(
        self,
        addon_name: str,
        domain: str | None = None,
        client_id: str | None = None,
    ) -> bool:
        """Check if addon is enabled for the given context.

        NOTE: This is a temporary compatibility hook for the PDP migration.
        The main contract is evaluate(HttpEvent) -> PolicyDecision.

        TODO: Consider folding this into evaluate() by having addons check
        the PolicyDecision for an "addon_disabled" reason code, rather than
        maintaining two separate policy query paths.

        Args:
            addon_name: Name of addon to check
            domain: Request domain (optional)
            client_id: Client identifier (optional)

        Returns:
            True if addon should process this request
        """
        pass

    @abstractmethod
    def get_stats(self) -> dict:
        """Get PDP statistics.

        Returns:
            Dict with engine stats (policy hash, evaluation counts, etc.)
        """
        pass

    @abstractmethod
    def get_sensor_config(self) -> dict:
        """Get sensor configuration: credential rules and scan patterns.

        Returns configuration for sensors/addons:
        - credential_rules: For credential detection and routing
        - scan_patterns: For content scanning
        - policy_hash: For cache invalidation

        Returns:
            Dict with credential_rules, scan_patterns, and policy_hash
        """
        pass


class LocalPolicyClient(PolicyClient):
    """
    In-process policy client - calls PDPCore directly.

    This is the default and fastest option. No network overhead.
    Use this for development and when PDP runs in same process as sensor.
    """

    def __init__(self, config: PolicyClientConfig):
        from .core import PDPCore

        self._pdp = PDPCore(
            baseline_path=config.baseline_path,
            budget_state_path=config.budget_state_path,
        )
        log.info("LocalPolicyClient initialized")

    def evaluate(self, event: HttpEvent) -> PolicyDecision:
        """Evaluate event using in-process PDPCore."""
        try:
            return self._pdp.evaluate(event)
        except Exception as e:
            log.error(f"LocalPolicyClient error: {type(e).__name__}: {e}")
            # Even local errors should fail closed
            return self._error_decision(event.event.event_id, str(e))

    def health_check(self) -> bool:
        """Local PDP is always healthy if initialized."""
        return True

    def shutdown(self) -> None:
        """Shutdown PDPCore."""
        self._pdp.shutdown()

    def is_addon_enabled(
        self,
        addon_name: str,
        domain: str | None = None,
        client_id: str | None = None,
    ) -> bool:
        """Check if addon is enabled via PDPCore."""
        return self._pdp.is_addon_enabled(addon_name, domain, client_id)

    def get_stats(self) -> dict:
        """Get PDP statistics."""
        return self._pdp.get_stats()

    def get_sensor_config(self) -> dict:
        """Get sensor configuration from PDPCore."""
        return self._pdp.get_sensor_config()

    def _error_decision(self, event_id: str, error: str) -> PolicyDecision:
        """Create error decision for internal failures."""
        return PolicyDecision(
            version=1,
            event=DecisionEventBlock(
                event_id=event_id,
                policy_hash="error",
                engine_version="pdp-error",
            ),
            effect=Effect.ERROR,
            reason=f"PDP internal error: {error}",
            reason_codes=["PDP_ERROR", "INTERNAL_ERROR"],
            immediate_response=ImmediateResponseBlock(
                status_code=500,
                headers={"content-type": "application/json"},
                body_json={
                    "error": "Internal Server Error",
                    "event_id": event_id,
                    "reason": "PDP evaluation failed",
                },
            ),
        )


class HttpPolicyClient(PolicyClient):
    """
    HTTP-based policy client - calls PDP via REST API.

    Use this when PDP runs as a separate service (different container/process).
    Includes:
    - Connection pooling (keep-alive)
    - Backpressure (semaphore)
    - Fail-closed logic
    - Timeouts
    """

    def __init__(self, config: PolicyClientConfig):
        try:
            import httpx
        except ImportError:
            raise ImportError(
                "httpx is required for HttpPolicyClient. "
                "Install with: pip install httpx"
            )

        self._config = config
        self._endpoint = config.endpoint.rstrip("/")
        self._timeout = config.timeout_ms / 1000.0
        self._unavailable_mode = config.unavailable_mode

        # Single client with connection pooling
        self._client = httpx.Client(
            base_url=self._endpoint,
            timeout=httpx.Timeout(self._timeout),
            limits=httpx.Limits(
                max_keepalive_connections=20,
                max_connections=config.max_inflight,
            ),
        )

        # Semaphore for backpressure
        self._semaphore = threading.Semaphore(config.max_inflight)

        log.info(
            "HttpPolicyClient initialized",
            extra={
                "endpoint": self._endpoint,
                "timeout_ms": config.timeout_ms,
                "max_inflight": config.max_inflight,
            }
        )

    def evaluate(self, event: HttpEvent) -> PolicyDecision:
        """Evaluate event via HTTP call to PDP service."""
        event_id = event.event.event_id

        # Backpressure: block if too many in-flight
        acquired = self._semaphore.acquire(timeout=self._timeout)
        if not acquired:
            log.warning("HttpPolicyClient backpressure: semaphore timeout")
            return self._unavailable_decision(event_id, "backpressure")

        try:
            return self._do_evaluate(event)
        finally:
            self._semaphore.release()

    def _do_evaluate(self, event: HttpEvent) -> PolicyDecision:
        """Actual HTTP call with error handling."""
        import httpx

        event_id = event.event.event_id

        try:
            response = self._client.post(
                "/v1/evaluate",
                json=event.model_dump(mode="json"),
            )

            if response.status_code == 200:
                return PolicyDecision.model_validate(response.json())

            # 4xx = client error (schema issue)
            if 400 <= response.status_code < 500:
                log.error(
                    f"PDP client error: {response.status_code}",
                    extra={"event_id": event_id, "body": response.text[:500]},
                )
                return self._error_decision(event_id, f"PDP rejected request: {response.status_code}")

            # 5xx = server error
            log.error(
                f"PDP server error: {response.status_code}",
                extra={"event_id": event_id},
            )
            return self._unavailable_decision(event_id, f"PDP error: {response.status_code}")

        except httpx.TimeoutException:
            log.warning("PDP timeout", extra={"event_id": event_id})
            return self._unavailable_decision(event_id, "timeout")

        except httpx.ConnectError as e:
            log.warning(f"PDP connection error: {type(e).__name__}", extra={"event_id": event_id})
            return self._unavailable_decision(event_id, "connection_error")

        except Exception as e:
            log.error(f"PDP unexpected error: {type(e).__name__}: {e}", extra={"event_id": event_id})
            return self._unavailable_decision(event_id, str(e))

    def health_check(self) -> bool:
        """Check PDP health endpoint."""

        try:
            response = self._client.get("/health", timeout=1.0)
            return response.status_code == 200
        except Exception:
            return False

    def shutdown(self) -> None:
        """Close HTTP client."""
        self._client.close()
        log.info("HttpPolicyClient shutdown")

    def is_addon_enabled(
        self,
        addon_name: str,
        domain: str | None = None,
        client_id: str | None = None,
    ) -> bool:
        """Check if addon is enabled.

        Not implemented for HTTP mode - requires /v1/addons/enabled endpoint.

        Raises:
            NotImplementedError: Always. HTTP mode doesn't support this yet.
                If you need addon bypass in split-process mode, either:
                1. Add GET /v1/addons/enabled endpoint to pdp/app.py
                2. Use local mode (PolicyClientConfig(mode="local"))
        """
        raise NotImplementedError(
            "is_addon_enabled() not supported in HTTP mode. "
            "Use local mode or implement /v1/addons/enabled endpoint."
        )

    def get_stats(self) -> dict:
        """Get PDP statistics via HTTP.

        Not implemented for HTTP mode - would require /v1/stats endpoint.
        Returns empty dict for compatibility.
        """
        # TODO: Implement /v1/stats endpoint in pdp/app.py
        return {}

    def get_sensor_config(self) -> dict:
        """Get sensor configuration via HTTP.

        Calls GET /v1/sensor_config endpoint.

        Returns:
            Dict with credential_rules, scan_patterns, and policy_hash
        """
        import httpx

        try:
            response = self._client.get("/v1/sensor_config", timeout=2.0)
            if response.status_code == 200:
                return response.json()
            log.warning(f"get_sensor_config failed: {response.status_code}")
            return {"credential_rules": [], "scan_patterns": [], "policy_hash": "error"}
        except httpx.TimeoutException:
            log.warning("get_sensor_config timeout")
            return {"credential_rules": [], "scan_patterns": [], "policy_hash": "timeout"}
        except Exception as e:
            log.warning(f"get_sensor_config error: {type(e).__name__}: {e}")
            return {"credential_rules": [], "scan_patterns": [], "policy_hash": "error"}

    def _unavailable_decision(self, event_id: str, reason: str) -> PolicyDecision:
        """Create decision when PDP is unavailable.

        Applies unavailable_mode: deny (default) or allow.
        """
        if self._unavailable_mode == UnavailableMode.ALLOW:
            log.warning("PDP unavailable, failing OPEN (dangerous)", extra={"event_id": event_id})
            return PolicyDecision(
                version=1,
                event=DecisionEventBlock(
                    event_id=event_id,
                    policy_hash="unavailable",
                    engine_version="pdp-fallback",
                ),
                effect=Effect.ALLOW,
                reason=f"PDP unavailable, fail-open mode: {reason}",
                reason_codes=["PDP_UNAVAILABLE", "FAIL_OPEN"],
            )

        # Default: fail closed (DENY)
        log.warning("PDP unavailable, failing CLOSED", extra={"event_id": event_id, "reason": reason})
        return PolicyDecision(
            version=1,
            event=DecisionEventBlock(
                event_id=event_id,
                policy_hash="unavailable",
                engine_version="pdp-fallback",
            ),
            effect=Effect.DENY,
            reason=f"PDP unavailable: {reason}",
            reason_codes=["PDP_UNAVAILABLE", "FAIL_CLOSED"],
            immediate_response=ImmediateResponseBlock(
                status_code=503,
                headers={"content-type": "application/json"},
                body_json={
                    "error": "Service Unavailable",
                    "event_id": event_id,
                    "reason": "Policy service unavailable",
                },
            ),
        )

    def _error_decision(self, event_id: str, error: str) -> PolicyDecision:
        """Create DENY decision for client/schema errors."""
        return PolicyDecision(
            version=1,
            event=DecisionEventBlock(
                event_id=event_id,
                policy_hash="error",
                engine_version="pdp-error",
            ),
            effect=Effect.DENY,
            reason=f"PDP error: {error}",
            reason_codes=["PDP_ERROR"],
            immediate_response=ImmediateResponseBlock(
                status_code=500,
                headers={"content-type": "application/json"},
                body_json={
                    "error": "Internal Server Error",
                    "event_id": event_id,
                    "reason": error,
                },
            ),
        )


# =============================================================================
# Registry API
# =============================================================================

_client_instance: PolicyClient | None = None
_client_lock = threading.Lock()


def configure_policy_client(config: PolicyClientConfig) -> None:
    """
    Configure the global PolicyClient singleton.

    Must be called before get_policy_client(). In mitmproxy context,
    the policy_engine addon calls this during load/configure.

    Args:
        config: Client configuration with paths and mode.

    Raises:
        RuntimeError: If client already configured with different config.
    """
    global _client_instance

    with _client_lock:
        if _client_instance is not None:
            # Already configured - check if config changed
            if getattr(_client_instance, "_config", None) == config:
                return  # Same config, no-op
            # Config changed - need reconfigure
            log.info("PolicyClient reconfiguring with new config")
            _client_instance.shutdown()
            _client_instance = None

        if config.mode == "http":
            _client_instance = HttpPolicyClient(config)
        else:
            _client_instance = LocalPolicyClient(config)
        _client_instance._config = config

        log.info(
            "PolicyClient configured",
            extra={
                "mode": config.mode,
                "baseline_path": str(config.baseline_path) if config.baseline_path else None,
            }
        )


def get_policy_client() -> PolicyClient:
    """
    Get the configured PolicyClient singleton.

    Fails closed if not configured - this prevents silent feature loss
    from using an unconfigured/empty policy.

    Returns:
        PolicyClient instance

    Raises:
        RuntimeError: If configure_policy_client() was not called first.
    """
    with _client_lock:
        if _client_instance is None:
            raise RuntimeError(
                "PolicyClient not configured. "
                "Ensure policy_engine addon is loaded before other addons."
            )
        return _client_instance


def is_policy_client_configured() -> bool:
    """Check if PolicyClient has been configured."""
    with _client_lock:
        return _client_instance is not None


def reset_policy_client() -> None:
    """Reset the global client (for testing only)."""
    global _client_instance
    with _client_lock:
        if _client_instance:
            _client_instance.shutdown()
        _client_instance = None
