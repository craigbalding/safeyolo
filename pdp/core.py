"""
core.py - PDP Core Library (pure Python, no FastAPI)

This module provides the Policy Decision Point logic as a library.
FastAPI (app.py) is just a thin adapter over this.

Design:
- Pure Python, no web framework dependencies
- Wraps existing PolicyEngine
- Translates HttpEvent -> PolicyEngine calls -> PolicyDecision
- Atomic budget check+consume
- Task policy management

Usage (in-process):
    from pdp.core import PDPCore

    pdp = PDPCore()
    decision = pdp.evaluate(http_event)

Usage (via FastAPI):
    See app.py - it just calls PDPCore methods
"""

import hashlib
import logging
import sys
import threading
from pathlib import Path

# Import existing policy engine components
# Note: When running as standalone service, these need to be on PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent.parent / "addons"))
from policy_engine import PolicyDecision as LegacyDecision
from policy_engine import PolicyEngine, UnifiedPolicy

from .schemas import (
    BudgetBlock,
    ChecksBlock,
    DecisionEventBlock,
    Effect,
    HttpEvent,
    ImmediateResponseBlock,
    PolicyDecision,
)

log = logging.getLogger("safeyolo.pdp.core")

# Engine version for provenance
ENGINE_VERSION = "pdp-0.1.0"


def _sanitize_for_log(value):
    """Sanitize user-controlled values before logging to prevent log injection.

    Strips CR/LF characters from strings to prevent log line injection.
    Non-string values are returned unchanged.
    """
    if value is None:
        return value
    if isinstance(value, str):
        return value.replace("\r", "").replace("\n", "")
    return value


class PDPCore:
    """
    Policy Decision Point core library.

    Wraps PolicyEngine and provides the canonical evaluate() interface.
    Thread-safe for concurrent evaluation.
    """

    def __init__(
        self,
        baseline_path: Path | str | None = None,
        budget_state_path: Path | str | None = None,
    ):
        """Initialize PDP with policy paths.

        Args:
            baseline_path: Path to baseline policy YAML (enables file watching)
            budget_state_path: Path to budget state JSON (enables persistence)
        """
        # Ensure paths are Path objects
        if baseline_path is not None and not isinstance(baseline_path, Path):
            baseline_path = Path(baseline_path)
        if budget_state_path is not None and not isinstance(budget_state_path, Path):
            budget_state_path = Path(budget_state_path)

        self._engine = PolicyEngine(
            baseline_path=baseline_path,
            budget_state_path=budget_state_path,
        )
        self._lock = threading.RLock()
        self._task_policies: dict[str, dict] = {}  # task_id -> policy_data

        log.info(
            "PDPCore initialized",
            extra={
                "baseline_path": str(baseline_path) if baseline_path else None,
                "budget_state_path": str(budget_state_path) if budget_state_path else None,
            }
        )

    @property
    def policy_hash(self) -> str:
        """Compute hash of current policy for cache invalidation."""
        baseline = self._engine.get_baseline()
        task = self._engine.get_task_policy()

        # Simple hash of policy content
        content = ""
        if baseline:
            content += baseline.model_dump_json()
        if task:
            content += task.model_dump_json()

        return f"sha256:{hashlib.sha256(content.encode()).hexdigest()[:16]}"

    def evaluate(self, event: HttpEvent) -> PolicyDecision:
        """
        Evaluate an HTTP event against policy.

        This is the primary entry point. It:
        1. Determines what checks are needed
        2. Evaluates credential policy (if credential detected)
        3. Evaluates network policy (rate limiting)
        4. Returns atomic decision with budget already consumed

        Args:
            event: The HTTP event to evaluate

        Returns:
            PolicyDecision with effect and all relevant metadata
        """
        event_id = event.event.event_id
        policy_hash = self.policy_hash

        safe_event_id = _sanitize_for_log(event_id)
        safe_host = _sanitize_for_log(event.http.host)
        safe_method = _sanitize_for_log(event.http.method)
        log.debug(
            "Evaluating event",
            extra={
                "event_id": safe_event_id,
                "host": safe_host,
                "method": safe_method,
                "credential_detected": event.credential.detected,
            }
        )

        # Load task policy if specified
        if event.context and event.context.task_id:
            self._apply_task_policy(event.context.task_id)

        # Determine which checks to require
        required_checks = self._determine_required_checks(event)

        # First: credential validation (if credential detected)
        if event.credential.detected and "credential_validation" in required_checks:
            cred_decision = self._evaluate_credential(event)
            if cred_decision.effect != Effect.ALLOW:
                return self._build_decision(
                    event_id=event_id,
                    policy_hash=policy_hash,
                    legacy_decision=cred_decision,
                    required_checks=required_checks,
                )

        # Second: network policy (rate limiting)
        if "rate_limit" in required_checks:
            network_decision = self._evaluate_network(event)
            if network_decision.effect != Effect.ALLOW:
                return self._build_decision(
                    event_id=event_id,
                    policy_hash=policy_hash,
                    legacy_decision=network_decision,
                    required_checks=required_checks,
                )
            # Pass budget_remaining from network check
            return self._build_decision(
                event_id=event_id,
                policy_hash=policy_hash,
                legacy_decision=network_decision,
                required_checks=required_checks,
            )

        # Default allow
        return PolicyDecision(
            version=1,
            event=DecisionEventBlock(
                event_id=event_id,
                policy_hash=policy_hash,
                engine_version=ENGINE_VERSION,
            ),
            effect=Effect.ALLOW,
            reason="Allowed by policy",
            reason_codes=["ALLOWED"],
            checks=ChecksBlock(required=required_checks),
        )

    def _determine_required_checks(self, event: HttpEvent) -> list[str]:
        """Determine which checks are required for this event."""
        checks = []

        # Always check rate limits
        checks.append("rate_limit")

        # Credential checks if credential present
        if event.credential.detected:
            checks.append("credential_detection")
            checks.append("credential_validation")

        # Check if body inspection is needed (based on host/policy)
        # For v1, we don't do body inspection in PDP
        # checks.append("body_inspection")

        return checks

    def _evaluate_credential(self, event: HttpEvent) -> LegacyDecision:
        """Evaluate credential policy using existing engine."""
        cred_type = event.credential.type.value if event.credential.type else "unknown"
        fingerprint = event.credential.fingerprint

        return self._engine.evaluate_credential(
            credential_type=cred_type,
            destination=event.http.host,
            path=event.http.path,
            credential_hmac=fingerprint,
        )

    def _evaluate_network(self, event: HttpEvent) -> LegacyDecision:
        """Evaluate network policy using existing engine."""
        return self._engine.evaluate_request(
            host=event.http.host,
            path=event.http.path,
            method=event.http.method,
        )

    def _build_decision(
        self,
        event_id: str,
        policy_hash: str,
        legacy_decision: LegacyDecision,
        required_checks: list[str],
    ) -> PolicyDecision:
        """Convert legacy PolicyDecision to new schema."""
        # Map legacy effect to new Effect enum
        effect_map = {
            "allow": Effect.ALLOW,
            "deny": Effect.DENY,
            "prompt": Effect.REQUIRE_APPROVAL,
            "budget_exceeded": Effect.BUDGET_EXCEEDED,
        }
        effect = effect_map.get(legacy_decision.effect, Effect.ERROR)

        # Build reason codes
        reason_codes = self._effect_to_reason_codes(legacy_decision)

        # Build budget block if relevant
        budget = None
        if legacy_decision.budget_remaining is not None:
            budget = BudgetBlock(
                remaining=legacy_decision.budget_remaining,
            )
        elif legacy_decision.effect == "budget_exceeded":
            budget = BudgetBlock(
                remaining=0,
                retry_after_seconds=60,  # Default retry after
            )

        # Build immediate response for non-allow
        immediate_response = None
        if effect != Effect.ALLOW:
            immediate_response = self._build_immediate_response(
                event_id=event_id,
                effect=effect,
                reason=legacy_decision.reason,
                reason_codes=reason_codes,
            )

        return PolicyDecision(
            version=1,
            event=DecisionEventBlock(
                event_id=event_id,
                policy_hash=policy_hash,
                engine_version=ENGINE_VERSION,
            ),
            effect=effect,
            reason=legacy_decision.reason or f"Decision: {effect.value}",
            reason_codes=reason_codes,
            checks=ChecksBlock(required=required_checks),
            budget=budget,
            immediate_response=immediate_response,
        )

    def _effect_to_reason_codes(self, decision: LegacyDecision) -> list[str]:
        """Generate stable reason codes from decision."""
        codes = []

        if decision.effect == "allow":
            codes.append("ALLOWED")
            if decision.permission:
                codes.append(f"PERMISSION_{decision.permission.action.upper().replace(':', '_')}")
        elif decision.effect == "deny":
            codes.append("DENIED")
        elif decision.effect == "prompt":
            codes.append("REQUIRE_APPROVAL")
            if "credential" in decision.reason.lower():
                codes.append("CREDENTIAL_NOT_APPROVED")
            if "destination" in decision.reason.lower():
                codes.append("CREDENTIAL_DESTINATION_MISMATCH")
        elif decision.effect == "budget_exceeded":
            codes.append("BUDGET_EXCEEDED")
            codes.append("RATE_LIMITED")

        return codes

    def _build_immediate_response(
        self,
        event_id: str,
        effect: Effect,
        reason: str,
        reason_codes: list[str],
    ) -> ImmediateResponseBlock:
        """Build HTTP response for non-allow decisions."""
        status_code_map = {
            Effect.DENY: 403,
            Effect.REQUIRE_APPROVAL: 428,  # Precondition Required
            Effect.BUDGET_EXCEEDED: 429,
            Effect.ERROR: 500,
        }
        status_code = status_code_map.get(effect, 403)

        headers = {"content-type": "application/json"}
        if effect == Effect.BUDGET_EXCEEDED:
            headers["retry-after"] = "60"

        body = {
            "error": effect.value.replace("_", " ").title(),
            "event_id": event_id,
            "reason": reason,
            "reason_codes": reason_codes,
        }

        return ImmediateResponseBlock(
            status_code=status_code,
            headers=headers,
            body_json=body,
        )

    def _apply_task_policy(self, task_id: str) -> None:
        """Apply task policy if one exists for this task_id."""
        with self._lock:
            if task_id in self._task_policies:
                policy_data = self._task_policies[task_id]
                try:
                    policy = UnifiedPolicy.model_validate(policy_data)
                    policy.metadata.task_id = task_id
                    self._engine._loader._task_policy = policy
                    log.debug(f"Applied task policy for {task_id}")
                except Exception as e:
                    log.warning(f"Failed to apply task policy {task_id}: {type(e).__name__}: {e}")

    # -------------------------------------------------------------------------
    # Baseline Policy Management
    # -------------------------------------------------------------------------

    def get_baseline(self) -> dict | None:
        """
        Get the current baseline policy.

        Returns:
            Policy data as dict, or None if no baseline loaded
        """
        baseline = self._engine.get_baseline()
        if baseline is None:
            return None
        return baseline.model_dump()

    def get_baseline_path(self) -> str | None:
        """Get the path to the baseline policy file."""
        path = self._engine.baseline_path
        return str(path) if path else None

    def update_baseline(self, policy_data: dict) -> dict:
        """
        Update the baseline policy.

        Args:
            policy_data: New policy document

        Returns:
            Status dict with permission count
        """
        try:
            result = self._engine.update_baseline(policy_data)
            log.info("Baseline policy updated", extra={"permissions": result.get("permission_count", 0)})
            return {
                "status": "ok",
                "permission_count": result.get("permission_count", 0),
            }
        except ValueError as e:
            log.warning(f"Invalid baseline policy: {type(e).__name__}: {e}")
            return {
                "status": "error",
                "error": "Invalid policy document",
            }
        except Exception as e:
            log.error(f"Failed to update baseline: {type(e).__name__}: {e}")
            return {
                "status": "error",
                "error": "Failed to update baseline policy",
            }

    # -------------------------------------------------------------------------
    # Credential Approval Management
    # -------------------------------------------------------------------------

    def add_credential_approval(
        self,
        destination: str,
        credential: str,
        tier: str = "explicit",
    ) -> dict:
        """
        Add a credential approval to the baseline.

        This allows a credential (by type or HMAC fingerprint) to access
        a destination.

        Args:
            destination: Destination pattern (e.g., "api.example.com/*")
            credential: Credential identifier (e.g., "openai:*" or "hmac:abc123")
            tier: Permission tier (default: "explicit")

        Returns:
            Status dict
        """
        try:
            result = self._engine.add_credential_approval(
                destination=destination,
                credential=credential,
                tier=tier,
            )
            log.info(
                "Credential approval added",
                extra={
                    "destination": destination,
                    "credential": credential,
                    "tier": tier,
                }
            )
            return {
                "status": "ok",
                "destination": destination,
                "credential": credential,
                "tier": tier,
                "permission_count": result.get("permission_count", 1),
            }
        except ValueError as e:
            log.warning(f"Invalid credential approval: {type(e).__name__}: {e}")
            return {
                "status": "error",
                "error": "Invalid credential approval parameters",
            }
        except Exception as e:
            log.error(f"Failed to add credential approval: {type(e).__name__}: {e}")
            return {
                "status": "error",
                "error": "Failed to add credential approval",
            }

    # -------------------------------------------------------------------------
    # Budget Management
    # -------------------------------------------------------------------------

    def get_budget_stats(self) -> dict:
        """
        Get current budget usage statistics.

        Returns:
            Dict with tracked keys and their states
        """
        return self._engine.get_budget_stats()

    def reset_budgets(self, resource: str | None = None) -> dict:
        """
        Reset budget counters.

        Args:
            resource: Optional resource pattern to reset. If None, resets all.

        Returns:
            Status dict
        """
        try:
            result = self._engine.reset_budgets(resource=resource)
            log.info("Budget counters reset", extra={"resource": resource or "all"})
            return {
                "status": "ok",
                "resource": resource or "all",
                "reset_count": result.get("reset_count", 0) if isinstance(result, dict) else 0,
            }
        except Exception as e:
            log.error(f"Failed to reset budgets: {type(e).__name__}: {e}")
            return {
                "status": "error",
                "error": "Failed to reset budget counters",
            }

    # -------------------------------------------------------------------------
    # Task Policy Management
    # -------------------------------------------------------------------------

    def upsert_task_policy(self, task_id: str, policy_data: dict) -> dict:
        """
        Upsert a task policy.

        Args:
            task_id: Unique task identifier
            policy_data: Policy document (will be validated)

        Returns:
            Status dict with task_id and validation result
        """
        with self._lock:
            # Validate policy
            try:
                policy = UnifiedPolicy.model_validate(policy_data)
                policy.metadata.task_id = task_id
            except Exception as e:
                log.warning(f"Invalid task policy for {task_id}: {type(e).__name__}: {e}")
                return {
                    "status": "error",
                    "task_id": task_id,
                    "error": "Invalid policy document",
                }

            self._task_policies[task_id] = policy_data

            log.info("Upserted task policy", extra={"task_id": task_id})
            return {
                "status": "ok",
                "task_id": task_id,
                "permissions": len(policy.permissions),
            }

    def delete_task_policy(self, task_id: str) -> dict:
        """
        Delete a task policy.

        Args:
            task_id: Task identifier to delete

        Returns:
            Status dict
        """
        with self._lock:
            if task_id in self._task_policies:
                del self._task_policies[task_id]
                # Clear from engine if it was active
                if self._engine._loader._task_policy:
                    if self._engine._loader._task_policy.metadata.task_id == task_id:
                        self._engine._loader._task_policy = None
                log.info("Deleted task policy", extra={"task_id": task_id})
                return {"status": "ok", "task_id": task_id}
            else:
                return {"status": "not_found", "task_id": task_id}

    def get_task_policy(self, task_id: str) -> dict | None:
        """Get task policy data if it exists."""
        with self._lock:
            return self._task_policies.get(task_id)

    # -------------------------------------------------------------------------
    # Addon Management
    # -------------------------------------------------------------------------

    def is_addon_enabled(
        self,
        addon_name: str,
        domain: str | None = None,
        client_id: str | None = None,
    ) -> bool:
        """
        Check if addon is enabled for the given context.

        Args:
            addon_name: Name of addon to check
            domain: Request domain (optional)
            client_id: Client identifier (optional)

        Returns:
            True if addon should process this request
        """
        return self._engine.is_addon_enabled(addon_name, domain, client_id)

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Get PDP statistics."""
        return {
            "engine_version": ENGINE_VERSION,
            "policy_hash": self.policy_hash,
            "task_policies": len(self._task_policies),
            "engine_stats": self._engine.get_stats() if hasattr(self._engine, "get_stats") else {},
        }

    def shutdown(self) -> None:
        """Graceful shutdown - flush budget state."""
        log.info("PDPCore shutting down")
        if hasattr(self._engine, "done"):
            self._engine.done()


# Module-level singleton for simple usage
_pdp_instance: PDPCore | None = None
_pdp_lock = threading.Lock()


def get_pdp(
    baseline_path: Path | None = None,
    budget_state_path: Path | None = None,
) -> PDPCore:
    """
    Get or create the global PDP instance.

    Thread-safe singleton pattern. First call initializes with provided paths.
    Subsequent calls return the same instance (paths are ignored).
    """
    global _pdp_instance

    with _pdp_lock:
        if _pdp_instance is None:
            _pdp_instance = PDPCore(
                baseline_path=baseline_path,
                budget_state_path=budget_state_path,
            )
        return _pdp_instance


def reset_pdp() -> None:
    """Reset the global PDP instance (for testing)."""
    global _pdp_instance
    with _pdp_lock:
        if _pdp_instance:
            _pdp_instance.shutdown()
        _pdp_instance = None
