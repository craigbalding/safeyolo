"""
credential_guard.py - Credential protection for AI coding agents

Detects credentials in HTTP requests and validates they're going to
authorized destinations. Emits structured events to JSONL for external
processing (approval workflow, notifications, alerting).

Design:
- Credential detection stays in sensor (never sends raw creds to PDP)
- PolicyClient abstracts whether PDP is in-process or remote service
- All decisions logged to JSONL for correlation

Usage:
    mitmdump -s addons/credential_guard.py --set credguard_block=true
"""

import logging
import os
import sys
from pathlib import Path

from base import SecurityAddon
from detection import (
    CredentialRule,
    analyze_headers,
    detect_credential_type,
)
from mitmproxy import ctx, http

from audit_schema import ApprovalRequest, Decision, Severity

# Add pdp to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from sensor_utils import build_http_event_from_flow
from utils import (
    get_client_ip,
    hmac_fingerprint,
    load_hmac_secret,
    make_block_response,
    sanitize_for_log,
)

from pdp import (
    Effect,
    get_policy_client,
)

log = logging.getLogger("safeyolo.credential-guard")


# =============================================================================
# Decision Engine (PolicyClient-based)
# =============================================================================

def evaluate_credential_with_pdp(
    flow: http.HTTPFlow,
    credential: str,
    rule_name: str,
    confidence: str,
    rules: list[CredentialRule],
    hmac_secret: bytes,
    principal_id: str,
) -> tuple[Effect, dict]:
    """Evaluate credential using PolicyClient.

    Returns:
        (Effect, context_dict) - Effect enum and additional context.
        On any evaluation failure (PDP unreachable, client misconfigured,
        internal error), returns (Effect.ERROR, context) so the caller can
        fail closed rather than letting the request through.
    """
    try:
        client = get_policy_client()
    except RuntimeError as exc:
        log.error("PDP not configured during credential evaluation: %s", exc)
        return Effect.ERROR, {
            "fingerprint": f"hmac:{hmac_fingerprint(credential, hmac_secret)}",
            "reason_codes": ["PDP_NOT_CONFIGURED"],
            "reason": "Policy engine not configured (fail-closed)",
        }

    # Detect credential type and compute fingerprint
    credential_type = detect_credential_type(credential, rules)
    if credential_type is None:
        credential_type = "unknown"

    fingerprint = hmac_fingerprint(credential, hmac_secret)

    # Build HttpEvent using shared builder
    event = build_http_event_from_flow(
        flow=flow,
        principal_id=principal_id,
        credential_detected=True,
        credential_type=credential_type,
        credential_fingerprint=fingerprint,
        credential_confidence=confidence,
    )

    try:
        decision = client.evaluate(event)
    except Exception as exc:
        log.error(
            "PDP evaluation failed for credential %s on %s: %s: %s",
            sanitize_for_log(rule_name),
            sanitize_for_log(flow.request.host),
            type(exc).__name__,
            exc,
        )
        return Effect.ERROR, {
            "fingerprint": f"hmac:{fingerprint}",
            "reason_codes": ["PDP_EVALUATION_FAILED"],
            "reason": f"Policy evaluation failed: {type(exc).__name__}",
        }

    # Build context for response building
    context = {
        "fingerprint": f"hmac:{fingerprint}",
        "reason_codes": decision.reason_codes,
        "reason": decision.reason,
        "decision": decision,  # Full decision for immediate_response access
    }

    # Add expected_hosts for mismatch cases
    if decision.effect in (Effect.DENY, Effect.REQUIRE_APPROVAL):
        for rule in rules:
            if rule.name == credential_type:
                context["expected_hosts"] = rule.allowed_hosts
                context["suggested_url"] = rule.suggested_url
                break

    return decision.effect, context


# =============================================================================
# Response Builders
# =============================================================================

def create_mismatch_response(
    credential_type: str,
    host: str,
    expected_hosts: list[str],
    fingerprint: str,
    path: str,
    suggested_url: str = ""
) -> http.Response:
    """Create 428 response for destination mismatch."""
    body = {
        "error": "Credential routing error",
        "type": "destination_mismatch",
        "credential_type": credential_type,
        "destination": host,
        "expected_hosts": expected_hosts,
        "credential_fingerprint": fingerprint,
        "action": "self_correct",
        "reflection": f"You sent a {credential_type} credential to {host}, but it should go to {expected_hosts}. Please verify the URL.",
    }
    if suggested_url:
        body["suggested_url"] = suggested_url
    return make_block_response(428, body, "credential-guard")


def create_approval_response(
    credential_type: str,
    host: str,
    fingerprint: str,
    path: str,
    reason: str
) -> http.Response:
    """Create 428 response for approval required."""
    body = {
        "error": "Credential requires approval",
        "type": "requires_approval",
        "credential_type": credential_type,
        "destination": host,
        "credential_fingerprint": fingerprint,
        "reason": reason,
        "action": "wait_for_approval",
        "reflection": "This credential requires human approval before use.",
    }
    return make_block_response(428, body, "credential-guard")


def response_from_decision(decision, addon_name: str = "credential-guard") -> http.Response:
    """Convert PolicyDecision.immediate_response to mitmproxy Response.

    Falls back to generic error if immediate_response not provided.
    """
    if decision.immediate_response:
        ir = decision.immediate_response
        return make_block_response(ir.status_code, ir.body_json, addon_name)

    # Fallback for decisions without immediate_response
    status_map = {
        Effect.DENY: 403,
        Effect.REQUIRE_APPROVAL: 428,
        Effect.BUDGET_EXCEEDED: 429,
        Effect.ERROR: 500,
    }
    status = status_map.get(decision.effect, 403)
    body = {
        "error": decision.effect.value.replace("_", " ").title(),
        "reason": decision.reason,
        "reason_codes": decision.reason_codes,
    }
    return make_block_response(status, body, addon_name)


# =============================================================================
# Main Addon
# =============================================================================

class CredentialGuard(SecurityAddon):
    """Credential protection addon - detect, validate, decide, emit."""

    name = "credential-guard"

    def __init__(self):
        # Custom stats - don't call super().__init__()
        self.rules: list[CredentialRule] = []
        self.config: dict = {}
        self.safe_headers_config: dict = {}
        self.hmac_secret: bytes = b""
        self.violations_total = 0
        self.violations_by_type: dict[str, int] = {}
        self._last_policy_hash: str = ""

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option("credguard_block", bool, True, "Block violations (default: true)")
        loader.add_option("credguard_scan_urls", bool, False, "Scan URLs for credentials")
        loader.add_option("credguard_scan_bodies", bool, False, "Scan request bodies")

    def configure(self, updates):
        """Handle configuration updates."""
        if not self.hmac_secret:
            data_dir = os.environ.get("SAFEYOLO_DATA_DIR", "/safeyolo/data")
            self.hmac_secret = load_hmac_secret(Path(data_dir) / "hmac_secret")

    def _load_config_from_pdp(self, sensor_config: dict):
        """Load config from PDP sensor config.

        Args:
            sensor_config: Dict from PolicyClient.get_sensor_config()
        """
        cg = sensor_config.get("addons", {}).get("credential_guard", {})
        self.config = {
            "entropy": cg.get("entropy", {
                "min_length": 20,
                "min_charset_diversity": 0.5,
                "min_shannon_entropy": 3.5,
            }),
            "detection_level": cg.get("detection_level", "standard"),
            "standard_auth_headers": cg.get("standard_auth_headers", [
                "authorization", "x-api-key", "api-key", "x-auth-token", "apikey"
            ]),
        }
        self.safe_headers_config = cg.get("safe_headers", {})

    def _load_rules_from_policy(self, config: dict):
        """Load credential rules from policy configuration.

        Args:
            config: Sensor config dict with credential_rules
        """
        raw_rules = config.get("credential_rules", [])
        self.rules = []

        for r in raw_rules:
            try:
                self.rules.append(CredentialRule(
                    name=r["name"],
                    patterns=r.get("patterns", []),
                    allowed_hosts=r.get("allowed_hosts", []),
                    header_names=r.get("header_names", ["authorization", "x-api-key"]),
                    suggested_url=r.get("suggested_url", ""),
                ))
            except Exception as e:
                log.warning(f"Invalid credential rule '{r.get('name', 'unknown')}': {type(e).__name__}: {e}")

        if self.rules:
            log.info(f"Loaded {len(self.rules)} credential rules from policy")
        else:
            log.warning("No credential rules loaded from policy")

    def _maybe_reload_rules(self):
        """Reload credential rules and config if policy changed.

        On first load (_last_policy_hash is empty), a failure is logged at
        ERROR level because the addon is running with zero rules. On
        subsequent reloads, the previous rules survive, so a WARNING suffices.
        """
        import config_cache

        try:
            sensor_config = config_cache.get_or_raise()
        except RuntimeError:
            # PolicyClient not configured yet — skip reload. If this is the
            # first attempt the addon has zero rules, which is the expected
            # startup state before the PDP finishes loading.
            return
        except Exception as e:
            if self._last_policy_hash == "":
                log.error(
                    "First credential rule load failed — addon running with zero rules: "
                    "%s: %s", type(e).__name__, e,
                )
            else:
                log.warning(
                    "Failed to reload credential rules (previous rules preserved): "
                    "%s: %s", type(e).__name__, e,
                )
            return
        policy_hash = sensor_config.get("policy_hash", "")
        if policy_hash != self._last_policy_hash:
            self._load_rules_from_policy(sensor_config)
            self._load_config_from_pdp(sensor_config)
            self._last_policy_hash = policy_hash

    def should_block(self) -> bool:
        """Override base - uses credguard_block option."""
        return ctx.options.credguard_block

    def _get_project_id(self, flow: http.HTTPFlow) -> str:
        """Get project ID from service discovery."""
        client_ip = get_client_ip(flow)
        if client_ip == "unknown":
            return "default"

        try:
            from service_discovery import get_service_discovery
            sd = get_service_discovery()
            if sd:
                return sd.get_client_for_ip(client_ip)
        except Exception as e:
            log.debug(f"Service discovery lookup failed: {type(e).__name__}: {e}")
        return "default"

    def _record_violation(self, rule: str, host: str):
        """Record violation for stats."""
        self.violations_total += 1
        self.violations_by_type[rule] = self.violations_by_type.get(rule, 0) + 1

    def _is_enabled(self, flow: http.HTTPFlow) -> bool:
        """Check if addon is enabled via PolicyClient."""
        try:
            client = get_policy_client()
            return client.is_addon_enabled(
                "credential-guard",
                domain=flow.request.host,
                client_id=self._get_project_id(flow),
            )
        except RuntimeError:
            # PolicyClient not configured - default to enabled
            return True

    def request(self, flow: http.HTTPFlow):
        """Inspect request for credential leakage."""
        if flow.response:
            return

        # Reload rules if policy changed
        self._maybe_reload_rules()

        # Check if addon is disabled via policy
        if not self._is_enabled(flow):
            return

        host = flow.request.host.lower()
        path = flow.request.path
        project_id = self._get_project_id(flow)

        entropy_config = self.config.get("entropy", {
            "min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5
        })
        detection_level = self.config.get("detection_level", "standard")
        standard_auth_headers = self.config.get("standard_auth_headers", [
            "authorization", "x-api-key", "api-key", "x-auth-token", "apikey"
        ])

        detections = analyze_headers(
            headers=dict(flow.request.headers),
            rules=self.rules,
            safe_headers_config=self.safe_headers_config,
            entropy_config=entropy_config,
            standard_auth_headers=standard_auth_headers,
            detection_level=detection_level
        )

        for det in detections:
            credential = det["credential"]
            rule_name = det["rule_name"]
            header = det["header_name"]
            confidence = det["confidence"]
            tier = det["tier"]
            fp = hmac_fingerprint(credential, self.hmac_secret)

            # Evaluate via PolicyClient (PDP)
            effect, context = evaluate_credential_with_pdp(
                flow=flow,
                credential=credential,
                rule_name=rule_name,
                confidence=confidence,
                rules=self.rules,
                hmac_secret=self.hmac_secret,
                principal_id=f"project:{project_id}",
            )

            fingerprint_str = context.get("fingerprint", f"hmac:{fp}")
            detail_fields = {
                "rule": rule_name, "location": f"header:{header}",
                "fingerprint": fingerprint_str,
                "confidence": confidence, "tier": tier,
                "project_id": project_id,
                "reason_codes": context.get("reason_codes", []),
            }

            if effect == Effect.ALLOW:
                self.log_decision(
                    flow, Decision.ALLOW,
                    severity=Severity.LOW,
                    summary=f"Credential {rule_name} allowed to {sanitize_for_log(host)}",
                    host=host,
                    **detail_fields,
                )
                continue

            # Non-allow decision - record violation
            self._record_violation(rule_name, host)
            flow.metadata["credential_fingerprint"] = fingerprint_str

            # Map effect to log reason and Decision enum
            if effect == Effect.DENY:
                detail_fields["reason"] = "destination_mismatch"
                detail_fields["expected_hosts"] = context.get("expected_hosts", [])
                audit_decision = Decision.DENY
            elif effect == Effect.REQUIRE_APPROVAL:
                detail_fields["reason"] = "requires_approval"
                audit_decision = Decision.REQUIRE_APPROVAL
            elif effect == Effect.BUDGET_EXCEEDED:
                detail_fields["reason"] = "budget_exceeded"
                audit_decision = Decision.BUDGET_EXCEEDED
            else:
                detail_fields["reason"] = context.get("reason", "policy_violation")
                audit_decision = Decision.DENY

            # Build approval request for blocks needing human action
            approval = None
            if effect in (Effect.DENY, Effect.REQUIRE_APPROVAL):
                approval = ApprovalRequest(
                    required=True,
                    approval_type="credential",
                    key=fingerprint_str,
                    target=host,
                    scope_hint={"rule": rule_name, "expected_hosts": context.get("expected_hosts", [])},
                )

            reason_str = detail_fields.get("reason", "policy_violation")

            if self.should_block():
                flow.metadata["blocked_by"] = self.name
                self.log_decision(
                    flow, audit_decision,
                    severity=Severity.CRITICAL,
                    summary=f"Credential {rule_name} blocked to {sanitize_for_log(host)}: {reason_str}",
                    host=host,
                    approval=approval,
                    **detail_fields,
                )
                # Use PDP's immediate_response if available
                pdp_decision = context.get("decision")
                if pdp_decision:
                    flow.response = response_from_decision(pdp_decision, self.name)
                else:
                    # Fallback to legacy response builders
                    if effect == Effect.DENY:
                        flow.response = create_mismatch_response(
                            rule_name, host, context.get("expected_hosts", []),
                            fingerprint_str, path,
                            context.get("suggested_url", "")
                        )
                    else:
                        flow.response = create_approval_response(
                            rule_name, host, fingerprint_str,
                            path, context.get("reason", "unknown")
                        )
                return
            else:
                self.log_decision(
                    flow, Decision.WARN,
                    severity=Severity.HIGH,
                    summary=f"Credential {rule_name} would be blocked to {sanitize_for_log(host)}: {reason_str}",
                    host=host,
                    approval=approval,
                    **detail_fields,
                )

    def get_stats(self) -> dict:
        """Get stats for admin API."""
        return {
            "violations_total": self.violations_total,
            "violations_by_type": self.violations_by_type,
            "rules_count": len(self.rules),
        }


addons = [CredentialGuard()]
