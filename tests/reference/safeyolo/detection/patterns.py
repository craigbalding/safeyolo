"""
patterns.py - User-configurable pattern matching

A framework for security-conscious users to define custom patterns for detecting
sensitive data crossing the proxy boundary. Scans URLs, headers, and/or bodies.

Use cases:
- Internal project identifiers that shouldn't leak to external APIs
- Customer/employee IDs for audit logging
- Compliance-related terms (CONFIDENTIAL, INTERNAL-ONLY)
- Secret detection (enable 'secrets' builtin set)
- PII patterns (enable 'pii' builtin set)

Patterns are loaded from policy. The shipped SafeYolo configuration enables the
`secrets` builtin set; operators can add rules under `scan_patterns` or change
the enabled builtin sets.

Example policy configuration:
    pattern_scanner:
      builtin_sets: [secrets]  # Enable builtin secret detection

    scan_patterns:
      - name: internal-project-ids
        pattern: "PROJ-[0-9]{5}"
        target: request
        scope: [body, url]     # Where to scan (default: [body])
        action: block
        message: "Internal project ID detected"
"""

import logging
import re
from dataclasses import dataclass, field

from .credential_catalog import build_dlp_pattern_configs

log = logging.getLogger("safeyolo.patterns")

# Valid scope values
VALID_SCOPES = {"url", "headers", "body"}


@dataclass
class PatternRule:
    """A user-defined pattern detection rule.

    Attributes:
        name: Human-readable rule name (used as bounded finding identity)
        pattern: Compiled regex pattern
        target: Direction to scan - "request", "response", or "both"
        scope: Where to scan - set of "url", "headers", "body"
        action: What to do on match - "block" or "log"
        severity: For logging/alerting - "low", "medium", "high", "critical"
        message: Custom policy message retained for configuration; the scanner
            does not publish it in logs or block responses
        case_sensitive: Whether pattern matching is case-sensitive
    """
    name: str
    pattern: re.Pattern
    target: str = "both"  # "request", "response", "both"
    scope: set[str] = field(default_factory=lambda: {"body"})
    action: str = "log"  # "block", "log"
    severity: str = "medium"  # "low", "medium", "high", "critical"
    message: str = ""
    case_sensitive: bool = True

    def matches(self, text: str) -> re.Match | None:
        """Check if pattern matches text."""
        return self.pattern.search(text)

    @property
    def should_block(self) -> bool:
        """Whether this rule should block traffic when matched."""
        return self.action == "block"

    @property
    def rule_id(self) -> str:
        """Generate rule ID from name."""
        return f"scan:{self.name}"


def compile_pattern(pattern_str: str, case_sensitive: bool = True) -> re.Pattern | None:
    """Safely compile a regex pattern with ReDoS protection.

    Args:
        pattern_str: The regex pattern string
        case_sensitive: Whether to compile with case sensitivity

    Returns:
        Compiled pattern or None if invalid/dangerous
    """
    # Basic ReDoS protection - reject obviously dangerous patterns
    dangerous_indicators = [
        r'(.+)+',  # Nested quantifiers on capturing groups
        r'(.*)*',
        r'(.+)*',
        r'(.*)+',
        r'(\w+)+',
        r'(\d+)+',
    ]

    for indicator in dangerous_indicators:
        if indicator in pattern_str:
            log.warning("Rejected potentially dangerous pattern (length=%d)", len(pattern_str))
            return None

    try:
        flags = 0 if case_sensitive else re.IGNORECASE
        return re.compile(pattern_str, flags)
    except re.error as err:
        # Regex diagnostics can include excerpts of the policy pattern. Keep
        # operational logs structural; the policy store remains the source of
        # configuration details for an authorized operator.
        log.warning("Invalid regex pattern (%s)", type(err).__name__)
        return None


def _parse_scope(scope_config) -> set[str]:
    """Parse scope configuration into a set of valid scope values."""
    if scope_config is None:
        return {"body"}

    if isinstance(scope_config, str):
        scope_config = [scope_config]

    result = set()
    for s in scope_config:
        s_lower = s.lower()
        if s_lower in VALID_SCOPES:
            result.add(s_lower)
        else:
            log.warning("Invalid scope value, ignoring (valid scopes=%d)", len(VALID_SCOPES))

    return result if result else {"body"}


def load_patterns_from_config(scan_patterns: list[dict]) -> list[PatternRule]:
    """Load pattern rules from policy configuration.

    Args:
        scan_patterns: List of pattern config dicts from policy file

    Returns:
        List of compiled PatternRule objects

    Example config format:
        scan_patterns:
          - name: internal-ids
            pattern: "PROJ-[0-9]{5}"
            target: request        # request | response | both
            scope: [body, url]     # url | headers | body (default: [body])
            action: block          # block | log
            severity: high         # low | medium | high | critical
            message: "Internal ID detected"
            case_sensitive: false  # optional, default true
    """
    rules = []

    for config in scan_patterns:
        name = config.get("name")
        pattern_str = config.get("pattern")

        if not name or not pattern_str:
            log.warning("Skipping pattern config missing name or pattern")
            continue

        # Normalize target (accept both "request"/"response" and "input"/"output")
        target = config.get("target", "both")
        target_map = {"input": "request", "output": "response"}
        target = target_map.get(target, target)

        if target not in ("request", "response", "both"):
            log.warning("Invalid pattern target, defaulting to 'both'")
            target = "both"

        # Parse scope
        scope = _parse_scope(config.get("scope"))

        # Normalize action
        action = config.get("action", "log")
        if action not in ("block", "log"):
            log.warning("Invalid pattern action, defaulting to 'log'")
            action = "log"

        case_sensitive = config.get("case_sensitive", True)
        compiled = compile_pattern(pattern_str, case_sensitive)

        if compiled is None:
            continue

        rules.append(PatternRule(
            name=name,
            pattern=compiled,
            target=target,
            scope=scope,
            action=action,
            severity=config.get("severity", "medium"),
            message=config.get("message", f"Pattern matched: {name}"),
            case_sensitive=case_sensitive,
        ))

    if rules:
        log.info(f"Loaded {len(rules)} user-defined scan patterns")
    return rules


# =============================================================================
# Built-in Pattern Sets
# =============================================================================
# Optional pattern sets users can enable. The shipped configuration enables the
# secrets set. Configure sets via:
#   pattern_scanner:
#     builtin_sets: [secrets]

BUILTIN_PATTERN_SETS = {
    "secrets": [
        *build_dlp_pattern_configs(),
        # DLP-only entries below do not have enough information to bind a
        # credential to one provider destination.  Keep them separate from
        # the shared routing/DLP catalogue by design.
        {
            "name": "aws-access-key",
            "pattern": r"AKIA[0-9A-Z]{16}",
            "target": "both",
            "scope": ["body", "url", "headers"],
            "action": "block",
            "severity": "critical",
            "message": "AWS access key ID detected",
        },
        {
            "name": "private-key",
            "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "target": "both",
            "scope": ["body"],
            "action": "block",
            "severity": "critical",
            "message": "Private key detected",
        },
        {
            "name": "db-connection-string",
            "pattern": r"(postgres|mysql|mongodb)://[^\s]+:[^\s]+@",
            "target": "both",
            "scope": ["body", "url"],
            "action": "block",
            "severity": "critical",
            "message": "Database connection string with credentials detected",
            "case_sensitive": False,
        },
        {
            "name": "generic-bearer-in-body",
            "pattern": r"bearer\s+[a-zA-Z0-9_-]{20,}",
            "target": "both",
            "scope": ["body"],
            "action": "log",
            "severity": "high",
            "message": "Bearer token in request/response body",
            "case_sensitive": False,
        },
    ],
    "pii": [
        {
            "name": "ssn-pattern",
            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
            "target": "both",
            "scope": ["body"],
            "action": "log",
            "severity": "high",
            "message": "Potential SSN pattern detected",
        },
        {
            "name": "credit-card",
            "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
            "target": "both",
            "scope": ["body"],
            "action": "log",
            "severity": "high",
            "message": "Potential credit card number detected",
        },
        {
            "name": "email-address",
            "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "target": "both",
            "scope": ["body"],
            "action": "log",
            "severity": "medium",
            "message": "Email address detected",
        },
    ],
}


def load_builtin_set(set_name: str) -> list[dict]:
    """Load a builtin pattern set by name.

    Args:
        set_name: Name of the builtin set (e.g., "secrets", "pii")

    Returns:
        List of pattern config dicts, or empty list if not found
    """
    if set_name not in BUILTIN_PATTERN_SETS:
        log.warning("Unknown builtin pattern set (available=%d)", len(BUILTIN_PATTERN_SETS))
        return []

    return BUILTIN_PATTERN_SETS[set_name]


def scan_text(text: str, direction: str, rules: list[PatternRule]) -> PatternRule | None:
    """Scan text for matching patterns.

    Args:
        text: Text to scan
        direction: "request" or "response" - which direction to match
        rules: List of PatternRule objects to match against

    Returns:
        First matching PatternRule, or None if no match
    """
    for rule in rules:
        if rule.target != direction and rule.target != "both":
            continue

        if rule.matches(text):
            return rule

    return None
