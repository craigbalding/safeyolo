"""
patterns.py - Regex pattern matching for secrets and jailbreak detection
"""

import re
from dataclasses import dataclass


@dataclass
class PatternRule:
    """A pattern detection rule."""
    rule_id: str
    name: str
    pattern: re.Pattern
    target: str  # "input", "output", "both"
    severity: int  # 1-5
    category: str  # "secret", "jailbreak", "pii"

    def matches(self, text: str) -> re.Match | None:
        return self.pattern.search(text)

    @property
    def should_block(self) -> bool:
        return self.severity >= 4


# Built-in secret patterns (scan output/responses)
BUILTIN_SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{48}", "openai_api_key", "OpenAI API Key", 5),
    (r"sk-ant-[a-zA-Z0-9-]{95}", "anthropic_api_key", "Anthropic API Key", 5),
    (r"AKIA[0-9A-Z]{16}", "aws_access_key", "AWS Access Key ID", 5),
    (r"AIza[0-9A-Za-z-_]{35}", "google_api_key", "Google API Key", 5),
    (r"ghp_[a-zA-Z0-9]{36}", "github_pat", "GitHub Personal Access Token", 5),
    (r"gho_[a-zA-Z0-9]{36}", "github_oauth", "GitHub OAuth Token", 5),
    (r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,})", "generic_api_key", "Generic API Key", 4),
    (r"(?i)bearer\s+[a-zA-Z0-9_-]{20,}", "bearer_token", "Bearer Token", 4),
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private_key", "Private Key", 5),
    (r"(?i)(postgres|mysql|mongodb)://[^\s]+:[^\s]+@", "db_connection_string", "Database Connection String", 5),
]

# Built-in jailbreak patterns (scan input/requests)
BUILTIN_JAILBREAK_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)", "ignore_instructions", "Instruction override", 4),
    (r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)", "disregard_instructions", "Instruction override", 4),
    (r"forget\s+(everything|all)\s+(you|that)\s+(know|learned|were)", "forget_training", "Memory reset attempt", 4),
    (r"you\s+are\s+(now\s+)?(?:DAN|jailbroken|unrestricted|unfiltered)", "dan_jailbreak", "DAN jailbreak", 5),
    (r"pretend\s+(you\s+)?(are|to\s+be)\s+(a|an)?\s*(evil|malicious|unrestricted)", "evil_roleplay", "Malicious roleplay", 4),
    (r"developer\s+mode\s+(enabled?|activated?|on)", "developer_mode", "Fake developer mode", 4),
    (r"enable\s+(developer|debug|admin)\s+mode", "enable_mode", "Privileged mode attempt", 4),
    (r"(what|show|tell|reveal|repeat|print)\s+(is\s+)?(your|the)\s+(system\s+)?(prompt|instructions?)", "prompt_extraction", "System prompt extraction", 3),
    (r"\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>", "instruction_markers", "LLM instruction markers", 4),
    (r"<<SYS>>|<</SYS>>", "llama_system", "Llama system markers", 4),
]


def compile_rules(
    secret_patterns: list[tuple] = None,
    jailbreak_patterns: list[tuple] = None,
) -> list[PatternRule]:
    """Compile patterns into PatternRule objects.

    Args:
        secret_patterns: List of (pattern, rule_id, name, severity) tuples for output scanning
        jailbreak_patterns: List of (pattern, rule_id, name, severity) tuples for input scanning

    Returns:
        List of compiled PatternRule objects
    """
    if secret_patterns is None:
        secret_patterns = BUILTIN_SECRET_PATTERNS
    if jailbreak_patterns is None:
        jailbreak_patterns = BUILTIN_JAILBREAK_PATTERNS

    rules = []

    for pattern_str, rule_id, desc, severity in secret_patterns:
        try:
            rules.append(PatternRule(
                rule_id=f"secret:{rule_id}",
                name=desc,
                pattern=re.compile(pattern_str, re.IGNORECASE),
                target="output",
                severity=severity,
                category="secret",
            ))
        except re.error:
            pass  # Skip invalid patterns

    for pattern_str, rule_id, desc, severity in jailbreak_patterns:
        try:
            rules.append(PatternRule(
                rule_id=f"jailbreak:{rule_id}",
                name=desc,
                pattern=re.compile(pattern_str, re.IGNORECASE),
                target="input",
                severity=severity,
                category="jailbreak",
            ))
        except re.error:
            pass  # Skip invalid patterns

    return rules


def scan_text(text: str, target: str, rules: list[PatternRule]) -> PatternRule | None:
    """Scan text for matching patterns.

    Args:
        text: Text to scan
        target: "input" or "output" - which direction to match
        rules: List of PatternRule objects to match against

    Returns:
        First matching PatternRule, or None if no match
    """
    for rule in rules:
        if rule.target != target and rule.target != "both":
            continue

        if rule.matches(text):
            return rule

    return None
