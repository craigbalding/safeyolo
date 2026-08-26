"""Shared credential-family catalogue for routing and DLP detection.

The credential guard and pattern scanner have different jobs, but overlapping
provider signatures must come from one source.  A catalogue entry therefore
contains routing metadata plus optional DLP metadata.  When ``dlp_patterns`` is
omitted, the precise routing patterns are reused.  Broader DLP expressions are
explicit so a reviewer can distinguish intentional breadth from drift.

Only provider-distinct token shapes receive a provider routing type.  Generic
``sk-`` keys are deliberately classified as ``ambiguous-sk``: OpenAI-compatible
providers including DeepSeek and Kimi use indistinguishable values.  An
operator can bind one such credential fingerprint to its real destination via
the existing approval workflow without allowing every ``sk-`` key there.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CredentialFamilySpec:
    """One provider-distinct credential signature and its security metadata."""

    family_id: str
    credential_type: str
    classifier_patterns: tuple[str, ...]
    allowed_hosts: tuple[str, ...]
    header_names: tuple[str, ...] = ("authorization", "x-api-key")
    suggested_url: str = ""
    dlp_name: str | None = None
    dlp_patterns: tuple[str, ...] | None = None
    dlp_message: str = "Credential detected"
    source_urls: tuple[str, ...] = ()

    @property
    def effective_dlp_patterns(self) -> tuple[str, ...]:
        """Return intentional DLP overrides or the classifier signatures."""
        if self.dlp_name is None:
            return ()
        return self.dlp_patterns or self.classifier_patterns


# Ordering is security-significant: provider-specific namespaces must be
# consulted before the provider-ambiguous ``sk-`` fallback.
CREDENTIAL_FAMILIES: tuple[CredentialFamilySpec, ...] = (
    CredentialFamilySpec(
        family_id="openai-admin",
        credential_type="openai-admin",
        classifier_patterns=(r"sk-admin-[A-Za-z0-9_-]{8,}",),
        allowed_hosts=("api.openai.com",),
        header_names=("authorization",),
        suggested_url="https://platform.openai.com/settings/organization/admin-keys",
        dlp_name="openai-admin-key",
        dlp_message="OpenAI organization admin key detected",
        source_urls=(
            "https://developers.openai.com/api/reference/resources/admin/"
            "subresources/organization/subresources/admin_api_keys/methods/create",
        ),
    ),
    CredentialFamilySpec(
        family_id="openrouter-api-key",
        credential_type="openrouter",
        classifier_patterns=(r"sk-or-v1-[0-9a-f]{64}",),
        allowed_hosts=("openrouter.ai",),
        header_names=("authorization",),
        suggested_url="https://openrouter.ai/settings/keys",
        dlp_name="openrouter-api-key",
        # Routing requires the documented v1 shape. DLP stays deliberately
        # tolerant of copied/truncated or future opaque bodies in content.
        dlp_patterns=(r"sk-or-v1-[A-Za-z0-9_-]{20,}",),
        dlp_message="OpenRouter API key detected",
        source_urls=(
            "https://openrouter.ai/docs/api/api-reference/api-keys/create-keys",
        ),
    ),
    CredentialFamilySpec(
        family_id="openai-project-api-key",
        credential_type="openai",
        classifier_patterns=(
            r"sk-proj-[A-Za-z0-9_-]{20,}",
            r"sk-svcacct-[A-Za-z0-9_-]{20,}",
        ),
        allowed_hosts=("api.openai.com",),
        header_names=("authorization",),
        suggested_url="https://platform.openai.com/api-keys",
        dlp_name="openai-api-key",
        dlp_patterns=(r"sk-(?:proj|svcacct)-[A-Za-z0-9_-]{20,}",),
        dlp_message="OpenAI project or service-account API key detected",
        source_urls=(
            "https://developers.openai.com/api/reference/typescript/resources/admin/"
            "subresources/organization/subresources/projects",
        ),
    ),
    CredentialFamilySpec(
        family_id="anthropic-routine",
        credential_type="anthropic",
        classifier_patterns=(
            r"sk-ant-api\d{2}-[A-Za-z0-9_-]{93}AA",
            r"sk-ant-oat\d{2}-[A-Za-z0-9_-]{93}AA",
        ),
        allowed_hosts=("api.anthropic.com", "console.anthropic.com"),
        header_names=("authorization", "x-api-key"),
        suggested_url="https://console.anthropic.com/settings/keys",
        dlp_name="anthropic-api-key",
        # DLP intentionally includes session/sandbox/ingress families that
        # are secrets but do not have safe default routing permissions.
        dlp_patterns=(r"sk-ant-[a-z]+\d{0,2}-[A-Za-z0-9_.-]{20,}",),
        dlp_message="Anthropic credential detected",
        source_urls=(
            "https://docs.anthropic.com/en/api/admin-api/apikeys/get-api-key",
        ),
    ),
    CredentialFamilySpec(
        family_id="anthropic-admin",
        credential_type="anthropic-admin",
        classifier_patterns=(r"sk-ant-admin\d{2}-[A-Za-z0-9_-]{93}AA",),
        allowed_hosts=("api.anthropic.com",),
        header_names=("x-api-key",),
        suggested_url="https://console.anthropic.com/settings/keys",
        # Covered by the broader, explicit Anthropic DLP expression above.
        source_urls=(
            "https://docs.anthropic.com/en/api/admin-api/apikeys/get-api-key",
        ),
    ),
    CredentialFamilySpec(
        family_id="anthropic-refresh",
        credential_type="anthropic-refresh",
        classifier_patterns=(r"sk-ant-ort\d{2}-[A-Za-z0-9_-]{93}AA",),
        allowed_hosts=("console.anthropic.com",),
        header_names=("authorization",),
        # Covered by the broader, explicit Anthropic DLP expression above.
        source_urls=(
            "https://docs.anthropic.com/en/api/admin-api/apikeys/get-api-key",
        ),
    ),
    CredentialFamilySpec(
        family_id="github-classic-pat",
        credential_type="github",
        classifier_patterns=(r"ghp_[A-Za-z0-9._-]{36,}",),
        allowed_hosts=("api.github.com", "github.com"),
        header_names=("authorization",),
        suggested_url="https://github.com/settings/tokens",
        dlp_name="github-pat",
        dlp_message="GitHub personal access token detected",
        source_urls=(
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/"
            "about-authentication-to-github",
        ),
    ),
    CredentialFamilySpec(
        family_id="github-oauth",
        credential_type="github",
        classifier_patterns=(r"gho_[A-Za-z0-9._-]{36,}",),
        allowed_hosts=("api.github.com", "github.com"),
        header_names=("authorization",),
        dlp_name="github-oauth",
        dlp_message="GitHub OAuth token detected",
        source_urls=(
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/"
            "about-authentication-to-github",
        ),
    ),
    CredentialFamilySpec(
        family_id="github-app-user",
        credential_type="github",
        classifier_patterns=(r"ghu_[A-Za-z0-9._-]{36,}",),
        allowed_hosts=("api.github.com", "github.com"),
        header_names=("authorization",),
        dlp_name="github-app-user",
        dlp_message="GitHub App user-to-server token detected",
        source_urls=(
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/"
            "about-authentication-to-github",
        ),
    ),
    CredentialFamilySpec(
        family_id="github-app-installation",
        credential_type="github",
        classifier_patterns=(r"ghs_[A-Za-z0-9._-]{36,}",),
        allowed_hosts=("api.github.com", "github.com"),
        header_names=("authorization",),
        dlp_name="github-app-server",
        dlp_message="GitHub App installation token detected",
        source_urls=(
            "https://github.blog/changelog/2026-05-15-github-app-installation-tokens-"
            "per-request-override-header/",
        ),
    ),
    CredentialFamilySpec(
        family_id="github-refresh",
        credential_type="github-refresh",
        classifier_patterns=(r"ghr_[A-Za-z0-9._-]{36,}",),
        allowed_hosts=("github.com",),
        header_names=("authorization",),
        dlp_name="github-refresh",
        dlp_message="GitHub refresh token detected",
        source_urls=(
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/"
            "about-authentication-to-github",
        ),
    ),
    CredentialFamilySpec(
        family_id="github-fine-grained-pat",
        credential_type="github",
        classifier_patterns=(r"github_pat_[A-Za-z0-9._-]{60,}",),
        allowed_hosts=("api.github.com", "github.com"),
        header_names=("authorization",),
        suggested_url="https://github.com/settings/personal-access-tokens",
        dlp_name="github-fine-grained-pat",
        dlp_message="GitHub fine-grained personal access token detected",
        source_urls=(
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/"
            "about-authentication-to-github",
        ),
    ),
    CredentialFamilySpec(
        family_id="google-api-key",
        credential_type="google",
        classifier_patterns=(
            r"AIza[0-9A-Za-z_-]{35}",
            r"AQ\.[A-Za-z0-9_-]{40,}",
        ),
        allowed_hosts=("*.googleapis.com",),
        header_names=("x-goog-api-key",),
        suggested_url="https://aistudio.google.com/app/apikey",
        dlp_name="google-api-key",
        dlp_patterns=(r"(?:AIza[0-9A-Za-z_-]{35}|AQ\.[A-Za-z0-9_-]{40,})",),
        dlp_message="Google API or authorization key detected",
        source_urls=(
            "https://docs.cloud.google.com/docs/authentication/api-keys",
            "https://ai.google.dev/gemini-api/docs/api-key",
        ),
    ),
    CredentialFamilySpec(
        family_id="xai-api-key",
        credential_type="xai",
        classifier_patterns=(r"xai-[A-Za-z0-9_-]{20,}",),
        allowed_hosts=("api.x.ai",),
        header_names=("authorization",),
        suggested_url="https://console.x.ai/",
        dlp_name="xai-api-key",
        dlp_message="xAI API key detected",
        source_urls=("https://docs.x.ai/build/overview",),
    ),
    CredentialFamilySpec(
        family_id="groq-api-key",
        credential_type="groq",
        classifier_patterns=(r"gsk_[A-Za-z0-9_-]{20,}",),
        allowed_hosts=("api.groq.com",),
        header_names=("authorization",),
        suggested_url="https://console.groq.com/keys",
        dlp_name="groq-api-key",
        dlp_message="Groq API key detected",
        source_urls=(
            "https://console.groq.com/docs/production-readiness/security-onboarding",
        ),
    ),
    CredentialFamilySpec(
        family_id="huggingface-token",
        credential_type="huggingface",
        classifier_patterns=(
            r"hf_[A-Za-z0-9]{20,}",
            r"hf_(?:jwt|oauth)_[A-Za-z0-9_-]{20,}",
        ),
        allowed_hosts=("huggingface.co", "*.huggingface.co"),
        header_names=("authorization",),
        suggested_url="https://huggingface.co/settings/tokens",
        dlp_name="huggingface-token",
        dlp_patterns=(r"hf_(?:(?:jwt|oauth)_)?[A-Za-z0-9_-]{20,}",),
        dlp_message="Hugging Face access token detected",
        source_urls=(
            "https://huggingface.co/docs/hub/en/security-tokens",
            "https://huggingface.co/docs/hub/en/trusted-publishers",
        ),
    ),
    CredentialFamilySpec(
        family_id="ambiguous-sk",
        credential_type="ambiguous-sk",
        classifier_patterns=(
            r"sk-(?!admin-)(?!ant-)(?!or-v1-)(?!proj-)(?!svcacct-)"
            r"[A-Za-z0-9_-]{20,}",
        ),
        allowed_hosts=(),
        header_names=("authorization", "x-api-key", "api-key", "apikey"),
        dlp_name="ambiguous-sk-api-key",
        dlp_message="Provider-ambiguous sk- API key detected",
        source_urls=(
            "https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/providers.md",
            "https://github.com/NousResearch/hermes-agent/blob/main/website/docs/"
            "integrations/providers.md",
        ),
    ),
)


def build_default_rule_configs() -> list[dict]:
    """Build routing-rule constructor arguments from the catalogue."""
    return [
        {
            "name": family.credential_type,
            "patterns": list(family.classifier_patterns),
            "allowed_hosts": list(family.allowed_hosts),
            "header_names": list(family.header_names),
            "suggested_url": family.suggested_url,
        }
        for family in CREDENTIAL_FAMILIES
    ]


def build_dlp_pattern_configs() -> list[dict]:
    """Build blocking DLP rules for every catalogue family that exposes one."""
    configs: list[dict] = []
    for family in CREDENTIAL_FAMILIES:
        for pattern in family.effective_dlp_patterns:
            configs.append(
                {
                    "name": family.dlp_name,
                    "pattern": pattern,
                    "target": "both",
                    "scope": ["body", "url", "headers"],
                    "action": "block",
                    "severity": "critical",
                    "message": family.dlp_message,
                }
            )
    return configs


def validate_catalogue() -> None:
    """Fail fast on catalogue mistakes that would silently weaken detection."""
    family_ids = [family.family_id for family in CREDENTIAL_FAMILIES]
    if len(family_ids) != len(set(family_ids)):
        raise ValueError("credential catalogue family_id values must be unique")

    for family in CREDENTIAL_FAMILIES:
        if not family.classifier_patterns:
            raise ValueError(f"credential family {family.family_id!r} has no classifier patterns")
        if not family.source_urls:
            raise ValueError(f"credential family {family.family_id!r} has no primary source")
        if family.dlp_patterns is not None and family.dlp_name is None:
            raise ValueError(
                f"credential family {family.family_id!r} has DLP patterns but no finding name"
            )


validate_catalogue()
