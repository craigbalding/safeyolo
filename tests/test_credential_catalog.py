"""Regression tests for the shared credential-family catalogue."""

import re

import pytest

from safeyolo.detection import (
    BUILTIN_PATTERN_SETS,
    CREDENTIAL_FAMILIES,
    DEFAULT_RULES,
    build_default_rule_configs,
    build_dlp_pattern_configs,
    detect_credential_type,
)
from safeyolo.detection.credentials import analyze_headers


def _anthropic_token(family: str) -> str:
    return f"sk-ant-{family}01-{'A' * 46}_{'b' * 46}AA"


@pytest.mark.parametrize(
    ("token", "expected_type"),
    [
        ("sk-admin-" + "A_b-" * 8, "openai-admin"),
        ("sk-or-v1-" + "a" * 64, "openrouter"),
        ("sk-proj-" + "A_b-" * 8, "openai"),
        ("sk-svcacct-" + "A_b-" * 8, "openai"),
        (_anthropic_token("api"), "anthropic"),
        (_anthropic_token("oat"), "anthropic"),
        (_anthropic_token("admin"), "anthropic-admin"),
        (_anthropic_token("ort"), "anthropic-refresh"),
        ("ghp_" + "A" * 36, "github"),
        ("ghr_" + "A" * 36, "github-refresh"),
        ("github_pat_" + "A" * 82, "github"),
        ("AIza" + "A" * 35, "google"),
        ("AQ." + "A_b-" * 12, "google"),
        ("xai-" + "A_b-" * 8, "xai"),
        ("gsk_" + "A_b-" * 8, "groq"),
        ("hf_" + "A" * 24, "huggingface"),
        ("hf_oauth_" + "A_b-" * 8, "huggingface"),
        ("sk-" + "A_b-" * 8, "ambiguous-sk"),
        ("sk-deepseekCompatibleOpaqueValue123", "ambiguous-sk"),
    ],
)
def test_catalogue_classifies_provider_families(token, expected_type):
    assert detect_credential_type(token, DEFAULT_RULES) == expected_type


@pytest.mark.parametrize(
    "embedded_shape",
    ["hf_" + "A" * 28, "ghp_" + "A" * 40, "sk-" + "A" * 30],
)
def test_provider_shape_inside_bearer_jwt_does_not_route_as_provider(embedded_shape):
    """A token prefix inside another credential must not require approval."""
    jwt = "eyJhbGciOiJIUzI1NiJ9." + "abc" + embedded_shape + "xyz.signature"

    assert detect_credential_type(jwt, DEFAULT_RULES) is None
    assert analyze_headers(
        {"Authorization": f"Bearer {jwt}"}, DEFAULT_RULES, {}, {}, ["authorization"]
    ) == []


def test_actual_huggingface_bearer_token_is_still_detected():
    huggingface = "hf_" + "A" * 28
    assert any(
        item["rule_name"] == "huggingface"
        for item in analyze_headers(
            {"Authorization": f"Bearer {huggingface}"}, DEFAULT_RULES, {}, {}, ["authorization"]
        )
    )


def test_huggingface_dlp_distinguishes_embedded_jwt_text_from_a_real_token():
    jwt = "eyJhbGciOiJIUzI1NiJ9." + "hf_" + "A" * 28 + ".signature"
    huggingface = "hf_" + "A" * 28
    family = next(f for f in CREDENTIAL_FAMILIES if f.family_id == "huggingface-token")

    assert not any(re.search(pattern, f"Bearer {jwt}") for pattern in family.effective_dlp_patterns)
    assert any(re.search(pattern, f"Bearer {huggingface}") for pattern in family.effective_dlp_patterns)
    assert any(
        re.search(pattern, f'{{"token":"{huggingface}"}}')
        for pattern in family.effective_dlp_patterns
    )


@pytest.mark.parametrize("prefix", ["hf_", "hf_jwt_", "hf_oauth_"])
def test_huggingface_dlp_respects_token_shape_and_length(prefix):
    family = next(f for f in CREDENTIAL_FAMILIES if f.family_id == "huggingface-token")

    for length, expected in [(19, False), (20, True)]:
        token = prefix + "A" * length
        found = any(
            re.search(pattern, f'{{"token":"{token}"}}')
            for pattern in family.effective_dlp_patterns
        )
        assert found is expected

    if prefix == "hf_":
        # A prefix of a longer invalid token is not a complete credential.
        assert not any(
            re.search(pattern, '"hf_' + "A" * 20 + '_suffix"')
            for pattern in family.effective_dlp_patterns
        )
    else:
        # Specialized tokens may contain underscores and hyphens in their body.
        assert any(
            re.search(pattern, f'{{"token":"{prefix + "A_b-" * 5}"}}')
            for pattern in family.effective_dlp_patterns
        )


def test_default_rules_are_exact_catalogue_projection():
    """Tier 1 must not gain a second hand-maintained provider list."""
    assert [
        {
            "name": rule.name,
            "patterns": rule.patterns,
            "allowed_hosts": rule.allowed_hosts,
            "header_names": rule.header_names,
            "suggested_url": rule.suggested_url,
        }
        for rule in DEFAULT_RULES
    ] == build_default_rule_configs()


def test_dlp_provider_rules_are_exact_catalogue_projection():
    """The secrets set starts with the generated provider DLP rules."""
    generated = build_dlp_pattern_configs()
    assert BUILTIN_PATTERN_SETS["secrets"][: len(generated)] == generated


def test_ambiguous_fallback_is_last_and_destination_unbound():
    ambiguous = CREDENTIAL_FAMILIES[-1]

    assert ambiguous.family_id == "ambiguous-sk"
    assert ambiguous.allowed_hosts == ()


def test_catalogue_entries_have_unique_ids_and_primary_sources():
    family_ids = [family.family_id for family in CREDENTIAL_FAMILIES]

    assert len(family_ids) == len(set(family_ids))
    assert all(family.source_urls for family in CREDENTIAL_FAMILIES)
    assert all(
        url.startswith("https://")
        for family in CREDENTIAL_FAMILIES
        for url in family.source_urls
    )


def test_broader_anthropic_dlp_is_explicit_not_a_tier1_classifier():
    token = "sk-ant-sid01-" + "A_b-" * 8
    anthropic = next(f for f in CREDENTIAL_FAMILIES if f.family_id == "anthropic-routine")

    assert detect_credential_type(token, DEFAULT_RULES) is None
    assert any(re.search(pattern, token) for pattern in anthropic.effective_dlp_patterns)


def test_openrouter_dlp_is_broader_than_destination_classifier():
    token = "sk-or-v1-" + "Z" * 32
    openrouter = next(f for f in CREDENTIAL_FAMILIES if f.family_id == "openrouter-api-key")

    assert detect_credential_type(token, DEFAULT_RULES) is None
    assert any(re.search(pattern, token) for pattern in openrouter.effective_dlp_patterns)
