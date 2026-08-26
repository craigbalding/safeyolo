"""Tests for sensor-to-PDP event translation."""


def test_catalogue_credential_type_is_not_collapsed_to_unknown(make_flow):
    from safeyolo.core.sensor_utils import build_http_event_from_flow

    flow = make_flow(
        method="POST",
        url="https://openrouter.ai/api/v1/chat/completions",
        headers={"Authorization": "Bearer redacted"},
    )
    event = build_http_event_from_flow(
        flow,
        "agent:test",
        credential_detected=True,
        credential_type="openrouter",
        credential_fingerprint="abc123",
        credential_confidence="high",
    )

    assert event.credential.type == "openrouter"


def test_known_credential_type_keeps_compatibility_enum(make_flow):
    from pdp import CredentialType
    from safeyolo.core.sensor_utils import build_http_event_from_flow

    flow = make_flow(url="https://api.openai.com/v1/models")
    event = build_http_event_from_flow(
        flow,
        "agent:test",
        credential_detected=True,
        credential_type="OPENAI",
        credential_fingerprint="abc123",
        credential_confidence="high",
    )

    assert event.credential.type == CredentialType.OPENAI
