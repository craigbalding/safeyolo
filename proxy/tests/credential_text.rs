use safeyolo_proxy::{
    credential_guard::{CredentialGuard, Error, Options, OutcomeKind, Pdp},
    network_guard::Identity,
    policy::{Format, Policy},
};
use serde_json::json;

fn sensor() -> serde_json::Value {
    json!({
        "policy_hash": "text-adapter",
        "addons": {"credential_guard": {"use_default_credential_rules": false}},
        "credential_rules": [{
            "name": "synthetic",
            "patterns": ["key-[a-z]+"],
            "allowed_hosts": ["api.example"],
            "header_names": ["authorization", "x-api-key"]
        }]
    })
}

fn policy() -> Policy {
    Policy::parse(
        &json!({
            "permissions": [
                {"action": "credential:use", "resource": "*", "effect": "allow"},
                {"action": "network:request", "resource": "*", "effect": "allow"}
            ]
        })
        .to_string(),
        Format::Json,
    )
    .unwrap()
}

#[test]
fn ordered_grouped_fields_reach_one_guard_call_without_header_map_reconstruction() {
    let guard = CredentialGuard::new(b"synthetic-key");
    guard.load_sensor_config(&sensor()).unwrap();
    let policy = policy();
    let fields = [
        (b"X-Api-Key".as_slice(), b"ordinary".as_slice()),
        (
            b"Authorization".as_slice(),
            b"Bearer key-synthetic".as_slice(),
        ),
        // This is the source-combined duplicate value supplied by
        // RequestHeaders, including the exact comma-space separator.
        (b"x-api-key".as_slice(), b"first, key-second".as_slice()),
    ];
    let outcome = guard
        .enforce_ordered(
            Pdp::Ready(&policy),
            Identity::Resolved("alice"),
            "api.example",
            443,
            "GET",
            "/signed/%2F?Q=a%2Bb&Q=%252F",
            "https",
            Some("req-text-adapter"),
            "conn-text-adapter",
            false,
            fields,
            Options { block: true },
            1000.,
        )
        .unwrap();
    assert_eq!(outcome.kind, OutcomeKind::Allowed);
    assert_eq!(outcome.evaluations.len(), 2);
    assert_eq!(
        outcome
            .evaluations
            .iter()
            .map(|evaluation| evaluation.finding.header.as_str())
            .collect::<Vec<_>>(),
        ["Authorization", "x-api-key"]
    );
    assert!(outcome.response.is_none());
    assert_eq!(guard.stats().unwrap().violations_total, 0);
    let event = outcome.audit[0].event(safeyolo_proxy::audit::Attribution {
        evidence_owner: Some("alice".into()),
        trusted_transport_identity: Some("alice".into()),
        initiator: Some(safeyolo_proxy::audit::Initiator::Agent),
        status: Some(safeyolo_proxy::audit::AttributionStatus::Resolved),
        provenance: None,
    });
    assert_eq!(event.event, "security.credential_guard");
    assert_eq!(event.agent.as_deref(), Some("alice"));
    assert!(!event.summary.contains("key-synthetic"));
}

#[test]
fn invalid_admitted_bytes_are_an_error_and_cannot_become_no_detection() {
    let guard = CredentialGuard::new(b"synthetic-key");
    guard.load_sensor_config(&sensor()).unwrap();
    let policy = policy();
    let result = guard.enforce_ordered(
        Pdp::Ready(&policy),
        Identity::Resolved("alice"),
        "api.example",
        443,
        "GET",
        "/",
        "https",
        Some("req-invalid-text"),
        "conn-invalid-text",
        false,
        [(b"Authorization".as_slice(), b"Bearer key-a\xff".as_slice())],
        Options { block: true },
        1000.,
    );
    assert_eq!(result, Err(Error::InvalidHeaderEncoding));
    assert!(!result.unwrap_err().to_string().contains("key-a"));
}

#[test]
fn bypass_and_identity_containment_precede_strict_text_conversion() {
    let guard = CredentialGuard::new(b"synthetic-key");
    guard.load_sensor_config(&sensor()).unwrap();
    let policy = policy();
    let fields = [(b"Authorization".as_slice(), b"Bearer key-a\xff".as_slice())];
    let bypassed = guard
        .enforce_ordered(
            Pdp::Ready(&policy),
            Identity::Resolved("alice"),
            "api.example",
            443,
            "GET",
            "/",
            "https",
            Some("req-prior"),
            "conn-prior",
            true,
            fields,
            Options::default(),
            1000.,
        )
        .unwrap();
    assert_eq!(bypassed.kind, OutcomeKind::Bypassed);

    let disabled = Policy::parse(
        &json!({"permissions":[],"addons":{"credential_guard":{"enabled":false}}}).to_string(),
        Format::Json,
    )
    .unwrap();
    let bypassed = guard
        .enforce_ordered(
            Pdp::Ready(&disabled),
            Identity::Resolved("alice"),
            "api.example",
            443,
            "GET",
            "/",
            "https",
            Some("req-disabled"),
            "conn-disabled",
            false,
            fields,
            Options::default(),
            1000.,
        )
        .unwrap();
    assert_eq!(bypassed.kind, OutcomeKind::Bypassed);

    let conflict = guard
        .enforce_ordered(
            Pdp::Ready(&policy),
            Identity::Conflict,
            "api.example",
            443,
            "GET",
            "/",
            "https",
            Some("req-conflict"),
            "conn-conflict",
            false,
            fields,
            Options::default(),
            1000.,
        )
        .unwrap();
    assert_eq!(conflict.kind, OutcomeKind::Blocked);
    assert_eq!(
        conflict.response.as_ref().map(|response| response.status),
        Some(403)
    );
}
