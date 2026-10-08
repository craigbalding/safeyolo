use hyper::header::{HeaderMap, HeaderValue};
use safeyolo_proxy::{
    credential_injection::*,
    credentials::{Credential, ErrorKind as VaultErrorKind, Secret, Vault, VaultError},
    oauth::{
        NotNeeded, OAuthRefresh, RefreshError, RefreshOutcome, RefreshResponse, RefreshStart,
        TransportFailure,
    },
    services::CredentialSelection,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_704_067_200).unwrap()
}
fn selection(kind: Option<&str>) -> CredentialSelection {
    CredentialSelection {
        agent: "alice".into(),
        service: "demo".into(),
        capability: "reader".into(),
        vault_token: "demo-key".into(),
        account: "operator".into(),
        auth_kind: kind.map(str::to_owned),
        auth_header: "X-Credential".into(),
        auth_scheme: "Bearer".into(),
        allow_http: false,
        refresh_on_401: false,
        risky_route: None,
        contract_operation: None,
    }
}
fn credential() -> Credential {
    Credential::new("demo-key", "api_key", Secret::new("synthetic-value"))
}
fn oauth() -> Credential {
    let mut c = credential();
    c.credential_type = "oauth2".into();
    c.refresh_token = Some(Secret::new("synthetic-refresh"));
    c.token_url = Some("https://provider.invalid/token".into());
    c.expires_at = Some("2020-01-01T00:00:00+00:00".into());
    c
}
fn vault() -> (tempfile::TempDir, Vault) {
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::unlock(
        directory.path().join("vault.enc"),
        &Secret::new("synthetic-passphrase"),
    )
    .unwrap();
    (directory, vault)
}
fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("before", HeaderValue::from_static("one"));
    headers.append("x-credential", HeaderValue::from_static("sgw_synthetic"));
    headers.append("x-credential", HeaderValue::from_static("sgw_duplicate"));
    headers.insert("after", HeaderValue::from_static("two"));
    headers
}
fn start(
    selection: CredentialSelection,
    vault: Option<&Vault>,
    scheme: &str,
) -> Result<Start, Error> {
    let url = Secret::new(format!(
        "{scheme}://api.example:8080/signed/%2F?Q=a%2Bb&Q=%252F"
    ));
    prepare(
        selection,
        vault,
        RequestInfo {
            method: "GET",
            host: "api.example",
            path: "/signed/%2F?Q=a%2Bb&Q=%252F",
            scheme,
            full_url: &url,
            request_id: Some("req-generated"),
        },
        now(),
    )
}
fn ready(start: Start) -> HeaderReplacement {
    match start {
        Start::Ready(value) => value,
        _ => panic!("expected ready"),
    }
}
fn pending(start: Start) -> Box<PendingInjection> {
    match start {
        Start::Refresh(value) => value,
        _ => panic!("expected refresh"),
    }
}
#[test]
fn exact_auth_kind_drives_validated_sensitive_header_replacement() {
    let (_directory, vault) = vault();
    vault.store(credential()).unwrap();
    for (kind, expected) in [
        (Some("bearer"), Some("Bearer synthetic-value")),
        (Some("api_key"), Some("synthetic-value")),
        (Some("Bearer"), None),
        (Some("custom"), None),
        (Some(""), None),
        (None, None),
    ] {
        let mut headers = headers();
        let header_name = if kind.is_some() {
            "x-credential"
        } else {
            "authorization"
        };
        if kind.is_none() {
            headers.remove("x-credential");
            headers.insert("authorization", HeaderValue::from_static("sgw_synthetic"));
        }
        let result = ready(start(selection(kind), Some(&vault), "https").unwrap())
            .apply(&mut headers)
            .unwrap();
        assert_eq!(
            headers.get_all(header_name).iter().count(),
            usize::from(expected.is_some())
        );
        assert_eq!(
            headers
                .get(header_name)
                .map(|value| value.to_str().unwrap()),
            expected
        );
        if let Some(value) = headers.get(header_name) {
            assert!(value.is_sensitive());
            assert!(!format!("{value:?}").contains("synthetic-value"));
        }
        assert_eq!(headers["before"], "one");
        assert_eq!(headers["after"], "two");
        assert_eq!(
            result.metadata["gateway_injected_header"],
            if kind.is_some() {
                json!("X-Credential")
            } else {
                Value::Null
            }
        );
        assert_eq!(result.stats.injected, u64::from(kind.is_some()));
        assert_eq!(
            result.trace.as_ref().unwrap().outcome,
            if kind.is_some() {
                "injected"
            } else {
                "authorized"
            }
        );
        assert_eq!(result.audit.last().unwrap().event, "gateway.allow");
    }
    let mut selected = selection(Some("bearer"));
    selected.auth_scheme = String::new();
    let mut empty = credential();
    empty.value = Secret::new("");
    vault.store(empty).unwrap();
    let mut headers = headers();
    ready(start(selected, Some(&vault), "https").unwrap())
        .apply(&mut headers)
        .unwrap();
    assert_eq!(headers["x-credential"], " ");
}
#[test]
fn redirects_vault_denials_and_expiry_follow_the_actual_stage_order() {
    let (_directory, vault) = vault();
    vault.store(credential()).unwrap();
    let Start::Redirect(redirect) = start(selection(Some("bearer")), Some(&vault), "http").unwrap()
    else {
        panic!("expected redirect")
    };
    assert_eq!(
        redirect.location().expose_secret(),
        "https://api.example:8080/signed/%2F?Q=a%2Bb&Q=%252F"
    );
    assert!(redirect.body().is_empty());
    assert_eq!(redirect.evidence.stats, StatsDelta::default());
    assert!(redirect.evidence.metadata.as_object().unwrap().is_empty());
    assert!(redirect.evidence.trace.is_none());
    let mut selected = selection(Some("api_key"));
    selected.allow_http = true;
    let result = ready(start(selected, Some(&vault), "http").unwrap())
        .apply(&mut headers())
        .unwrap();
    assert_eq!(
        result
            .audit
            .iter()
            .map(|event| event.event)
            .collect::<Vec<_>>(),
        vec!["gateway.http_injection_allowed", "gateway.allow"]
    );
    let Start::Blocked(unavailable) = start(selection(Some("bearer")), None, "http").unwrap()
    else {
        panic!("expected block")
    };
    assert_eq!(
        unavailable.response.body["reason_codes"],
        json!(["VAULT_UNAVAILABLE"])
    );
    vault.remove("demo-key").unwrap();
    let Start::Blocked(missing) = start(selection(Some("bearer")), Some(&vault), "http").unwrap()
    else {
        panic!("expected block")
    };
    assert_eq!(missing.response.status, 503);
    assert_eq!(missing.response.body["action"], "self_correct");
    let mut token_headers = HeaderMap::new();
    token_headers.insert("authorization", HeaderValue::from_static("sgw_synthetic"));
    let no_auth = ready(start(selection(None), None, "http").unwrap())
        .apply(&mut token_headers)
        .unwrap();
    assert!(!token_headers.contains_key("authorization"));
    assert_eq!(no_auth.metadata["gateway_injected_header"], Value::Null);
    assert_eq!(no_auth.stats.injected, 0);
    let mut c = oauth();
    c.expires_at = Some("2020-01-01T00:00:00".into());
    vault.store(c).unwrap();
    let error = match start(selection(Some("bearer")), Some(&vault), "https") {
        Err(error) => error,
        _ => panic!("naive expiry must fail even with refresh flag false"),
    };
    assert!(matches!(error.kind, ErrorKind::Expiry(_)));
    assert!(matches!(
        start(selection(None), Some(&vault), "https").unwrap(),
        Start::Ready(_)
    ));
}
#[test]
fn actual_oauth_refresh_reloads_vault_and_happens_before_plaintext_redirect() {
    let (_directory, vault) = vault();
    vault.store(oauth()).unwrap();
    let refresh = OAuthRefresh::new(vault.clone());
    let mut selected = selection(Some("bearer"));
    selected.refresh_on_401 = true;
    let prepared = pending(start(selected.clone(), Some(&vault), "http").unwrap());
    let RefreshStart::Leader(attempt) = refresh.begin(prepared.credential_name(), now()).unwrap()
    else {
        panic!("leader expected")
    };
    let outcome = attempt.complete(
        Ok(RefreshResponse::new(
            200,
            br#"{"access_token":"synthetic-new","expires_in":3600}"#.to_vec(),
        )),
        now(),
    );
    assert_eq!(outcome, RefreshOutcome::Refreshed);
    let Start::Redirect(redirect) = prepared.resume(outcome).unwrap() else {
        panic!("refresh must finish before redirect")
    };
    assert_eq!(redirect.evidence.stats.refreshed, 1);
    assert_eq!(redirect.evidence.stats.injected, 0);
    assert_eq!(
        vault
            .get("demo-key")
            .unwrap()
            .unwrap()
            .value
            .expose_secret(),
        "synthetic-new"
    );
    vault.store(oauth()).unwrap();
    let prepared = pending(start(selected.clone(), Some(&vault), "https").unwrap());
    let RefreshStart::Leader(attempt) = refresh.begin(prepared.credential_name(), now()).unwrap()
    else {
        panic!("leader expected")
    };
    let outcome = attempt.complete(
        Ok(RefreshResponse::new(
            200,
            br#"{"access_token":"synthetic-new"}"#.to_vec(),
        )),
        now(),
    );
    let mut replacement = credential();
    replacement.value = Secret::new("synthetic-admin-current");
    vault.store(replacement).unwrap();
    let mut headers = headers();
    let result = ready(prepared.resume(outcome).unwrap())
        .apply(&mut headers)
        .unwrap();
    assert_eq!(headers["x-credential"], "Bearer synthetic-admin-current");
    assert_eq!(result.stats.refreshed, 1);
    vault.store(oauth()).unwrap();
    let prepared = pending(start(selected, Some(&vault), "https").unwrap());
    vault.remove("demo-key").unwrap();
    let Start::Blocked(missing) = prepared.resume(RefreshOutcome::Refreshed).unwrap() else {
        panic!("no fallback")
    };
    assert_eq!(
        missing.response.body["error"],
        "Credential lost after refresh"
    );
    assert_eq!(missing.evidence.stats.refreshed, 1);
}
#[test]
fn rejected_cancelled_superseded_and_changed_retained_results_never_inject_old_snapshot() {
    let (_directory, vault) = vault();
    let mut selected = selection(Some("bearer"));
    selected.refresh_on_401 = true;
    for outcome in [
        RefreshOutcome::Rejected(RefreshError::MissingAccessToken),
        RefreshOutcome::Cancelled,
        RefreshOutcome::Superseded,
    ] {
        vault.store(oauth()).unwrap();
        let prepared = pending(start(selected.clone(), Some(&vault), "https").unwrap());
        assert!(prepared.resume(outcome).is_err());
    }
    let retained = RefreshOutcome::Retained(RefreshError::Transport(TransportFailure::Timeout));
    vault.store(oauth()).unwrap();
    let prepared = pending(start(selected.clone(), Some(&vault), "https").unwrap());
    let Err(error) = prepared.resume(retained) else {
        panic!("a failed refresh cannot fall back to ordinary injection")
    };
    assert_eq!(
        error.kind,
        ErrorKind::Refresh(RefreshError::Transport(TransportFailure::Timeout))
    );
    vault.store(oauth()).unwrap();
    let prepared = pending(start(selected.clone(), Some(&vault), "https").unwrap());
    let Start::Blocked(blocked) = prepared.resume_for_gateway(retained).unwrap() else {
        panic!("gateway refresh failure must be an explicit blocked result")
    };
    assert_eq!(blocked.response.status, 503);
    assert_eq!(blocked.evidence.stats, StatsDelta::default());
    assert_eq!(
        blocked.response.body["reason_codes"],
        json!(["REFRESH_TRANSPORT"])
    );
    assert!(
        !blocked
            .response
            .body
            .to_string()
            .contains("synthetic-value")
    );
    for mutation in ["store", "remove", "aba"] {
        vault.store(oauth()).unwrap();
        let prepared = pending(start(selected.clone(), Some(&vault), "https").unwrap());
        match mutation {
            "store" => vault.store(oauth()).unwrap(),
            "remove" => {
                vault.remove("demo-key").unwrap();
            }
            _ => {
                vault.remove("demo-key").unwrap();
                vault.store(oauth()).unwrap();
            }
        }
        let Err(error) = prepared.resume(retained) else {
            panic!("must reject stale snapshot")
        };
        assert_eq!(error.kind, ErrorKind::Superseded);
    }
    let mut no_refresh = oauth();
    no_refresh.refresh_token = None;
    vault.store(no_refresh).unwrap();
    let prepared = pending(start(selected.clone(), Some(&vault), "https").unwrap());
    assert!(matches!(
        prepared.not_needed(NotNeeded::MissingRefreshToken).unwrap(),
        Start::Ready(_)
    ));
    let mut no_url = oauth();
    no_url.token_url = None;
    vault.store(no_url).unwrap();
    let prepared = pending(start(selected.clone(), Some(&vault), "https").unwrap());
    assert!(matches!(
        prepared.not_needed(NotNeeded::MissingTokenUrl).unwrap(),
        Start::Ready(_)
    ));
    vault.store(oauth()).unwrap();
    let prepared = pending(start(selected, Some(&vault), "https").unwrap());
    let Err(error) = prepared.not_needed(NotNeeded::NotExpired) else {
        panic!("changed refresh observation")
    };
    assert_eq!(error.kind, ErrorKind::Superseded);
}

#[test]
fn gateway_refresh_failures_are_categorical_secret_free_and_counted_as_blocked() {
    let (_directory, vault) = vault();
    let mut selected = selection(Some("bearer"));
    selected.refresh_on_401 = true;
    let failures = [
        (
            RefreshOutcome::Rejected(RefreshError::MissingAccessToken),
            "REFRESH_INVALID_RESPONSE",
        ),
        (
            RefreshOutcome::Rejected(RefreshError::ExpiryType),
            "REFRESH_EXPIRY",
        ),
        (
            RefreshOutcome::Rejected(RefreshError::Vault(VaultError {
                kind: VaultErrorKind::Io,
                io_kind: None,
            })),
            "REFRESH_SAVE",
        ),
        (
            RefreshOutcome::Rejected(RefreshError::Vault(VaultError {
                kind: VaultErrorKind::Activation,
                io_kind: None,
            })),
            "REFRESH_ACTIVATION",
        ),
        (RefreshOutcome::Superseded, "REFRESH_SUPERSEDED"),
        (RefreshOutcome::Cancelled, "REFRESH_CANCELLED"),
    ];
    for (outcome, reason) in failures {
        vault.store(oauth()).unwrap();
        let prepared = pending(start(selected.clone(), Some(&vault), "https").unwrap());
        let Start::Blocked(blocked) = prepared.resume_for_gateway(outcome).unwrap() else {
            panic!("refresh failure must block before injection")
        };
        assert_eq!(blocked.response.status, 503);
        assert_eq!(blocked.evidence.stats, StatsDelta::default());
        assert_eq!(blocked.response.body["reason_codes"], json!([reason]));
        assert_eq!(blocked.evidence.audit.len(), 1);
        assert_eq!(blocked.evidence.audit[0].event, "gateway.refresh_failed");
        let serialized = format!(
            "{}{}{}",
            blocked.response.body,
            blocked.evidence.metadata,
            blocked.evidence.trace.as_ref().unwrap().details
        );
        assert!(!serialized.contains("synthetic-value"));
    }
}
#[test]
fn malformed_header_material_is_rejected_before_gateway_token_removal() {
    let (_directory, vault) = vault();
    for value in [
        "synthetic\r\nX-Injected: yes",
        "synthetic\nX-Injected: yes",
        "synthetic\0value",
    ] {
        let mut c = credential();
        c.value = Secret::new(value);
        vault.store(c).unwrap();
        let original = headers();
        let Err(error) = start(selection(Some("bearer")), Some(&vault), "https") else {
            panic!("invalid field value")
        };
        assert_eq!(error.kind, ErrorKind::InvalidHeaderValue);
        assert_eq!(original.get_all("x-credential").iter().count(), 2);
        assert!(!format!("{error:?}").contains(value));
    }
    vault.store(credential()).unwrap();
    let mut selected = selection(Some("api_key"));
    selected.auth_header = "Bad\r\nName".into();
    let Err(error) = start(selected, Some(&vault), "https") else {
        panic!("invalid field name")
    };
    assert_eq!(error.kind, ErrorKind::InvalidHeaderName);
    let mut missing = HeaderMap::new();
    missing.insert("untouched", HeaderValue::from_static("value"));
    let before = missing.clone();
    let Err(error) =
        ready(start(selection(Some("bearer")), Some(&vault), "https").unwrap()).apply(&mut missing)
    else {
        panic!("missing header")
    };
    assert_eq!(error.kind, ErrorKind::MissingHeader);
    assert_eq!(missing, before);
}

#[test]
fn existing_service_selection_and_credential_guard_see_the_injected_secret() {
    use safeyolo_proxy::{
        contracts::ContractRequest,
        credential_guard::{CredentialGuard, Header, Options, OutcomeKind, Pdp, Request},
        network_guard::Identity,
        policy::{Format, Policy},
        services::{
            GatewayDecision, GatewayRequest, Registry, RouteMode, TokenBinding, TrustedIdentity,
            select_route,
        },
    };
    let document = json!({"schema_version":1,"name":"demo","auth":{"type":"bearer","header":"Authorization"},"capabilities":{"reader":{"routes":[{"methods":["GET"],"path":"/**"}]}}});
    let registry =
        Registry::from_sources(&[("demo.yaml".into(), document.to_string())], &[]).unwrap();
    let hosts = [("api.example".into(), "demo".into())].into();
    let token = TokenBinding {
        token: Secret::new("sgw_synthetic"),
        agent: "alice".into(),
        service: "demo".into(),
        capability: "reader".into(),
        vault_token: "demo-key".into(),
        account: "operator".into(),
    };
    let input_headers = vec![("Authorization".into(), "Bearer sgw_synthetic".into())];
    let route_policy = Policy::parse("{\"permissions\":[]}", Format::Json)
        .unwrap()
        .with_gateway_routes(&safeyolo_proxy::services::compile_routes(
            &registry.services["demo"],
            &token,
            &[],
        ));
    let GatewayDecision::Selected {
        credential: selected,
    } = select_route(
        &registry,
        &hosts,
        &[token],
        &[],
        GatewayRequest {
            identity: TrustedIdentity::Agent("alice"),
            host: "api.example",
            route_mode: RouteMode::CompiledPolicy(&route_policy),
            request: ContractRequest {
                method: "GET",
                target: "/resource",
                headers: &input_headers,
                body: b"",
            },
        },
    )
    else {
        panic!("selected service")
    };
    assert_eq!(selected.auth_kind.as_deref(), Some("bearer"));
    let (_directory, vault) = vault();
    let mut c = credential();
    c.value = Secret::new(format!("ghp_{}", "A".repeat(36)));
    vault.store(c).unwrap();
    let guard = CredentialGuard::new(b"synthetic-hmac");
    guard.load_sensor_config(&json!({})).unwrap();
    let original = Secret::new("Bearer sgw_synthetic");
    assert!(
        guard
            .classify_headers(&[Header {
                name: "Authorization",
                value: &original
            }])
            .unwrap()
            .is_empty()
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_static("Bearer sgw_synthetic"),
    );
    ready(start(*selected, Some(&vault), "https").unwrap())
        .apply(&mut headers)
        .unwrap();
    let value = Secret::new(headers["authorization"].to_str().unwrap());
    let input = [Header {
        name: "Authorization",
        value: &value,
    }];
    let findings = guard.classify_headers(&input).unwrap();
    assert_eq!(findings[0].credential_type.as_deref(), Some("github"));
    let policy=Policy::parse(r#"{"permissions":[{"action":"credential:use","resource":"*","effect":"deny"},{"action":"network:request","resource":"*","effect":"allow"}]}"#,Format::Json).unwrap();
    let outcome = guard
        .enforce(
            Pdp::Ready(&policy),
            Request {
                identity: Identity::Resolved("alice"),
                host: "api.example",
                port: 443,
                method: "GET",
                path: "/resource",
                scheme: "https",
                request_id: Some("req-generated"),
                connection_id: "conn-generated",
                prior_response: false,
                headers: &input,
            },
            Options::default(),
            1000.,
        )
        .unwrap();
    assert_eq!(outcome.kind, OutcomeKind::Blocked);
    assert_eq!(outcome.response.unwrap().status, 403);
}
