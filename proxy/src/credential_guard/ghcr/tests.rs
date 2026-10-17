use super::*;
use crate::{
    credential_guard::{Options, OutcomeKind, Pdp},
    credentials::Secret,
    network_guard::Identity,
    policy::{Format, Policy},
};
use serde_json::json;

const QUERY: &str = "/token?service=ghcr.io&scope=repository:owner/image:pull";
const BEARER: &str = "v1.Abcdef0123456789ZYXwvUTSRQPOnmlkjihg";

fn policy(extra: &str) -> Policy {
    Policy::parse(
        &format!("[hosts]\n'*'={{egress='allow',unknown_creds='prompt'}}\n{extra}"),
        Format::Toml,
    )
    .unwrap()
}
fn guard() -> CredentialGuard {
    let guard = CredentialGuard::new(b"ghcr-unit-key");
    guard.load_sensor_config(&json!({})).unwrap();
    guard
}
fn learn(guard: &CredentialGuard, token: &str, now_ms: f64) {
    guard
        .observe_ghcr_response(
            Exchange::from_path(QUERY).unwrap(),
            json!({"token": token}).to_string().as_bytes(),
            now_ms,
        )
        .unwrap();
}
#[allow(clippy::too_many_arguments)]
fn check(
    guard: &CredentialGuard,
    policy: &Policy,
    token: &str,
    host: &str,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    now_ms: f64,
) -> super::super::Outcome {
    let auth = Secret::new(format!("Bearer {token}"));
    let extra: Vec<_> = extra
        .iter()
        .map(|(key, value)| (*key, Secret::new(*value)))
        .collect();
    let mut headers = vec![Header {
        name: "Authorization",
        value: &auth,
    }];
    headers.extend(extra.iter().map(|(name, value)| Header { name, value }));
    guard
        .enforce(
            Pdp::Ready(policy),
            Request {
                identity: Identity::Resolved("alice"),
                host,
                port: 443,
                method,
                path,
                scheme: "https",
                request_id: Some("test-ghcr"),
                connection_id: "test",
                prior_response: false,
                headers: &headers,
            },
            Options::default(),
            now_ms,
        )
        .unwrap()
}

#[test]
fn anonymous_request_requires_exact_origin_and_all_scopes() {
    let guard = guard();
    for query in [
        QUERY,
        "/token?service=ghcr.io",
        "/token?service=ghcr.io&client_id=&offline_token=false&account=",
        "/token?service=ghcr.io&scope=repository:owner/image:pull&offline_token=true",
        "/token?scope=repository%3Aowner%2Fimage%3Apull&service=ghcr.io&client_id=oci-client",
        "/token?service=ghcr.io&scope=repository:owner/image:pull%20repository:other/image:pull",
    ] {
        assert!(
            guard
                .ghcr_exchange(
                    "https",
                    "ghcr.io",
                    443,
                    &Method::GET,
                    query,
                    &HeaderMap::new(),
                    true,
                    false
                )
                .unwrap()
                .is_some()
        );
    }
    for suffix in [
        "&scope=repository:owner/private:pull,push",
        "&scope=repository:owner/private:push",
        "&service=other",
        "&service=ghcr.io",
        "&refresh_token=abc",
        "&account=user",
        "&offline_token=secret",
        "&access_token=abc",
        "&scope=",
        "&scope=repository:owner/../image:pull",
        "&scope=repository:owner%252Fimage:pull",
    ] {
        assert!(
            Exchange::from_path(&format!("{QUERY}{suffix}")).is_none(),
            "{suffix}"
        );
    }
    for (scheme, host, port, method, path, empty, injected) in [
        ("http", "ghcr.io", 443, Method::GET, QUERY, true, false),
        ("https", "other.test", 443, Method::GET, QUERY, true, false),
        ("https", "ghcr.io.", 443, Method::GET, QUERY, true, false),
        ("https", "ghcr.io", 8443, Method::GET, QUERY, true, false),
        ("https", "ghcr.io", 443, Method::POST, QUERY, true, false),
        (
            "https",
            "ghcr.io",
            443,
            Method::GET,
            "/token/?service=ghcr.io&scope=repository:owner/image:pull",
            true,
            false,
        ),
        ("https", "ghcr.io", 443, Method::GET, QUERY, false, false),
        ("https", "ghcr.io", 443, Method::GET, QUERY, true, true),
    ] {
        assert!(
            guard
                .ghcr_exchange(
                    scheme,
                    host,
                    port,
                    &method,
                    path,
                    &HeaderMap::new(),
                    empty,
                    injected
                )
                .unwrap()
                .is_none()
        );
    }
    for name in [
        "authorization",
        "cookie",
        "cookie2",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "trailer",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::HeaderName::from_static(name),
            "".parse().unwrap(),
        );
        assert!(
            guard
                .ghcr_exchange(
                    "https",
                    "ghcr.io",
                    443,
                    &Method::GET,
                    QUERY,
                    &headers,
                    true,
                    false
                )
                .unwrap()
                .is_none(),
            "{name}"
        );
    }
}

#[test]
fn observed_token_retains_policy_and_other_secret_checks() {
    let guard = guard();
    let policy = policy("");
    learn(&guard, BEARER, 1000.);
    learn(&guard, "opaque", 1000.);
    assert_eq!(
        check(
            &guard,
            &policy,
            "opaque",
            "ghcr.io",
            "GET",
            "/v2/owner/image/manifests/latest",
            &[],
            1001.
        )
        .kind,
        OutcomeKind::Allowed
    );
    assert_eq!(
        check(
            &guard,
            &policy,
            "opaque",
            "other.test",
            "GET",
            "/v2/owner/image/manifests/latest",
            &[],
            1001.
        )
        .kind,
        OutcomeKind::Blocked
    );
    for path in [
        "/v2/",
        "/v2",
        "/v2/owner/image/manifests/latest",
        "/v2/owner/image/blobs/sha256:abc",
        "/v2/owner/image/tags/list?n=20",
    ] {
        for method in ["GET", "HEAD"] {
            let outcome = check(&guard, &policy, BEARER, "ghcr.io", method, path, &[], 1001.);
            assert_eq!(outcome.kind, OutcomeKind::Allowed, "{method} {path}");
            assert!(outcome.audit.iter().all(|row| row.approval.is_none()));
            let evidence = serde_json::to_string(&outcome).unwrap();
            assert!(evidence.contains("observed_anonymous_ghcr_pull"));
            assert!(!evidence.contains(BEARER));
        }
    }
    let path = "/v2/owner/image/manifests/latest";
    for (host, method, path) in [
        ("other.test", "GET", path),
        ("ghcr.io", "POST", path),
        ("ghcr.io", "GET", "/v2/owner/private/manifests/latest"),
        ("ghcr.io", "GET", "/v2/owner/image/blobs/uploads/"),
        (
            "ghcr.io",
            "GET",
            "/v2/owner/image/../private/manifests/latest",
        ),
        ("ghcr.io", "GET", "/v2/owner/image/manifests/%2e%2e"),
        (
            "ghcr.io",
            "GET",
            "/v2/owner/image%2Fprivate/manifests/latest",
        ),
    ] {
        assert_eq!(
            check(&guard, &policy, BEARER, host, method, path, &[], 1001.).kind,
            OutcomeKind::Blocked
        );
    }
    for token in [
        format!("{BEARER}x"),
        "v1.UnobservedABC123abcZYX098zyxKLM456klm".into(),
        format!("ghp_{}", "A".repeat(36)),
    ] {
        assert_eq!(
            check(&guard, &policy, &token, "ghcr.io", "GET", path, &[], 1001.).kind,
            OutcomeKind::Blocked
        );
    }
    let outcome = check(
        &guard,
        &policy,
        BEARER,
        "ghcr.io",
        "GET",
        path,
        &[("x-api-key", "sk-abcdefghijklmnopqrstuvwxyz0123456789")],
        1001.,
    );
    assert_eq!(outcome.kind, OutcomeKind::Blocked);
    assert!(
        outcome
            .evaluations
            .iter()
            .any(|entry| entry.finding.header == "x-api-key"
                && entry.effect != crate::network_guard::PdpEffect::Allow)
    );
    for permission in [
        json!({"action":"credential:use","resource":"ghcr.io/*","effect":"deny"}),
        json!({"action":"credential:use","resource":"*","effect":"deny"}),
        json!({"action":"credential:use","resource":"ghcr.io/*","effect":"prompt"}),
        json!({"action":"credential:use","resource":"ghcr.io/*","effect":"deny","condition":{"credential":["unknown:*"]}}),
    ] {
        let deny=Policy::parse(&json!({"hosts":{"*":{"egress":"allow","unknown_credentials":"prompt"},"ghcr.io":{"rules":[permission]}}}).to_string(),Format::Json).unwrap();
        assert_eq!(
            check(&guard, &deny, BEARER, "ghcr.io", "GET", path, &[], 1001.).kind,
            OutcomeKind::Blocked
        );
    }
    for extra in [
        "'ghcr.io'={egress='deny'}",
        "'*'={egress='allow',unknown_creds='deny'}",
    ] {
        let deny = if extra.starts_with("'*'") {
            Policy::parse(&format!("[hosts]\n{extra}"), Format::Toml).unwrap()
        } else {
            self::policy(extra)
        };
        assert_eq!(
            check(&guard, &deny, BEARER, "ghcr.io", "GET", path, &[], 1001.).kind,
            OutcomeKind::Blocked,
            "{extra}"
        );
    }
}

#[test]
fn generated_scopes_response_types_and_bearer_mutations_do_not_broaden_recognition() {
    for service in ["ghcr.io", "ghcr%2Eio"] {
        for repository in ["owner/other", "owner/deep/image", "owner/image-copy"] {
            for action in [
                "pull",
                "push",
                "pull,push",
                "delete",
                "",
                "pull%00",
                "pull%2Cpush",
                "pull%252Cpush",
            ] {
                let query = format!(
                    "/token?service={service}&scope=repository:owner/image:pull&scope=repository:{repository}:{action}"
                );
                assert_eq!(
                    Exchange::from_path(&query).is_some(),
                    action == "pull",
                    "{query}"
                );
            }
        }
    }
    for field in ["token", "access_token", "expires_in", "issued_at"] {
        for invalid in [json!(null), json!(false), json!([]), json!({}), json!("")] {
            let guard = guard();
            let mut response = json!({"token":BEARER});
            response[field] = invalid;
            guard
                .observe_ghcr_response(
                    Exchange::from_path(QUERY).unwrap(),
                    response.to_string().as_bytes(),
                    1000.,
                )
                .unwrap();
            assert!(
                guard.ghcr_tokens.lock().unwrap().0.is_empty(),
                "invalid {field} accepted"
            );
        }
    }
    let guard = guard();
    let policy = policy("");
    learn(&guard, BEARER, 1000.);
    let path = "/v2/owner/image/manifests/latest";
    for index in 0..BEARER.len() {
        let mut altered = BEARER.as_bytes().to_vec();
        altered[index] = if altered[index] == b'X' { b'Y' } else { b'X' };
        assert_eq!(
            check(
                &guard,
                &policy,
                std::str::from_utf8(&altered).unwrap(),
                "ghcr.io",
                "GET",
                path,
                &[],
                1001.
            )
            .kind,
            OutcomeKind::Blocked
        );
    }
    assert_eq!(
        check(
            &guard,
            &policy,
            BEARER,
            "ghcr.io",
            "GET",
            path,
            &[("Authorization", BEARER)],
            1001.
        )
        .kind,
        OutcomeKind::Blocked
    );
}

#[test]
fn malformed_response_never_registers_and_missing_expiry_is_bounded() {
    let guard = guard();
    let now = Instant::now();
    for body in [
        json!({}),
        json!({"token":null}),
        json!({"token":42}),
        json!({"token":BEARER,"access_token":"different"}),
        json!({"token":BEARER,"expires_in":0}),
        json!({"token":BEARER,"expires_in":-1}),
        json!({"token":BEARER,"expires_in":"3600"}),
        json!({"token":BEARER,"issued_at":"bad"}),
        json!({"token":BEARER,"expires_in":1,"issued_at":"1970-01-01T00:00:00Z"}),
        json!({"token":"bad bearer"}),
    ] {
        guard
            .observe_ghcr_at(
                Exchange::from_path(QUERY).unwrap(),
                body.to_string().as_bytes(),
                1000.,
                now,
            )
            .unwrap();
        assert_eq!(guard.ghcr_tokens.lock().unwrap().0.len(), 0);
    }
    for body in [
        format!("{{\"token\":\"{BEARER}\",\"token\":\"other\"}}"),
        format!("{{\"token\":\"{BEARER}\"}} trailing"),
        "[1,2,3]".into(),
        "{".into(),
    ] {
        guard
            .observe_ghcr_at(
                Exchange::from_path(QUERY).unwrap(),
                body.as_bytes(),
                1000.,
                now,
            )
            .unwrap();
        assert!(guard.ghcr_tokens.lock().unwrap().0.is_empty());
    }
    for index in 0..MAX_TOKENS + 20 {
        learn(&guard, &format!("{BEARER}{index}"), 1000.);
    }
    assert_eq!(guard.ghcr_tokens.lock().unwrap().0.len(), MAX_TOKENS);
    let policy = policy("");
    let path = "/v2/owner/image/manifests/latest";
    assert_eq!(
        check(
            &guard,
            &policy,
            &format!("{BEARER}0"),
            "ghcr.io",
            "GET",
            path,
            &[],
            1001.
        )
        .kind,
        OutcomeKind::Blocked
    );
    let latest = format!("{BEARER}{}", MAX_TOKENS + 19);
    assert_eq!(
        check(&guard, &policy, &latest, "ghcr.io", "GET", path, &[], 1001.).kind,
        OutcomeKind::Allowed
    );
    // Cache retention is monotonic even if wall time does not advance.
    guard
        .observe_ghcr_at(
            Exchange::from_path(QUERY).unwrap(),
            json!({"token":BEARER}).to_string().as_bytes(),
            1000.,
            now + RETENTION + Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(guard.ghcr_tokens.lock().unwrap().0.len(), 1);
    // Process replacement and a changed fingerprint key clear recognition.
    let restarted = self::guard();
    assert_eq!(
        check(
            &restarted,
            &policy,
            BEARER,
            "ghcr.io",
            "GET",
            path,
            &[],
            1001.
        )
        .kind,
        OutcomeKind::Blocked
    );
    let (reload, _) = guard.prepare_policy(&policy).unwrap();
    assert_eq!(
        check(&reload, &policy, BEARER, "ghcr.io", "GET", path, &[], 1001.).kind,
        OutcomeKind::Allowed
    );
    let (rekey, _) = guard
        .prepare_policy_with_key(&policy, Some(b"replacement-key"))
        .unwrap();
    assert_eq!(
        check(&rekey, &policy, BEARER, "ghcr.io", "GET", path, &[], 1001.).kind,
        OutcomeKind::Blocked
    );
    let expiring = self::guard();
    expiring
        .observe_ghcr_response(
            Exchange::from_path(QUERY).unwrap(),
            json!({"access_token":BEARER,"expires_in":1})
                .to_string()
                .as_bytes(),
            1000.,
        )
        .unwrap();
    assert_eq!(
        check(
            &expiring,
            &policy,
            BEARER,
            "ghcr.io",
            "GET",
            path,
            &[],
            1999.
        )
        .kind,
        OutcomeKind::Allowed
    );
    assert_eq!(
        check(
            &expiring,
            &policy,
            BEARER,
            "ghcr.io",
            "GET",
            path,
            &[],
            2000.
        )
        .kind,
        OutcomeKind::Blocked
    );
}
