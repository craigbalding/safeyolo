use base64::{Engine as _, engine::general_purpose::STANDARD};
use safeyolo_proxy::{
    contracts::ContractRequest,
    credentials::Secret,
    github_git::GitHubRequest,
    services::{
        GatewayDecision, GatewayRequest, HostMap, Registry, RouteMode, TokenBinding,
        TrustedIdentity, select_route,
    },
};
use serde_json::json;

const TOKEN: &str = "sgw_git_fixture";

fn registry() -> Registry {
    let source = include_str!("../../cli/src/safeyolo/services/github-git.yaml")
        .replace("/*/*.git/", "/owner/allowed.git/");
    Registry::from_sources(&[("github-git.yaml".into(), source)], &[]).unwrap()
}

fn select(
    capability: &str,
    agent: &str,
    host: &str,
    method: &str,
    target: &str,
    authorization: &str,
) -> GatewayDecision {
    let registry = registry();
    let headers = vec![("Authorization".into(), authorization.into())];
    let binding = TokenBinding {
        token: Secret::new(TOKEN),
        agent: json!("alice"),
        service: json!("github-git"),
        capability: json!(capability),
        vault_token: json!("host-pat"),
        account: json!("owned"),
    };
    let hosts = HostMap::from([("github.com".into(), "github-git".into())]);
    select_route(
        &registry,
        &hosts,
        &[binding],
        &[],
        GatewayRequest {
            identity: TrustedIdentity::Agent(agent),
            host,
            request: ContractRequest {
                method,
                target,
                headers: &headers,
                body: &[],
            },
            route_mode: RouteMode::LocalFallback,
        },
    )
}

fn basic(password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("guest:{password}")))
}

#[test]
fn git_discovery_and_pack_have_the_same_canonical_repository_operation() {
    let discover =
        GitHubRequest::parse("GET", "/Owner/Allowed/info/refs?service=git-receive-pack").unwrap();
    let pack = GitHubRequest::parse("POST", "/owner/allowed.git/git-receive-pack").unwrap();
    assert_eq!(discover.repository, "owner/allowed");
    assert_eq!(discover.path, pack.path);
    assert_eq!(discover.operation, pack.operation);
    assert!(discover.discovery);
    assert!(!pack.discovery);
    for (method, target) in [
        (
            "GET",
            "/owner/allowed.git/info/refs?service=git-upload-pack&service=git-receive-pack",
        ),
        (
            "GET",
            "/owner/allowed.git/info/refs?service=git%2dreceive-pack",
        ),
        (
            "GET",
            "/owner/allowed.git/info/refs?service=git-receive-pack&x=1",
        ),
        (
            "POST",
            "/owner/allowed.git/git-upload-pack?service=git-receive-pack",
        ),
        ("GET", "/owner/allowed.git/git-receive-pack"),
        ("POST", "/owner/allowed.git/extra/git-receive-pack"),
    ] {
        assert!(
            GitHubRequest::parse(method, target).is_none(),
            "{method} {target}"
        );
    }
}

#[test]
fn repository_and_operation_policy_apply_before_credential_selection() {
    let auth = basic(TOKEN);
    for target in [
        "/owner/allowed.git/info/refs?service=git-upload-pack",
        "/Owner/Allowed/info/refs?service=git-upload-pack",
    ] {
        let GatewayDecision::Selected { credential } =
            select("fetch", "alice", "github.com", "GET", target, &auth)
        else {
            panic!("fetch must select");
        };
        assert!(credential.risky_route.is_none());
        assert_eq!(credential.github_git.unwrap().repository, "owner/allowed");
    }
    assert!(matches!(
        select(
            "fetch",
            "alice",
            "github.com",
            "GET",
            "/owner/allowed.git/info/refs?service=git-receive-pack",
            &auth
        ),
        GatewayDecision::Deny { status: 403, .. }
    ));
    let GatewayDecision::Selected { credential } = select(
        "push",
        "alice",
        "github.com",
        "GET",
        "/owner/allowed.git/info/refs?service=git-receive-pack",
        &auth,
    ) else {
        panic!("push discovery must select");
    };
    assert!(credential.risky_route.is_some());
    for (agent, host, target) in [
        ("bob", "github.com", "/owner/allowed.git/git-upload-pack"),
        (
            "alice",
            "evil.invalid",
            "/owner/allowed.git/git-upload-pack",
        ),
        ("alice", "github.com", "/owner/other.git/git-upload-pack"),
        (
            "alice",
            "github.com",
            "/owner/allowed.git/../other.git/git-upload-pack",
        ),
        (
            "alice",
            "github.com",
            "/owner%2fother/allowed.git/git-upload-pack",
        ),
    ] {
        assert!(matches!(
            select("push", agent, host, "POST", target, &auth),
            GatewayDecision::Deny { status: 403, .. }
        ));
    }
}

#[test]
fn basic_tokens_cannot_fall_through_at_wrong_hosts_or_with_wrong_credentials() {
    for auth in [
        format!("{}, Basic eDp5", basic(TOKEN)),
        format!("{} extra", basic(TOKEN)),
        basic("sgw_unknown"),
        format!("Bearer {TOKEN}"),
        TOKEN.into(),
        format!("Basic {}", STANDARD.encode(format!("{TOKEN}:password"))),
    ] {
        assert!(matches!(
            select(
                "push",
                "alice",
                "github.com",
                "POST",
                "/owner/allowed.git/git-receive-pack",
                &auth
            ),
            GatewayDecision::Deny { .. }
        ));
    }
}

#[test]
fn basic_padding_aliases_keep_credential_binding_checks() {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let target = "/owner/allowed.git/git-upload-pack";
    for username in ["0", "000"] {
        let encoded = STANDARD.encode(format!("{username}:{TOKEN}"));
        let padding = encoded.len() - encoded.trim_end_matches('=').len();
        assert!(matches!(padding, 1 | 2));
        let last = encoded.len() - padding - 1;
        let canonical = alphabet
            .iter()
            .position(|byte| *byte == encoded.as_bytes()[last])
            .unwrap();
        for bits in 1..(1 << (padding * 2)) {
            let mut alias = encoded.as_bytes().to_vec();
            alias[last] = alphabet[canonical | bits];
            let auth = format!("Basic {}", String::from_utf8(alias).unwrap());
            assert!(matches!(
                select("fetch", "alice", "github.com", "POST", target, &auth),
                GatewayDecision::Selected { .. }
            ));
            for (agent, host) in [("bob", "github.com"), ("alice", "127.0.0.1")] {
                assert!(matches!(
                    select("fetch", agent, host, "POST", target, &auth),
                    GatewayDecision::Deny { status: 403, .. }
                ));
            }
            for malformed in [format!("{auth}, Basic eDp5"), format!("{auth} extra")] {
                assert!(matches!(
                    select("fetch", "alice", "github.com", "POST", target, &malformed),
                    GatewayDecision::Deny { .. }
                ));
            }
        }
    }
}
