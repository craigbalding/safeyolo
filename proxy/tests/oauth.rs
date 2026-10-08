use safeyolo_proxy::{
    credentials::{Credential, Secret, Vault},
    oauth::*,
};
use serde_json::{Value, json};
use time::OffsetDateTime;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1704067200).unwrap()
}
fn credential() -> Credential {
    let mut value = Credential::new("mail", "oauth2", Secret::new("synthetic-old-access"));
    value.refresh_token = Some(Secret::new("synthetic-refresh +/é😀&=%~"));
    value.token_url = Some("http://token.example.invalid/token?fixed=a%2Bb".into());
    value.client_id = Some("synthetic client".into());
    value.client_secret = Some(Secret::new("synthetic secret&="));
    value.expires_at = Some("2020-01-01T00:00:00+00:00".into());
    value
}
fn setup() -> (tempfile::TempDir, Vault, OAuthRefresh) {
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::unlock(
        directory.path().join("vault.enc"),
        &Secret::new("synthetic passphrase"),
    )
    .unwrap();
    vault.store(credential()).unwrap();
    let oauth = OAuthRefresh::new(vault.clone());
    (directory, vault, oauth)
}
fn leader(oauth: &OAuthRefresh) -> RefreshAttempt {
    match oauth.begin("mail", now()).unwrap() {
        RefreshStart::Leader(attempt) => attempt,
        _ => panic!("expected one refresh leader"),
    }
}
fn response(value: Value) -> std::result::Result<RefreshResponse, TransportFailure> {
    Ok(RefreshResponse::new(
        200,
        serde_json::to_vec(&value).unwrap(),
    ))
}

#[test]
fn request_preserves_host_management_form_timeout_and_eligibility() {
    let (_directory, vault, oauth) = setup();
    let attempt = leader(&oauth);
    let request = attempt.request();
    assert_eq!(request.authority(), Authority::HostCredentialManagement);
    assert_eq!(
        request.endpoint().expose_secret(),
        "http://token.example.invalid/token?fixed=a%2Bb"
    );
    assert_eq!(request.method(), "POST");
    assert_eq!(request.content_type(), "application/x-www-form-urlencoded");
    assert_eq!(request.io_timeout(), std::time::Duration::from_secs(10));
    assert!(!request.follow_redirects());
    assert_eq!(
        request.form_body().expose_secret(),
        "grant_type=refresh_token&refresh_token=synthetic-refresh+%2B%2F%C3%A9%F0%9F%98%80%26%3D%25~&client_id=synthetic+client&client_secret=synthetic+secret%26%3D"
    );
    assert_eq!(
        request.content_length(),
        request.form_body().expose_secret().len()
    );
    drop(attempt);
    for (change, reason) in [
        (0, NotNeeded::NotOAuth2),
        (1, NotNeeded::MissingRefreshToken),
        (2, NotNeeded::MissingTokenUrl),
        (3, NotNeeded::NotExpired),
        (4, NotNeeded::NotExpired),
    ] {
        let mut value = credential();
        match change {
            0 => value.credential_type = "bearer".into(),
            1 => value.refresh_token = Some(Secret::new("")),
            2 => value.token_url = None,
            3 => value.expires_at = Some("2099-01-01T00:00:00+00:00".into()),
            _ => value.expires_at = None,
        };
        vault.store(value).unwrap();
        assert!(
            matches!(oauth.begin("mail",now()).unwrap(),RefreshStart::NotNeeded(value) if value==reason)
        );
    }
    vault.remove("mail").unwrap();
    assert!(matches!(
        oauth.begin("mail", now()).unwrap(),
        RefreshStart::NotNeeded(NotNeeded::MissingCredential)
    ));
    let mut naive = credential();
    naive.expires_at = Some("2020-01-01T00:00:00".into());
    vault.store(naive).unwrap();
    assert!(matches!(
        oauth.begin("mail", now()).err().unwrap(),
        RefreshError::Vault(_)
    ));
    let mut malformed = credential();
    malformed.expires_at = Some("invalid expiry".into());
    vault.store(malformed).unwrap();
    drop(leader(&oauth));
}

#[tokio::test]
async fn single_flight_completion_cancellation_and_retry_release_all_callers() {
    let (_directory, vault, oauth) = setup();
    let barrier = std::sync::Barrier::new(20);
    let starts = std::thread::scope(|scope| {
        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let oauth = oauth.clone();
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    oauth.begin("mail", now()).unwrap()
                })
            })
            .collect();
        tasks
            .into_iter()
            .map(|task| task.join().unwrap())
            .collect::<Vec<_>>()
    });
    let mut attempts = Vec::new();
    let mut followers = Vec::new();
    for start in starts {
        match start {
            RefreshStart::Leader(value) => attempts.push(value),
            RefreshStart::Follower(value) => followers.push(value),
            _ => panic!("eligible credential"),
        }
    }
    assert_eq!(attempts.len(), 1);
    assert_eq!(followers.len(), 19);
    let attempt = attempts.pop().unwrap();
    assert_eq!(attempt.complete(response(json!({"access_token":"synthetic-new","refresh_token":"synthetic-rotated","expires_in":3600})),now()),RefreshOutcome::Refreshed);
    for follower in &mut followers {
        assert_eq!(follower.wait().await, RefreshOutcome::Refreshed);
    }
    assert_eq!(
        vault.get("mail").unwrap().unwrap().value.expose_secret(),
        "synthetic-new"
    );
    assert!(matches!(
        oauth.begin("mail", now()).unwrap(),
        RefreshStart::NotNeeded(NotNeeded::NotExpired)
    ));
    vault.store(credential()).unwrap();
    let cancelled = leader(&oauth);
    let RefreshStart::Follower(mut waiting) = oauth.begin("mail", now()).unwrap() else {
        panic!("expected follower")
    };
    drop(cancelled);
    assert_eq!(waiting.wait().await, RefreshOutcome::Cancelled);
    let failed = leader(&oauth);
    assert_eq!(
        failed.complete(Err(TransportFailure::Timeout), now()),
        RefreshOutcome::Retained(RefreshError::Transport(TransportFailure::Timeout))
    );
    drop(leader(&oauth));
    // A different credential can refresh while mail is in flight.
    let first = leader(&oauth);
    let mut other = credential();
    other.name = "other".into();
    vault.store(other).unwrap();
    assert!(matches!(
        oauth.begin("other", now()).unwrap(),
        RefreshStart::Leader(_)
    ));
    drop(first);
}

#[test]
fn success_preserves_missing_fields_and_persists_explicit_rotation_and_clear() {
    let (directory, vault, oauth) = setup();
    let original = credential();
    assert_eq!(
        leader(&oauth).complete(response(json!({"access_token":"synthetic-new"})), now()),
        RefreshOutcome::Refreshed
    );
    let after = vault.get("mail").unwrap().unwrap();
    assert_eq!(after.expires_at, original.expires_at);
    assert_eq!(
        after.refresh_token.unwrap().expose_secret(),
        original.refresh_token.unwrap().expose_secret()
    );
    // Missing expires_in keeps expired status, so the next independent request
    // may refresh again. No hidden near-expiry timer or backoff is added.
    assert_eq!(
        leader(&oauth).complete(
            response(json!({"access_token":"","refresh_token":null,"expires_in":0.0000015})),
            now()
        ),
        RefreshOutcome::Refreshed
    );
    let after = vault.get("mail").unwrap().unwrap();
    assert!(after.value.expose_secret().is_empty());
    assert!(after.refresh_token.is_none());
    assert_eq!(
        after.expires_at.as_deref(),
        Some("2024-01-01T00:00:00.000002+00:00")
    );
    let reopened = Vault::unlock(
        directory.path().join("vault.enc"),
        &Secret::new("synthetic passphrase"),
    )
    .unwrap();
    let after = reopened.get("mail").unwrap().unwrap();
    assert!(after.value.expose_secret().is_empty());
    assert!(after.refresh_token.is_none());
}

#[tokio::test]
async fn conditional_publication_never_overwrites_removal_store_reload_or_other_vault() {
    let (directory, vault, oauth) = setup();
    for change in 0..3 {
        vault.store(credential()).unwrap();
        let attempt = leader(&oauth);
        let RefreshStart::Follower(mut follower) = oauth.begin("mail", now()).unwrap() else {
            panic!("follower")
        };
        match change {
            0 => {
                vault.remove("mail").unwrap();
            }
            1 => {
                let mut value = credential();
                value.value = Secret::new("synthetic-admin-edit");
                vault.store(value).unwrap();
            }
            _ => {
                let external = Vault::unlock(
                    directory.path().join("vault.enc"),
                    &Secret::new("synthetic passphrase"),
                )
                .unwrap();
                let mut replacement = credential();
                replacement.value = Secret::new("synthetic-external-edit");
                external.store(replacement).unwrap();
                vault.reload().unwrap();
            }
        };
        assert_eq!(
            attempt.complete(
                response(json!({"access_token":"synthetic-stale-response"})),
                now()
            ),
            RefreshOutcome::Superseded
        );
        assert_eq!(follower.wait().await, RefreshOutcome::Superseded);
        assert!(
            vault
                .get("mail")
                .unwrap()
                .is_none_or(|value| value.value.expose_secret() != "synthetic-stale-response")
        );
    }
    vault.store(credential()).unwrap();
    let attempt = leader(&oauth);
    let mut other = credential();
    other.name = "other".into();
    vault.store(other).unwrap();
    assert_eq!(
        attempt.complete(response(json!({"access_token":"synthetic-new"})), now()),
        RefreshOutcome::Refreshed,
        "unrelated edits must not invalidate mail's revision"
    );
    let snapshot = vault.snapshot("mail").unwrap().unwrap();
    let other_vault = Vault::unlock(
        directory.path().join("other.enc"),
        &Secret::new("synthetic passphrase"),
    )
    .unwrap();
    other_vault.store(credential()).unwrap();
    assert!(
        !other_vault
            .replace_if_current(&snapshot, credential(), |_| Ok(()))
            .unwrap()
    );
}

#[tokio::test]
async fn malformed_publication_and_activation_failures_keep_exact_prior_state() {
    let (directory, vault, oauth) = setup();
    let path = directory.path().join("vault.enc");
    let original = std::fs::read(&path).unwrap();
    for (value, error) in [
        (json!([]), RefreshError::ResponseShape),
        (json!({}), RefreshError::MissingAccessToken),
        (json!({"access_token":null}), RefreshError::AccessTokenType),
        (
            json!({"access_token":"synthetic-new","refresh_token":23}),
            RefreshError::RefreshTokenType,
        ),
        (
            json!({"access_token":"synthetic-new","expires_in":"3600"}),
            RefreshError::ExpiryType,
        ),
        (
            json!({"access_token":"synthetic-new","expires_in":1e99}),
            RefreshError::ExpiryRange,
        ),
        (
            json!({"access_token":{"$serde_json::private::Number":"42"}}),
            RefreshError::AccessTokenType,
        ),
    ] {
        assert_eq!(
            leader(&oauth).complete(response(value), now()),
            RefreshOutcome::Rejected(error)
        );
        assert_eq!(
            vault.get("mail").unwrap().unwrap().value.expose_secret(),
            "synthetic-old-access"
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
    for status in [100, 301, 400, 401, 429, 500] {
        let result = leader(&oauth).complete(
            Ok(RefreshResponse::new(
                status,
                br#"{"error_description":"synthetic-private-provider-error"}"#.to_vec(),
            )),
            now(),
        );
        assert_eq!(
            result,
            RefreshOutcome::Retained(RefreshError::HttpStatus(status))
        );
        assert!(!format!("{result:?}").contains("synthetic"));
    }
    assert_eq!(
        leader(&oauth).complete(
            Ok(RefreshResponse::new(
                200,
                b"synthetic invalid JSON".to_vec()
            )),
            now()
        ),
        RefreshOutcome::Retained(RefreshError::Json)
    );
    let failed = leader(&oauth);
    let RefreshStart::Follower(mut follower) = oauth.begin("mail", now()).unwrap() else {
        panic!("follower")
    };
    let mut calls = 0;
    let outcome = failed.complete_with_activation(
        response(json!({"access_token":"synthetic-new","expires_in":3600})),
        now(),
        |_| {
            calls += 1;
            if calls == 1 { Err(()) } else { Ok(()) }
        },
    );
    assert!(matches!(
        outcome,
        RefreshOutcome::Rejected(RefreshError::Vault(_))
    ));
    assert_eq!(calls, 2);
    assert_eq!(follower.wait().await, outcome);
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert_eq!(
        vault.get("mail").unwrap().unwrap().value.expose_secret(),
        "synthetic-old-access"
    );
    drop(leader(&oauth));
    // A filesystem failure leaves the in-memory credential untouched too.
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(matches!(
        leader(&oauth).complete(response(json!({"access_token":"synthetic-new"})), now()),
        RefreshOutcome::Rejected(RefreshError::Vault(_))
    ));
    assert_eq!(
        vault.get("mail").unwrap().unwrap().value.expose_secret(),
        "synthetic-old-access"
    );
}
