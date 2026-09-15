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

fn plain(credential: Option<Credential>) -> Value {
    let Some(credential) = credential else {
        return Value::Null;
    };
    let mut value = json!({"name":credential.name,"type":credential.credential_type,"value":credential.value.expose_secret()});
    for (key, field) in [
        (
            "refresh_token",
            credential.refresh_token.as_ref().map(Secret::expose_secret),
        ),
        ("token_url", credential.token_url.as_deref()),
        ("client_id", credential.client_id.as_deref()),
        (
            "client_secret",
            credential.client_secret.as_ref().map(Secret::expose_secret),
        ),
        ("expires_at", credential.expires_at.as_deref()),
    ] {
        if let Some(field) = field.filter(|field| !field.is_empty()) {
            value[key] = json!(field);
        }
    }
    value
}
fn cases() -> Vec<Value> {
    let mut cases = Vec::new();
    for expires in [
        json!(3600),
        json!(true),
        json!(false),
        json!(0),
        json!(-1),
        json!(0.0000005),
        json!(-0.0000005),
        json!(0.0000015),
        json!(0.0000025),
        json!(0.9999995),
        json!(-0.9999995),
        json!(2000000000.0000005),
        json!(251698233599i64),
        json!(-63839664000i64),
    ] {
        cases.push(json!({"label":"valid expiry","body":json!({"access_token":"synthetic-new","refresh_token":"synthetic-rotated","expires_in":expires}).to_string()}));
    }
    for body in [
        json!({"access_token":"synthetic-new"}),
        json!({"access_token":"","refresh_token":""}),
        json!({"access_token":"synthetic-new","refresh_token":null}),
        json!({"access_token":"synthetic-é😀","unknown":"ignored","expires_in":10}),
    ] {
        cases.push(json!({"label":"valid replacement","body":body.to_string()}));
    }
    for encoding in [
        "utf8bom",
        "utf16le",
        "utf16be",
        "utf32le",
        "utf32be",
        "utf16lebom",
        "utf16bebom",
        "utf32lebom",
        "utf32bebom",
    ] {
        cases.push(json!({"label":"JSON byte encoding","encoding":encoding,"body":json!({"access_token":"synthetic-é😀","expires_in":1.5}).to_string()}));
    }
    cases.push(json!({"label":"last duplicate wins","body":"{\"access_token\":\"synthetic-first\",\"access_token\":\"synthetic-last\",\"expires_in\":0}"}));
    for status in [201, 204, 299, 301, 400, 401, 429, 500] {
        cases.push(json!({"label":"HTTP status","status":status,"body":"{\"access_token\":\"synthetic-new\"}"}));
    }
    for body in ["", "not-json", "{broken"] {
        cases.push(json!({"label":"malformed JSON","body":body}));
    }
    cases.push(json!({"label":"encoding error","body":"","encoding":"invalid"}));
    cases.push(json!({"label":"transport timeout","body":"{}","transport":true}));
    cases.push(json!({"label":"missing client fields","body":"{\"access_token\":\"synthetic-new\"}","credential":{"client_id":null,"client_secret":null}}));
    for (field, value) in [
        ("type", json!("bearer")),
        ("refresh_token", Value::Null),
        ("refresh_token", json!("")),
        ("token_url", Value::Null),
        ("expires_at", Value::Null),
        ("expires_at", json!("2099-01-01T00:00:00+00:00")),
        ("expires_at", json!("bad-date")),
    ] {
        let mut change = json!({});
        change[field] = value;
        cases.push(json!({"label":"eligibility","body":"{\"access_token\":\"synthetic-new\"}","credential":change}));
    }
    for (body, old) in [
        ("{}", "raised:KeyError"),
        ("[]", "raised:TypeError"),
        ("{\"access_token\":null}", "refreshed"),
        ("{\"access_token\":12}", "refreshed"),
        (
            "{\"access_token\":{\"$serde_json::private::Number\":\"12\"}}",
            "refreshed",
        ),
        (
            "{\"access_token\":\"synthetic-new\",\"refresh_token\":false}",
            "refreshed",
        ),
        (
            "{\"access_token\":\"synthetic-new\",\"expires_in\":\"3600\"}",
            "raised:TypeError",
        ),
        (
            "{\"access_token\":\"synthetic-new\",\"expires_in\":null}",
            "raised:TypeError",
        ),
        (
            "{\"access_token\":\"synthetic-new\",\"expires_in\":251698233600}",
            "raised:OverflowError",
        ),
        (
            "{\"access_token\":\"synthetic-new\",\"expires_in\":-63839664001}",
            "raised:OverflowError",
        ),
        (
            "{\"access_token\":\"synthetic-new\",\"expires_in\":9007199254740993}",
            "raised:OverflowError",
        ),
        (
            "{\"access_token\":\"synthetic-new\",\"expires_in\":1e99}",
            "raised:OverflowError",
        ),
    ] {
        cases.push(json!({"label":"checked publication repair","body":body,"repair":"checked","old_outcome":old}));
    }
    cases.push(json!({"label":"activation-independent disk failure repair","body":"{\"access_token\":\"synthetic-new\"}","save_fail":true,"repair":"save","old_outcome":"raised:OSError"}));
    cases.push(json!({"label":"stale admin replacement repair","body":"{\"access_token\":\"synthetic-new\"}","mutation":"replace","repair":"stale","old_outcome":"refreshed"}));
    cases.push(json!({"label":"removed credential","body":"{\"access_token\":\"synthetic-new\"}","mutation":"remove","repair":"removed","old_outcome":"retained"}));
    cases
}
fn body_bytes(case: &Value) -> Vec<u8> {
    let text = case["body"].as_str().unwrap();
    let encoding = case["encoding"].as_str().unwrap_or("utf8");
    let mut bytes = Vec::new();
    match encoding {
        "invalid" => bytes.extend_from_slice(&[0xff]),
        "utf8" | "utf8bom" => {
            if encoding == "utf8bom" {
                bytes.extend_from_slice(&[0xef, 0xbb, 0xbf]);
            }
            bytes.extend_from_slice(text.as_bytes());
        }
        value if value.starts_with("utf16") => {
            let little = value.starts_with("utf16le");
            if value.ends_with("bom") {
                bytes.extend_from_slice(if little { &[0xff, 0xfe] } else { &[0xfe, 0xff] });
            }
            for word in text.encode_utf16() {
                bytes.extend_from_slice(&if little {
                    word.to_le_bytes()
                } else {
                    word.to_be_bytes()
                });
            }
        }
        value => {
            let little = value.starts_with("utf32le");
            if value.ends_with("bom") {
                bytes.extend_from_slice(if little {
                    &[0xff, 0xfe, 0, 0]
                } else {
                    &[0, 0, 0xfe, 0xff]
                });
            }
            for character in text.chars() {
                let point = character as u32;
                bytes.extend_from_slice(&if little {
                    point.to_le_bytes()
                } else {
                    point.to_be_bytes()
                });
            }
        }
    };
    bytes
}
fn changed_credential(case: &Value) -> Credential {
    let mut value = credential();
    if let Some(change) = case["credential"].as_object() {
        for (key, field) in change {
            match key.as_str() {
                "type" => value.credential_type = field.as_str().unwrap().into(),
                "refresh_token" => value.refresh_token = field.as_str().map(Secret::new),
                "token_url" => value.token_url = field.as_str().map(str::to_owned),
                "client_id" => value.client_id = field.as_str().map(str::to_owned),
                "client_secret" => value.client_secret = field.as_str().map(Secret::new),
                "expires_at" => value.expires_at = field.as_str().map(str::to_owned),
                _ => panic!("unknown fixture field"),
            }
        }
    }
    value
}

#[test]
#[ignore = "requires actual Python Vault/HTTPX; set SAFEYOLO_POLICY_PYTHON"]
fn protocol_expiry_and_publication_match_python_with_named_repairs() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let cases = cases();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let input = json!({"credential":plain(Some(credential())),"cases":cases});
    let script = r#"
import json,pathlib,sys,tempfile,logging
from datetime import datetime,UTC
from unittest.mock import patch
import httpx
from safeyolo.core.vault import Vault,VaultCredential
logging.disable(logging.CRITICAL)
class Clock(datetime):
 @classmethod
 def now(cls,tz=None):return cls(2024,1,1,0,0,0,123456,tzinfo=UTC)
def record(credential):return credential.to_dict() if credential else None
x=json.load(sys.stdin);rows=[]
with tempfile.TemporaryDirectory() as directory:
 path=pathlib.Path(directory)/'vault.enc';vault=Vault(path);vault.unlock('synthetic passphrase')
 for case in x['cases']:
  credential={**x['credential'],**case.get('credential',{})};vault.store(VaultCredential.from_dict(credential));before=path.read_bytes();calls=[]
  encoding=case.get('encoding','utf8');body=case['body']
  if encoding=='invalid':raw=b'\xff'
  elif encoding=='utf8bom':raw=b'\xef\xbb\xbf'+body.encode()
  else:
   codec={'utf8':'utf-8','utf16le':'utf-16-le','utf16be':'utf-16-be','utf32le':'utf-32-le','utf32be':'utf-32-be'}[encoding.removesuffix('bom')]
   raw=body.encode(codec)
   if encoding.endswith('bom'):raw={'utf16lebom':b'\xff\xfe','utf16bebom':b'\xfe\xff','utf32lebom':b'\xff\xfe\0\0','utf32bebom':b'\0\0\xfe\xff'}[encoding]+raw
  def post(url,*,data,timeout):
   request=httpx.Request('POST',url,data=data)
   calls.append({'endpoint':url,'form':request.content.decode(),'content_type':request.headers['Content-Type'],'timeout':timeout})
   if case.get('transport'):raise httpx.ReadTimeout('synthetic private provider message')
   if case.get('mutation')=='remove':vault.remove('mail')
   if case.get('mutation')=='replace':vault.store(VaultCredential(name='mail',type='bearer',value='synthetic-admin-edit'))
   return httpx.Response(case.get('status',200),content=raw,request=request)
  original_save=vault.save
  def save():
   if case.get('save_fail'):raise OSError('synthetic private path')
   return original_save()
  with patch('httpx.post',side_effect=post),patch('safeyolo.core.vault.datetime',Clock),patch.object(vault,'save',side_effect=save):
   try:outcome='refreshed' if vault.refresh_oauth2('mail') else 'retained'
   except (KeyError,TypeError,OverflowError,OSError) as error:outcome='raised:'+type(error).__name__
  persisted=Vault(path);persisted.unlock('synthetic passphrase')
  rows.append({'outcome':outcome,'calls':calls,'active':record(vault.get('mail')),'persisted':record(persisted.get('mail')),'unchanged_bytes':path.read_bytes()==before})
json.dump(rows,sys.stdout)
"#;
    let mut child = Command::new(
        std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON"),
    )
    .arg("-c")
    .arg(script)
    .env(
        "PYTHONPATH",
        format!("{}:{}", root.join("cli/src").display(), root.display()),
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&input).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
    let response_time = now().replace_microsecond(123456).unwrap();
    let (directory, vault, oauth) = setup();
    let path = directory.path().join("vault.enc");
    let mut repairs = 0;
    for (index, case) in cases.iter().enumerate() {
        vault.store(changed_credential(case)).unwrap();
        let before = std::fs::read(&path).unwrap();
        let old = plain(vault.get("mail").unwrap());
        let (outcome, calls) = match oauth.begin("mail", response_time).unwrap() {
            RefreshStart::NotNeeded(_) => (None, json!([])),
            RefreshStart::Follower(_) => panic!("sequential oracle cannot have a follower"),
            RefreshStart::Leader(attempt) => {
                let request = attempt.request();
                let calls = json!([{"endpoint":request.endpoint().expose_secret(),"form":request.form_body().expose_secret(),"content_type":request.content_type(),"timeout":request.io_timeout().as_secs_f64()}]);
                match case["mutation"].as_str() {
                    Some("remove") => {
                        vault.remove("mail").unwrap();
                    }
                    Some("replace") => vault
                        .store(Credential::new(
                            "mail",
                            "bearer",
                            Secret::new("synthetic-admin-edit"),
                        ))
                        .unwrap(),
                    _ => {}
                }
                let response = if case["transport"] == true {
                    Err(TransportFailure::Timeout)
                } else {
                    Ok(RefreshResponse::new(
                        case["status"].as_u64().unwrap_or(200) as u16,
                        body_bytes(case),
                    ))
                };
                let result = if case["save_fail"] == true {
                    // The native writer cannot inject a Python OSError callback;
                    // reject activation and verify its stronger exact rollback.
                    let mut calls = 0;
                    attempt.complete_with_activation(response, response_time, |_| {
                        calls += 1;
                        if calls == 1 { Err(()) } else { Ok(()) }
                    })
                } else {
                    attempt.complete(response, response_time)
                };
                (Some(result), calls)
            }
        };
        let observed = &expected[index];
        assert_eq!(calls, observed["calls"], "protocol case {index}");
        if let Some(repair) = case["repair"].as_str() {
            repairs += 1;
            assert_eq!(
                observed["outcome"], case["old_outcome"],
                "baseline repair {index}: {case}"
            );
            if matches!(repair, "checked" | "save") {
                assert!(
                    matches!(outcome, Some(RefreshOutcome::Rejected(_))),
                    "case {index}: {outcome:?}"
                );
                assert_eq!(plain(vault.get("mail").unwrap()), old);
                assert_eq!(std::fs::read(&path).unwrap(), before);
            } else {
                assert_eq!(outcome, Some(RefreshOutcome::Superseded));
                assert_eq!(
                    plain(vault.get("mail").unwrap()),
                    if repair == "removed" {
                        Value::Null
                    } else {
                        json!({"name":"mail","type":"bearer","value":"synthetic-admin-edit"})
                    }
                );
            }
        } else {
            let name = match outcome {
                Some(RefreshOutcome::Refreshed) => "refreshed",
                None | Some(RefreshOutcome::Retained(_)) => "retained",
                other => panic!("case {index}: {other:?}"),
            };
            assert_eq!(name, observed["outcome"], "case {index}: {case}");
            assert_eq!(
                plain(vault.get("mail").unwrap()),
                observed["active"],
                "active case {index}: {case}"
            );
            let persisted = Vault::unlock(&path, &Secret::new("synthetic passphrase")).unwrap();
            assert_eq!(
                plain(persisted.get("mail").unwrap()),
                observed["persisted"],
                "persisted case {index}"
            );
            assert_eq!(
                std::fs::read(&path).unwrap() == before,
                observed["unchanged_bytes"].as_bool().unwrap()
            );
        }
    }
    eprintln!(
        "OAuth Python oracle: {} cases, {repairs} named publication/race repairs",
        cases.len()
    );
}

#[tokio::test]
#[ignore = "actual Python concurrent refresh defect evidence; set SAFEYOLO_POLICY_PYTHON"]
async fn one_native_flight_corrects_python_duplicate_refresh_and_late_overwrite() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let script = r#"
import json,pathlib,tempfile,threading,logging
from unittest.mock import patch
import httpx
from safeyolo.core.vault import Vault,VaultCredential
logging.disable(logging.CRITICAL)
with tempfile.TemporaryDirectory() as directory:
 vault=Vault(pathlib.Path(directory)/'vault.enc');vault.unlock('synthetic passphrase')
 vault.store(VaultCredential(name='mail',type='oauth2',value='synthetic-old-access',refresh_token='synthetic-old-refresh',token_url='https://example.invalid/token',expires_at='2020-01-01T00:00:00+00:00'))
 barrier=threading.Barrier(2);published=threading.Event();calls=[];results={};lock=threading.Lock()
 def post(url,*,data,timeout):
  name=threading.current_thread().name
  with lock:calls.append(data['refresh_token'])
  barrier.wait(timeout=5)
  if name=='older':assert published.wait(timeout=5)
  return httpx.Response(200,json={'access_token':'synthetic-'+name,'refresh_token':'synthetic-rotated-'+name,'expires_in':3600},request=httpx.Request('POST',url))
 def run():
  name=threading.current_thread().name;results[name]=vault.refresh_oauth2('mail')
  if name=='newer':published.set()
 with patch('httpx.post',side_effect=post):
  threads=[threading.Thread(target=run,name=name) for name in ('older','newer')]
  for thread in threads:thread.start()
  for thread in threads:thread.join(timeout=10);assert not thread.is_alive()
 print(json.dumps({'calls':len(calls),'same_original_token':calls==['synthetic-old-refresh']*2,'results':results,'older_overwrote_newer':vault.get('mail').value=='synthetic-older'}))
"#;
    let output = std::process::Command::new(
        std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON"),
    )
    .arg("-c")
    .arg(script)
    .env(
        "PYTHONPATH",
        format!("{}:{}", root.join("cli/src").display(), root.display()),
    )
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let observed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        observed,
        json!({"calls":2,"same_original_token":true,"results":{"older":true,"newer":true},"older_overwrote_newer":true})
    );
    let (_directory, _vault, oauth) = setup();
    let attempt = leader(&oauth);
    let RefreshStart::Follower(mut follower) = oauth.clone().begin("mail", now()).unwrap() else {
        panic!("a clone must join the existing refresh")
    };
    let result = attempt.complete(
        response(json!({"access_token":"synthetic-one-result","expires_in":3600})),
        now(),
    );
    assert_eq!(result, RefreshOutcome::Refreshed);
    assert_eq!(follower.wait().await, result);
    eprintln!(
        "Python duplicate-refresh oracle: two posts and late overwrite; native clone joins one flight"
    );
}
