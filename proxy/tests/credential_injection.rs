use hyper::header::{HeaderMap, HeaderValue};
use safeyolo_proxy::{
    credential_injection::*,
    credentials::{Credential, Secret, Vault},
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
fn evidence(value: &Evidence) -> Value {
    let audit:Vec<_>=value.audit.iter().map(|entry|{let mut details=entry.details.clone();if let Some(redirect)=entry.redirect(){details["redirect"]=json!(redirect.expose_secret());}json!({"event":entry.event,"kind":entry.kind,"addon":entry.addon,"decision":entry.decision,"severity":entry.severity,"summary":entry.summary,"host":entry.host,"agent":entry.agent,"request_id":entry.request_id,"details":details})}).collect();
    json!({"metadata":value.metadata,"audit":audit,"trace":value.trace,"stats":value.stats})
}
fn fields(headers: &HeaderMap) -> Value {
    let mut fields: Vec<_> = headers
        .iter()
        .map(|(name, value)| {
            json!([
                name.as_str(),
                std::str::from_utf8(value.as_bytes()).unwrap()
            ])
        })
        .collect();
    fields.sort_by_key(Value::to_string);
    json!(fields)
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
                "X-Credential"
            } else {
                "Authorization"
            }
        );
        assert_eq!(result.stats.injected, 1);
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
    let Start::Blocked(unavailable) = start(selection(None), None, "http").unwrap() else {
        panic!("expected block")
    };
    assert_eq!(
        unavailable.response.body["reason_codes"],
        json!(["VAULT_UNAVAILABLE"])
    );
    vault.remove("demo-key").unwrap();
    let Start::Blocked(missing) = start(selection(None), Some(&vault), "http").unwrap() else {
        panic!("expected block")
    };
    assert_eq!(missing.response.status, 503);
    assert_eq!(missing.response.body["action"], "self_correct");
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
    let mut headers = headers();
    ready(prepared.resume(retained).unwrap())
        .apply(&mut headers)
        .unwrap();
    assert_eq!(headers["x-credential"], "Bearer synthetic-value");
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

fn cases() -> Vec<Value> {
    let mut cases = vec![];
    for kind in [
        Some("bearer"),
        Some("api_key"),
        Some("Bearer"),
        Some("custom"),
        Some(""),
        None,
    ] {
        for scheme in ["https", "http"] {
            for allow in [false, true] {
                cases.push(json!({"kind":kind,"scheme":scheme,"allow_http":allow,"credential_type":"api_key","value":"synthetic-value"}));
            }
        }
    }
    for expiry in [
        Value::Null,
        json!("malformed"),
        json!("2020-01-01T00:00:00+00:00"),
        json!("2099-01-01T00:00:00+00:00"),
        json!("2020-01-01T00:00:00"),
    ] {
        for flag in [false, true] {
            for mode in ["success", "failure"] {
                cases.push(json!({"kind":"bearer","scheme":"https","refresh_on_401":flag,"credential_type":"oauth2","expiry":expiry,"refresh_mode":mode}));
            }
        }
    }
    cases.extend([
        json!({"kind":"bearer","scheme":"http","refresh_on_401":true,"credential_type":"oauth2","expiry":"2020-01-01T00:00:00+00:00","refresh_mode":"success"}),
        json!({"kind":"bearer","scheme":"http","allow_http":true,"refresh_on_401":true,"credential_type":"oauth2","expiry":"malformed","refresh_mode":"failure"}),
        json!({"kind":"bearer","scheme":"https","auth_scheme":"","value":""}),
        json!({"kind":"bearer","scheme":"https","auth_scheme":"Token"}),
        json!({"kind":"api_key","scheme":"https","duplicate":true}),
        json!({"kind":"bearer","scheme":"https","missing_header":true}),
        json!({"kind":"bearer","scheme":"http","lookup":"unavailable"}),
        json!({"kind":"bearer","scheme":"http","lookup":"missing"}),
        json!({"kind":"bearer","scheme":"https","refresh_on_401":true,"credential_type":"oauth2","expiry":"malformed","refresh_mode":"missing_after_success"}),
        json!({"kind":"bearer","scheme":"https","refresh_on_401":true,"credential_type":"oauth2","expiry":"malformed","missing_refresh":true}),
        json!({"kind":"bearer","scheme":"https","refresh_on_401":true,"credential_type":"oauth2","expiry":"malformed","missing_url":true}),
    ]);
    cases.push(json!({"kind":"bearer","scheme":"https","value":"synthetic-é-世界"}));
    cases.push(json!({"kind":"bearer","scheme":"https","value":"synthetic\r\nX-Injected: yes","repair":"crlf_value"}));
    cases
}
fn observe(case: &Value, vault: &Vault) -> Value {
    vault.remove("demo-key").unwrap();
    let mut c = credential();
    c.credential_type = case["credential_type"].as_str().unwrap_or("api_key").into();
    c.value = Secret::new(case["value"].as_str().unwrap_or("synthetic-value"));
    c.expires_at = case["expiry"].as_str().map(str::to_owned);
    if c.credential_type == "oauth2" {
        if !case["missing_refresh"].as_bool().unwrap_or(false) {
            c.refresh_token = Some(Secret::new("synthetic-refresh"));
        }
        if !case["missing_url"].as_bool().unwrap_or(false) {
            c.token_url = Some("https://provider.invalid/token".into());
        }
    }
    if case["lookup"] != "missing" {
        vault.store(c).unwrap();
    }
    let mut selected = selection(case["kind"].as_str());
    selected.auth_header = if selected.auth_kind.is_some() {
        "X-Credential"
    } else {
        "Authorization"
    }
    .into();
    selected.auth_scheme = case["auth_scheme"].as_str().unwrap_or("Bearer").into();
    selected.allow_http =
        selected.auth_kind.is_some() && case["allow_http"].as_bool().unwrap_or(false);
    selected.refresh_on_401 =
        selected.auth_kind.is_some() && case["refresh_on_401"].as_bool().unwrap_or(false);
    let mut headers = HeaderMap::new();
    headers.insert("before", HeaderValue::from_static("one"));
    if !case["missing_header"].as_bool().unwrap_or(false) {
        headers.append(
            selected
                .auth_header
                .parse::<hyper::header::HeaderName>()
                .unwrap(),
            HeaderValue::from_static("sgw_synthetic"),
        );
    }
    if case["duplicate"].as_bool().unwrap_or(false) {
        headers.append("x-credential", HeaderValue::from_static("sgw_duplicate"));
    }
    headers.insert("after", HeaderValue::from_static("two"));
    let mut refresh_calls = 0;
    let mut result = start(
        selected,
        if case["lookup"] == "unavailable" {
            None
        } else {
            Some(vault)
        },
        case["scheme"].as_str().unwrap(),
    );
    if let Ok(Start::Refresh(prepared)) = result {
        refresh_calls += 1;
        let refresh = OAuthRefresh::new(vault.clone());
        result = match refresh.begin(prepared.credential_name(), now()).unwrap() {
            RefreshStart::NotNeeded(reason) => prepared.not_needed(reason),
            RefreshStart::Leader(attempt) => {
                let response = if case["refresh_mode"] == "failure" {
                    RefreshResponse::new(500, b"owned provider failure".to_vec())
                } else {
                    RefreshResponse::new(
                        200,
                        br#"{"access_token":"synthetic-refreshed","expires_in":3600}"#.to_vec(),
                    )
                };
                let outcome = attempt.complete(Ok(response), now());
                if case["refresh_mode"] == "missing_after_success" {
                    vault.remove("demo-key").unwrap();
                }
                prepared.resume(outcome)
            }
            RefreshStart::Follower(_) => panic!("single request fixture"),
        };
    }
    let mut response = Value::Null;
    let mut result_evidence = Value::Null;
    let mut failure = Value::Null;
    match result {
        Ok(Start::Ready(ready)) => match ready.apply(&mut headers) {
            Ok(value) => result_evidence = evidence(&value),
            Err(error) => {
                failure = json!(match error.kind {
                    ErrorKind::MissingHeader => "KeyError",
                    _ => "native_error",
                })
            }
        },
        Ok(Start::Blocked(blocked)) => {
            response = json!({"status":blocked.response.status,"headers":blocked.response.headers,"body_bytes":String::from_utf8(blocked.response.body_bytes()).unwrap()});
            result_evidence = evidence(&blocked.evidence);
        }
        Ok(Start::Redirect(redirect)) => {
            response = json!({"status":301,"headers":[["Location",redirect.location().expose_secret()],["X-SafeYolo-Reason",redirect.reason()]],"body_bytes":""});
            result_evidence = evidence(&redirect.evidence);
        }
        Ok(Start::Refresh(_)) => panic!("unresolved refresh"),
        Err(error) => {
            failure = json!(match error.kind {
                ErrorKind::Expiry(_) => "TypeError",
                ErrorKind::InvalidHeaderValue => "InvalidHeaderValue",
                _ => "native_error",
            })
        }
    }
    json!({"headers":fields(&headers),"response":response,"evidence":result_evidence,"failure":failure,"refresh_calls":refresh_calls,"header_injection":headers.values().any(|value|value.as_bytes().windows(b"\r\nX-Injected:".len()).any(|window|window==b"\r\nX-Injected:"))})
}

#[test]
#[ignore = "historical Python oracle; set SAFEYOLO_POLICY_PYTHON"]
fn injection_protocol_and_expiry_order_match_actual_python_gateway() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let cases = cases();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let script = r#"
import json,pathlib,sys,tempfile,logging
from datetime import datetime,UTC
from unittest.mock import patch
from types import SimpleNamespace
import httpx
from mitmproxy import http
from mitmproxy.test import tflow
from safeyolo.mitm_addons import service_gateway as module
from safeyolo.core.service_loader import ServiceRegistry,ServiceDefinition
from safeyolo.core.vault import Vault,VaultCredential
from safeyolo.proxy_modes.unix_listener import UnixMode
from pdp.client import LocalPolicyClient,PolicyClientConfig
logging.disable(logging.CRITICAL)
patch('safeyolo.policy.loader.write_event').start()
class Clock(datetime):
 @classmethod
 def now(cls,tz=None):return datetime(2024,1,1,tzinfo=UTC)
rows=[]
with tempfile.TemporaryDirectory() as directory:
 directory=pathlib.Path(directory);vault=Vault(directory/'vault.enc');vault.unlock('synthetic-passphrase')
 path=directory/'policy.json';path.write_text(json.dumps({'permissions':[{'action':'gateway:request','resource':'*','effect':'allow'}]}))
 client=LocalPolicyClient(PolicyClientConfig(baseline_path=path));client._pdp._engine._loader.stop_watcher()
 registry=ServiceRegistry(directory/'services',directory/'builtin')
 for case in json.load(sys.stdin):
  vault.remove('demo-key')
  c=VaultCredential(name='demo-key',type=case.get('credential_type','api_key'),value=case.get('value','synthetic-value'),expires_at=case.get('expiry'))
  if c.type=='oauth2':
   c.refresh_token=None if case.get('missing_refresh') else 'synthetic-refresh';c.token_url=None if case.get('missing_url') else 'https://provider.invalid/token'
  if case.get('lookup')!='missing':vault.store(c)
  kind=case['kind'];auth_header='X-Credential' if kind is not None else 'Authorization'
  document={'schema_version':1,'name':'demo','capabilities':{'reader':{'routes':[{'methods':['GET'],'path':'/**'}]}}}
  if kind is not None:document['auth']={'type':kind,'header':auth_header,'scheme':case.get('auth_scheme','Bearer'),'allow_http':case.get('allow_http',False),'refresh_on_401':case.get('refresh_on_401',False)}
  registry._services={'demo':ServiceDefinition.from_dict(document)}
  guard=module.ServiceGateway();guard._host_map={'api.example':'demo'};guard._token_map={'sgw_synthetic':module.TokenBinding(agent='alice',service_name='demo',capability_name='reader',vault_token='demo-key',account='operator')}
  url=case['scheme']+'://api.example:8080/signed/%2F?Q=a%2Bb&Q=%252F'
  flow=tflow.tflow();flow.request=http.Request.make('GET',url);fields=[(b'before',b'one')]
  if not case.get('missing_header'):fields.append((auth_header.lower().encode(),b'sgw_synthetic'))
  if case.get('duplicate'):fields.append((b'X-CREDENTIAL',b'sgw_duplicate'))
  fields.append((b'after',b'two'));flow.request.headers=http.Headers(fields);flow.metadata['request_id']='req-generated';flow.metadata['agent']='alice';flow.client_conn.proxy_mode=UnixMode.parse('unix:/tmp/10.0.0.5_alice/proxy.sock')
  audits=[];steps=[];refresh_calls=[]
  def event(event,**kw):
   audits.append({'event':event,**{key:kw[key] for key in ('kind','addon','decision','severity','summary','host','agent','request_id','details')}})
  def trace(flow,**kw):steps.append({'outcome':kw.pop('outcome'),'details':{key:value for key,value in kw.items() if key!='addon'}})
  real_refresh=vault.refresh_oauth2
  def refresh(name):
   refresh_calls.append(name);value=real_refresh(name)
   if value and case.get('refresh_mode')=='missing_after_success':vault.remove(name)
   return value
  def post(url,**kwargs):return httpx.Response(500 if case.get('refresh_mode')=='failure' else 200,json={'access_token':'synthetic-refreshed','expires_in':3600},request=httpx.Request('POST',url))
  # No-auth, duplicate and missing-header cases explicitly isolate the selected
  # stage. Ordinary cases retain real token extraction and trusted scope checks.
  extract=patch.object(guard,'_extract_sgw_token',return_value='sgw_synthetic') if kind is None or case.get('duplicate') or case.get('missing_header') else patch.object(guard,'_extract_sgw_token',wraps=guard._extract_sgw_token)
  failure=None
  with patch.object(module,'ctx',SimpleNamespace(options=SimpleNamespace(gateway_enabled=True))),patch.object(module,'get_service_registry',return_value=registry),patch.object(module,'get_vault',return_value=None if case.get('lookup')=='unavailable' else vault),patch.object(module,'write_event',side_effect=event),patch.object(module,'trace_evaluated',side_effect=trace),patch('pdp.get_policy_client',return_value=client),patch('pdp.is_policy_client_configured',return_value=True),patch.object(vault,'refresh_oauth2',side_effect=refresh),patch('httpx.post',side_effect=post),patch('safeyolo.core.vault.datetime',Clock),extract:
   try:guard.request(flow)
   except Exception as error:failure=type(error).__name__
  response=None
  if flow.response:response={'status':flow.response.status_code,'headers':[[k,v] for k,v in flow.response.headers.items() if k.lower()!='content-length'],'body_bytes':flow.response.content.decode()}
  metadata={key:value for key,value in flow.metadata.items() if key.startswith('gateway_') or key=='blocked_by'}
  evidence=None if failure else {'metadata':metadata,'audit':audits,'trace':steps[-1] if steps else None,'stats':{'injected':guard.stats.injected,'refreshed':guard.stats.refreshed}}
  rows.append({'headers':sorted([[k.lower(),v] for k,v in flow.request.headers.items(multi=True)]),'response':response,'evidence':evidence,'failure':failure,'refresh_calls':len(refresh_calls),'header_injection':b'\r\nX-Injected:' in bytes(flow.request.headers)})
 client._pdp._engine.done()
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
        .write_all(json!(cases).to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
    let (_directory, vault) = vault();
    for (index, case) in cases.iter().enumerate() {
        let actual = observe(case, &vault);
        if case["repair"] == "crlf_value" {
            assert_eq!(expected[index]["header_injection"], true);
            assert_eq!(expected[index]["evidence"]["stats"]["injected"], 1);
            assert!(expected[index]["failure"].is_null());
            assert_eq!(actual["failure"], "InvalidHeaderValue");
            assert_eq!(actual["header_injection"], false);
            assert!(
                actual["headers"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(["x-credential", "sgw_synthetic"]))
            );
        } else {
            assert_eq!(
                actual, expected[index],
                "source injection case {index}: {case}"
            );
        }
    }
    eprintln!(
        "{} actual Python service-gateway injection cases",
        cases.len()
    );
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
        token: "sgw_synthetic".into(),
        agent: "alice".into(),
        service: "demo".into(),
        capability: "reader".into(),
        vault_token: "demo-key".into(),
        account: "operator".into(),
    };
    let input_headers = vec![("Authorization".into(), "Bearer sgw_synthetic".into())];
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
            route_mode: RouteMode::CompiledPolicy,
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
