//! Post-selection credential injection for the native simple-service path. The
//! root runs service/contract/risky-route checks before entering this stage, and
//! all later network/credential/content checks before egress. A ready header
//! change is not permission to contact an upstream.
//!
//! Existing Vault clones share state; no vault, OAuth coordinator, HTTP client or
//! background task is constructed here. Snapshot/refresh resolution can touch the
//! filesystem and belongs on the root's blocking executor. Header application is
//! synchronous in-memory work. Current-snapshot checks are observations, not leases
//! across later transport work.

use crate::{
    credentials::{CredentialSnapshot, Secret, Vault, VaultError},
    network_guard::{AuditDecision, Response, Severity, sanitize},
    oauth::{FailureCategory, NotNeeded, RefreshError, RefreshOutcome},
    services::CredentialSelection,
};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use serde::Serialize;
use serde_json::{Value, json};
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct StatsDelta {
    pub injected: u64,
    pub refreshed: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Vault(VaultError),
    Expiry(VaultError),
    Refresh(RefreshError),
    Cancelled,
    Superseded,
    InvalidHeaderName,
    InvalidHeaderValue,
    MissingHeader,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub stats: StatsDelta,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.kind {
            ErrorKind::Vault(_) => "credential vault lookup failed",
            ErrorKind::Expiry(_) => "credential expiry evaluation failed",
            ErrorKind::Refresh(_) => "credential refresh rejected",
            ErrorKind::Cancelled => "credential injection cancelled",
            ErrorKind::Superseded => "credential injection snapshot superseded",
            ErrorKind::InvalidHeaderName => "invalid credential header name",
            ErrorKind::InvalidHeaderValue => "invalid credential header value",
            ErrorKind::MissingHeader => "selected gateway header is missing",
        })
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn error(kind: ErrorKind, refreshed: u64) -> Error {
    Error {
        kind,
        stats: StatsDelta {
            injected: 0,
            refreshed,
        },
    }
}

/// Full URL can contain a signed query. It has no Debug/Serialize representation.
pub struct RequestInfo<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    pub scheme: &'a str,
    pub full_url: &'a Secret,
    pub request_id: Option<&'a str>,
}
struct Context {
    selection: CredentialSelection,
    method: String,
    host: String,
    path: String,
    scheme: String,
    full_url: Secret,
    request_id: Option<String>,
}
impl Context {
    fn new(selection: CredentialSelection, request: RequestInfo<'_>) -> Self {
        Self {
            selection,
            method: request.method.into(),
            host: request.host.into(),
            path: request.path.split('?').next().unwrap().into(),
            scheme: request.scheme.into(),
            full_url: request.full_url.clone(),
            request_id: request.request_id.map(str::to_owned),
        }
    }
}

/// Source audit intent. A redirect URL is deliberately separate from safe JSON
/// details; the root's audit boundary must handle that sensitive URL explicitly.
/// This type and the containing evidence have no Debug/Serialize implementation.
pub struct AuditIntent {
    pub event: &'static str,
    pub kind: &'static str,
    pub addon: &'static str,
    pub decision: AuditDecision,
    pub severity: Severity,
    pub summary: String,
    pub host: String,
    pub agent: String,
    pub request_id: Option<String>,
    pub details: Value,
    redirect: Option<Secret>,
}
impl AuditIntent {
    pub fn redirect(&self) -> Option<&Secret> {
        self.redirect.as_ref()
    }

    /// Convert the secret-free injection intent at the canonical audit
    /// boundary. The redirect URL remains intentionally outside this event.
    pub fn event(&self, attribution: crate::audit::Attribution) -> crate::audit::Event {
        let severity = match self.severity {
            Severity::Low => crate::audit::Severity::Low,
            Severity::Medium => crate::audit::Severity::Medium,
            Severity::High => crate::audit::Severity::High,
            Severity::Critical => crate::audit::Severity::Critical,
        };
        let decision = match self.decision {
            AuditDecision::Allow => crate::audit::Decision::Allow,
            AuditDecision::Deny => crate::audit::Decision::Deny,
            AuditDecision::Warn => crate::audit::Decision::Warn,
            AuditDecision::RequireApproval => crate::audit::Decision::RequireApproval,
            AuditDecision::BudgetExceeded => crate::audit::Decision::BudgetExceeded,
        };
        let mut event = crate::audit::Event::new(
            self.event,
            crate::audit::Kind::Gateway,
            severity,
            &self.summary,
        );
        event.addon = Some(self.addon.into());
        event.decision = Some(decision);
        event.host = Some(self.host.clone());
        event.agent = Some(self.agent.clone());
        event.request_id = self.request_id.clone();
        event.attribution = Some(attribution);
        event.details = self.details.clone().into();
        event
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TraceIntent {
    pub outcome: &'static str,
    pub details: Value,
}
pub struct Evidence {
    pub metadata: Value,
    pub audit: Vec<AuditIntent>,
    pub trace: Option<TraceIntent>,
    pub stats: StatsDelta,
}
pub struct Blocked {
    pub response: Response,
    pub evidence: Evidence,
}
pub struct Redirect {
    location: Secret,
    pub evidence: Evidence,
}
impl Redirect {
    pub fn status(&self) -> u16 {
        301
    }
    pub fn location(&self) -> &Secret {
        &self.location
    }
    pub fn reason(&self) -> &'static str {
        "credential-injection-requires-https"
    }
    pub fn body(&self) -> &'static [u8] {
        b""
    }
}
pub enum Start {
    Blocked(Blocked),
    Redirect(Redirect),
    Ready(HeaderReplacement),
    Refresh(Box<PendingInjection>),
}

/// Header mutation values have no Debug or Serialize implementation. HeaderValue
/// is also marked sensitive before it reaches the root's request HeaderMap.
///
/// ```compile_fail
/// use safeyolo_proxy::credential_injection::HeaderReplacement;
/// fn debug(value:&HeaderReplacement){let _=format!("{value:?}");}
/// ```
/// ```compile_fail
/// use safeyolo_proxy::credential_injection::HeaderReplacement;
/// fn serialize(value:&HeaderReplacement){let _=serde_json::to_string(value);}
/// ```
pub struct HeaderReplacement {
    name: HeaderName,
    value: Option<HeaderValue>,
    evidence: Evidence,
}
impl HeaderReplacement {
    pub fn name(&self) -> &HeaderName {
        &self.name
    }
    /// Both name and value were validated before this point. Missing selected
    /// header mirrors Python's KeyError and preserves every input header.
    pub fn apply(self, headers: &mut HeaderMap) -> Result<Evidence> {
        if !headers.contains_key(&self.name) {
            return Err(error(
                ErrorKind::MissingHeader,
                self.evidence.stats.refreshed,
            ));
        }
        headers.remove(&self.name);
        if let Some(value) = self.value {
            headers.insert(self.name, value);
        }
        Ok(self.evidence)
    }
}

pub struct PendingInjection {
    context: Context,
    vault: Vault,
    snapshot: CredentialSnapshot,
}
impl PendingInjection {
    pub fn credential_name(&self) -> &str {
        &self.snapshot.credential().name
    }
    /// Root feeds the outcome from the existing OAuth coordinator. A successful
    /// refresh always re-fetches the current Vault record; no old-clone fallback.
    pub fn resume(self, outcome: RefreshOutcome) -> Result<Start> {
        match outcome {
            RefreshOutcome::Refreshed => {
                let current = self
                    .vault
                    .snapshot(self.credential_name())
                    .map_err(|e| error(ErrorKind::Vault(e), 1))?;
                match current {
                    Some(snapshot) => finish(self.context, snapshot, 1),
                    None => Ok(Start::Blocked(deny(self.context, Missing::AfterRefresh, 1))),
                }
            }
            RefreshOutcome::Retained(reason) => {
                self.check_current()?;
                Err(error(ErrorKind::Refresh(reason), 0))
            }
            RefreshOutcome::Rejected(reason) => Err(error(ErrorKind::Refresh(reason), 0)),
            RefreshOutcome::Superseded => Err(error(ErrorKind::Superseded, 0)),
            RefreshOutcome::Cancelled => Err(error(ErrorKind::Cancelled, 0)),
        }
    }

    /// Resolve a refresh outcome for the live gateway owner. Every failed
    /// refresh becomes a local, categorical 503 with safe audit/trace evidence;
    /// the retained credential is never turned into an ordinary allow.
    pub fn resume_for_gateway(self, outcome: RefreshOutcome) -> Result<Start> {
        match outcome {
            RefreshOutcome::Refreshed => {
                let current = match self.vault.snapshot(self.credential_name()) {
                    Ok(current) => current,
                    Err(_error) => {
                        return Ok(self.refresh_failed(FailureCategory::Save));
                    }
                };
                match current {
                    Some(snapshot) => finish(self.context, snapshot, 1),
                    None => Ok(Start::Blocked(deny(self.context, Missing::AfterRefresh, 1))),
                }
            }
            RefreshOutcome::Retained(reason) => {
                let category = match self.check_current() {
                    Ok(()) => reason.category(),
                    Err(error) => failure_category(&error),
                };
                Ok(self.refresh_failed(category))
            }
            RefreshOutcome::Rejected(reason) => Ok(self.refresh_failed(reason.category())),
            RefreshOutcome::Superseded => Ok(self.refresh_failed(FailureCategory::Superseded)),
            RefreshOutcome::Cancelled => Ok(self.refresh_failed(FailureCategory::Cancelled)),
        }
    }
    /// A missing refresh field in the unchanged snapshot is ordinary source
    /// false. Other NotNeeded outcomes mean the prepare/begin state changed.
    pub fn not_needed(self, reason: NotNeeded) -> Result<Start> {
        self.check_current()?;
        let credential = self.snapshot.credential();
        let matches = match reason {
            NotNeeded::MissingRefreshToken => credential
                .refresh_token
                .as_ref()
                .is_none_or(|value| value.expose_secret().is_empty()),
            NotNeeded::MissingTokenUrl => {
                credential
                    .refresh_token
                    .as_ref()
                    .is_some_and(|value| !value.expose_secret().is_empty())
                    && credential.token_url.as_deref().is_none_or(str::is_empty)
            }
            // An explicit injected clock may move backwards between stages;
            // root must re-evaluate that changed observation, not guess a token.
            _ => false,
        };
        if !matches {
            return Err(error(ErrorKind::Superseded, 0));
        }
        finish(self.context, self.snapshot, 0)
    }

    pub fn not_needed_for_gateway(self, reason: NotNeeded) -> Result<Start> {
        if let Err(error) = self.check_current() {
            return Ok(self.refresh_failed(failure_category(&error)));
        }
        let credential = self.snapshot.credential();
        let matches = match reason {
            NotNeeded::MissingRefreshToken => credential
                .refresh_token
                .as_ref()
                .is_none_or(|value| value.expose_secret().is_empty()),
            NotNeeded::MissingTokenUrl => {
                credential
                    .refresh_token
                    .as_ref()
                    .is_some_and(|value| !value.expose_secret().is_empty())
                    && credential.token_url.as_deref().is_none_or(str::is_empty)
            }
            _ => false,
        };
        if !matches {
            return Ok(self.refresh_failed(FailureCategory::Superseded));
        }
        finish(self.context, self.snapshot, 0)
    }

    fn refresh_failed(self, category: FailureCategory) -> Start {
        let code = category.code();
        let mut evidence = empty_evidence(0);
        evidence.metadata = json!({
            "blocked_by": "service-gateway",
            "refresh_failure": code,
        });
        evidence.audit.push(audit(
            &self.context,
            "gateway.refresh_failed",
            AuditDecision::Deny,
            Severity::High,
            format!("Gateway OAuth refresh failed ({code})"),
            json!({"reason_code": format!("REFRESH_{}", code.to_ascii_uppercase())}),
        ));
        evidence.trace = Some(TraceIntent {
            outcome: "refresh_failed",
            details: json!({"reason_code": format!("REFRESH_{}", code.to_ascii_uppercase())}),
        });
        let response = Response {
            status: 503,
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("X-Blocked-By".into(), "service-gateway".into()),
            ],
            body: json!({
                "error": "Credential refresh failed",
                "type": "credential_refresh_failed",
                "reason_codes": [format!("REFRESH_{}", code.to_ascii_uppercase())],
                "action": "retry",
                "reflection": "The credential refresh failed before injection.",
                "addon": "service-gateway",
            }),
        };
        Start::Blocked(Blocked { response, evidence })
    }
    fn check_current(&self) -> Result<()> {
        if !self
            .vault
            .is_current(&self.snapshot)
            .map_err(|e| error(ErrorKind::Vault(e), 0))?
        {
            return Err(error(ErrorKind::Superseded, 0));
        }
        Ok(())
    }
}

fn failure_category(error: &Error) -> FailureCategory {
    match error.kind {
        ErrorKind::Refresh(reason) => reason.category(),
        ErrorKind::Superseded => FailureCategory::Superseded,
        ErrorKind::Cancelled => FailureCategory::Cancelled,
        ErrorKind::Vault(_) => FailureCategory::Save,
        ErrorKind::Expiry(_) => FailureCategory::Expiry,
        ErrorKind::InvalidHeaderName | ErrorKind::InvalidHeaderValue | ErrorKind::MissingHeader => {
            FailureCategory::State
        }
    }
}

/// Enter only after selection and risky-route/grant enforcement. The caller owns
/// any grant lease, including its release for local responses or cancellation.
pub fn prepare(
    selection: CredentialSelection,
    vault: Option<&Vault>,
    request: RequestInfo<'_>,
    now: OffsetDateTime,
) -> Result<Start> {
    let context = Context::new(selection, request);
    let Some(vault) = vault else {
        return Ok(Start::Blocked(deny(context, Missing::Vault, 0)));
    };
    let Some(snapshot) = vault
        .snapshot(&context.selection.vault_token)
        .map_err(|e| error(ErrorKind::Vault(e), 0))?
    else {
        return Ok(Start::Blocked(deny(context, Missing::Initial, 0)));
    };
    let credential = snapshot.credential();
    // Match short-circuit order literally: a naive expiry fails even when the
    // final refresh flag is false; missing refresh fields are checked by OAuth.
    if context.selection.auth_kind.is_some()
        && credential.credential_type == "oauth2"
        && credential
            .is_expired(now)
            .map_err(|e| error(ErrorKind::Expiry(e), 0))?
        && context.selection.refresh_on_401
    {
        return Ok(Start::Refresh(Box::new(PendingInjection {
            context,
            vault: vault.clone(),
            snapshot,
        })));
    }
    finish(context, snapshot, 0)
}

fn audit(
    context: &Context,
    event: &'static str,
    decision: AuditDecision,
    severity: Severity,
    summary: String,
    details: Value,
) -> AuditIntent {
    AuditIntent {
        event,
        kind: "gateway",
        addon: "service-gateway",
        decision,
        severity,
        summary,
        host: context.host.clone(),
        agent: context.selection.agent.clone(),
        request_id: context.request_id.clone(),
        details,
        redirect: None,
    }
}
fn empty_evidence(refreshed: u64) -> Evidence {
    Evidence {
        metadata: json!({}),
        audit: vec![],
        trace: None,
        stats: StatsDelta {
            injected: 0,
            refreshed,
        },
    }
}
fn finish(context: Context, snapshot: CredentialSnapshot, refreshed: u64) -> Result<Start> {
    let mut evidence = empty_evidence(refreshed);
    let selection = &context.selection;
    if context.scheme == "http" {
        if !(selection.auth_kind.is_some() && selection.allow_http) {
            // RequestInfo is the source-equivalent full URL, not a reconstructed
            // host/path pair. Preserve source spelling, port and signed query.
            let url = context.full_url.expose_secret();
            let location = Secret::new(format!(
                "https://{}",
                url.chars().skip(7).collect::<String>()
            ));
            let mut entry = audit(
                &context,
                "gateway.https_redirect",
                AuditDecision::Deny,
                Severity::High,
                format!(
                    "Gateway redirected HTTP→HTTPS: {}{}",
                    selection.service, context.path
                ),
                json!({"service":selection.service,"path":context.path}),
            );
            entry.redirect = Some(location.clone());
            evidence.audit.push(entry);
            return Ok(Start::Redirect(Redirect { location, evidence }));
        }
        evidence.audit.push(audit(
            &context,
            "gateway.http_injection_allowed",
            AuditDecision::Allow,
            Severity::Medium,
            format!(
                "Gateway injected over HTTP (allow_http): {}{}",
                selection.service, context.path
            ),
            json!({"service":selection.service,"path":context.path}),
        ));
    }
    let auth_header = if selection.auth_kind.is_some() {
        selection.auth_header.as_str()
    } else {
        "Authorization"
    };
    let name = HeaderName::from_bytes(auth_header.as_bytes())
        .map_err(|_| error(ErrorKind::InvalidHeaderName, refreshed))?;
    let credential = snapshot.credential();
    let value = match selection.auth_kind.as_deref() {
        Some("bearer") => Some(Secret::new(format!(
            "{} {}",
            selection.auth_scheme,
            credential.value.expose_secret()
        ))),
        Some("api_key") => Some(credential.value.clone()),
        _ => None,
    };
    let value = value
        .map(|value| {
            let mut header = HeaderValue::from_bytes(value.expose_secret().as_bytes())
                .map_err(|_| error(ErrorKind::InvalidHeaderValue, refreshed))?;
            header.set_sensitive(true);
            Ok(header)
        })
        .transpose()?;
    evidence.metadata = json!({"gateway_service":selection.service,"gateway_capability":selection.capability,"gateway_agent":selection.agent,"gateway_account":selection.account,"gateway_injected_header":auth_header});
    evidence.audit.push(audit(&context,"gateway.allow",AuditDecision::Allow,Severity::Low,format!("Gateway {} {}{} → injected ({})",context.method,selection.service,context.path,selection.capability),json!({"service":selection.service,"capability":selection.capability,"account":selection.account,"method":context.method,"path":context.path})));
    evidence.trace = Some(TraceIntent {
        outcome: "injected",
        details: json!({"service":selection.service,"capability":selection.capability}),
    });
    evidence.stats.injected = 1;
    Ok(Start::Ready(HeaderReplacement {
        name,
        value,
        evidence,
    }))
}
enum Missing {
    Vault,
    Initial,
    AfterRefresh,
}
fn deny(context: Context, missing: Missing, refreshed: u64) -> Blocked {
    let (reason,code,action,reflection)=match missing {
        Missing::Vault=>("Vault not available","VAULT_UNAVAILABLE","abort","The credential vault is not loaded. The proxy may still be starting up.".into()),
        Missing::Initial=>("Credential not found in vault","CREDENTIAL_NOT_FOUND","self_correct",format!("Credential '{}' is not in the vault. Re-run `safeyolo agent authorize` to store it.",sanitize(&context.selection.vault_token))),
        Missing::AfterRefresh=>("Credential lost after refresh","CREDENTIAL_NOT_FOUND","abort","The credential was lost during OAuth2 token refresh. Re-run `safeyolo agent authorize` to restore it.".into()),
    };
    let body = json!({"error":reason,"type":code.to_lowercase(),"reason_codes":[code],"action":action,"reflection":reflection,"addon":"service-gateway"});
    let mut headers = vec![
        ("Content-Type".into(), "application/json".into()),
        ("X-Blocked-By".into(), "service-gateway".into()),
    ];
    if let Some(id) = context.request_id.as_ref().filter(|id| !id.is_empty()) {
        headers.push(("X-SafeYolo-Request-Id".into(), id.clone()));
    }
    let mut evidence = empty_evidence(refreshed);
    evidence.metadata = json!({"blocked_by":"service-gateway"});
    evidence.trace = Some(TraceIntent {
        outcome: "blocked",
        details: json!({"status":503,"code":code}),
    });
    evidence.audit.push(audit(&context,"gateway.deny",AuditDecision::Deny,Severity::High,format!("Gateway denied {} {}{}: {}",sanitize(&context.method),sanitize(&context.selection.service),sanitize(&context.path),sanitize(reason)),json!({"reason":reason,"code":code,"method":context.method,"path":context.path,"service":context.selection.service})));
    Blocked {
        response: Response {
            status: 503,
            headers,
            body,
        },
        evidence,
    }
}
