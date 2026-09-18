//! Body-aware local declarations, sharing the existing API auth and read routes.

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Body;

use super::*;
use crate::{circuits::CircuitValue, http_content, test_context};

/// Native control owners share process state across request/reload snapshots.
pub struct Controls<'a> {
    pub gateway: Option<GatewayContext<'a>>,
    pub memory: Option<MemoryContext<'a>>,
    pub traces: Option<TraceContext<'a>>,
    pub discovery: Option<&'a std::sync::Arc<crate::agent_discovery::AgentDiscovery>>,
    pub audit: Option<&'a std::sync::Arc<crate::audit::Writer>>,
    pub flows: Option<&'a std::sync::Arc<crate::flow_store::FlowStore>>,
    pub circuits: Option<CircuitContext<'a>>,
    pub declarations: Option<DeclarationContext<'a>>,
    pub(crate) plumb: Option<&'a crate::agent_api::plumb::PlumbOwner>,
}

/// Trace expiry samples wall time only when an authorized lookup is reached.
pub struct TraceContext<'a> {
    pub store: &'a crate::trace::TraceStore,
    pub now: &'a (dyn Fn() -> f64 + Sync),
}

/// Sample monotonic time after a POST body arrives, at the declaration operation.
pub struct DeclarationContext<'a> {
    pub owner: &'a test_context::TestContext,
    pub now: fn() -> f64,
}

/// Scalar result of this reader reaching its body terminal and then applying
/// the existing decode. It is not independent proof of a parser-validated EOM.
/// Give each API call a fresh default value; routes that never read leave it
/// absent. Streamed/absent raw content has the source's decoded size zero.
#[derive(Default)]
pub struct BodyObservation {
    pub decoded_size: Option<Result<u64, http_content::ContentError>>,
    /// Source raw_content length before later RequestId header hygiene.
    pub encoded_size: Option<u64>,
}

/// Encoded request content. Only authorized routes that consume JSON poll it.
pub struct RequestBody<'a, B> {
    pub body: &'a mut B,
    pub content_encoding: &'a [u8],
    pub content_length: Option<u64>,
    pub observation: Option<&'a mut BodyObservation>,
}

pub async fn respond_with_body<'p, B>(
    request: Request<'_>,
    token_path: &Path,
    policy: PolicyState<'p>,
    tasks: &crate::tasks::Registry,
    now_ms: f64,
    controls: Controls<'_>,
    body: RequestBody<'_, B>,
) -> Result<Outcome<'p>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    respond_with_body_and_audit_id(
        request, token_path, policy, tasks, now_ms, controls, body, None,
    )
    .await
}

/// An already-established trusted source request ID, when present, belongs to
/// declaration audit metadata only. Normal production AgentAPI dispatch precedes
/// RequestIdGenerator; callers must not substitute headers or native ingress IDs.
// Retain the existing body facade's call signature while providing the single
// optional source-stage fact independently of its native containment request ID.
#[allow(clippy::too_many_arguments)]
pub async fn respond_with_body_and_audit_id<'p, B>(
    request: Request<'_>,
    token_path: &Path,
    policy: PolicyState<'p>,
    tasks: &crate::tasks::Registry,
    now_ms: f64,
    controls: Controls<'_>,
    body: RequestBody<'_, B>,
    source_request_id: Option<&str>,
) -> Result<Outcome<'p>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    if let Err(outcome) = authorize(request, token_path).await {
        return Ok(outcome);
    }
    // Reconciliation is the single request-boundary owner decision. Scoped
    // routes reject a quarantined snapshot before reading a body or invoking
    // a provider, so a stale legacy agent field cannot re-open ownership.
    if matches!(request.identity, Identity::Conflict | Identity::Unavailable)
        && (matches!(
            route(request),
            "/explain"
                | "/trace"
                | "/gateway/services"
                | "/gateway/request-access"
                | "/gateway/submit-binding"
                | "/api/test-context/current"
        ) || route(request).starts_with("/api/flows")
            || route(request).starts_with("/plumb")
            || route(request) == "/desktop/present")
    {
        return Ok(response(403, json!({"error":"Could not identify agent"})));
    }
    if route(request) == "/memory" {
        return Ok(memory::respond(request, controls.memory).await);
    }
    if route(request) == "/explain" {
        return Ok(explain::respond(request, controls.audit).await);
    }
    if route(request) == "/trace" {
        return Ok(trace::respond(request, controls.traces));
    }
    if route(request) == "/gateway/services" {
        return Ok(gateway::respond(request, controls.gateway));
    }
    if route(request) == "/gateway/request-access" {
        let content = read_content(body).await?;
        let content = match content {
            Ok(content) => content,
            Err(error) => return Ok(content_error(error)),
        };
        return Ok(gateway::request_access(request, controls.gateway, &content));
    }
    if route(request) == "/gateway/submit-binding" {
        let content = read_content(body).await?;
        let content = match content {
            Ok(content) => content,
            Err(error) => return Ok(content_error(error)),
        };
        return Ok(gateway::submit_binding(request, controls.gateway, &content));
    }
    if route(request).starts_with("/plumb") {
        return plumb::respond(request, body, controls.plumb).await;
    }
    if route(request) == "/agents" {
        return Ok(discovery::respond(request, controls.discovery, controls.audit).await);
    }
    if let Some(route) = flows::recognize(request) {
        return flows::respond(route, request, controls.flows, body).await;
    }
    if route(request) != "/api/test-context/current" {
        return Ok(authenticated_read(
            request,
            policy,
            tasks,
            now_ms,
            controls.circuits,
        ));
    }
    let owner = controls.declarations.as_ref().map(|context| context.owner);
    if let Some(outcome) =
        test_context::api_current_preflight(owner, request.client_ip, agent(request.identity))
    {
        return Ok(declaration_response(source_request_id, outcome));
    }
    let mut parsed = None;
    if request.method == "POST" {
        let content = read_content(body).await?;
        let content = match content {
            Ok(content) => content,
            Err(error) => return Ok(content_error(error)),
        };
        parsed = if content.is_empty() {
            Some(CircuitValue::Object(Default::default()))
        } else {
            crate::python_json::decode_json_text(&content)
                .ok()
                .and_then(|text| CircuitValue::parse_json(&text).ok())
        };
    }
    let context = controls.declarations.expect("preflight requires owner");
    Ok(
        match test_context::api_current_typed(
            owner,
            request.client_ip,
            agent(request.identity),
            request.method,
            parsed.as_ref(),
            (context.now)(),
        ) {
            Ok(outcome) => declaration_response(source_request_id, outcome),
            Err(error) => {
                let kind = error.kind();
                let class = match kind {
                    test_context::ContextErrorKind::Value => "ValueError",
                    test_context::ContextErrorKind::Overflow => "OverflowError",
                    test_context::ContextErrorKind::Type => "TypeError",
                    test_context::ContextErrorKind::Attribute => "AttributeError",
                    test_context::ContextErrorKind::Poisoned => "RuntimeError",
                };
                let mut outcome =
                    response(500, json!({"error":format!("Internal error: {class}")}));
                outcome.failure = Some(Failure::Declaration(kind));
                outcome
            }
        },
    )
}

pub(super) async fn read_content<B>(
    mut body: RequestBody<'_, B>,
) -> Result<Result<Zeroizing<Vec<u8>>, http_content::ContentError>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    if let Some(observation) = body.observation.as_deref_mut() {
        observation.decoded_size = None;
        observation.encoded_size = None;
    }
    let mut content = http_content::BufferedContent::new(body.content_length, false);
    while let Some(frame) = body.body.frame().await {
        let frame = frame?;
        if let Ok(data) = frame.into_data() {
            content.push(&data);
        }
    }
    // Consume through the Body terminal even after raw content becomes absent; a
    // later transport failure still prevents a local operation or decoding.
    let encoded = content.into_content();
    let encoded_size = encoded.as_ref().map_or(0, |bytes| bytes.len() as u64);
    let decoded = match encoded {
        Some(encoded) => http_content::decode(&encoded, body.content_encoding),
        None => Ok(Zeroizing::new(Vec::new())),
    };
    if let Some(observation) = body.observation {
        observation.encoded_size = Some(encoded_size);
        observation.decoded_size = Some(
            decoded
                .as_ref()
                .map(|bytes| bytes.len() as u64)
                .map_err(|error| *error),
        );
    }
    Ok(decoded)
}

pub(super) fn content_error(error: http_content::ContentError) -> Outcome<'static> {
    let class = match error {
        http_content::ContentError::Value => "ValueError",
        http_content::ContentError::Type => "TypeError",
        http_content::ContentError::Allocation => "MemoryError",
    };
    let mut outcome = response(500, json!({"error":format!("Internal error: {class}")}));
    outcome.failure = Some(Failure::ContentDecoding(error));
    outcome
}

fn declaration_response(
    source_request_id: Option<&str>,
    result: test_context::ApiOutcome,
) -> Outcome<'static> {
    let mut outcome = response(result.status, result.body);
    outcome.audit = result.audit.map(|audit| {
        let (kind, action) = if audit.event == "security.test_context_declared" {
            (AuditKind::TestContextDeclared, "Declared")
        } else {
            (AuditKind::TestContextCleared, "Cleared")
        };
        AuditIntent {
            kind,
            event: audit.event,
            severity: "low",
            addon: "agent-api",
            summary: format!(
                "{action} test context for agent {}",
                sanitize(&audit.trusted_agent)
            ),
            agent: Some(audit.trusted_agent),
            request_id: source_request_id.map(str::to_owned),
            host: Some(API_HOST.into()),
            details: audit.details,
            approval: None,
        }
    });
    outcome
}
