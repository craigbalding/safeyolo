//! Body-aware local declarations, sharing the existing API auth and read routes.

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Body;

use super::*;
use crate::{circuits::CircuitValue, http_content, test_context};

/// Native control owners share process state across request/reload snapshots.
pub struct Controls<'a> {
    pub circuits: Option<CircuitContext<'a>>,
    pub declarations: Option<DeclarationContext<'a>>,
}

/// Sample monotonic time after a POST body arrives, at the declaration operation.
pub struct DeclarationContext<'a> {
    pub owner: &'a test_context::TestContext,
    pub now: fn() -> f64,
}

/// Encoded request content. Only an authorized declaration POST polls this body.
pub struct RequestBody<'a, B> {
    pub body: &'a mut B,
    pub content_encoding: &'a [u8],
    pub content_length: Option<u64>,
}

// The existing production stream_large_bodies=10m threshold selects whether
// request.content exists. It is not an admission or decoded-content size limit.
const BUFFERED_BODY_THRESHOLD: usize = 10 * 1024 * 1024;

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
    if let Err(outcome) = authorize(request, token_path).await {
        return Ok(outcome);
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
        return Ok(declaration_response(request, outcome));
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
            Ok(outcome) => declaration_response(request, outcome),
            Err(error) => {
                let kind = error.kind();
                let class = match kind {
                    test_context::ContextErrorKind::Value => "ValueError",
                    test_context::ContextErrorKind::Overflow => "OverflowError",
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

async fn read_content<B>(
    body: RequestBody<'_, B>,
) -> Result<Result<Zeroizing<Vec<u8>>, http_content::ContentError>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    let mut encoded = Zeroizing::new(Vec::new());
    let mut streamed = body
        .content_length
        .is_some_and(|length| length > BUFFERED_BODY_THRESHOLD as u64);
    while let Some(frame) = body.body.frame().await {
        let frame = frame?;
        if let Ok(data) = frame.into_data()
            && !streamed
        {
            if data.len() > BUFFERED_BODY_THRESHOLD - encoded.len() {
                // Once streaming begins, source raw_content is absent. Continue
                // consuming through EOM, including transport errors, without
                // retaining or attempting to decode a partial request body.
                zeroize::Zeroize::zeroize(&mut *encoded);
                streamed = true;
            } else {
                encoded.extend_from_slice(&data);
            }
        }
    }
    Ok(if streamed {
        Ok(Zeroizing::new(Vec::new()))
    } else {
        http_content::decode(&encoded, body.content_encoding)
    })
}

fn content_error(error: http_content::ContentError) -> Outcome<'static> {
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
    request: Request<'_>,
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
            request_id: Some(request.request_id.into()),
            host: Some(API_HOST),
            details: audit.details,
        }
    });
    outcome
}
