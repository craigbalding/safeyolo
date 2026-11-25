//! Trusted issuer for the local Service Gateway host capability. The existing
//! policy carries bindings; the vault holds signing keys; the target owns jobs.
use super::*;
use crate::{Runtime, RuntimeState, approvals::pending, host_runs::AgentRun, policy::Policy};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{path::PathBuf, sync::Arc};

#[cfg(all(test, target_os = "linux"))]
mod tests;
mod transport;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub target: Target,
    pub issuer_id: String,
    pub grant_id: String,
    pub key_id: String,
    /// Reference in the existing encrypted credential store. Never key bytes.
    pub credential: String,
    pub service: String,
    pub endpoint: Endpoint,
    pub task_revision: String,
    pub timeout_ms: u64,
    pub request_bytes: usize,
    pub response_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "transport", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Endpoint {
    Unix {
        socket: PathBuf,
        executor_uid: u32,
    },
    Https {
        host: String,
        port: u16,
        certificate_pem: String,
    },
}

impl Endpoint {
    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Unix { socket, .. } => {
                if !socket.is_absolute()
                    || socket
                        .components()
                        .any(|p| matches!(p, std::path::Component::ParentDir))
                {
                    return Err(
                        "host socket must be an absolute path without parent traversal".into(),
                    );
                }
            }
            Self::Https {
                host,
                port,
                certificate_pem,
            } => {
                rustls::pki_types::ServerName::try_from(host.clone())?;
                if *port == 0 {
                    return Err("host HTTPS needs a nonzero port".into());
                }
                transport::tls_configuration(certificate_pem)?;
            }
        }
        Ok(())
    }
}

pub(crate) fn bindings(document: &Value) -> Result<BTreeMap<String, Binding>, Error> {
    let Some(raw) = document.get("host_bindings") else {
        return Ok(BTreeMap::new());
    };
    let values = raw
        .as_object()
        .ok_or("host_bindings must be a table of JSON binding documents")?;
    values
        .iter()
        .map(|(name, raw)| {
            let binding: Binding =
                serde_json::from_str(raw.as_str().ok_or("host binding must be a JSON string")?)?;
            binding.validate()?;
            if !literal(name) {
                return Err("host binding names must be literal selectors".into());
            }
            Ok((name.clone(), binding))
        })
        .collect()
}

fn literal(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

fn refused(code: RefusalCode, message: &str) -> Refusal {
    Refusal {
        code,
        message: message.into(),
    }
}

impl Binding {
    fn issuer_current(&self, policy: &Policy) -> bool {
        policy
            .identity_root()
            .and_then(|root| crate::peer_support::events::instance(root).ok())
            .as_deref()
            == Some(self.issuer_id.as_str())
    }
    fn grant(&self) -> Result<&Grant, Refusal> {
        self.target
            .issuers
            .get(&self.issuer_id)
            .and_then(|issuer| issuer.authority.grants.get(&self.grant_id))
            .ok_or_else(|| {
                refused(
                    RefusalCode::Authority,
                    "host binding grant is absent or revoked",
                )
            })
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        self.target.validate()?;
        self.endpoint.validate()?;
        let grant = self.grant()?;
        if !literal(&self.issuer_id)
            || !literal(&self.grant_id)
            || !literal(&self.key_id)
            || self.credential.is_empty()
            || self.service.is_empty()
            || grant
                .principal
                .task_id
                .as_deref()
                .is_none_or(|id| !literal(id))
            || self.task_revision.len() != 64
            || self.timeout_ms == 0
            || self.request_bytes == 0
            || self.response_bytes == 0
            || !self.target.issuers[&self.issuer_id]
                .public_keys
                .contains_key(&self.key_id)
        {
            return Err("host binding needs a target issuer/grant/key, vault reference, service, authenticated endpoint, approved task revision and positive transport limits".into());
        }
        Ok(())
    }

    pub(crate) fn principal(
        &self,
        runtime: &Runtime,
        run: &AgentRun,
    ) -> Result<Principal, Refusal> {
        let policy = runtime
            .policy
            .as_ref()
            .ok_or_else(|| refused(RefusalCode::Unavailable, "host policy unavailable"))?;
        if !self.issuer_current(policy) {
            return Err(refused(
                RefusalCode::Issuer,
                "host binding belongs to another issuing instance",
            ));
        }
        let grant = self.grant()?;
        let active = runtime
            .tasks
            .active()
            .map_err(|_| refused(RefusalCode::Unavailable, "task registry unavailable"))?;
        let authority = &self.target.issuers[&self.issuer_id].authority;
        if now() < grant.not_before
            || now() >= grant.expires_at
            || now() < authority.observed_at
            || now() >= authority.valid_until
            || now().saturating_sub(authority.observed_at) >= self.target.max_authority_age_seconds
        {
            return Err(refused(
                RefusalCode::Expired,
                "host grant or authority freshness expired",
            ));
        }
        if !run.current(policy)
            || grant.principal.run != *run
            || active.as_ref().is_none_or(|(id, task)| {
                Some(id) != grant.principal.task_id.as_ref()
                    || revision(task.document()) != self.task_revision
            })
        {
            return Err(refused(
                RefusalCode::Principal,
                "host binding requires its trusted current run and activated operator task revision",
            ));
        }
        Ok(grant.principal.clone())
    }

    fn request(&self, principal: Principal, input: &Input) -> Result<Request, Refusal> {
        let issuer = &self.target.issuers[&self.issuer_id];
        // A stable expiry is part of operation identity. Repeating identical
        // client input must not acquire a new signed request after a lost reply.
        let expires_at = issuer
            .authority
            .valid_until
            .min(
                issuer
                    .authority
                    .observed_at
                    .saturating_add(self.target.max_authority_age_seconds),
            )
            .min(self.grant()?.expires_at);
        Ok(Request {
            version: VERSION.into(),
            required_features: FEATURES.iter().map(|s| s.to_string()).collect(),
            request_id: input.request_id.clone(),
            target_id: self.target.target_id.clone(),
            issuer_id: self.issuer_id.clone(),
            grant_id: self.grant_id.clone(),
            principal,
            expires_at,
            expected: input.expected.clone(),
            action: input.action.clone(),
            untrusted_rationale: input.untrusted_rationale.clone(),
        })
    }

    fn permission(&self, policy: &Policy, run: &AgentRun, action: &Action) -> Result<(), Refusal> {
        // Current gateway/task hard denials remain effective. Native bounds are
        // additional requirements, never a replacement policy evaluator.
        let decision = policy.evaluate_gateway_request(crate::policy::GatewayRequest {
            agent: &run.agent,
            service: &self.service,
            capability: "host_execution",
            method: "POST",
            path: action.verb().path(),
        });
        if decision.effect != crate::policy::Effect::Allow {
            return Err(refused(
                RefusalCode::Authority,
                "current gateway/task policy does not allow this host protocol operation",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    pub request_id: String,
    pub expected: Option<AuthorityRevisions>,
    pub action: Action,
    #[serde(default)]
    pub untrusted_rationale: String,
    #[serde(default)]
    pub challenge_id: Option<String>,
}

pub(crate) fn binding(policy: &Policy, name: &str) -> Result<Binding, Refusal> {
    policy
        .host_bindings()
        .map_err(|_| refused(RefusalCode::Unavailable, "host bindings unavailable"))?
        .remove(name)
        .ok_or_else(|| {
            refused(
                RefusalCode::Authority,
                "host binding unavailable for this caller",
            )
        })
}

fn action(
    runtime: &Runtime,
    name: &str,
    binding: &Binding,
    request: &Request,
    credential_binding: &str,
) -> Result<Value, Error> {
    let policy = runtime.policy.as_ref().ok_or("host policy unavailable")?;
    let operation = match &request.action {
        Action::Invoke { invocation } => invocation.operation_id.as_str(),
        _ => "",
    };
    let mut action = json!({"kind":"host_operation","agent":request.principal.run.agent,"agent_id":request.principal.run.agent_id,
        "run":request.principal.run,"service":binding.service,"capability":operation,"method":"POST","path":Verb::Invoke.path(),
        "host_binding":name,"binding_revision":revision(binding),"request":request,"credential":binding.credential,
        "credential_binding":credential_binding,"policy_revision":policy.host_gateway_revision()});
    action["control_update"] = crate::policy::checks::challenges::binding(policy, &action);
    if policy.named_checks().route_challenges.values().any(|c| {
        c.applies(&action)
            && c.steps.iter().any(|s| {
                matches!(
                    s,
                    crate::policy::checks::challenges::Step::TaskAction { .. }
                )
            })
    }) {
        let task = runtime.tasks.active()?.ok_or("approved task unavailable")?;
        let operation = &binding.target.package.operations[operation];
        let invocation = match &request.action {
            Action::Invoke { invocation } => invocation,
            _ => unreachable!(),
        };
        let mut normalized = invocation.clone();
        normalized.arguments = operation.arguments(&invocation.arguments)?;
        let history = crate::policy::checks::task_action::history(
            runtime,
            &request.principal.run,
            &request.request_id,
        )?;
        action["task_action"] = json!({
            "task":{"id":task.0,"revision":binding.task_revision,"objective":task.1.document()["metadata"]["description"]},
            "requester":request.principal,
            "action":{"kind":"host_operation","target":request.target_id,"invocation":normalized,
                "package_revision":revision(&binding.target.package)},
            "prepared":{"effects":operation.effects,"semantics":operation.semantics,"enforcement":operation.enforcement,
                "revisions":request.expected,"grant":binding.target.effective_operations(binding.grant()?).get(&invocation.operation_id)},
            "constraints":{"task_permissions":task.1.document()["permissions"],"policy_revision":policy.host_gateway_revision(),
                "binding_revision":revision(binding),"expiry":request.expires_at},
            "history":history
        });
    }
    Ok(action)
}

/// Approval/current-state readers use the same binding and revision owners.
/// The target still rechecks its independently adopted authority at admission.
pub(crate) fn approval_revision(policy: &Policy, action: &Value) -> Option<String> {
    let binding = binding(policy, action["host_binding"].as_str()?).ok()?;
    let request: Request = serde_json::from_value(action["request"].clone()).ok()?;
    let grant = binding.grant().ok()?;
    if !binding.issuer_current(policy)
        || request.principal != grant.principal
        || !request.principal.run.current(policy)
        || action["binding_revision"] != revision(&binding)
        || action["policy_revision"] != policy.host_gateway_revision()
        || !crate::policy::checks::challenges::current(policy, action)
        || now() >= request.expires_at
        || binding
            .permission(policy, &request.principal.run, &request.action)
            .is_err()
    {
        return None;
    }
    Some(revision(action))
}

pub(crate) struct Reply {
    pub status: u16,
    pub value: Value,
}
impl Reply {
    fn target(response: Response) -> Self {
        let status = match &response {
            Response::Refused { refusal } => status(refusal.code),
            _ => 200,
        };
        Self {
            status,
            value: json!(response),
        }
    }
}
pub(crate) fn status(code: RefusalCode) -> u16 {
    match code {
        RefusalCode::Malformed
        | RefusalCode::Protocol
        | RefusalCode::Selector
        | RefusalCode::Arguments => 400,
        RefusalCode::Stale | RefusalCode::Conflict => 409,
        RefusalCode::Budget => 429,
        RefusalCode::Unavailable => 503,
        _ => 403,
    }
}

/// No caller-supplied issuer, target, credential, principal or lifetime enters
/// the signed protocol. All target operations pass the same owner checks.
pub(crate) async fn execute(
    state: &RuntimeState,
    run: &AgentRun,
    name: &str,
    input: Input,
) -> Result<Reply, Error> {
    let result = dispatch(state, run, name, &input).await;
    if let Err(error) = &result {
        let runtime = state
            .read()
            .map_err(|_| "host gateway unavailable")?
            .clone();
        let mut event = crate::audit::Event::new(
            "gateway.host_refused",
            crate::audit::Kind::Gateway,
            crate::audit::Severity::Low,
            "Host gateway did not dispatch this request",
        );
        event.agent = Some(run.agent.clone());
        event.request_id = Some(input.request_id.clone());
        event.details =
            json!({"host_binding":name,"run":run,"action":input.action,"expected":input.expected,
            "refusal":error.downcast_ref::<Refusal>(),"outcome":"issuer_refused_or_unavailable"})
            .into();
        runtime.audit.emit_confirmed(event).await?;
    }
    result
}

async fn dispatch(
    state: &RuntimeState,
    run: &AgentRun,
    name: &str,
    input: &Input,
) -> Result<Reply, Error> {
    let runtime = state
        .read()
        .map_err(|_| "host gateway unavailable")?
        .clone();
    let policy = runtime.policy.as_ref().ok_or("host policy unavailable")?;
    let binding = binding(policy, name)?;
    let principal = binding.principal(&runtime, run)?;
    binding.permission(policy, run, &input.action)?;
    let request = binding.request(principal, input)?;
    let loaded = runtime
        .gateway_vault
        .load_async()
        .await?
        .ok_or("host signing credential unavailable")?;
    let vault = &loaded.vault;
    vault.reload_if_changed()?;
    let credential = vault
        .snapshot(&binding.credential)?
        .ok_or("host signing credential unavailable")?;
    if !vault.is_current(&credential)?
        || credential
            .credential()
            .is_expired(time::OffsetDateTime::now_utc())?
    {
        return Err(refused(
            RefusalCode::Expired,
            "host signing credential changed or expired",
        )
        .into());
    }
    let guard = runtime
        .credential_guard
        .as_ref()
        .ok_or("credential guard unavailable")?;
    let credential_binding = guard.approval_binding(credential.credential());
    let bytes =
        zeroize::Zeroizing::new(STANDARD.decode(credential.credential().value.expose_secret())?);
    let key = Ed25519KeyPair::from_pkcs8(&bytes)
        .map_err(|_| "host signing credential is not Ed25519 PKCS#8")?;
    if STANDARD.encode(key.public_key().as_ref())
        != binding.target.issuers[&binding.issuer_id].public_keys[&binding.key_id]
    {
        return Err(refused(
            RefusalCode::Issuer,
            "vault key differs from the adopted issuer key",
        )
        .into());
    }
    let signed = SignedRequest::sign(request.clone(), binding.key_id.clone(), &key);
    let bytes = serde_json::to_vec(&signed)?;
    let authorized =
        binding
            .target
            .authenticate("POST", request.action.verb().path(), &bytes, now())?;
    if matches!(
        request.action,
        Action::Propose { .. } | Action::Invoke { .. }
    ) {
        binding.target.prepare(&authorized, Usage::default())?;
    }
    let assessed_action = if matches!(request.action, Action::Invoke { .. }) {
        let action = action(&runtime, name, &binding, &request, &credential_binding)?;
        if let Some(reply) = admission(
            state,
            &runtime,
            action.clone(),
            input.challenge_id.as_deref(),
        )
        .await?
        {
            return Ok(reply);
        }
        Some(action)
    } else {
        None
    };
    let mut event = crate::audit::Event::new(
        "gateway.host_admission",
        crate::audit::Kind::Gateway,
        crate::audit::Severity::Low,
        "Host gateway request passed issuer admission",
    );
    event.agent = Some(run.agent.clone());
    event.request_id = Some(input.request_id.clone());
    event.details = json!({"host_binding":name,"scope":request,"binding_revision":revision(&binding),"credential_binding":credential_binding,
        "outcome":"issuer_admitted; target admission and execution remain separate"}).into();
    runtime.audit.emit_confirmed(event).await?;
    // A lost response is never retried here. The deterministic target job ID
    // and original client request ID remain available for reconciliation.
    let response = transport::send(&binding, request.action.verb(), bytes, || {
        let current = state
            .read()
            .map_err(|_| "host gateway unavailable")?
            .clone();
        let active = current.policy.as_ref().ok_or("host policy unavailable")?;
        if !Arc::ptr_eq(policy, active)
            || binding.principal(&current, run).is_err()
            || !vault.is_current(&credential)?
            || credential
                .credential()
                .is_expired(time::OffsetDateTime::now_utc())?
            || current
                .gateway_vault
                .load()?
                .is_none_or(|current| current.identity != loaded.identity)
        {
            return Err(refused(
                RefusalCode::Stale,
                "host authority changed before transport admission",
            )
            .into());
        }
        if let Some(previous) = &assessed_action {
            let current_action = action(&current, name, &binding, &request, &credential_binding)?;
            if *previous != current_action {
                return Err(refused(
                    RefusalCode::Stale,
                    "task/action history changed before dispatch; reassess this action",
                )
                .into());
            }
        }
        Ok(())
    })
    .await;
    let job_id = input.action.job_id().map(str::to_owned).unwrap_or_else(|| {
        format!(
            "job-{}",
            revision(&(
                &binding.target.target_id,
                &binding.issuer_id,
                &input.request_id
            ))
        )
    });
    match response {
        Ok(mut response) => {
            if validate_response(&binding, &request, &response).is_err() {
                let mut reply = unavailable_result(
                    &runtime,
                    name,
                    &binding,
                    input,
                    &job_id,
                    "HOST_RESPONSE_MISMATCH",
                )
                .await;
                if let Response::Discovery { discovery } = &response {
                    reply.value["expected_package_sha256"] =
                        json!(revision(&binding.target.package));
                    reply.value["observed_package_sha256"] = json!(discovery.package_sha256);
                }
                return Ok(reply);
            }
            if let Response::Discovery { discovery } = &mut response {
                let grant = binding.grant()?;
                discovery.operations.retain(|op| {
                    grant.operations.contains_key(&op.operation_id)
                        || grant
                            .families
                            .iter()
                            .any(|family| family.contains(&op.operation_id, &op.definition))
                });
                if let Some(catalogue) = &mut discovery.catalogue {
                    catalogue.discovered.retain(|id, op| {
                        grant.operations.contains_key(id)
                            || grant.families.iter().any(|family| family.contains(id, op))
                    });
                    catalogue.changes.retain(|id, _| {
                        discovery.operations.iter().any(|op| op.operation_id == *id)
                            || catalogue.discovered.contains_key(id)
                    });
                }
            }
            let mut event = crate::audit::Event::new(
                "gateway.host_result",
                crate::audit::Kind::Gateway,
                crate::audit::Severity::Low,
                "Host target returned a protocol result",
            );
            event.agent = Some(run.agent.clone());
            event.request_id = Some(input.request_id.clone());
            // Output bytes stay in the target's bounded output owner.
            event.details = json!({"host_binding":name,"run":run,"target_id":binding.target.target_id,"result":match &response {
                Response::Output { job_id, revision, sha256, .. } => json!({"kind":"output","job_id":job_id,"revision":revision,"sha256":sha256}),
                Response::File { job_id, revision, path, file_revision, chunk_sha256, .. } => json!({"kind":"file","job_id":job_id,"revision":revision,"path":path,"file_revision":file_revision,"chunk_sha256":chunk_sha256}),
                _ => json!(response)
            }}).into();
            if runtime.audit.emit_confirmed(event).await.is_err() {
                return Ok(Reply {
                    status: 503,
                    value: json!({"error":"HOST_RESULT_AUDIT_UNAVAILABLE","request_id":input.request_id,
                    "host_binding":name,"target_result":response,"next_action":"Inspect the retained target receipt before retrying; the target has already replied."}),
                });
            }
            Ok(Reply::target(response))
        }
        Err(error) if error.downcast_ref::<Refusal>().is_some() => Err(error),
        Err(_) => Ok(unavailable_result(
            &runtime,
            name,
            &binding,
            input,
            &job_id,
            "HOST_RESULT_UNAVAILABLE",
        )
        .await),
    }
}

async fn unavailable_result(
    runtime: &Runtime,
    name: &str,
    binding: &Binding,
    input: &Input,
    job_id: &str,
    code: &str,
) -> Reply {
    let uncertain = matches!(input.action, Action::Invoke { .. } | Action::Cancel { .. });
    let outcome = if uncertain {
        "uncertain"
    } else {
        "unavailable"
    };
    let next_action = if uncertain {
        "Inspect the original job through this binding before retrying. Do not change the operation ID or replay a mutation whose effect is unknown."
    } else if code == "HOST_RESPONSE_MISMATCH" && matches!(input.action, Action::Discover) {
        "Compare expected_package_sha256 and observed_package_sha256 with the target and gateway owners; adopt a compatible package snapshot, then rediscover. No invocation was retried."
    } else {
        "Inspect the selected target connection and active revisions, then repeat this read or proposal when ready. No invocation was sent by this request."
    };
    let mut value = json!({"error":code,"execution_outcome":outcome,"request_id":input.request_id,
        "host_binding":name,"target_id":binding.target.target_id,"next_action":next_action});
    if uncertain {
        value["possible_job_id"] = json!(job_id);
    } else if let Some(job_id) = input.action.job_id() {
        value["job_id"] = json!(job_id);
    }
    let mut event = crate::audit::Event::new(
        "gateway.host_result_unavailable",
        crate::audit::Kind::Gateway,
        crate::audit::Severity::High,
        "Host target reply unavailable or mismatched",
    );
    event.agent = Some(
        binding
            .grant()
            .expect("validated binding")
            .principal
            .run
            .agent
            .clone(),
    );
    event.request_id = Some(input.request_id.clone());
    event.details = json!({"host_binding":name,"target_id":binding.target.target_id,
        "possible_job_id":uncertain.then_some(job_id),"reason":code,"execution_outcome":outcome})
    .into();
    let _ = runtime.audit.emit_confirmed(event).await;
    Reply { status: 503, value }
}

/// Full operator-adopted authority, rather than an example payload. The
/// existing policy assessment owns its audience and never probes an endpoint.
pub(crate) fn assess(policy: &Policy) -> Result<Value, Error> {
    let entries=policy.host_bindings()?.into_iter().map(|(name,binding)| {
        let grant=binding.grant()?;
        let checkers = policy.named_checks().route_challenges.iter().flat_map(|(name,challenge)| {
            challenge.steps.iter().filter_map(move |step| {
                let crate::policy::checks::challenges::Step::TaskAction { check, max_attempts, disclose_rationale, .. } = step else { return None };
                let definition = policy.named_checks().checks.get(check)?;
                Some(json!({"challenge":name,"selectors":challenge,"check":check,
                    "definition_revision":revision(definition),"source":definition.source,
                    "implementation_version":definition.implementation_version,"configuration_version":definition.configuration_version,
                    "model_inputs":definition.inputs,"max_attempts":max_attempts,"disclose_rationale":disclose_rationale}))
            })
        }).collect::<Vec<_>>();
        let model=if binding.target.package.semantics.is_some() {
            semantics::assess_target(&binding.target,&binding.issuer_id,&grant.principal,None,&[],now())
                .unwrap_or_else(|error|json!({"status":"unavailable","reason":error.to_string()}))
        } else {json!({"status":"uncharacterised","reason":"No reviewed host effect model. Enforceable grant bounds are shown separately."})};
        Ok(json!({"binding":name,"target_id":binding.target.target_id,"issuer_id":binding.issuer_id,
            "grant_id":binding.grant_id,"principal":grant.principal,"full_grant":grant,"target_ceiling":binding.target.ceiling,
            "target_families":binding.target.families,"binding_revision":revision(&binding),"task_revision":binding.task_revision,
            "credential_custody":"Signing material remains in the existing encrypted vault. The binding contains only its reference.",
            "enforcement_and_effects":model,"limitations":["Issuer-adopted input, not a current target or running-job observation. Gateway policy and action checks still apply.",
                "A grant ending does not undo persistent effects or stop an admitted job. Target execution deadlines and explicit cancellation govern running work."],
            "independent_task_action_checks":{"adopted":checkers,
                "configuration_owner":"The issuing instance's policy, task registry, pinned job and existing service grants. Agent rationale selects none of these.",
                "composed_authority":"Compare the full grant, target ceiling and modeled combined effects with the checker paths and model dependencies shown here. Broad host authority can include authority to change the checker, policy or credentials; configuration separation alone cannot establish independence.",
                "limitation":"Another model can share failure modes or be misled. Its finding is an additional signal, never a containment guarantee."}}))
    }).collect::<Result<Vec<_>,Error>>()?;
    Ok(json!(entries))
}

fn validate_response(
    binding: &Binding,
    request: &Request,
    response: &Response,
) -> Result<(), Refusal> {
    let valid = match (response, &request.action) {
        (Response::Refused { .. }, _) => true,
        (Response::Discovery { discovery }, Action::Discover) => {
            discovery.target_id == binding.target.target_id
                && discovery.package_sha256 == revision(&binding.target.package)
        }
        (Response::Proposal { prepared, .. }, Action::Propose { invocation }) => {
            prepared.invocation.operation_id == invocation.operation_id
                && prepared.invocation.resource_id == invocation.resource_id
                && prepared.invocation.operation_sha256 == invocation.operation_sha256
                && prepared.invocation.implementation_sha256 == invocation.implementation_sha256
                && prepared.invocation.arguments
                    == binding.target.package.operations[&invocation.operation_id]
                        .arguments(&invocation.arguments)?
                && prepared.file_roots
                    == binding.target.package.operations[&invocation.operation_id]
                        .execution
                        .filesystem
                        .write
                && request.expected.as_ref() == Some(&prepared.revisions)
                && prepared.valid_until == request.expires_at
        }
        (
            Response::Job { receipt },
            Action::Invoke { .. } | Action::Job { .. } | Action::Cancel { .. },
        ) => {
            receipt.target_id == request.target_id
                && receipt.issuer_id == request.issuer_id
                && receipt.grant_id == request.grant_id
                && receipt.principal == request.principal
                && if matches!(request.action, Action::Invoke { .. }) {
                    receipt.request_id == request.request_id
                        && receipt.request_sha256 == revision(request)
                } else {
                    request.action.job_id() == Some(receipt.job_id.as_str())
                }
        }
        (
            Response::Output { job_id, .. },
            Action::Output {
                job_id: expected, ..
            },
        ) => job_id == expected,
        (
            Response::File {
                job_id,
                path,
                offset,
                file_revision,
                data_base64,
                eof,
                total_bytes,
                chunk_sha256,
                ..
            },
            Action::File {
                job_id: expected,
                path: expected_path,
                offset: expected_offset,
                max_bytes,
                expected_file_revision,
            },
        ) => {
            job_id == expected
                && path == expected_path
                && offset == expected_offset
                && expected_file_revision
                    .as_ref()
                    .is_none_or(|expected| expected == file_revision)
                && STANDARD.decode(data_base64).is_ok_and(|data| {
                    data.len() as u64 <= *max_bytes
                        && offset
                            .checked_add(data.len() as u64)
                            .is_some_and(|end| end <= *total_bytes && *eof == (end == *total_bytes))
                        && ring::digest::digest(&ring::digest::SHA256, &data)
                            .as_ref()
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                            == *chunk_sha256
                })
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(refused(
            RefusalCode::Stale,
            "target response differs from the adopted request; inspect the original operation before retrying",
        ))
    }
}

async fn admission(
    state: &RuntimeState,
    runtime: &Arc<Runtime>,
    action: Value,
    selected: Option<&str>,
) -> Result<Option<Reply>, Error> {
    let policy = runtime.policy.as_ref().ok_or("host policy unavailable")?;
    let authority = pending::Authority { revision:approval_revision(policy,&action).ok_or("host approval authority unavailable")?,
        action:action.clone(), method:"POST".into(), scheme:"local".into(), port:None, resource_digest:revision(&action),
        options:vec![pending::OptionScope { id:"exact".into(), session_id:None,
            effect:"Permit only this exact host invocation under its current run, task, binding, target revisions and operation ID. Target authority and all hard denials still apply. Approval does not execute or retry the operation; revocation does not stop an admitted job.".into(), parameters:Value::Null }],
        expires_at:Some(time::OffsetDateTime::from_unix_timestamp(action["request"]["expires_at"].as_u64().ok_or("host expiry unavailable")? as i64)?.format(&time::format_description::well_known::Rfc3339)?),
        credential_bindings:BTreeMap::from([(action["credential"].as_str().ok_or("host credential unavailable")?.into(),action["credential_binding"].as_str().ok_or("host credential binding unavailable")?.into())]) };
    if let Some(id) = selected {
        let record = pending::lookup(&runtime.audit, id)?.ok_or("host challenge unavailable")?;
        if record.authority.action != action || record.authority.revision != authority.revision {
            return Err(refused(
                RefusalCode::Stale,
                "host challenge belongs to different invocation or authority",
            )
            .into());
        }
        if record.status == "approved"
            && approval_revision(policy, &record.authority.action).as_deref()
                == Some(record.authority.revision.as_str())
            && crate::policy::checks::challenges::evidence_current(policy, &record)
        {
            return Ok(None);
        }
    }
    // Use the existing action subject and adopted check runner even for a
    // route already allowed by policy. Private iteration never pages anyone.
    let authority_digest = pending::digest(&authority.material());
    let private_record = if policy.named_checks().route_challenges.values().any(|c| {
        c.applies(&action)
            && c.steps.iter().any(|s| {
                matches!(
                    s,
                    crate::policy::checks::challenges::Step::TaskAction { .. }
                )
            })
    }) {
        let store = runtime.audit.approvals().clone();
        let (authority, policy) = (authority.clone(), policy.clone());
        Some(
            tokio::task::spawn_blocking(move || {
                store.submit_status(
                    authority,
                    &uuid::Uuid::new_v4().to_string(),
                    &policy,
                    "challenged",
                )
            })
            .await??,
        )
    } else {
        None
    };
    let assessment = crate::policy::checks::challenges::assess(
        &authority_digest,
        &authority.action,
        &BTreeMap::new(),
        runtime,
        state,
    )
    .await?;
    if assessment.denied {
        if let Some(record) = private_record {
            runtime
                .audit
                .approvals()
                .decide(&record.approval_id, |record| {
                    record.status = "rejected".into();
                    record.result["refusal_source"] = json!("adopted_task_action_check");
                    record.result["challenge"] = assessment.view.clone();
                    record.result["evidence"] = json!(assessment.evidence);
                    Ok(())
                })?;
        }
        return Ok(Some(Reply {
            status: 403,
            value: json!({"error":"HOST_OPERATION_REFUSED",
            "assessment":assessment.view,"next_action":"Propose a narrower or relevant action under current authority."}),
        }));
    }
    if assessment.ready {
        if let Some(record) = private_record {
            runtime
                .audit
                .approvals()
                .decide(&record.approval_id, |record| {
                    record.result["challenge"] = assessment.view.clone();
                    record.result["evidence"] = json!(assessment.evidence);
                    // A passed optional check needs no permission exception.
                    record.status = "completed".into();
                    Ok(())
                })?;
        }
        return Ok(None);
    }
    let store = runtime.audit.approvals().clone();
    let policy_owned = policy.clone();
    // The client operation ID belongs to the target ledger; the private
    // challenge uses a distinct host-owned request ID in the approval owner.
    let request_id = uuid::Uuid::new_v4().to_string();
    let record = if let Some(record) = private_record {
        record
    } else {
        tokio::task::spawn_blocking(move || {
            store.submit_status(authority, &request_id, &policy_owned, "challenged")
        })
        .await??
    };
    Ok(Some(Reply {
        status: 428,
        value: json!({"error":"HOST_OPERATION_CHALLENGE","challenge_id":record.approval_id,"status":record.current_status(policy)?,
        "assessment":assessment.view,"scope":record.authority,"reconsideration":"Abandon or revise this operation privately. Explain the task, source and alternatives before explicit eligible escalation.",
        "escalate":format!("/gateway/challenges/{}/escalate",record.approval_id)}),
    }))
}
