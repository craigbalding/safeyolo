//! Adopted job and Service Gateway operations. Findings use the shared evaluator.
use super::*;
use crate::{Error, Runtime, RuntimeState};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use std::{
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{Semaphore, watch};
use zeroize::Zeroize;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub timeout_ms: u64,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub max_concurrent: usize,
    pub max_pending: usize,
    pub max_cached: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceOperation {
    pub gate_id: String,
    pub service: String,
    pub capability: String,
    /// Operator-owned endpoint, never a callback supplied by the workload.
    pub endpoint: String,
    pub method: String,
    pub path: String,
    pub effects: Effects,
    pub mapping: Mapping,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Effects {
    Passive,
    RetainsInput,
    Active,
    Unknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mapping {
    Typed,
    #[serde(rename = "github_issue")]
    GitHubIssue,
    RdapRegistration,
}

#[derive(Debug)]
struct CheckExecution {
    running: Arc<Semaphore>,
    pending: Arc<Semaphore>,
}
#[derive(Default, Debug)]
pub(crate) struct CheckExecutions {
    slots: Mutex<BTreeMap<String, Arc<CheckExecution>>>,
    cache: Mutex<BTreeMap<String, BTreeMap<String, Evidence>>>,
}
impl CheckExecutions {
    fn cached(&self, name: &str, key: &str, check: &Check) -> Result<Option<Evidence>> {
        let mut caches = self
            .cache
            .lock()
            .map_err(|_| invalid("check cache unavailable"))?;
        let Some(cache) = caches.get_mut(name) else {
            return Ok(None);
        };
        cache.retain(|_, entry| {
            validate_evidence(check, entry, now());
            entry.unavailable.is_none()
        });
        Ok(cache.get(key).cloned())
    }

    fn remember(&self, name: &str, key: String, entry: Evidence, maximum: usize) -> Result<()> {
        if entry.unavailable.is_some() || maximum == 0 {
            return Ok(());
        }
        let mut caches = self
            .cache
            .lock()
            .map_err(|_| invalid("check cache unavailable"))?;
        let cache = caches.entry(name.into()).or_default();
        if cache.len() >= maximum
            && let Some(old) = cache.keys().next().cloned()
        {
            cache.remove(&old);
        }
        cache.insert(key, entry);
        Ok(())
    }

    pub(super) fn reuse_feed(
        &self,
        name: &str,
        check: &Check,
        mut entry: Evidence,
    ) -> Result<Evidence> {
        let key = content_digest(
            &serde_json::to_vec(&json!({
                "check":check,"subject":entry.subject,"input_digest":entry.input_digest,
                "feed_version":entry.feed_version
            }))
            .expect("feed binding JSON"),
        );
        if let Some(mut result) = self.cached(name, &key, check)? {
            result.acquisition = "reused_managed_feed_snapshot".into();
            return Ok(result);
        }
        validate_evidence(check, &mut entry, now());
        // Membership is already an in-memory binary search. Retain only the
        // most recent subject in the existing cache, without a second store.
        self.remember(name, key, entry.clone(), 1)?;
        Ok(entry)
    }
}

pub(super) fn validate_source(source: &mut EvidenceSource) -> Result<()> {
    let limits = match source {
        EvidenceSource::Job { limits, .. } => limits,
        EvidenceSource::Service { operation, limits } => {
            let uri: hyper::Uri = operation
                .endpoint
                .parse()
                .map_err(|_| invalid("invalid check service endpoint"))?;
            if operation.gate_id.is_empty()
                || operation.service.is_empty()
                || operation.capability.is_empty()
                || !matches!(uri.scheme_str(), Some("http" | "https"))
                || uri.host().is_none()
                || uri.authority().is_some_and(|v| v.as_str().contains('@'))
                || matches!(operation.mapping, Mapping::GitHubIssue)
                    && (operation.endpoint != "https://api.github.com" || operation.method != "GET")
                || uri.path() != "/"
                || uri.query().is_some()
                || operation.method.parse::<hyper::Method>().is_err()
                || !operation.path.starts_with('/')
                || operation.path.contains(['\r', '\n', '#'])
            {
                return Err(invalid(
                    "service checks require a named dependency, HTTP endpoint and explicit operation",
                ));
            }
            limits
        }
        _ => return Ok(()),
    };
    if limits.timeout_ms == 0
        || limits.max_input_bytes == 0
        || limits.max_output_bytes == 0
        || limits.max_concurrent == 0
        || limits
            .max_concurrent
            .checked_add(limits.max_pending)
            .is_none()
        || limits.max_concurrent.saturating_add(limits.max_pending) > Semaphore::MAX_PERMITS
    {
        return Err(invalid(
            "check execution requires positive deadline, byte and concurrency limits",
        ));
    }
    Ok(())
}

impl Checks {
    /// Manual invocation is still an adopted check. Callers supply no host
    /// paths, expected values, implementation or authoritative result.
    pub(crate) async fn invoke_named(
        &self,
        name: &str,
        caller: &str,
        subject: Subject,
        runtime: &Runtime,
        state: &RuntimeState,
    ) -> std::result::Result<Evidence, Error> {
        let check = self.checks.get(name).ok_or("unknown adopted check")?;
        if !check
            .invokers
            .iter()
            .any(|allowed| allowed == caller || allowed == "*")
        {
            return Err("caller is not an adopted check invoker".into());
        }
        let kind = match &subject {
            Subject::Hostname { .. } => SubjectKind::Hostname,
            Subject::Ip { .. } => SubjectKind::Ip,
            Subject::HttpPath { .. } => SubjectKind::HttpPath,
            Subject::Value { .. } => SubjectKind::Value,
        };
        if kind != check.subject
            || !matches!(
                check.source,
                EvidenceSource::Job { .. } | EvidenceSource::Service { .. }
            )
        {
            return Err("unsupported adopted check subject or execution source".into());
        }
        let subject = subject.normalized()?;
        let entry = Evidence {
            check: name.into(),
            source_id: check.source_id.clone(),
            meaning: check.meaning.clone(),
            scale: check.scale.clone(),
            input_digest: Some(check.input_digest(&subject)?),
            subject: Some(subject),
            acquisition: "live".into(),
            file_digest: None,
            file_version: None,
            result: None,
            unavailable: None,
            expires_at_ms: None,
            execution: None,
            feed_version: None,
        };
        self.execute(name, check, entry, runtime, state, vec![name.into()])
            .await
    }

    // The boxed boundary also prevents recursive proxy-listener futures from
    // recursively expanding their Send types.
    pub(crate) fn collect_live<'a>(
        &'a self,
        request: &'a Request<'a>,
        stage: Stage,
        runtime: &'a Runtime,
        state: &'a RuntimeState,
        ancestry: &'a [String],
    ) -> futures_util::future::BoxFuture<'a, Result<BTreeMap<String, Evidence>>> {
        Box::pin(async move {
            let mut evidence = self.collect(request, stage).await?;
            for (name, entry) in &mut evidence {
                let check = &self.checks[name];
                if !matches!(
                    check.source,
                    EvidenceSource::Job { .. } | EvidenceSource::Service { .. }
                ) || entry.subject.is_none()
                {
                    continue;
                }
                entry.acquisition = "live".into();
                entry.execution = None;
                entry.unavailable = None;
                if ancestry.contains(name) {
                    entry.unavailable = Some("recursive/cyclic check dependency".into());
                    continue;
                }
                let mut stack = ancestry.to_vec();
                stack.push(name.clone());
                let outcome = self
                    .execute(name, check, entry.clone(), runtime, state, stack)
                    .await;
                match outcome {
                    Ok(result) => *entry = result,
                    Err(reason) => entry.unavailable = Some(reason.to_string()),
                }
            }
            Ok(evidence)
        })
    }

    async fn execute(
        &self,
        name: &str,
        check: &Check,
        entry: Evidence,
        runtime: &Runtime,
        state: &RuntimeState,
        stack: Vec<String>,
    ) -> std::result::Result<Evidence, Error> {
        let (limits, prepared) = match &check.source {
            EvidenceSource::Job { spec, limits, .. } => {
                let (bytes, version) = read_bounded(spec, limits.max_input_bytes).await?;
                let mut job: crate::jobs::JobSpec = serde_json::from_slice(&bytes)?;
                job.resolve_artifacts(spec.parent().ok_or("check job spec has no parent")?);
                job.validate()?;
                if job.retain_bytes > limits.max_output_bytes
                    || job.max_input_bytes > limits.max_input_bytes as u64
                {
                    return Err("job specification exceeds adopted check byte limits".into());
                }
                (
                    limits,
                    Prepared::Job {
                        job,
                        path: spec.clone(),
                        version,
                        digest: content_digest(&bytes),
                    },
                )
            }
            EvidenceSource::Service { operation, limits } => {
                // Recheck the adopted capability even on a cache hit. The actual
                // call still goes through all normal network and gateway controls.
                let service = service_request(runtime, operation, check, &entry)?;
                (
                    limits,
                    Prepared::Service {
                        operation: operation.clone(),
                        request: service,
                    },
                )
            }
            _ => unreachable!(),
        };
        let input = serde_json::to_vec(
            &json!({"subject":entry.subject,"input_digest":entry.input_digest,
            "inputs":check.inputs,"implementation_version":check.implementation_version,
            "configuration_version":check.configuration_version}),
        )?;
        if input.len() > limits.max_input_bytes {
            return Err("check input limit exceeded".into());
        }
        let key = content_digest(&serde_json::to_vec(
            &json!({"input":content_digest(&input),"source":check.source,"definition":prepared.digest()}),
        )?);
        let execution = self
            .execution
            .slots
            .lock()
            .map_err(|_| "check execution unavailable")?
            .entry(name.into())
            .or_insert_with(|| {
                Arc::new(CheckExecution {
                    running: Arc::new(Semaphore::new(limits.max_concurrent)),
                    pending: Arc::new(Semaphore::new(limits.max_concurrent + limits.max_pending)),
                })
            })
            .clone();
        if let Some(mut result) = self.execution.cached(name, &key, check)? {
            result.acquisition = "reused_live_evidence".into();
            return Ok(result);
        }
        let pending = execution
            .pending
            .clone()
            .try_acquire_owned()
            .map_err(|_| "check pending limit exceeded")?;
        let (cancel, mut cancelled) = watch::channel(false);
        // Dropping the admission cancels the owned worker. The worker retains
        // its permits until job/listener cleanup finishes; no late result caches.
        let cancellation = Cancel(cancel);
        let deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(limits.timeout_ms))
            .ok_or("check deadline exceeds the supported clock range")?;
        let runtime = runtime.clone();
        let state = state.clone();
        let current_runtime = runtime.clone();
        let current_state = state.clone();
        let worker_check = check.clone();
        let limits = limits.clone();
        let worker_execution = execution.clone();
        let check_tasks = runtime.check_tasks.clone();
        let audit = runtime.audit.clone();
        let cancelled_notice = cancelled.clone();
        let check_name = name.to_owned();
        let work = async move {
            let _pending = pending;
            let _running = tokio::select! {
                result = worker_execution.running.clone().acquire_owned() => result.map_err(|_| "check concurrency unavailable")?,
                _ = cancelled.changed() => return Err::<Evidence, Error>("check cancelled while pending".into()),
            };
            if *cancelled.borrow() {
                return Err("check cancelled before execution".into());
            }
            run(
                prepared,
                &worker_check,
                entry,
                &runtime,
                &state,
                input,
                stack,
                cancelled.clone(),
            )
            .await
        };

        let (send, mut worker) = tokio::sync::oneshot::channel();
        {
            let mut tasks = check_tasks
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            while let Some(result) = tasks.try_join_next() {
                if let Err(error) = result {
                    eprintln!("policy check cleanup task failed: {error}");
                }
            }
            tasks.spawn(async move {
                let mut result = work.await;
                // Retain reached execution facts before admission revalidates
                // policy, file versions or run authority. A late result stays
                // inspectable without acquiring decision authority.
                let evidence = result.as_ref().ok().map(|entry| json!({"source_id":entry.source_id,
                    "subject":entry.subject,"input_digest":entry.input_digest,"execution":entry.execution,
                    "result":entry.result,"unavailable":entry.unavailable}));
                let cancelled = *cancelled_notice.borrow();
                if cancelled {
                    result = match result {
                        Ok(entry) => Err(entry.unavailable.unwrap_or_else(|| "check cancelled; late result discarded".into()).into()),
                        Err(error) => Err(error),
                    };
                }
                let reason = result.as_ref().err().map(ToString::to_string);
                let receiver_gone = send.is_closed();
                let discarded = cancelled || receiver_gone;
                let mut event = crate::audit::Event::new(
                    if discarded {"ops.policy_check_cancelled"} else {"ops.policy_check_executed"},
                    crate::audit::Kind::Ops, crate::audit::Severity::Low, "Named policy check execution ended");
                event.details = json!({"check":check_name,"execution_cancelled":cancelled,"receiver_available":!receiver_gone,"evidence":evidence,"error":reason}).into();
                if let Err(error) = audit.emit(event) { // DOC: docs/policy-checks.md
                    result = Err(format!("check execution audit unavailable: {error}").into());
                }
                // Dependency authority belongs to the adopted check. Retaining
                // its evidence does not disclose raw provider data to every
                // workload that can request the derived finding.
                if let Ok(entry) = &mut result {
                    redact_captured_bodies(entry);
                }
                // Admission may disappear after its execution was recorded.
                let _ = send.send(result);
            });
        }
        let result = tokio::select! {
            biased;
            _ = crate::jobs::network::wait_policy_change(&current_state, &current_runtime) => {
                cancellation.0.send_replace(true);
                let _ = worker.await;
                return Err("check policy changed while pending; late result discarded".into());
            },
            result = &mut worker => result??,
            _ = tokio::time::sleep_until(deadline) => {
                cancellation.0.send_replace(true);
                // Teardown has the existing platform/listener bounds. Await it
                // before allowing another execution to take this work's slot.
                let cleanup = match worker.await {
                    Ok(Err(error)) => format!("; {error}"),
                    Err(error) => format!("; check cleanup result unavailable: {error}"),
                    Ok(Ok(_)) => String::new(),
                };
                return Err(format!("check execution deadline exceeded{cleanup}; late result discarded").into());
            },
        };
        let mut result = result;
        validate_evidence(check, &mut result, now());
        self.execution
            .remember(name, key, result.clone(), limits.max_cached)?;
        Ok(result)
    }
}
struct Cancel(watch::Sender<bool>);

fn redact_captured_bodies(entry: &mut Evidence) {
    let Some(execution) = entry.execution.as_mut() else {
        return;
    };
    if execution["kind"] != "job" {
        return;
    }
    if let Some(captures) = execution
        .get_mut("service_evidence")
        .and_then(Value::as_array_mut)
    {
        for capture in captures {
            if let Some(record) = capture.as_object_mut() {
                record.remove("retained_base64");
                record.remove("request_body_base64");
            }
        }
    }
}
impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}
fn now() -> u64 {
    crate::policy::current_time_ms() as u64
}

struct ServiceRequest {
    uri: hyper::Uri,
    auth_header: String,
    authorization: crate::credentials::Secret,
    body: Vec<u8>,
}
enum Prepared {
    Job {
        job: crate::jobs::JobSpec,
        path: PathBuf,
        version: FileVersion,
        digest: String,
    },
    Service {
        operation: ServiceOperation,
        request: ServiceRequest,
    },
}
impl Prepared {
    fn digest(&self) -> Option<&str> {
        match self {
            Self::Job { digest, .. } => Some(digest),
            _ => None,
        }
    }
}

fn service_request(
    runtime: &Runtime,
    operation: &ServiceOperation,
    check: &Check,
    entry: &Evidence,
) -> std::result::Result<ServiceRequest, Error> {
    let policy = runtime
        .policy
        .as_ref()
        .ok_or("check dependency policy unavailable")?;
    let gateway = policy
        .gateway()
        .ok_or("check dependency gateway unavailable")?;
    if matches!(operation.mapping, Mapping::GitHubIssue)
        && gateway.provider_for_host("api.github.com").is_some()
    {
        return Err("GitHub provenance requires the authoritative external GitHub API".into());
    }
    let principal = format!("gate:{}", operation.gate_id);
    let token = gateway
        .capability_token(&principal, &operation.service, &operation.capability)
        .ok_or("missing check dependency grant for adopted capability")?;
    let endpoint: hyper::Uri = operation.endpoint.parse()?;
    let subject = entry.subject.as_ref().ok_or("check subject unavailable")?;
    let path = render_path(&operation.path, subject, &check.inputs)?;
    let uri: hyper::Uri = format!(
        "{}://{}{}",
        endpoint.scheme_str().unwrap(),
        endpoint.authority().unwrap(),
        path
    )
    .parse()?;
    let body = if operation.method.eq_ignore_ascii_case("GET")
        || operation.method.eq_ignore_ascii_case("HEAD")
    {
        Vec::new()
    } else {
        serde_json::to_vec(
            &json!({"subject":subject,"input_digest":entry.input_digest,"inputs":check.inputs}),
        )?
    };
    let registry = gateway
        .registry()
        .ok_or("check service registry unavailable")?;
    let auth = registry
        .services
        .get(&operation.service)
        .and_then(|service| service.auth.as_ref());
    let auth_header = auth
        .map_or("Authorization", |auth| auth.header.as_str())
        .to_owned();
    let authorization =
        crate::credentials::Secret::new(match auth.map(|auth| auth.kind.as_str()) {
            Some("basic") => format!(
                "Basic {}",
                STANDARD.encode(format!(
                    "{}:{}",
                    auth.unwrap().username,
                    token.expose_secret()
                ))
            ),
            Some("bearer") | None => format!("Bearer {}", token.expose_secret()),
            _ => token.expose_secret().to_owned(),
        });
    let mut headers = vec![
        (
            auth_header.clone(),
            authorization.expose_secret().to_owned(),
        ),
        ("content-type".into(), "application/json".into()),
        ("user-agent".into(), "SafeYolo-policy-check".into()),
    ];
    let decision = gateway.select(crate::services::GatewayRequest {
        identity: crate::services::TrustedIdentity::Agent(&principal),
        host: uri.host().unwrap(),
        request: crate::contracts::ContractRequest {
            method: &operation.method,
            target: uri.path_and_query().unwrap().as_str(),
            headers: &headers,
            body: &body,
        },
        route_mode: crate::services::RouteMode::CompiledPolicy(policy),
    });
    for (_, value) in &mut headers {
        value.zeroize();
    }
    match decision {
        crate::services::GatewayDecision::Selected { credential }
            if credential.service == operation.service
                && credential.capability == operation.capability
                && !credential.missing_route_allow => {}
        crate::services::GatewayDecision::Deny { code, .. } => {
            return Err(format!("check dependency operation is not authorized: {code}").into());
        }
        _ => return Err("check dependency operation is not authorized".into()),
    }
    Ok(ServiceRequest {
        uri,
        auth_header,
        authorization,
        body,
    })
}

fn render_path(
    template: &str,
    subject: &Subject,
    inputs: &BTreeMap<String, String>,
) -> std::result::Result<String, Error> {
    let value = match subject {
        Subject::Hostname { hostname } => hostname.clone(),
        Subject::Ip { address } => address.to_string(),
        Subject::HttpPath { hostname, .. } => hostname.clone(),
        Subject::Value { value } => value.clone(),
    };
    const URI_COMPONENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    let encode =
        |value: &str| percent_encoding::utf8_percent_encode(value, URI_COMPONENT).to_string();
    let mut path = template.replace("{subject}", &encode(&value));
    if let Subject::HttpPath {
        path: subject_path, ..
    } = subject
    {
        path = path.replace("{path}", subject_path);
    }
    for (name, value) in inputs {
        path = path.replace(&format!("{{input.{name}}}"), &encode(value));
    }
    if path.contains(['{', '}', '\r', '\n', '#']) || !path.starts_with('/') {
        return Err("unresolved check operation path mapping".into());
    }
    Ok(path)
}

pub(super) async fn read_bounded(
    path: &Path,
    limit: usize,
) -> std::result::Result<(Vec<u8>, FileVersion), Error> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("check specification must be a regular file".into());
    }
    let mut file = tokio::fs::File::from_std(file);
    let version = FileVersion::from_metadata(&file.metadata().await?);
    let mut bytes = Vec::new();
    (&mut file)
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > limit {
        return Err("check specification/input limit exceeded".into());
    }
    if FileVersion::from_metadata(&file.metadata().await?) != version {
        return Err("check specification changed during read".into());
    }
    Ok((bytes, version))
}

// Keep the adopted operation, bound input, runtime and cancellation explicit.
#[allow(clippy::too_many_arguments)]
async fn run(
    prepared: Prepared,
    check: &Check,
    mut entry: Evidence,
    runtime: &Runtime,
    state: &RuntimeState,
    input: Vec<u8>,
    stack: Vec<String>,
    mut cancelled: watch::Receiver<bool>,
) -> std::result::Result<Evidence, Error> {
    if *cancelled.borrow() {
        return Err("check cancelled before execution".into());
    }
    let collected = now();
    let mut captured_source = None;
    let limits = match &check.source {
        EvidenceSource::Job { limits, .. } | EvidenceSource::Service { limits, .. } => limits,
        _ => unreachable!(),
    };
    let (bytes, execution, mapping, path) = match prepared {
        Prepared::Job {
            job,
            path,
            version,
            digest,
        } => {
            let config = runtime
                .config
                .native_config_path
                .as_deref()
                .ok_or("job check requires selected native instance configuration")?;
            let parent = config
                .parent()
                .ok_or("check instance has no directory")?
                .join("data");
            let input_directory = tempfile::Builder::new()
                .prefix("check-input-")
                .tempdir_in(parent)?;
            tokio::fs::write(input_directory.path().join("request.json"), &input).await?;
            let result = crate::jobs::run_check(
                config,
                &job,
                input_directory.path(),
                cancelled.clone(),
                &stack,
            )
            .await?;
            let execution = json!({"kind":"job","engine":result.engine,"outcome_source":result.outcome_source,
                "runtime_report":result.runtime_report,"helper_process_status":result.helper_process_status,
                "run_id":result.run_id,"gate_principal":result.gate_principal,
                "authorization_principal":result.authorization_principal,"definition_digest":digest,
                "gate_definition_sha256":result.gate_definition_sha256,"service_evidence":result.service_evidence,
                "rootfs":result.rootfs,"input_digest":result.input_sha256,"started_at_ms":result.started_unix_ms,
                "ended_at_ms":result.ended_unix_ms,"outcome":result.outcome,"observation_error":result.observation_error,
                "stdout":{"bytes":result.stdout.bytes,"sha256":result.stdout.sha256},
                "stderr":{"bytes":result.stderr.bytes,"sha256":result.stderr.sha256}});
            entry.execution = Some(execution.clone());
            if !matches!(read_bounded(&path, limits.max_input_bytes).await, Ok((_, current)) if current == version)
            {
                entry.unavailable =
                    Some("check job definition changed or became unavailable while pending".into());
                return Ok(entry);
            }
            if result.observation_error.is_some()
                || result.outcome != Some(crate::jobs::Outcome::Exit { code: 0 })
            {
                entry.unavailable = Some("job execution failed or unavailable observation".into());
                return Ok(entry);
            }
            if !matches!(job.engine, crate::jobs::JobEngine::Platform) {
                captured_source = Some(Provenance {
                    source_id: check.source_id.clone(),
                    source_revision: None,
                    content_digest: Some(format!("sha256:{}", result.stdout.sha256)),
                    source_observed_at_ms: None,
                });
            }
            if job.mediated_services.is_some() {
                if result.service_evidence.is_empty()
                    || result
                        .service_evidence
                        .iter()
                        .any(|capture| capture.error.is_some())
                {
                    entry.unavailable =
                        Some("mediated job evidence missing or delegated call failed".into());
                    return Ok(entry);
                }
                captured_source = Some(Provenance {
                    source_id: check.source_id.clone(),
                    source_revision: if result.service_evidence.len() == 1 {
                        result.service_evidence[0].source_revision.clone()
                    } else {
                        None
                    },
                    content_digest: Some(content_digest(&serde_json::to_vec(
                        &result.service_evidence,
                    )?)),
                    // Raw upstream Date/Last-Modified headers remain in the
                    // host captures. Guest timestamps are never observations.
                    source_observed_at_ms: None,
                });
            }
            if result.stderr.bytes > limits.max_output_bytes as u64
                || result.stdout.bytes > limits.max_output_bytes as u64
                || result.stdout.bytes > job.retain_bytes as u64
            {
                entry.unavailable = Some("check output limit exceeded".into());
                return Ok(entry);
            }
            (
                STANDARD.decode(result.stdout.retained_base64)?,
                execution,
                Mapping::Typed,
                None,
            )
        }
        Prepared::Service { operation, request } => {
            if request.body.len() > limits.max_input_bytes {
                return Err("check service input limit exceeded".into());
            }
            #[cfg(not(target_os = "macos"))]
            let parent = runtime
                .config
                .native_config_dir
                .as_deref()
                .ok_or("service check requires a selected instance directory")?
                .join("data");
            #[cfg(target_os = "macos")]
            let parent = std::env::temp_dir();
            let directory = tempfile::Builder::new()
                .prefix("check-")
                // Protect the delegated path before binding, even with umask 000.
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir_in(parent)?;
            let (listener, authority) = crate::jobs::network::local(
                state.clone(),
                &operation.gate_id,
                stack,
                &directory.path().join("p.sock"),
            )?;
            let mut observed_status = None;
            let mut request_started = false;
            let work = async {
                let socket =
                    tokio::net::UnixStream::connect(directory.path().join("p.sock")).await?;
                let (mut client, connection) =
                    hyper::client::conn::http1::handshake(TokioIo::new(socket)).await?;
                let _driver = ServiceConnection(tokio::spawn(connection));
                let request = hyper::Request::builder()
                    .method(operation.method.as_str())
                    .uri(request.uri.clone())
                    .header("host", request.uri.authority().unwrap().as_str())
                    .header(
                        request.auth_header.as_str(),
                        request.authorization.expose_secret(),
                    )
                    .header("content-type", "application/json")
                    .header("user-agent", "SafeYolo-policy-check")
                    .body(Full::new(Bytes::from(request.body)))?;
                request_started = true;
                let response = client.send_request(request).await?;
                let status = response.status();
                observed_status = Some(status.as_u16());
                let mut body = response.into_body();
                let mut bytes = Vec::new();
                while let Some(frame) = body.frame().await {
                    if let Ok(data) = frame?.into_data() {
                        if data.len() > limits.max_output_bytes.saturating_sub(bytes.len()) {
                            return Err::<_, Error>("check output limit exceeded".into());
                        }
                        bytes.extend_from_slice(&data);
                    }
                }
                if !status.is_success() {
                    return Err(format!(
                        "check provider unavailable or refused operation: HTTP {status}"
                    )
                    .into());
                }
                Ok::<_, Error>(bytes)
            };
            let result = tokio::select! { result=work=>result, _=cancelled.changed()=>Err("check service cancelled".into()) };
            let cleanup = listener.stop().await;
            let mut execution = json!({"kind":"service","service":operation.service,"capability":operation.capability,
                "method":operation.method,"path":request.uri.path(),"effects":operation.effects,
                "gate_principal":authority.principal,"caller_id":authority.run.agent_id,
                "run_id":authority.run.run_id,"proxy_request_started":request_started,"http_status":observed_status,
                "started_at_ms":collected,"ended_at_ms":now()});
            let result = match (result, cleanup) {
                (result, Ok(())) => result,
                (result, Err(cleanup)) => Err(format!(
                    "{}; check listener cleanup failed: {cleanup}",
                    result
                        .as_ref()
                        .err()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "check operation finished".into())
                )
                .into()),
            };
            let bytes = match result {
                Ok(bytes) => bytes,
                Err(error) => {
                    entry.execution = Some(execution);
                    entry.unavailable = Some(error.to_string());
                    return Ok(entry);
                }
            };
            execution["response_digest"] = json!(content_digest(&bytes));
            execution["response_bytes"] = json!(bytes.len());
            (
                bytes,
                execution,
                operation.mapping,
                Some(request.uri.path().to_owned()),
            )
        }
    };
    entry.execution = Some(execution);
    let mapped = match mapping {
        Mapping::Typed => serde_json::from_slice::<ProviderResult>(&bytes)
            .map_err(|_| "malformed typed check result".into()),
        Mapping::GitHubIssue => github_issue(&bytes, path.as_deref().unwrap(), &check.inputs),
        Mapping::RdapRegistration => rdap_registration(&bytes, entry.subject.as_ref().unwrap()),
    };
    match mapped {
        Ok(result) => {
            entry.result = Some(CheckResult {
                subject: entry.subject.clone().unwrap(),
                input_digest: entry.input_digest.clone().unwrap(),
                implementation_version: check.implementation_version.clone(),
                configuration_version: check.configuration_version.clone(),
                collected_at_ms: now(),
                valid_until_ms: result.valid_until_ms,
                source: captured_source.unwrap_or(Provenance {
                    source_id: check.source_id.clone(),
                    source_revision: result.source_revision,
                    content_digest: Some(content_digest(&bytes)),
                    source_observed_at_ms: result.source_observed_at_ms,
                }),
                finding: result.finding,
            })
        }
        Err(error) => entry.unavailable = Some(error.to_string()),
    }
    Ok(entry)
}

struct ServiceConnection(tokio::task::JoinHandle<hyper::Result<()>>);
impl Drop for ServiceConnection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Providers supply findings and source facts; the host binds identity, subject,
/// inputs, versions, collection time, execution and response digest.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderResult {
    finding: Finding,
    #[serde(default)]
    source_revision: Option<String>,
    #[serde(default)]
    source_observed_at_ms: Option<u64>,
    #[serde(default)]
    valid_until_ms: Option<u64>,
}

/// RFC 9083 registration evidence for the exact queried domain. A registry
/// record for a parent says nothing about the creation of a hosted tenant.
fn rdap_registration(
    bytes: &[u8],
    subject: &Subject,
) -> std::result::Result<ProviderResult, Error> {
    let Subject::Hostname { .. } = subject else {
        return Err("RDAP registration requires a hostname subject".into());
    };
    let record: Value = serde_json::from_slice(bytes)?;
    let domain = record["ldhName"]
        .as_str()
        .ok_or("RDAP domain name missing")?;
    if record["objectClassName"] != "domain"
        || (Subject::Hostname {
            hostname: domain.into(),
        })
        .normalized()?
            != *subject
    {
        return Err(
            "RDAP record does not describe the exact hostname; tenant age is unknown".into(),
        );
    }
    let events = record["events"].as_array().ok_or("RDAP events missing")?;
    let mut registrations = events
        .iter()
        .filter(|event| event["eventAction"] == "registration");
    let date = registrations
        .next()
        .and_then(|event| event["eventDate"].as_str())
        .ok_or("RDAP registration event missing")?;
    if registrations.next().is_some() {
        return Err("RDAP registration event is ambiguous".into());
    }
    let timestamp =
        time::OffsetDateTime::parse(date, &time::format_description::well_known::Rfc3339)?;
    let unix_ms = u64::try_from(timestamp.unix_timestamp_nanos().div_euclid(1_000_000))
        .map_err(|_| "RDAP registration predates the supported Unix time range")?;
    if unix_ms > now() {
        return Err("RDAP registration event is in the future".into());
    }
    Ok(ProviderResult {
        finding: Finding::Timestamp { unix_ms },
        // Registration time is the finding, not the age of the provider's
        // dataset. No revision or source observation time is invented.
        source_revision: None,
        source_observed_at_ms: None,
        valid_until_ms: None,
    })
}
fn github_issue(
    bytes: &[u8],
    path: &str,
    inputs: &BTreeMap<String, String>,
) -> std::result::Result<ProviderResult, Error> {
    let issue: Value = serde_json::from_slice(bytes)?;
    let expected_author = inputs
        .get("expected_author")
        .ok_or("GitHub check requires policy-owned expected_author")?;
    let expected_owner = inputs
        .get("expected_repository_owner")
        .ok_or("GitHub check requires policy-owned expected_repository_owner")?;
    let author = issue["user"]["login"]
        .as_str()
        .ok_or("GitHub author unavailable")?;
    let updated = issue["updated_at"]
        .as_str()
        .ok_or("GitHub issue revision unavailable")?;
    let id = issue["id"]
        .as_u64()
        .ok_or("GitHub issue identity unavailable")?;
    if issue["url"] != format!("https://api.github.com{path}")
        || !issue["body"].is_string()
        || !issue["title"].is_string()
    {
        return Err("GitHub issue content/subject unavailable or mismatched".into());
    }
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() != 6
        || parts[1] != "repos"
        || parts[4] != "issues"
        || parts[5].parse::<u64>().is_err()
    {
        return Err("GitHub issue operation path mismatch".into());
    }
    Ok(ProviderResult {
        finding: Finding::Finding {
            positive: author.eq_ignore_ascii_case(expected_author)
                && parts[2].eq_ignore_ascii_case(expected_owner),
        },
        source_revision: Some(format!("issue:{id}:{updated}")),
        source_observed_at_ms: None,
        valid_until_ms: None,
    })
}

#[cfg(test)]
mod tests;
