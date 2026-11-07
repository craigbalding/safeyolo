//! Private operation receipts fence duplicate effects across replies and restarts.

use std::{path::PathBuf, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    Error, RuntimeState, audit,
    host_agents::Agent,
    host_runs::AgentRun,
    policy::{
        Policy,
        support::{Grant, Lifecycle},
    },
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Action {
    Inspect,
    GuestCommand {
        command: String,
        timeout_seconds: u64,
    },
    GuestLog {
        path: String,
    },
    GuestProbe {
        timeout_seconds: u64,
    },
    Lifecycle {
        operation: Lifecycle,
    },
}

impl Action {
    fn permitted(&self, grant: &Grant) -> bool {
        match self {
            Self::Inspect => true,
            Self::GuestCommand { .. } | Self::GuestProbe { .. } => grant.guest_admin,
            Self::GuestLog { path } => grant.guest_admin || grant.guest_logs.contains(path),
            Self::Lifecycle { operation } => grant.lifecycle.contains(operation),
        }
    }

    // Commands never enter ordinary events or receipts. Only their digest is
    // retained for retry comparison. Selected log paths remain private too.
    fn permission(&self) -> Self {
        match self {
            Self::GuestCommand {
                timeout_seconds, ..
            } => Self::GuestCommand {
                command: String::new(),
                timeout_seconds: *timeout_seconds,
            },
            other => other.clone(),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::GuestCommand { .. } => "guest_command",
            Self::GuestLog { .. } => "guest_log",
            Self::GuestProbe { .. } => "guest_probe",
            Self::Lifecycle { .. } => "lifecycle",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub operation_id: String,
    pub grant: String,
    pub instance_id: Option<String>,
    pub target_id: String,
    pub expected_run: Option<String>,
    pub operation: Action,
}

fn valid_operation_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024
}

fn authorize(policy: &Policy, run: &AgentRun, input: &Request) -> Result<(Grant, Agent), Error> {
    if !run.current(policy) {
        return Err(super::refuse(
            403,
            "trusted current support-agent run required",
        ));
    }
    let instance = super::instance_id()?;
    if input
        .instance_id
        .as_ref()
        .is_some_and(|selected| selected != &instance)
    {
        return Err(super::refuse(
            403,
            "support operation belongs to a different owning instance",
        ));
    }
    let grant = policy.support_grants().remove(&input.grant)
        .filter(|grant| grant.active() && grant.instance_id == instance
            && grant.support.name == run.agent && grant.support.agent_id == run.agent_id)
        .ok_or_else(|| super::refuse(403, "current support grant required; ask the operator to preview or change support authority"))?;
    let target = grant
        .targets
        .iter()
        .find(|target| target.agent_id == input.target_id)
        .filter(|target| policy.evidence_agent_id(&target.name) == Some(target.agent_id.as_str()))
        .ok_or_else(|| {
            super::refuse(
                403,
                "selected durable target is outside current support authority",
            )
        })?;
    if !input.operation.permitted(&grant) {
        return Err(super::refuse(
            403,
            "missing support authority for this action; ask the operator to preview or change the grant",
        ));
    }
    let agents = crate::host_agents::list()?;
    let agent = crate::host_agents::by_id(&agents, &target.agent_id)?
        .cloned()
        .filter(|agent| agent.name == target.name)
        .ok_or("durable target configuration changed")?;
    Ok((grant, agent))
}

fn receipt_path(run: &AgentRun, operation_id: &str) -> Result<PathBuf, Error> {
    if !valid_operation_id(operation_id) {
        return Err(super::refuse(400, "invalid support operation_id"));
    }
    let directory = crate::host_platform::config_dir().join("data/support-operations");
    std::fs::create_dir_all(&directory)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    let id = crate::approvals::pending::digest(&json!([run.agent_id, operation_id]));
    Ok(directory.join(format!("{id}.json")))
}

fn reconcile(mut receipt: Value, active: bool) -> Value {
    if matches!(receipt["state"].as_str(), Some("queued" | "running")) {
        if !active {
            receipt["last_recorded_state"] = receipt["state"].clone();
            receipt["state"] = json!("outcome_unknown");
        }
        receipt["completion_verified"] = json!(false);
        receipt["recovery"] = json!(
            "Inspect the target before a new operation. This operation is never replayed, including after a proxy restart."
        );
    }
    receipt
}

fn agent_view(receipt: Value, active: bool) -> Value {
    let mut value = reconcile(receipt, active);
    if let Some(fields) = value.as_object_mut() {
        for field in ["request_digest", "permission"] {
            fields.shift_remove(field);
        }
    }
    value
}

pub(crate) fn discover(state: &RuntimeState, run: &AgentRun) -> Result<Value, Error> {
    let policy = super::current_policy(state)?;
    if !run.current(&policy) {
        return Err(super::refuse(
            403,
            "trusted current support-agent run required",
        ));
    }
    let instance = super::instance_id()?;
    let grants: Vec<_> = policy
        .support_grants()
        .into_iter()
        .filter(|(_, grant)| {
            grant.instance_id == instance
                && grant.support.name == run.agent
                && grant.support.agent_id == run.agent_id
        })
        .map(|(name, grant)| super::grant_view(&policy, &name, &grant, &instance))
        .collect();
    Ok(json!({"instance_id":instance,"grants":grants}))
}

pub(crate) fn read(
    state: &RuntimeState,
    run: &AgentRun,
    operation_id: &str,
) -> Result<Value, Error> {
    let path = receipt_path(run, operation_id)?;
    if !path.try_exists()? {
        return Err(super::refuse(404, "support operation unavailable"));
    }
    let lock = match crate::host_platform::try_lock_host_state(&path.with_extension("lock")) {
        Ok(lock) => Some(lock),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => None,
        Err(error) => return Err(error.into()),
    };
    let receipt = crate::guest_commands::read_state_bounded(&path, 1024 * 1024)?
        .ok_or_else(|| super::refuse(404, "support operation unavailable"))?;
    let input: Request = serde_json::from_value(receipt["permission"].clone())?;
    authorize(&super::current_policy(state)?, run, &input)?;
    Ok(agent_view(receipt, lock.is_none()))
}

pub(crate) async fn submit(
    state: &RuntimeState,
    writer: &Arc<audit::Writer>,
    run: &AgentRun,
    input: Request,
) -> Result<Value, Error> {
    if !valid_operation_id(&input.operation_id) {
        return Err(super::refuse(400, "invalid support operation_id"));
    }
    if let Action::GuestCommand {
        command,
        timeout_seconds,
    } = &input.operation
        && (command.is_empty() || command.contains('\0') || *timeout_seconds == 0)
    {
        return Err(super::refuse(
            400,
            "guest command needs a command without NUL and a positive timeout_seconds",
        ));
    }
    if matches!(input.operation, Action::GuestProbe { timeout_seconds: 0 }) {
        return Err(super::refuse(
            400,
            "guest probe needs a positive timeout_seconds",
        ));
    }
    if let Action::GuestLog { path } = &input.operation
        && (!path.starts_with('/') || path.contains('\0') || path.len() >= 4096)
    {
        return Err(super::refuse(
            400,
            "select an absolute guest log path that fits the Linux guest's 4096-byte path limit including NUL",
        ));
    }
    if let Action::GuestCommand {
        timeout_seconds, ..
    }
    | Action::GuestProbe { timeout_seconds } = &input.operation
        && std::time::Instant::now()
            .checked_add(Duration::from_secs(*timeout_seconds))
            .is_none()
    {
        return Err(super::refuse(
            400,
            "timeout exceeds the host clock's representable interval",
        ));
    }
    let owner = state
        .read()
        .map_err(|_| "runtime unavailable")?
        .service_mutations
        .clone();
    let (state, writer, run) = (state.clone(), writer.clone(), run.clone());
    let config = crate::operator_actions::config_path(&state)?;
    // Existing process-owned mutation tasks survive a canceled HTTP response
    // and drain before the audit writer closes. There is no replay worker.
    owner
        .spawn_blocking(move || {
            Ok(
                tokio::runtime::Handle::current().block_on(crate::host_platform::in_config(
                    config,
                    execute(&state, &writer, &run, input),
                )),
            )
        })
        .await?
        .await??
}

async fn emit(
    writer: &audit::Writer,
    run: &AgentRun,
    receipt: &Value,
    phase: &str,
) -> Result<(), Error> {
    let mut event = audit::Event::new(
        format!("agent.support_operation_{phase}"),
        audit::Kind::Agent,
        audit::Severity::High,
        format!("Delegated support operation {phase}"),
    );
    event.agent = Some(run.agent.clone());
    event.details = json!({"instance_id":receipt["instance_id"],"initiator":run,
        "target_id":receipt["target_id"],"target_run":receipt["target_run"],
        "grant":receipt["grant"],"grant_revision":receipt["grant_revision"],"target_binding":receipt.get("target_binding").cloned().unwrap_or(json!("authorized")),
        "operation_id":receipt["operation_id"],"action":receipt["action"],
        "lifecycle_operation":receipt["lifecycle_operation"],"state":receipt["state"],"result_state":receipt["result"]["state"],
        "exit_code":receipt["result"]["exit_code"],"transport_exit_code":receipt["result"]["transport_exit_code"],
        "transport_signal":receipt["result"]["transport_signal"],"resulting_run":receipt["resulting_run"]})
    .into();
    writer.emit_confirmed(event).await?;
    Ok(())
}

async fn execute(
    state: &RuntimeState,
    writer: &audit::Writer,
    run: &AgentRun,
    input: Request,
) -> Result<Value, Error> {
    let policy = super::current_policy(state)?;
    let (grant, target) = match authorize(&policy, run, &input) {
        Ok(authorization) => authorization,
        Err(error) => {
            let denied = json!({"instance_id":super::instance_id().ok(),"target_id":input.target_id.chars().take(128).collect::<String>(),
                "grant":input.grant.chars().take(63).collect::<String>(),"operation_id":input.operation_id,
                "action":input.operation.name(),"state":"denied","target_binding":"unverified"});
            emit(writer, run, &denied, "denied").await?;
            return Err(error);
        }
    };
    let path = receipt_path(run, &input.operation_id)?;
    let digest = crate::approvals::pending::digest(&json!(input));
    let lock_path = path.with_extension("lock");
    let _operation_lock =
        tokio::task::spawn_blocking(move || crate::host_platform::lock_host_state(&lock_path))
            .await??;
    authorize(&super::current_policy(state)?, run, &input)?;
    if let Some(previous) = crate::guest_commands::read_state_bounded(&path, 1024 * 1024)? {
        if previous["request_digest"] != digest {
            return Err(super::refuse(
                409,
                "operation_id already belongs to different inputs; read its original result",
            ));
        }
        return Ok(agent_view(previous, false));
    }
    let mut permission = input.clone();
    permission.operation = input.operation.permission();
    let mut receipt = json!({"operation_id":input.operation_id,"request_digest":digest,
        "permission":permission,"instance_id":grant.instance_id,"initiator":run,
        "target_id":target.id,"target_run":null,"grant":input.grant,"grant_revision":grant.revision(),
        "action":input.operation.name(),"lifecycle_operation":match &input.operation { Action::Lifecycle { operation } => json!(operation), _ => Value::Null },"state":"queued","completion_verified":false,
        "requested_at":time::OffsetDateTime::now_utc().unix_timestamp()});
    crate::guest_commands::write_json(&path, &receipt)?;
    let result = execute_locked(state, writer, run, &input, &target, &path, &mut receipt).await;
    match result {
        Ok(value) => {
            let result_state = value["state"].as_str().unwrap_or("completed");
            receipt["state"] = json!(result_state);
            receipt["completion_verified"] = json!(result_state == "completed");
            // Lifecycle owners return their observation while holding the
            // target lock. A later human action must not become our result.
            receipt["resulting_run"] = value
                .get("run_id")
                .unwrap_or(&receipt["target_run"])
                .clone();
            receipt["result"] = value;
        }
        Err(error) => {
            receipt["state"] = json!(if receipt["execution_started"] == true {
                "outcome_unknown"
            } else {
                "refused"
            });
            receipt["resulting_run"] = Value::Null;
            receipt["diagnostic"] = json!(error.downcast_ref::<super::Refusal>().map_or("Current authority, runtime identity or control did not establish completion. Inspect the current grant and target state before a new operation. Earlier effects can remain when execution started.", |refusal| refusal.message));
        }
    }
    receipt["finished_at"] = json!(time::OffsetDateTime::now_utc().unix_timestamp());
    crate::guest_commands::write_json(&path, &receipt)?;
    if emit(writer, run, &receipt, "finished").await.is_err() {
        receipt["audit_status"] =
            json!("unavailable; the private receipt is saved. Inspect it before a new operation.");
        crate::guest_commands::write_json(&path, &receipt)?;
    }
    Ok(agent_view(receipt, false))
}

async fn execute_locked(
    state: &RuntimeState,
    writer: &audit::Writer,
    run: &AgentRun,
    input: &Request,
    target: &Agent,
    path: &std::path::Path,
    receipt: &mut Value,
) -> Result<Value, Error> {
    let directory = crate::host_platform::config_dir()
        .join("agents")
        .join(&target.name);
    let lock = tokio::task::spawn_blocking(move || {
        crate::host_lifecycle::SetupLock::acquire_in(&directory, None)
    })
    .await??;
    let (grant, target) = authorize(&super::current_policy(state)?, run, input)?;
    let observed = crate::host_runs::observe(&target.name).await;
    let actual_run = observed["run_id"].as_str().map(str::to_owned);
    receipt["target_run"] = json!(actual_run);
    receipt["grant_revision"] = json!(grant.revision());
    if !matches!(input.operation, Action::Inspect) && input.expected_run != actual_run {
        return Err(super::refuse(
            409,
            "target run changed; inspect the target and use a new operation_id for a deliberate new operation",
        ));
    }
    if !matches!(input.operation, Action::Inspect)
        && crate::host_runs::read(&target.name)?.is_some_and(|saved| saved["agent_id"] != target.id)
    {
        return Err(
            "saved runtime belongs to a different durable target; no mutation was attempted".into(),
        );
    }
    receipt["state"] = json!("running");
    crate::guest_commands::write_json(path, receipt)?;
    emit(writer, run, receipt, "started").await?;
    // Audit and diagnostics can wait too. Check host-held authority again at
    // the execution boundary, including the initiating run and target identity.
    let (authorizing_grant, _) = authorize(&super::current_policy(state)?, run, input)?;
    receipt["grant_revision"] = json!(authorizing_grant.revision());
    receipt["execution_started"] = json!(!matches!(
        input.operation,
        Action::GuestCommand { .. } | Action::GuestLog { .. }
    ));
    crate::guest_commands::write_json(path, receipt)?;
    match &input.operation {
        Action::Inspect => Ok(inspection(&crate::host_lifecycle::runtime(&target).await?)),
        Action::GuestCommand { .. } | Action::GuestLog { .. } => {
            require_live_owned(&target, &observed)?;
            let (command, timeout) = match &input.operation {
                Action::GuestCommand {
                    command,
                    timeout_seconds,
                } => (command.clone(), Duration::from_secs(*timeout_seconds)),
                Action::GuestLog { path } => (
                    format!("cat -- '{}'", path.replace('\'', "'\\''")),
                    Duration::from_secs(30),
                ),
                _ => unreachable!(),
            };
            crate::host_platform::guest_command_output_bounded(
                &target.name,
                &command,
                timeout,
                8192,
                &mut || {
                    let (grant, _) = authorize(&super::current_policy(state)?, run, input)?;
                    require_live_owned(&target, &observed)?;
                    receipt["grant_revision"] = json!(grant.revision());
                    receipt["execution_started"] = json!(true);
                    crate::guest_commands::write_json(path, receipt)
                },
            )
            .await
        }
        Action::GuestProbe { timeout_seconds } => {
            let root = crate::host_platform::config_dir();
            let authority = crate::host_runs::authority(&root, &target.name, &target.id)
                .ok_or_else(|| {
                    super::refuse(
                        409,
                        "guest runtime ownership is unverified; preserve its evidence",
                    )
                })?;
            if Some(&authority.run_id) != actual_run.as_ref() {
                return Err(super::refuse(
                    409,
                    "guest runtime changed before the independent probe",
                ));
            }
            let value = crate::host_lifecycle::recover_guest_probe_authorized(
                &root,
                &target.name,
                Duration::from_secs(*timeout_seconds),
                Some(lock),
                &|| authorize(&super::current_policy(state)?, run, input).map(|_| ()),
            )?;
            Ok(
                json!({"state":"completed","guest_probe":value["result"],"supervision_id":value["supervision_id"]}),
            )
        }
        Action::Lifecycle { operation } => {
            let value = lifecycle(state, run, input, &target, *operation, &observed, lock).await?;
            if value["status_code"]
                .as_u64()
                .is_some_and(|status| status >= 400)
            {
                return Err("selected lifecycle action was refused by the runtime owner".into());
            }
            Ok(inspection(&value))
        }
    }
}

fn require_live_owned(target: &Agent, observed: &Value) -> Result<(), Error> {
    let run =
        crate::host_runs::read(&target.name)?.ok_or("target runtime ownership unavailable")?;
    if run["agent_id"] != target.id
        || run["run_id"] != observed["run_id"]
        || observed["exec"] != true
    {
        return Err("target guest control is unavailable or ownership is unverified; inspect runtime and control separately".into());
    }
    Ok(())
}

async fn lifecycle(
    state: &RuntimeState,
    run: &AgentRun,
    input: &Request,
    target: &Agent,
    operation: Lifecycle,
    observed: &Value,
    lock: crate::host_lifecycle::SetupLock,
) -> Result<Value, Error> {
    use crate::host_lifecycle;
    let check = || authorize(&super::current_policy(state)?, run, input).map(|_| ());
    match operation {
        Lifecycle::StartSandbox => {
            if observed["runtime_state"] != "stopped" {
                return Err("sandbox start needs an observed stopped sandbox; missing proxy attachment alone does not justify a start".into());
            }
            host_lifecycle::start_authorized(
                target,
                "sandbox-start",
                Some(lock),
                None,
                false,
                &check,
            )
            .await
        }
        Lifecycle::StartHarness => {
            require_live_owned(target, observed)?;
            host_lifecycle::start_authorized(target, "start", Some(lock), None, false, &check).await
        }
        Lifecycle::RestartHarness => {
            require_live_owned(target, observed)?;
            host_lifecycle::restart_harness(target, lock, || {
                authorize(&super::current_policy(state)?, run, input).map(|_| ())
            })
            .await
        }
        Lifecycle::StopSandbox => host_lifecycle::stop_authorized(target, Some(lock), &check).await,
        Lifecycle::RestartSandbox => {
            host_lifecycle::stop_authorized(target, Some(lock), &check).await?;
            let directory = crate::host_platform::config_dir()
                .join("agents")
                .join(&target.name);
            let lock = tokio::task::spawn_blocking(move || {
                host_lifecycle::SetupLock::acquire_in(&directory, None)
            })
            .await??;
            authorize(&super::current_policy(state)?, run, input)?;
            let current = crate::host_runs::observe(&target.name).await;
            if current["runtime_state"] != "stopped" || current["run_id"] != observed["run_id"] {
                return Err(
                    "target changed during sandbox restart; inspect before a new operation".into(),
                );
            }
            host_lifecycle::start_authorized(target, "start", Some(lock), None, false, &check).await
        }
    }
}

/// Whitelist diagnostic facts. Host paths, scripts, control tokens, arbitrary
/// guest stderr, launch arguments and unrelated worker records never cross it.
fn inspection(observed: &Value) -> Value {
    let mut value = json!({});
    for field in [
        "agent_id",
        "name",
        "runtime_state",
        "control_state",
        "run_id",
        "exec",
        "terminal_state",
        "agent_state",
        "attachable",
        "launch_id",
        "exit_code",
    ] {
        value[field] = observed[field].clone();
    }
    value["proxy_attachment"] = observed["proxy_attachment"]["state"].clone();
    value["launcher_kind"] = observed["launcher"]["kind"].clone();
    value["runtime_diagnostic"] = if observed["runtime_error"].is_null() {
        Value::Null
    } else {
        json!(
            "Runtime ownership or control is degraded. Preserve this run; ask the operator to inspect host diagnostics if guest control is unavailable."
        )
    };
    value["launch_diagnostic"] = if observed["error"].is_null() {
        Value::Null
    } else {
        json!(
            "The recorded coding harness is unavailable or unverified. Inspect authorized guest evidence before selecting harness recovery."
        )
    };
    value["next_action"] = json!(if observed["runtime_state"] == "stopped" {
        "The sandbox is stopped. An authorized sandbox start can use its saved configuration."
    } else if observed["exec"] != true {
        "The sandbox is not proven stopped. Guest execution is unavailable; preserve runtime evidence and inspect control health."
    } else if observed["agent_state"] != "running" {
        "Guest execution is available independently of the harness. Inspect authorized guest evidence or select an authorized harness action."
    } else {
        "The guest and coding harness respond. Proxy attachment is a separate observation."
    });
    value
}
