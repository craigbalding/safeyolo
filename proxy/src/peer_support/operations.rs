//! Private operation receipts fence duplicate effects across replies and restarts.

use std::{path::PathBuf, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::Caller;
use crate::{
    Error, RuntimeState, audit,
    host_agents::Agent,
    policy::{
        Policy,
        support::{Grant, Lifecycle},
    },
};

pub(crate) mod receipts;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Action {
    Inspect,
    FactoryState {
        factory: String,
        snapshot_id: String,
    },
    FactoryDirection {
        factory: String,
        snapshot_id: String,
        kind: String,
        text: String,
    },
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
            Self::FactoryState {
                factory,
                snapshot_id,
            } => grant.factory_directions.iter().any(|selected| {
                &selected.factory == factory && &selected.snapshot_id == snapshot_id
            }),
            Self::FactoryDirection {
                factory,
                snapshot_id,
                kind,
                ..
            } => grant.factory_directions.iter().any(|selected| {
                &selected.factory == factory
                    && &selected.snapshot_id == snapshot_id
                    && selected.types.contains(kind)
            }),
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
            Self::FactoryDirection {
                factory,
                snapshot_id,
                kind,
                ..
            } => Self::FactoryDirection {
                factory: factory.clone(),
                snapshot_id: snapshot_id.clone(),
                kind: kind.clone(),
                text: String::new(),
            },
            other => other.clone(),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::FactoryState { .. } => "factory_state",
            Self::FactoryDirection { .. } => "factory_direction",
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

pub(crate) fn valid_operation_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024
}

pub(crate) fn authorize(
    policy: &Policy,
    run: &Caller,
    input: &Request,
) -> Result<(Grant, Agent), Error> {
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
            && run.matches(policy,grant))
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
    if let Action::FactoryState {
        factory,
        snapshot_id,
    }
    | Action::FactoryDirection {
        factory,
        snapshot_id,
        ..
    } = &input.operation
    {
        let kind = match &input.operation {
            Action::FactoryDirection { kind, .. } => Some(kind.as_str()),
            _ => None,
        };
        let snapshot = crate::factory::direction_binding(
            &crate::host_platform::config_dir(),
            factory,
            snapshot_id,
            kind,
        )
        .map_err(|_| super::refuse(403, "current approved factory and direction type required"))?;
        if snapshot.operator_agent() != target.name {
            return Err(super::refuse(
                403,
                "select the factory's current operator-input agent",
            ));
        }
    }
    Ok((grant, agent))
}

fn authorize_target(
    state: &RuntimeState,
    run: &Caller,
    input: &Request,
    target: &Agent,
) -> Result<(Grant, Agent), Error> {
    let (grant, current) = authorize(&super::current_policy(state)?, run, input)?;
    if current.name != target.name || current.id != target.id {
        return Err(super::refuse(
            409,
            "target configuration changed while waiting; inspect before a new operation",
        ));
    }
    Ok((grant, current))
}

fn receipt_path(run: &Caller, operation_id: &str) -> Result<PathBuf, Error> {
    if !valid_operation_id(operation_id) {
        return Err(super::refuse(400, "invalid support operation_id"));
    }
    let directory = super::audit_delivery::directory("support-operations")?;
    let id = crate::approvals::pending::digest(&json!([run.principal(), operation_id]));
    Ok(directory.join(format!("{id}.json")))
}

fn reconcile(mut receipt: Value, active: bool) -> Value {
    if matches!(receipt["state"].as_str(), Some("queued" | "running")) {
        if !active {
            receipt["last_recorded_state"] = receipt["state"].clone();
            receipt["state"] = json!("outcome_unknown");
            receipt["audit_status"] = json!(super::audit_delivery::PENDING);
        }
        receipt["completion_verified"] = json!(false);
        receipt["recovery"] = json!(
            "Inspect the target before a new operation. This operation is never replayed, including after a proxy restart."
        );
    }
    receipt
}

fn filter_observations(value: &mut Value, grant: Option<&Grant>) {
    if !value["observations"].is_object() {
        return;
    }
    if grant.is_none_or(|grant| grant.notifications.is_empty()) {
        value["observations"] = json!({"availability":if grant.is_some(){"not_selected"}else{"current_authority_unavailable"},"sources":[],
            "next_action":"Inspect current notice authority on the owner; retained health does not grant disclosure."});
    } else if let Some(sources) = value["observations"]["sources"].as_array_mut() {
        let count = sources.len();
        sources.retain(|row| {
            row["source"]
                .as_str()
                .is_some_and(|source| super::events::observation_selected(grant.unwrap(), source))
        });
        if sources.len() != count {
            value["observations"]["availability"] = json!("recorded_partial");
        }
    }
}

fn agent_view(receipt: Value, active: bool, grant: Option<&Grant>) -> Value {
    let mut value = reconcile(receipt, active);
    filter_observations(&mut value["result"], grant);
    if let Some(fields) = value.as_object_mut() {
        for field in ["request_digest", "permission", "audit_pending"] {
            fields.shift_remove(field);
        }
    }
    value
}

pub(crate) fn discover(state: &RuntimeState, run: &Caller) -> Result<Value, Error> {
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
        .filter(|(_, grant)| grant.instance_id == instance && run.matches(&policy, grant))
        .map(|(name, grant)| super::grant_view(&policy, &name, &grant, &instance))
        .collect();
    Ok(json!({"instance_id":instance,"grants":grants}))
}

pub(crate) fn read(state: &RuntimeState, run: &Caller, operation_id: &str) -> Result<Value, Error> {
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
    let (grant, _) = authorize(&super::current_policy(state)?, run, &input)?;
    Ok(agent_view(receipt, lock.is_none(), Some(&grant)))
}

pub(crate) async fn submit(
    state: &RuntimeState,
    writer: &Arc<audit::Writer>,
    run: &Caller,
    input: Request,
) -> Result<Value, Error> {
    if !valid_operation_id(&input.operation_id) {
        return Err(super::refuse(400, "invalid support operation_id"));
    }
    if let Action::FactoryDirection { text, .. } = &input.operation
        && (text.trim().is_empty() || text.len() > 256 * 1024)
    {
        return Err(super::refuse(
            400,
            "factory direction needs nonempty text within the Coord message bound",
        ));
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
        .spawn(Box::pin(async move {
            Ok(crate::host_platform::in_config(
                config,
                Box::pin(execute(&state, &writer, &run, input)),
            )
            .await)
        }))
        .await?
        .await??
}

fn event(run: &Caller, receipt: &Value, phase: &str) -> audit::Event {
    let mut event = audit::Event::new(
        format!("agent.support_operation_{phase}"),
        audit::Kind::Agent,
        audit::Severity::High,
        format!("Delegated support operation {phase}"),
    );
    event.agent = Some(
        run.remote
            .as_ref()
            .map_or(&run.run.agent, |remote| &remote.display_name)
            .clone(),
    );
    event.details = json!({"instance_id":receipt["instance_id"],"initiator":run,
        "target_id":receipt["target_id"],"target_run":receipt["target_run"],
        "grant":receipt["grant"],"grant_revision":receipt["grant_revision"],"target_binding":receipt.get("target_binding").cloned().unwrap_or(json!("authorized")),
        "operation_id":receipt["operation_id"],"action":receipt["action"],
        "lifecycle_operation":receipt["lifecycle_operation"],"state":receipt["state"],"result_state":receipt["result"]["state"],
        "exit_code":receipt["result"]["exit_code"],"transport_exit_code":receipt["result"]["transport_exit_code"],
        "transport_signal":receipt["result"]["transport_signal"],"resulting_run":receipt["resulting_run"],
        "execution_started":receipt["execution_started"],"completion_verified":receipt["completion_verified"],
        "last_recorded_state":receipt["last_recorded_state"],"requested_at":receipt["requested_at"],"finished_at":receipt["finished_at"],
        "phase":receipt["phase"],"reason":receipt["reason"],"untrusted_claims":receipt["untrusted_claims"]})
    .into();
    event
}

async fn emit(
    writer: &audit::Writer,
    run: &Caller,
    receipt: &Value,
    phase: &str,
) -> Result<(), Error> {
    writer.emit_confirmed(event(run, receipt, phase)).await?;
    Ok(())
}

async fn denied(
    writer: &audit::Writer,
    run: &Caller,
    input: &Request,
    phase: &str,
) -> Result<(), Error> {
    let denied = json!({"instance_id":super::instance_id().ok(),
        "untrusted_claims":{"target_id":Some(&input.target_id).filter(|id|crate::agent_api::coord::valid_agent_id(id)),
            "grant":Some(&input.grant).filter(|name|crate::host_platform::valid_agent_name(name))},
        "operation_id":input.operation_id,"action":input.operation.name(),
        "state":"refused","target_binding":"unverified","phase":phase,"reason":"authorization_changed_or_unavailable"});
    emit(writer, run, &denied, "denied").await
}

fn stage_final(receipt: &mut Value) -> Result<(), Error> {
    let run: Caller = serde_json::from_value(receipt["initiator"].clone())?;
    let mut final_event = event(&run, receipt, "finished");
    let id = format!(
        "evt-{}",
        &crate::approvals::pending::digest(&json!([
            receipt["instance_id"],
            receipt["initiator"],
            receipt["operation_id"],
            "finished"
        ]))[..32]
    );
    final_event.event_id = Some(id.clone());
    receipt["audit_event_id"] = json!(id);
    receipt["audit_pending"] = json!(final_event.encode_at(time::OffsetDateTime::now_utc())?);
    receipt["audit_status"] = json!(super::audit_delivery::PENDING);
    Ok(())
}

/// Called only with the operation lock held. Delivery retries an envelope,
/// never the operation. Retain the receipt's execution result unchanged.
async fn deliver_final(
    writer: &audit::Writer,
    path: &std::path::Path,
    receipt: &mut Value,
) -> Result<(), Error> {
    if receipt["audit_delivered"] == true {
        return Ok(());
    }
    if !receipt["audit_pending"].is_string() {
        *receipt = reconcile(std::mem::take(receipt), false);
        if receipt["finished_at"].is_null() {
            receipt["finished_at"] = json!(time::OffsetDateTime::now_utc().unix_timestamp());
        }
        stage_final(receipt)?;
        crate::guest_commands::write_json(path, receipt)?;
    }
    writer
        .deliver_coord(
            receipt["audit_pending"]
                .as_str()
                .ok_or("support audit obligation missing")?,
        )
        .await?;
    let mut delivered = receipt.clone();
    let fields = delivered
        .as_object_mut()
        .ok_or("support receipt unavailable")?;
    fields.shift_remove("audit_pending");
    fields.shift_remove("audit_status");
    delivered["audit_delivered"] = json!(true);
    crate::guest_commands::write_json(path, &delivered)?;
    *receipt = delivered;
    Ok(())
}

pub(super) async fn recover_audit(
    writer: &audit::Writer,
    path: &std::path::Path,
) -> Result<(), Error> {
    let _lock = crate::host_platform::try_lock_host_state(&path.with_extension("lock"))?;
    if let Some(mut receipt) = crate::guest_commands::read_state_bounded(path, 1024 * 1024)? {
        deliver_final(writer, path, &mut receipt).await?;
    }
    Ok(())
}

async fn execute(
    state: &RuntimeState,
    writer: &audit::Writer,
    run: &Caller,
    input: Request,
) -> Result<Value, Error> {
    let policy = super::current_policy(state)?;
    let (grant, target) = match authorize(&policy, run, &input) {
        Ok(authorization) => authorization,
        Err(error) => {
            denied(writer, run, &input, "initial_authorization").await?;
            return Err(error);
        }
    };
    let path = receipt_path(run, &input.operation_id)?;
    let digest = crate::approvals::pending::digest(&json!(input));
    let lock_path = path.with_extension("lock");
    let _operation_lock = crate::host_platform::lock_host_state_async(&lock_path).await?;
    if let Err(error) =
        super::current_policy(state).and_then(|policy| authorize(&policy, run, &input))
    {
        denied(writer, run, &input, "operation_lock").await?;
        return Err(error);
    }
    if let Some(mut previous) = crate::guest_commands::read_state_bounded(&path, 1024 * 1024)? {
        if previous["request_digest"] != digest {
            return Err(super::refuse(
                409,
                "operation_id already belongs to different inputs; read its original result",
            ));
        }
        let _ = deliver_final(writer, &path, &mut previous).await;
        let current = super::current_policy(state)
            .ok()
            .and_then(|policy| authorize(&policy, run, &input).ok());
        return Ok(agent_view(
            previous,
            false,
            current.as_ref().map(|(grant, _)| grant),
        ));
    }
    let mut permission = input.clone();
    permission.operation = input.operation.permission();
    let mut recorded_action = json!(permission.operation);
    for field in ["command", "text", "path"] {
        recorded_action.as_object_mut().unwrap().shift_remove(field);
    }
    let mut receipt = json!({"operation_id":input.operation_id,"request_digest":digest,
        "permission":permission,"instance_id":grant.instance_id,"initiator":run,
        "target_id":target.id,"target_name":target.name,"target_run":null,"grant":input.grant,"grant_revision":grant.revision(),"grant_expires_at":grant.expires_at,
        "action":input.operation.name(),"recorded_action":recorded_action,"lifecycle_operation":match &input.operation { Action::Lifecycle { operation } => json!(operation), _ => Value::Null },"state":"queued","completion_verified":false,
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
    stage_final(&mut receipt)?;
    crate::guest_commands::write_json(&path, &receipt)?;
    let _ = deliver_final(writer, &path, &mut receipt).await;
    let current = super::current_policy(state)
        .ok()
        .and_then(|policy| authorize(&policy, run, &input).ok());
    Ok(agent_view(
        receipt,
        false,
        current.as_ref().map(|(grant, _)| grant),
    ))
}

async fn execute_locked(
    state: &RuntimeState,
    writer: &audit::Writer,
    run: &Caller,
    input: &Request,
    target: &Agent,
    path: &std::path::Path,
    receipt: &mut Value,
) -> Result<Value, Error> {
    let directory = crate::host_platform::config_dir()
        .join("agents")
        .join(&target.name);
    let lock = crate::host_lifecycle::SetupLock::acquire_in_async(&directory).await?;
    let (grant, target) = authorize_target(state, run, input, target)?;
    let observed = crate::host_runs::observe(&target.name).await;
    let actual_run = observed["run_id"].as_str().map(str::to_owned);
    receipt["target_run"] = json!(actual_run);
    receipt["grant_revision"] = json!(grant.revision());
    receipt["grant_expires_at"] = json!(grant.expires_at);
    if !matches!(
        input.operation,
        Action::Inspect | Action::FactoryState { .. }
    ) && input.expected_run != actual_run
    {
        return Err(super::refuse(
            409,
            "target run changed; inspect the target and use a new operation_id for a deliberate new operation",
        ));
    }
    if !matches!(
        input.operation,
        Action::Inspect | Action::FactoryState { .. }
    ) && crate::host_runs::read(&target.name)?
        .is_some_and(|saved| saved["agent_id"] != target.id)
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
    let (authorizing_grant, _) = authorize_target(state, run, input, &target)?;
    receipt["grant_revision"] = json!(authorizing_grant.revision());
    receipt["grant_expires_at"] = json!(authorizing_grant.expires_at);
    receipt["execution_started"] = json!(!matches!(
        input.operation,
        Action::GuestCommand { .. } | Action::GuestLog { .. }
    ));
    crate::guest_commands::write_json(path, receipt)?;
    match &input.operation {
        Action::FactoryState {
            factory,
            snapshot_id,
        } => {
            let root = crate::host_platform::config_dir();
            let snapshot = crate::factory::direction_binding(&root, factory, snapshot_id, None)?;
            let state = crate::factory::management_state(&root, &snapshot).await?;
            Ok(json!({"state":"completed","factory":state}))
        }
        Action::FactoryDirection { .. } => {
            let client = state
                .read()
                .map_err(|_| "runtime unavailable")?
                .coord
                .clone();
            let result = client
                .send_factory_direction(run, input, &authorizing_grant.revision())
                .await?;
            Ok(json!({"state":"completed","publication":result}))
        }
        Action::Inspect => {
            let mut view = inspection(&crate::host_commands::diagnostics(&target).await?);
            view["observations"] = observations(state, &authorizing_grant, &target.id).await;
            let (current, _) = authorize_target(state, run, input, &target)?;
            filter_observations(&mut view, Some(&current));
            Ok(view)
        }
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
                    let (grant, _) = authorize_target(state, run, input, &target)?;
                    require_live_owned(&target, &observed)?;
                    receipt["grant_revision"] = json!(grant.revision());
                    receipt["grant_expires_at"] = json!(grant.expires_at);
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
            let (state, run, input) = (state.clone(), run.clone(), input.clone());
            let config = crate::host_platform::config_path();
            let timeout = Duration::from_secs(*timeout_seconds);
            tokio::task::spawn_blocking(move || {
                tokio::runtime::Handle::current().block_on(crate::host_platform::in_config(config, async {
                    let value = crate::host_lifecycle::recover_guest_probe_authorized(
                        &root, &target.name, timeout, Some(lock),
                        &|| {
                            authorize_target(&state, &run, &input, &target)?;
                            if crate::host_runs::authority(&root, &target.name, &target.id).as_ref() != Some(&authority) {
                                return Err("target run changed during the independent probe; its state was preserved".into());
                            }
                            Ok(())
                        },
                    )?;
                    Ok(json!({"state":"completed","guest_probe":value["result"],"supervision_id":value["supervision_id"]}))
                }))
            }).await?
        }
        Action::Lifecycle { operation } => {
            let value = Box::pin(lifecycle(
                state, run, input, &target, *operation, &observed, lock,
            ))
            .await?;
            if value["status_code"]
                .as_u64()
                .is_some_and(|status| status >= 400)
            {
                return Err("selected lifecycle action was refused by the runtime owner".into());
            }
            let verified = match operation {
                Lifecycle::StartSandbox => {
                    value["runtime_state"] == "running" && value["exec"] == true
                }
                Lifecycle::StopSandbox => value["runtime_state"] == "stopped",
                Lifecycle::StartHarness | Lifecycle::RestartHarness | Lifecycle::RestartSandbox => {
                    value["runtime_state"] == "running"
                        && matches!(
                            value["agent_state"].as_str(),
                            Some("running" | "observed" | "manual")
                        )
                }
            };
            let mut result = inspection(&value);
            // The existing owner can publish a launch before PID 1 observes
            // it. Preserve that uncertainty; never replay the lifecycle call.
            result["state"] = json!(if verified {
                "completed"
            } else {
                "outcome_unknown"
            });
            Ok(result)
        }
    }
}

async fn observations(state: &RuntimeState, grant: &Grant, target: &str) -> Value {
    if grant.notifications.is_empty() {
        return json!({"availability":"not_selected","sources":[],"next_action":"Select notices on the grant's owner if observation coverage is wanted."});
    }
    let client = match state.read() {
        Ok(runtime) => runtime.coord.clone(),
        Err(_) => {
            return json!({"availability":"unavailable","next_action":"On the owner, inspect Coord diagnostics and its observer."});
        }
    };
    match client.diagnostics().await {
        Ok(value) => {
            let now = time::OffsetDateTime::now_utc().unix_timestamp() * 1000;
            let sources: Vec<_> = value["observations"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|row| {
                    row["agent_id"] == target
                        && row["source"].as_str().is_some_and(|source| {
                            super::events::observation_selected(grant, source)
                        })
                })
                .map(|row| {
                    let mut row = row.clone();
                    row["age_ms"] = row["last_observed_at"]
                        .as_i64()
                        .map(|at| json!(now.saturating_sub(at)))
                        .unwrap_or(Value::Null);
                    row
                })
                .collect();
            json!({"availability":if sources.is_empty(){"not_observed"}else{"recorded"},"sources":sources,"read_at":now,
                "next_action":"Compare last_observed_at and age_ms with the current inspection. Missing, old or unavailable source evidence does not establish target failure. On the owner, inspect Coord diagnostics and restore the named observation source."})
        }
        Err(_) => {
            json!({"availability":"unavailable","sources":[],"next_action":"On the owner, inspect Coord diagnostics and restore its observation store. Current target inspection is separate."})
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
    run: &Caller,
    input: &Request,
    target: &Agent,
    operation: Lifecycle,
    observed: &Value,
    lock: crate::host_lifecycle::SetupLock,
) -> Result<Value, Error> {
    use crate::host_lifecycle;
    let check = || authorize_target(state, run, input, target).map(|_| ());
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
            host_lifecycle::restart_harness(target, lock, &check).await
        }
        Lifecycle::StopSandbox => host_lifecycle::stop_authorized(target, Some(lock), &check).await,
        Lifecycle::RestartSandbox => {
            host_lifecycle::stop_authorized(target, Some(lock), &check).await?;
            let directory = crate::host_platform::config_dir()
                .join("agents")
                .join(&target.name);
            let lock = host_lifecycle::SetupLock::acquire_in_async(&directory).await?;
            check()?;
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
    value["guest_exec_state"] = observed["shell"]["state"]
        .as_str()
        .map_or(json!("not_probed"), |state| json!(state));
    if observed["shell"]["state"] == "unavailable" {
        value["exec"] = json!(false);
    }
    value["runtime_diagnostic"] = if observed["runtime_error"].is_null()
        || observed["runtime_error"] == ""
    {
        Value::Null
    } else {
        json!(
            "Runtime ownership or control is degraded. Preserve this run; ask the operator to inspect host diagnostics if guest control is unavailable."
        )
    };
    value["launch_diagnostic"] = if observed["error"].is_null() || observed["error"] == "" {
        Value::Null
    } else {
        json!(
            "The recorded coding harness is unavailable or unverified. Inspect authorized guest evidence before selecting harness recovery."
        )
    };
    value["next_action"] = json!(if observed["runtime_state"] == "stopped" {
        "The sandbox is stopped. An authorized sandbox start can use its saved configuration."
    } else if value["exec"] != true {
        "The sandbox is not proven stopped. Guest execution is unavailable; preserve runtime evidence and inspect control health."
    } else if observed["agent_state"] != "running" {
        "Guest execution is available independently of the harness. Inspect authorized guest evidence or select an authorized harness action."
    } else {
        "The guest and coding harness respond. Proxy attachment is a separate observation."
    });
    value
}
