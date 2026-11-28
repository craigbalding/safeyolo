//! Host task preparation retains its signing material in the existing vault.
//! The existing human policy-change owner reviews and adopts the derived binding.
use super::*;
use crate::{
    RuntimeState,
    credentials::{Credential, Secret},
    host_runs::AgentRun,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature::{Ed25519KeyPair, KeyPair};
use safeyolo_host_executor::enrolment::{Enrolment, EnrolmentRequest, TaskPlan};
use zeroize::{Zeroize, Zeroizing};

const KEY_TYPE: &str = "host-task-signing";

#[derive(Deserialize, Serialize)]
pub(super) struct HostTaskKey {
    pub request: EnrolmentRequest,
    pub task_document: Value,
    pkcs8: String,
}
impl Drop for HostTaskKey {
    fn drop(&mut self) {
        self.pkcs8.zeroize();
        crate::credentials::wipe_json(&mut self.task_document);
    }
}

pub(super) fn read_key(credential: &Credential) -> Result<HostTaskKey, Error> {
    if credential.credential_type != KEY_TYPE {
        return Err("selected credential is not this host task's signing key".into());
    }
    Ok(serde_json::from_str(credential.value.expose_secret())?)
}

pub(crate) fn signing_bytes(credential: &Credential) -> Result<Zeroizing<Vec<u8>>, Error> {
    let encoded = if credential.credential_type == KEY_TYPE {
        read_key(credential)?.pkcs8.clone()
    } else {
        credential.value.expose_secret().to_owned()
    };
    let encoded = Zeroizing::new(encoded);
    Ok(Zeroizing::new(STANDARD.decode(encoded.as_bytes())?))
}

fn key_name(issuer: &str, run: &AgentRun, operation: &str) -> String {
    format!(
        "host-task-{}",
        revision(&(issuer, &run.agent_id, operation))
    )
}

pub(crate) async fn read_preparation(
    state: &RuntimeState,
    run: &AgentRun,
    operation: &str,
) -> Result<Value, Error> {
    if !crate::agent_api::valid_request_id(operation) {
        return Err("use the original req- operation_id".into());
    }
    let runtime = state.read().map_err(|_| "runtime unavailable")?.clone();
    let policy = runtime.policy.as_ref().ok_or("host policy unavailable")?;
    if !run.current(policy) {
        return Err("trusted current-run identity required".into());
    }
    let issuer = issuer(&runtime)?;
    let loaded = runtime
        .gateway_vault
        .load_async()
        .await?
        .ok_or("host signing preparation unavailable")?;
    let snapshot = loaded
        .vault
        .snapshot(&key_name(&issuer, run, operation))?
        .ok_or("original host preparation is absent; no new key was created")?;
    let saved = read_key(snapshot.credential())?;
    if saved.request.issuer_id != issuer || saved.request.principal.run.agent_id != run.agent_id {
        return Err("host preparation belongs to another identity".into());
    }
    Ok(
        json!({"operation_id":operation,"status":if now()<saved.request.expires_at {"prepared"}else{"expired"},
        "enrolment_request":saved.request,"permission_granted":false,
        "target_state":"not observed; inspect the original target enrolment and policy-change request before another effect"}),
    )
}

fn issuer(runtime: &crate::Runtime) -> Result<String, Error> {
    let policy = runtime.policy.as_ref().ok_or("host policy unavailable")?;
    let root = policy
        .identity_root()
        .ok_or("issuing instance identity unavailable")?;
    crate::peer_support::events::instance(root)
}

pub(super) fn owner(
    request: &EnrolmentRequest,
    runtime: &crate::Runtime,
    run: &AgentRun,
) -> Result<(), Error> {
    let policy = runtime.policy.as_ref().ok_or("host policy unavailable")?;
    let same = request.principal.run == *run
        || request.plan.allow_run_refresh
            && request.principal.run.agent_id == run.agent_id
            && request.principal.run.agent == run.agent;
    if !run.current(policy) || !same || request.issuer_id != issuer(runtime)? {
        return Err("host setup belongs to another current agent, task or issuing instance".into());
    }
    request.validate()?;
    Ok(())
}

pub(crate) async fn prepare(
    state: &RuntimeState,
    run: &AgentRun,
    operation: &str,
    plan: TaskPlan,
) -> Result<Value, Error> {
    if !crate::agent_api::valid_request_id(operation) {
        return Err("use a req- operation_id and retain it with the plan".into());
    }
    let runtime = state.read().map_err(|_| "runtime unavailable")?.clone();
    let policy = runtime.policy.as_ref().ok_or("host policy unavailable")?;
    if !run.current(policy) {
        return Err("trusted current-run identity required".into());
    }
    let issuer_id = issuer(&runtime)?;
    let name = key_name(&issuer_id, run, operation);
    let loaded = runtime.gateway_vault.load_async().await?.ok_or("host credential storage is not selected; on the issuing host run safeyolo credentials init for this instance, then resume this original preparation")?;
    let vault = &loaded.vault;
    vault.reload_if_changed()?;
    if vault.snapshot(&name)?.is_none() {
        let key = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|_| "cannot create a host signing key")?;
        let pair = Ed25519KeyPair::from_pkcs8(key.as_ref())
            .map_err(|_| "cannot read a host signing key")?;
        let not_before = now();
        let expires_at = not_before
            .checked_add(plan.duration_seconds)
            .ok_or("task authority duration is too large")?;
        let identity = revision(&(&issuer_id, &run.agent_id, operation));
        let (task_id, task_document) = runtime
            .tasks
            .active()?
            .map(|(id, task)| (id, task.document().clone()))
            .unwrap_or_else(|| {
                (
                    format!("host-{}", &identity[..20]),
                    json!({"metadata":{"description":plan.intent.outcome},"permissions":[]}),
                )
            });
        let request = EnrolmentRequest {
            operation_id: operation.into(),
            target_id: format!("host-{}", &identity[..20]),
            issuer_id: issuer_id.clone(),
            key_id: "task".into(),
            public_key: STANDARD.encode(pair.public_key().as_ref()),
            principal: Principal {
                run: run.clone(),
                task_id: Some(task_id),
            },
            task_revision: revision(&task_document),
            not_before,
            expires_at,
            plan: plan.clone(),
        };
        request.validate()?;
        let key = HostTaskKey {
            request,
            task_document,
            pkcs8: STANDARD.encode(key.as_ref()),
        };
        let encoded = Zeroizing::new(serde_json::to_string(&key)?);
        let mut credential = Credential::new(&name, KEY_TYPE, Secret::new(encoded.as_str()));
        credential.expires_at = Some(
            time::OffsetDateTime::from_unix_timestamp(i64::try_from(expires_at)?)?
                .format(&time::format_description::well_known::Rfc3339)?,
        );
        vault.store_if_absent(credential)?;
    }
    let saved = vault
        .snapshot(&name)?
        .ok_or("host signing preparation unavailable")?;
    let saved = read_key(saved.credential())?;
    owner(&saved.request, &runtime, run)?;
    if revision(&saved.request.plan) != revision(&plan) {
        return Err("this operation_id already retains another host plan; recover it or use a new operation_id for a changed plan".into());
    }
    let request = &saved.request;
    Ok(
        json!({"operation_id":operation,"status":"prepared","enrolment_request":request,
        "request_base64":STANDARD.encode(serde_json::to_vec(request)?),"credential_custody":"The issuer vault retains the signing key; this request contains its public key only.",
        "target_state":"unenrolled until the selected target's trusted bootstrap owner executes the prepared request",
        "bootstrap":{"program":"safeyolo-host-executor","arguments":["enrol","--request-base64","<request_base64>","--directory","<target private control directory>","--serve"],
            "target":request.plan.hostname,"account":"the target-local bootstrap account; the returned facts must be reviewed",
            "prerequisites":"The prebuilt native executor. Linux also needs bubblewrap and an operator-delegated cgroup v2 memory/pids scope. No target compiler or Python runtime is required.",
            "effects":"Create the private target configuration/TLS identity and task directory, qualify the actual native boundary, and serve the signed protocol. No task program executes during preparation.",
            "return":"The trusted transfer owner returns enrolment.json through the same authorized route. The operator does not assemble keys, scopes, identity JSON or bindings."},
        "next_action":"Have the selected target's existing trusted install/transfer owner run the bounded bootstrap. Submit its returned enrolment through host setup, review the existing policy approval, then resume the binding."}),
    )
}

pub(crate) async fn submit(
    state: &RuntimeState,
    run: &AgentRun,
    operation: &str,
    enrolment: Enrolment,
) -> Result<Value, Error> {
    let runtime = state.read().map_err(|_| "runtime unavailable")?.clone();
    let issuer_id = issuer(&runtime)?;
    let name = key_name(&issuer_id, run, &enrolment.request.operation_id);
    let loaded = runtime
        .gateway_vault
        .load_async()
        .await?
        .ok_or("host signing preparation unavailable")?;
    let snapshot = loaded
        .vault
        .snapshot(&name)?
        .ok_or("original host signing preparation unavailable")?;
    let saved = read_key(snapshot.credential())?;
    owner(&saved.request, &runtime, run)?;
    if revision(&saved.request) != revision(&enrolment.request)
        || enrolment.hostname != saved.request.plan.hostname
        || enrolment.port != saved.request.plan.control_listen.port()
        || enrolment.target.target_id != saved.request.target_id
    {
        return Err(
            "returned enrolment differs from the original selected target and request".into(),
        );
    }
    enrolment.validate()?;
    let binding_name = enrolment.request.target_id.clone();
    let binding = gateway::Binding {
        target: enrolment.target.clone(),
        issuer_id: issuer_id.clone(),
        grant_id: "task".into(),
        key_id: saved.request.key_id.clone(),
        credential: name,
        service: binding_name.clone(),
        endpoint: gateway::Endpoint::Https {
            host: enrolment.hostname.clone(),
            port: enrolment.port,
            certificate_pem: enrolment.certificate_pem.clone(),
        },
        task_revision: saved.request.task_revision.clone(),
        resume_task: true,
        intent: Some(saved.request.plan.intent.clone()),
        target_enrolled_at: Some(enrolment.enrolled_at),
        target_network_enforcement: enrolment.network_enforcement.clone(),
        timeout_ms: 30000,
        request_bytes: 1024 * 1024,
        response_bytes: 2 * 1024 * 1024,
    };
    binding.validate()?;
    let setup_revision = revision(&(&binding, &enrolment.catalogue));
    let writer = runtime.audit.clone();
    let (work_state, work_writer, work_run, work_operation) = (
        state.clone(),
        writer.clone(),
        run.clone(),
        operation.to_owned(),
    );
    let published_name = binding_name.clone();
    let agent_name = run.agent.clone();
    let record = tokio::task::spawn_blocking(move || {
        crate::approvals::pending::policy_change::submit_host_setup(
            &work_state,
            &work_writer,
            &work_run,
            &work_operation,
            &setup_revision,
            |source| {
                host_setup_policy(
                    source,
                    &binding_name,
                    &binding,
                    &enrolment.catalogue,
                    &agent_name,
                )
            },
        )
    })
    .await
    .map_err(|_| "host policy preparation unavailable; read the original operation_id")??;
    writer
        .emit_confirmed(crate::approvals::pending::policy_change::event(
            &record,
            "agent.policy_change_submitted",
        ))
        .await?;
    let current = state.read().map_err(|_| "runtime unavailable")?.clone();
    let policy = current.policy.as_deref().ok_or("policy unavailable")?;
    let mut view = crate::approvals::pending::policy_change::view(&writer, policy, &record)?;
    view["binding"] = json!(published_name);
    view["next_action"] = json!(
        "Review this exact request in safeyolo watch or the explicit approvals interface. After it is active, resume the returned binding and use authenticated discovery. A saved target receipt is not current application readiness or reach."
    );
    Ok(view)
}

pub(super) fn host_setup_policy(
    source: &str,
    binding_name: &str,
    binding: &gateway::Binding,
    catalogue: &CatalogueAdoption,
    agent_name: &str,
) -> Result<String, Error> {
    let (mut document, context) = crate::policy::parse_toml_for_edit(source)?;
    if document
        .get("host_bindings")
        .and_then(|bindings| bindings.get(binding_name))
        .is_some()
    {
        return Err("selected host binding already exists; inspect it before another setup".into());
    }
    document["host_bindings"][binding_name] = toml_edit::value(serde_json::to_string(binding)?);
    document["host_catalogues"][&catalogue.policy.package_name] =
        toml_edit::value(serde_json::to_string(catalogue)?);
    let mut permission = toml_edit::Table::new();
    permission["action"] = toml_edit::value("gateway:request");
    permission["resource"] = toml_edit::value(format!("{}:/v1/host-execution/*", binding.service));
    permission["effect"] = toml_edit::value("allow");
    let mut condition = toml_edit::InlineTable::new();
    condition.insert("agent", agent_name.into());
    permission["condition"] = toml_edit::value(condition);
    let permissions = if document.get("hosts").is_some() {
        // Host-form policies compile IAM rules here, rather than from the
        // top-level permissions field. Keep the permission scoped to this agent.
        let hosts = document["hosts"]
            .as_table_like_mut()
            .ok_or("policy hosts are not a table")?;
        let host = hosts
            .entry("*")
            .or_insert(toml_edit::value(toml_edit::InlineTable::new()))
            .as_table_like_mut()
            .ok_or("wildcard host policy is not a table")?;
        host.entry("rules")
            .or_insert(toml_edit::value(toml_edit::Array::new()))
    } else {
        if document.get("permissions").is_none() {
            document["permissions"] =
                toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
        }
        &mut document["permissions"]
    };
    if let Some(tables) = permissions.as_array_of_tables_mut() {
        tables.push(permission);
    } else if let Some(values) = permissions.as_array_mut() {
        values.push(toml_edit::Value::InlineTable(
            permission.into_inline_table(),
        ));
    } else {
        return Err("host gateway permissions are not an array".into());
    }
    Ok(crate::policy::restore_large_toml_integers(
        &document.to_string(),
        &context,
    ))
}
