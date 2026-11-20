//! Configured activation and host-observed dormancy share the ordinary lifecycle owner.
mod broker;
mod completion;
#[cfg(test)]
mod tests;

use super::SetupLock;
use crate::{Error, RuntimeState, coord_rooms, host_agents::Agent, host_platform};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};

pub(crate) use broker::Follow;

pub(crate) const HELP: &str = "safeyolo [--root ROOT] agent lifecycle NAME configure FILE.json\nsafeyolo [--root ROOT] agent lifecycle NAME status|pause|resume\nLifecycle configuration selects on_demand, continuous or scheduled operation, an optional native NATS calendar/timezone, elapsed operating window and stop boundary, and an adopted completion check. The running proxy reconciles schedules. pause disables future scheduled starts; agent stop ends the current run and preserves its schedule. An active run retains its captured cutoff. See docs/worker-lifecycle.md.";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mode {
    OnDemand,
    Continuous,
    Scheduled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Configuration {
    pub mode: Mode,
    #[serde(default)]
    pub paused: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    /// An elapsed operating window measured from the broker occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_seconds: Option<u64>,
    /// An elapsed limit measured from the selected activation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_after_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_room: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_check: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_require: Option<crate::policy::checks::Condition>,
    /// Explicit operator-selected future Work in the same room.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub completion_excluded_work_ids: Vec<String>,
}

pub(crate) fn configuration(value: &Value) -> Result<Configuration, Error> {
    let config: Configuration = serde_json::from_value(value.clone())?;
    if (config.mode == Mode::Scheduled) != config.schedule.is_some()
        || config
            .schedule
            .as_ref()
            .is_some_and(|s| s.trim().is_empty())
        || config
            .timezone
            .as_ref()
            .is_some_and(|s| s.trim().is_empty())
        || (config.schedule.as_ref().is_some_and(|s| {
            !s.starts_with('@')
                || matches!(
                    s.as_str(),
                    "@daily"
                        | "@hourly"
                        | "@weekly"
                        | "@monthly"
                        | "@yearly"
                        | "@annually"
                        | "@midnight"
                )
        }) && config.timezone.is_none())
        || (config.window_seconds.is_some() && config.mode != Mode::Scheduled)
        || config.window_seconds == Some(0)
        || config.stop_after_seconds == Some(0)
    {
        return Err("lifecycle needs a scheduled expression only in scheduled mode, an explicit timezone for calendar schedules, and positive selected limits".into());
    }
    if let Some(boundary) = &config.stop_by {
        timestamp(boundary)?;
    }
    let completion = [
        config.completion_room.is_some(),
        config.completion_check.is_some(),
        config.completion_require.is_some(),
    ];
    if completion.iter().any(|s| *s) && !completion.iter().all(|s| *s) {
        return Err("checked self-stop needs completion_room, completion_check and completion_require together".into());
    }
    if !config.completion_excluded_work_ids.is_empty() && config.completion_room.is_none() {
        return Err("future Work exclusions require a selected completion scope".into());
    }
    if config
        .completion_room
        .as_ref()
        .is_some_and(|s| s.is_empty())
        || config
            .completion_check
            .as_ref()
            .is_some_and(|s| s.is_empty())
    {
        return Err("completion room and check must be nonempty".into());
    }
    if let (Some(name), Some(condition)) = (&config.completion_check, &config.completion_require) {
        let mut names = std::collections::BTreeSet::new();
        condition.names(&mut names);
        if names != std::collections::BTreeSet::from([name.clone()]) {
            return Err("completion_require must use only the selected completion_check".into());
        }
    }
    if let Some(deadline) = cutoff(&config, now(), now())? {
        time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(deadline) * 1_000_000)?;
    }
    Ok(config)
}

fn now() -> i64 {
    (crate::circuit_runtime::now() * 1000.0) as i64
}

fn timestamp(value: &str) -> Result<i64, Error> {
    let at = time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)?;
    Ok(i64::try_from(at.unix_timestamp_nanos() / 1_000_000)?)
}

fn revision(agent: &Agent) -> Result<String, Error> {
    Ok(crate::policy::checks::content_digest(&serde_json::to_vec(
        &json!({
            "agent_id":agent.id, "lifecycle":agent.lifecycle,
        }),
    )?))
}

fn load(conn: &Connection, agent_id: &str) -> Result<Option<Value>, Error> {
    conn.query_row(
        "SELECT document_json FROM coord_lifecycle WHERE agent_id=?1",
        [agent_id],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(|s| Ok(serde_json::from_str(&s)?))
    .transpose()
}

fn save(conn: &Connection, agent_id: &str, value: &Value) -> Result<(), Error> {
    if let Some(activation) = value["activation_id"].as_str() {
        let hash = crate::policy::checks::content_digest(&serde_json::to_vec(&json!({
            "agent_id":agent_id,"activation_id":activation,"run_id":value["run_id"],
            "configuration_revision":value["configuration_revision"]
        }))?);
        conn.execute("INSERT OR IGNORE INTO coord_operations(principal_kind,principal_id,operation_type,operation_id,request_hash,outcome_kind,outcome_json,created_at) VALUES('machine',?1,'lifecycle_activation',?2,?3,?4,?5,?6)",
            params![agent_id,activation,hash,value["phase"].as_str().unwrap_or("unknown"),value.to_string(),now()])?;
        if matches!(
            value["phase"].as_str(),
            Some("stopped" | "failed" | "superseded" | "interrupted")
        ) {
            conn.execute("INSERT OR IGNORE INTO coord_operations(principal_kind,principal_id,operation_type,operation_id,request_hash,outcome_kind,outcome_json,created_at) VALUES('machine',?1,'lifecycle_activation_result',?2,?3,?4,?5,?6)",
                params![agent_id,activation,hash,value["phase"].as_str().unwrap_or("unknown"),value.to_string(),now()])?;
        }
    }
    conn.execute("INSERT INTO coord_lifecycle(agent_id,document_json) VALUES(?1,?2) ON CONFLICT(agent_id) DO UPDATE SET document_json=excluded.document_json",
        params![agent_id,value.to_string()])?;
    Ok(())
}

pub(crate) fn retained(root: &Path, agent_id: &str) -> Result<Option<Value>, Error> {
    if !coord_rooms::directory(root)?.join("v0.db").try_exists()? {
        return Ok(None);
    }
    load(&coord_rooms::open(root)?, agent_id)
}

pub(crate) fn planned_run(agent: &Agent) -> Result<Option<String>, Error> {
    if agent.lifecycle.is_none() {
        return Ok(None);
    }
    let state = retained(&host_platform::config_dir(), &agent.id)?;
    Ok(state
        .filter(|s| s["phase"] == "starting")
        .and_then(|s| s["run_id"].as_str().map(str::to_owned)))
}

fn live_phase(state: &Value) -> bool {
    matches!(
        state["phase"].as_str(),
        Some("starting" | "active" | "closing" | "uncertain")
    )
}

fn result_without_lifecycle(result: &Value) -> Value {
    let mut result = result.clone();
    if let Some(fields) = result.as_object_mut() {
        fields.remove("lifecycle");
    }
    result
}

/// Scope closure defers new claims. Deliveries remain visible to the existing
/// supervisor checkpoint, so shutdown cannot consume and lose an assignment.
pub(crate) fn work_deferred(
    conn: &Connection,
    agent_id: &str,
    room_id: &str,
) -> Result<bool, Error> {
    Ok(load(conn, agent_id)?.is_some_and(|s| {
        matches!(
            s["phase"].as_str(),
            Some("closing" | "stopped" | "failed" | "interrupted")
        ) && s["completion_room_id"] == room_id
    }))
}

pub(crate) fn observation(root: &Path, agent: &Agent, sandbox_state: &Value) -> Value {
    let state = retained(root, &agent.id);
    match state {
        Ok(receipt) => {
            if agent.lifecycle.is_none() && receipt.is_none() {
                return Value::Null;
            }
            let intentional = sandbox_state == "stopped"
                && (receipt
                    .as_ref()
                    .is_some_and(|s| s["phase"] == "stopped" && s["resources_released"] == true)
                    || (agent
                        .lifecycle
                        .as_ref()
                        .is_some_and(|c| c.mode != Mode::Continuous || c.paused)
                        && receipt
                            .as_ref()
                            .is_none_or(|s| s["activation_id"].is_null())));
            let paused = agent.lifecycle.as_ref().is_some_and(|c| c.paused);
            let schedule_unavailable = agent
                .lifecycle
                .as_ref()
                .is_some_and(|c| c.mode == Mode::Scheduled && !c.paused)
                && receipt.as_ref().is_none_or(|s| {
                    s["schedule_status"]["state"] != "adopted"
                        || s["schedule_status"]["configuration_revision"].as_str()
                            != revision(agent).ok().as_deref()
                });
            let start_failed = receipt.as_ref().is_some_and(|s| {
                s["start_error"]["configuration_revision"].as_str()
                    == revision(agent).ok().as_deref()
                    && s["start_error"]["sequence"].as_u64().unwrap_or(0)
                        > s["last_start_sequence"].as_u64().unwrap_or(0)
            });
            json!({"state":if sandbox_state == "running" {"running"}
                else if sandbox_state != "stopped" || schedule_unavailable || start_failed {"unavailable"}
                else if paused && intentional {"paused"} else if intentional {"dormant"} else {"unexpected_stop"},
                "intentional":intentional,"paused":paused,"saved_configuration":agent.lifecycle,
                "receipt":receipt,"automatic_execution":"The running proxy and its managed NATS are required.",
                "next_occurrence":next_occurrence(agent,receipt.as_ref()),
                "calendar":"Native NATS calendar semantics: a skipped local time can miss an occurrence; a repeated local time can produce two distinct occurrences. Elapsed windows use broker occurrence time.",
                "next_occurrence_source":"Nats-Schedule-Next from the broker; unknown before its first delivery"})
        }
        Err(error) => {
            json!({"state":"unavailable","error":error.to_string(),"saved_configuration":agent.lifecycle})
        }
    }
}

fn active_receipts(root: &Path) -> Result<bool, Error> {
    if !coord_rooms::directory(root)?.join("v0.db").try_exists()? {
        return Ok(false);
    }
    let conn = coord_rooms::open(root)?;
    Ok(conn.query_row("SELECT EXISTS(SELECT 1 FROM coord_lifecycle WHERE json_extract(document_json,'$.phase') IN ('starting','active','closing','uncertain'))",[],|r|r.get(0))?)
}

fn next_occurrence(agent: &Agent, receipt: Option<&Value>) -> Value {
    let Some(config) = agent
        .lifecycle
        .as_ref()
        .filter(|c| c.mode == Mode::Scheduled)
    else {
        return json!({"state":"not_scheduled"});
    };
    if config.paused {
        return json!({"state":"paused"});
    }
    let observed = receipt.map(|s| &s["schedule_observation"]);
    let current = revision(agent).ok();
    if let Some(observed) = observed
        && observed["configuration_revision"].as_str() == current.as_deref()
    {
        if observed["next"] == "purge" {
            return json!({"state":"no_further_occurrence","source":observed});
        }
        if observed["next"]
            .as_str()
            .and_then(|s| timestamp(s).ok())
            .is_some_and(|at| at > now())
        {
            return json!({"state":"observed","at":observed["next"],"source":observed});
        }
    }
    json!({"state":"unknown","reason":"No current future occurrence has been advertised by native NATS.","last_observation":observed})
}

fn cutoff(
    config: &Configuration,
    occurrence_at: i64,
    activated_at: i64,
) -> Result<Option<i64>, Error> {
    let add = |start: i64, seconds: u64| -> Result<i64, Error> {
        start
            .checked_add(
                i64::try_from(seconds)?
                    .checked_mul(1000)
                    .ok_or("lifecycle interval exceeds the host clock")?,
            )
            .ok_or_else(|| "lifecycle interval exceeds the host clock".into())
    };
    let mut limits = Vec::new();
    if let Some(seconds) = config.window_seconds {
        limits.push(add(occurrence_at, seconds)?);
    }
    if let Some(seconds) = config.stop_after_seconds {
        limits.push(add(activated_at, seconds)?);
    }
    if let Some(at) = &config.stop_by {
        limits.push(timestamp(at)?);
    }
    Ok(limits.into_iter().min())
}

/// Start the bounded stop sequence before its deadline using the existing waits:
/// 15s command supervisor, backend graceful/force observation, 5s listener reload.
fn stop_budget() -> Duration {
    Duration::from_secs(15 + if cfg!(target_os = "macos") { 15 } else { 10 } + 5)
}

pub(super) async fn start(
    agent: &Agent,
    operation: &str,
    setup_lock: Option<SetupLock>,
    arguments: Option<&[String]>,
    allow_unowned: bool,
    check: &(dyn Fn() -> Result<(), Error> + Send + Sync),
) -> Result<Value, Error> {
    if agent.lifecycle.is_none() {
        return super::start_inner(
            agent,
            operation,
            setup_lock,
            arguments,
            allow_unowned,
            check,
        )
        .await;
    }
    activate(
        agent,
        operation,
        setup_lock,
        arguments,
        allow_unowned,
        check,
        None,
    )
    .await
}

#[derive(Clone)]
struct Occurrence {
    sequence: u64,
    at: i64,
    revision: String,
    next: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn activate(
    agent: &Agent,
    operation: &str,
    setup_lock: Option<SetupLock>,
    arguments: Option<&[String]>,
    allow_unowned: bool,
    check: &(dyn Fn() -> Result<(), Error> + Send + Sync),
    occurrence: Option<Occurrence>,
) -> Result<Value, Error> {
    let root = host_platform::config_dir();
    let lock = match setup_lock {
        Some(lock) => lock,
        None => SetupLock::acquire_in_async(&root.join("agents").join(&agent.name)).await?,
    };
    let agent = crate::host_agents::refresh(agent)?;
    check()?;
    let config = agent
        .lifecycle
        .as_ref()
        .ok_or("worker lifecycle was removed")?;
    let revision = revision(&agent)?;
    let observed = crate::host_runs::observe(&agent.name).await;
    if occurrence.is_none() && observed["runtime_state"] == "running" {
        return super::start_inner(
            &agent,
            operation,
            Some(lock),
            arguments,
            allow_unowned,
            check,
        )
        .await;
    }
    let at = now();
    let scope_policy = if observed["runtime_state"] == "stopped" && config.completion_room.is_some()
    {
        Some(crate::policy::Policy::from_native_path(
            &crate::host_agents::policy_path()?,
        )?)
    } else {
        None
    };
    let mut state = (|| -> Result<Value, Error> {
        let mut conn = coord_rooms::open(&root)?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut previous = load(&tx, &agent.id)?;
        let latest = previous
            .as_ref()
            .and_then(|s| s["last_start_sequence"].as_u64())
            .unwrap_or(0);
        if let Some(event) = &occurrence {
            if event.sequence <= latest {
                return Ok(json!({"state":"ignored","reason":"occurrence already consumed"}));
            }
            // Record even an overlapping or stale occurrence before its ack.
            // A lost ack must not turn a skipped event into a later activation.
            let seen =
                previous.get_or_insert_with(|| json!({"agent_id":agent.id,"name":agent.name}));
            seen["last_start_sequence"] = json!(event.sequence);
            save(&tx, &agent.id, seen)?;
            if config.paused
                || event.revision != revision
                || observed["runtime_state"] != "stopped"
                || previous
                    .as_ref()
                    .and_then(|s| s["activated_at"].as_i64())
                    .is_some_and(|started| event.at <= started)
                || event
                    .next
                    .as_deref()
                    .filter(|n| *n != "purge")
                    .map(timestamp)
                    .transpose()?
                    .is_some_and(|next| next <= at)
            {
                tx.commit()?;
                return Ok(
                    json!({"state":"ignored","reason":"paused, duplicate, stale, already active or superseded occurrence"}),
                );
            }
        } else if observed["runtime_state"] != "stopped" {
            return Err("sandbox absence is unverified; inspect this worker's diagnostics before another activation".into());
        }
        let occurrence_at = occurrence.as_ref().map_or(at, |event| event.at);
        let stop_by = cutoff(config, occurrence_at, at)?;
        if stop_by.is_some_and(|deadline| deadline <= at) {
            tx.commit()?;
            return Ok(
                json!({"state":"ignored","reason":"configured operating window or stop boundary has expired"}),
            );
        }
        let room_id = config
            .completion_room
            .as_ref()
            .map(|room| {
                tx.query_row("SELECT room_id FROM rooms WHERE name=?1", [room], |r| {
                    r.get::<_, String>(0)
                })
            })
            .transpose()?;
        let (initial_work_ids, work_attention_at_activation) =
            if let Some(room_id) = room_id.as_deref() {
                completion::initial_scope(
                    &tx,
                    &agent,
                    config,
                    room_id,
                    scope_policy
                        .as_ref()
                        .ok_or("completion scope policy unavailable")?,
                )?
            } else {
                (Vec::new(), 0)
            };
        if let Some(mut previous) = previous.clone().filter(|s| s["activation_id"].is_string()) {
            if live_phase(&previous) {
                previous["phase"] = json!("interrupted");
                previous["resources_released"] = json!(true);
                previous["observed_at"] = json!(at);
                previous["result_reason"] = json!(
                    "Backend absence was verified before this distinct activation; unfinished Work remains retained."
                );
            }
            save(&tx, &agent.id, &previous)?;
        }
        let state = json!({"agent_id":agent.id,"name":agent.name,
        "activation_id":format!("activation-{}",uuid::Uuid::new_v4().simple()),
        "run_id":uuid::Uuid::new_v4().simple().to_string(),
        "configuration_revision":revision,"configuration":config,
        "occurrence":occurrence.as_ref().map(|e| json!({"sequence":e.sequence,"at":e.at,"next":e.next})),
        "last_start_sequence":occurrence.as_ref().map_or(latest,|e|e.sequence),
        "activated_at":at,"stop_by":stop_by,"phase":"starting","resources_released":false,
        "schedule_observation":previous.as_ref().map(|s|s["schedule_observation"].clone()),
        "schedule_status":previous.as_ref().map(|s|s["schedule_status"].clone()),
        "initial_work_ids":initial_work_ids,"work_attention_at_activation":work_attention_at_activation,
        "completion_room_id":room_id});
        save(&tx, &agent.id, &state)?;
        tx.commit()?;
        Ok(state)
    })()?;
    if state["phase"] != "starting" {
        return Ok(state);
    }
    let stop_by = state["stop_by"].as_i64();
    // Retain and arm the mandatory boundary before starting a new sandbox.
    // Broker failure leaves a concrete stopped/uncertain receipt, never an unbounded run.
    if let Some(deadline) = stop_by
        && let Err(error) =
            broker::arm_stop(&root, &state, deadline - stop_budget().as_millis() as i64).await
    {
        state["phase"] = json!("failed");
        state["resources_released"] = json!(observed["runtime_state"] == "stopped");
        state["error"] = json!(error.to_string());
        save(&coord_rooms::open(&root)?, &agent.id, &state)?;
        return Err(error);
    }
    let expected_run = state["run_id"].clone();
    let activation = state["activation_id"].clone();
    let guard = || {
        check()?;
        let current = retained(&root, &agent.id)?.ok_or("lifecycle receipt disappeared")?;
        if current["activation_id"] != activation
            || current["run_id"] != expected_run
            || current["phase"] != "starting"
            || current["stop_by"]
                .as_i64()
                .is_some_and(|deadline| now() >= deadline)
        {
            return Err(
                "activation was closed, replaced or passed its configured stop boundary".into(),
            );
        }
        Ok(())
    };
    let result = super::start_inner(
        &agent,
        operation,
        Some(lock),
        arguments,
        allow_unowned,
        &guard,
    )
    .await;
    let mut current = retained(&root, &agent.id)?.ok_or("lifecycle receipt disappeared")?;
    if current["activation_id"] == activation && current["phase"] == "starting" {
        current["phase"] = json!(if result
            .as_ref()
            .is_ok_and(|v| v["runtime_state"] == "running" && v["run_id"] == expected_run)
        {
            "active"
        } else {
            "uncertain"
        });
        current["start_result"] = match &result {
            Ok(value) => result_without_lifecycle(value),
            Err(error) => json!({"error":error.to_string()}),
        };
        save(&coord_rooms::open(&root)?, &agent.id, &current)?;
    }
    result
}

/// Called inside the existing setup lock, after the caller's authority check.
pub(super) fn stopping(agent: &Agent) -> Result<(), Error> {
    let root = host_platform::config_dir();
    if retained(&root, &agent.id)?.is_none() {
        return Ok(());
    }
    let conn = coord_rooms::open(&root)?;
    if let Some(mut state) = load(&conn, &agent.id)?
        && live_phase(&state)
        && state["phase"] != "closing"
    {
        state["stop_reason"] = json!("deliberate_stop");
        state["phase"] = json!("closing");
        state["closed_at"] = json!(now());
        save(&conn, &agent.id, &state)?;
    }
    Ok(())
}

pub(super) fn mandatory_command_wait(agent: &Agent) -> Result<Option<Duration>, Error> {
    Ok(retained(&host_platform::config_dir(), &agent.id)?
        .filter(|s| s["phase"] == "closing" && s["stop_reason"] == "mandatory_cutoff")
        .map(|s| {
            let remaining = s["stop_by"].as_i64().unwrap_or(now()) - now();
            let backend_and_reload = (stop_budget().as_millis() as i64) - 15_000;
            Duration::from_millis(
                remaining
                    .saturating_sub(backend_and_reload)
                    .clamp(0, 15_000) as u64,
            )
        }))
}

pub(super) fn stopped(agent: &Agent, result: &Value) -> Result<(), Error> {
    if retained(&host_platform::config_dir(), &agent.id)?.is_none() {
        return Ok(());
    }
    let conn = coord_rooms::open(&host_platform::config_dir())?;
    if let Some(mut state) = load(&conn, &agent.id)? {
        state["phase"] = json!(if result["runtime_state"] == "stopped" {
            "stopped"
        } else {
            "uncertain"
        });
        state["resources_released"] = json!(result["runtime_state"] == "stopped");
        state["observed_at"] = json!(now());
        state["stop_result"] = result_without_lifecycle(result);
        save(&conn, &agent.id, &state)?;
    }
    Ok(())
}

pub(super) fn release_previous_scope(agent: &Agent) -> Result<(), Error> {
    if agent.lifecycle.is_some() {
        return Ok(());
    }
    let root = host_platform::config_dir();
    if let Some(mut receipt) = retained(&root, &agent.id)? {
        receipt["phase"] = json!("superseded");
        receipt["scope_released_at"] = json!(now());
        save(&coord_rooms::open(&root)?, &agent.id, &receipt)?;
    }
    Ok(())
}

fn current_cutoff(state: &Value, event: &Value) -> bool {
    state["stop_by"].as_i64().is_some()
        && state["activation_id"] == event["activation_id"]
        && state["run_id"] == event["run_id"]
        && state["configuration_revision"] == event["configuration_revision"]
        && state["stop_by"] == event["stop_by"]
        && live_phase(state)
        && state["cutoff_attempted_at"].is_null()
}

async fn mandatory_stop(agent: Agent, event: &Value) -> Result<Value, Error> {
    let root = host_platform::config_dir();
    let lock = SetupLock::acquire_in_async(&root.join("agents").join(&agent.name)).await?;
    let state = (|| -> Result<Value, Error> {
        let mut conn = coord_rooms::open(&root)?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut state = load(&tx, &agent.id)?.ok_or("lifecycle receipt unavailable")?;
        if !current_cutoff(&state, event) {
            return Ok(
                json!({"state":"ignored","reason":"stale cutoff, replacement run or previously attempted stop; inspect the retained result before another effect"}),
            );
        }
        state["phase"] = json!("closing");
        state["stop_reason"] = json!("mandatory_cutoff");
        state["closed_at"] = json!(now());
        state["cutoff_attempted_at"] = json!(now());
        save(&tx, &agent.id, &state)?;
        tx.commit()?;
        Ok(state)
    })()?;
    if state["phase"] != "closing" {
        return Ok(state);
    }
    let guard = || {
        let run =
            crate::host_runs::read(&agent.name)?.ok_or("current sandbox run is unavailable")?;
        if run["agent_id"] != agent.id || run["run_id"] != event["run_id"] {
            return Err("cutoff does not identify the current sandbox run".into());
        }
        Ok(())
    };
    super::stop_authorized(&agent, Some(lock), &guard).await
}

pub(crate) async fn request(
    state: &RuntimeState,
    run: &crate::host_runs::AgentRun,
    input: Value,
) -> Result<Value, Error> {
    completion::request(state, run, input).await
}

pub(crate) fn read_request(root: &Path, agent: &str, id: &str) -> Result<Value, Error> {
    completion::read(root, agent, id)
}

pub(crate) async fn status(agent: &Agent) -> Result<Value, Error> {
    Ok(observation(
        &host_platform::config_dir(),
        agent,
        &crate::host_runs::observe(&agent.name).await["runtime_state"],
    ))
}

pub(crate) async fn command(
    name: &str,
    operation: &str,
    file: Option<&str>,
) -> Result<Value, Error> {
    let agents = crate::host_agents::list()?;
    let agent = agents
        .iter()
        .find(|agent| agent.name == name)
        .ok_or("agent not found")?;
    if operation == "status" {
        return Ok(observation(
            &host_platform::config_dir(),
            agent,
            &crate::host_runs::observe(name).await["runtime_state"],
        ));
    }
    let config = if operation == "configure" {
        configuration(&serde_json::from_slice(&std::fs::read(
            file.ok_or("lifecycle configure requires a JSON file")?,
        )?)?)?
    } else {
        let mut config = agent
            .lifecycle
            .clone()
            .ok_or("this agent has no configured lifecycle")?;
        config.paused = match operation {
            "pause" => true,
            "resume" => false,
            _ => return Err("unknown lifecycle operation".into()),
        };
        config
    };
    let _setup =
        SetupLock::acquire_in_async(&host_platform::config_dir().join("agents").join(name)).await?;
    let path = crate::host_agents::policy_path()?;
    let _policy = crate::approvals::lock_policy(&path)?;
    let mut document: toml_edit::DocumentMut = std::fs::read_to_string(&path)?.parse()?;
    if document["agents"][name]["agent_id"].as_str() != Some(&agent.id) {
        return Err("worker identity changed before lifecycle configuration".into());
    }
    // The policy's existing TOML/JSON conversion preserves the complete typed value.
    let json = serde_json::to_value(&config)?;
    document["agents"][name]["lifecycle"] = toml_edit::Item::Value(
        crate::admin_api::json_toml_value(&json)
            .map_err(|_| "lifecycle cannot be represented in TOML")?,
    );
    crate::policy::Policy::from_native_path(&path)?
        .reload_native_source(&document.to_string(), &path)?;
    crate::coord_supervisor::atomic_write(&path, document.to_string().as_bytes(), 0o600)?;
    Ok(
        json!({"agent_id":agent.id,"name":name,"saved_configuration":config,
        "activation":"The running proxy reconciles native schedules. The current run retains its captured cutoff; pause disables future scheduled starts. No sandbox was started or stopped by this edit."}),
    )
}
