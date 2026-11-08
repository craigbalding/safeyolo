//! The host observes local controls once. Owners retain evidence; Coord carries
//! small references, never guest output or another copy of the audit stream.
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    Error,
    host_agents::Agent,
    policy::{Policy, support::Notification},
};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Reference {
    pub event_id: String,
    pub instance_id: String,
    pub target: crate::policy::delegation::Agent,
    pub kind: Notification,
    pub source: String,
    pub run_id: Value,
    pub launch_id: Value,
    pub signal_id: Option<String>,
    pub source_id: String,
    pub sequence: u64,
    pub source_time: Value,
    pub observed_at: i64,
    pub expected_stop: bool,
    pub state: Value,
}

fn id(value: &Value) -> String {
    format!("evt-{}", &crate::approvals::pending::digest(value)[..32])
}

pub(crate) fn permits(
    policy: &Policy,
    instance: &str,
    principal: &str,
    reference: &Reference,
    selected: bool,
) -> bool {
    reference.instance_id == instance
        && policy.evidence_agent_id(&reference.target.name)
            == Some(reference.target.agent_id.as_str())
        && policy.support_grants().values().any(|grant| {
            grant.active()
                && grant.instance_id == instance
                && grant.support.agent_id == principal
                && policy.evidence_agent_id(&grant.support.name) == Some(principal)
                && grant.targets.contains(&reference.target)
                && (!selected || grant.notifications.contains(&reference.kind))
                && (reference.kind != Notification::NeedsOperator
                    || grant.signal_rooms.contains(&reference.source_id))
        })
}

pub(crate) fn instance(root: &Path) -> Result<String, Error> {
    let instance = std::fs::read_to_string(root.join("data/instance_id"))?;
    let instance = instance.trim();
    if instance.is_empty() {
        return Err("owning instance identity missing".into());
    }
    Ok(instance.into())
}

fn observation_path(root: &Path, name: &str) -> PathBuf {
    root.join("agents")
        .join(name)
        .join("operational-observation.json")
}

fn retain(snapshot: &mut Value, kind: Notification, state: Value, expected_stop: bool) {
    let sequence = snapshot["sequence"].as_u64().unwrap_or(0) + 1;
    snapshot["sequence"] = json!(sequence);
    let event = json!({"sequence":sequence,"kind":kind,"state":state,"expected_stop":expected_stop,
        "at":time::OffsetDateTime::now_utc().unix_timestamp()});
    if !snapshot["events"].is_array() {
        snapshot["events"] = json!([]);
    }
    let events = snapshot["events"].as_array_mut().expect("array");
    events.push(event);
    if events.len() > 64 {
        events.drain(..events.len() - 64);
    }
}

fn healthy(value: &Value) -> bool {
    value["runtime_state"] == "running" && value["control_state"] == "ready"
}

/// A local backend observation is the authority for availability. This does
/// not inspect room traffic, checkpoints, attachment or model responsiveness.
pub(crate) fn record_observation(
    root: &Path,
    agent: &Agent,
    run: &Value,
    health: Value,
) -> Result<Value, Error> {
    let path = observation_path(root, &agent.name);
    std::fs::create_dir_all(path.parent().ok_or("observation directory missing")?)?;
    let _lock = crate::host_platform::lock_host_state(&path.with_extension("lock"))?;
    let mut saved = crate::guest_commands::read_state(&path)?
        .filter(|saved| saved["agent_id"] == agent.id)
        .unwrap_or_else(|| json!({"agent_id":agent.id,"source_id":uuid::Uuid::new_v4().simple().to_string(),"sequence":0,"events":[]}));
    let before = saved["health"].clone();
    let expected_stop = matches!(run["state"].as_str(), Some("stopping" | "stopped"));
    let context = json!({"run_id":health["run_id"],"launch_id":health["launch_id"],
        "runtime_state":health["runtime_state"],"control_state":health["control_state"],
        "previous_runtime_state":before["runtime_state"],"previous_control_state":before["control_state"],
        "previous_expected_stop":saved["expected_stop"] == true});
    if before["runtime_state"] != health["runtime_state"]
        && (!before.is_null()
            || matches!(
                health["runtime_state"].as_str(),
                Some("degraded" | "unknown")
            )
            || (health["runtime_state"] == "stopped" && run["state"] == "running"))
    {
        retain(
            &mut saved,
            Notification::SandboxAvailability,
            context.clone(),
            expected_stop,
        );
    }
    if before["control_state"] != health["control_state"]
        && (!before.is_null()
            || matches!(
                health["control_state"].as_str(),
                Some("unknown" | "unavailable" | "recovered")
            ))
    {
        retain(
            &mut saved,
            Notification::ControlAvailability,
            context.clone(),
            expected_stop,
        );
    }
    if healthy(&health)
        && ((!before.is_null() && !healthy(&before))
            || (health["recovery_id"].is_string()
                && before["recovery_id"] != health["recovery_id"]))
    {
        retain(&mut saved, Notification::SandboxRecovered, context, false);
    }
    saved["health"] = health;
    saved["expected_stop"] = json!(expected_stop);
    crate::guest_commands::write_json(&path, &saved)?;
    Ok(saved)
}

fn reference(
    instance: &str,
    agent: &Agent,
    source: &str,
    source_id: &str,
    run: Value,
    launch: Value,
    event: &Value,
) -> Result<Reference, Error> {
    let kind = serde_json::from_value(event["kind"].clone())?;
    let sequence = event["sequence"]
        .as_u64()
        .ok_or("source event has no sequence")?;
    Ok(Reference {
        event_id: id(&json!([instance, agent.id, source, source_id, sequence])),
        instance_id: instance.into(),
        target: crate::policy::delegation::Agent {
            name: agent.name.clone(),
            agent_id: agent.id.clone(),
        },
        kind,
        source: source.into(),
        run_id: run,
        launch_id: launch,
        signal_id: None,
        source_id: source_id.into(),
        sequence,
        source_time: event["at"]
            .as_f64()
            .filter(|at| at.is_finite())
            .map(|_| event["at"].clone())
            .ok_or("source event has no time")?,
        observed_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        expected_stop: event["expected_stop"] == true,
        state: event["state"].clone(),
    })
}

pub(crate) async fn observe(
    root: &Path,
    instance: &str,
    agent: &Agent,
) -> Result<(Vec<Reference>, bool), Error> {
    let directory = root.join("agents").join(&agent.name);
    let (run, mut source_unavailable) = match crate::host_runs::read(&agent.name) {
        Ok(run) => (run.unwrap_or(Value::Null), false),
        Err(_) => (Value::Null, true),
    };
    let launch = match crate::guest_commands::read_state(&directory.join("current-launch.json")) {
        Ok(launch) => launch
            .filter(|launch| launch["agent_id"] == agent.id)
            .unwrap_or(Value::Null),
        Err(_) => {
            source_unavailable = true;
            Value::Null
        }
    };
    let start_failure =
        match crate::guest_commands::read_state(&directory.join("last-start-failure.json")) {
            Ok(failure) => failure.filter(|failure| failure["agent_id"] == agent.id),
            Err(_) => {
                source_unavailable = true;
                None
            }
        };
    let mut health = crate::host_runs::observe(&agent.name).await;
    // A generation changed during the probe. Leave both owners intact and
    // retry the new generation on the next bounded pass.
    if crate::host_runs::read(&agent.name)
        .ok()
        .flatten()
        .unwrap_or(Value::Null)
        != run
    {
        return Ok((Vec::new(), source_unavailable));
    }
    health = json!({"runtime_state":health["runtime_state"],"control_state":health["control_state"],
        "run_id":health["run_id"],"launch_id":launch["launch_id"],
        "recovery_id":start_failure.as_ref().filter(|failure|!failure["recovery"].is_null()).map(|failure|&failure["event_id"])});
    let saved = record_observation(root, agent, &run, health)?;
    let mut refs = Vec::new();
    for event in saved["events"].as_array().into_iter().flatten() {
        refs.push(reference(
            instance,
            agent,
            "host_runtime",
            saved["source_id"]
                .as_str()
                .ok_or("host observation identity missing")?,
            event["state"]["run_id"].clone(),
            event["state"]["launch_id"].clone(),
            event,
        )?);
    }
    if let Some(failure) = &start_failure {
        let event = json!({"sequence":0,"kind":"launch_failed","at":failure["at"],"state":"failed","expected_stop":false});
        refs.push(reference(
            instance,
            agent,
            "host_start",
            failure["event_id"]
                .as_str()
                .ok_or("failed start identity missing")?,
            failure["run_id"].clone(),
            failure["launch_id"].clone(),
            &event,
        )?);
    }
    if launch["state"] == "failed"
        && !launch["launch_id"].is_null()
        && start_failure
            .as_ref()
            .is_none_or(|failure| failure["launch_id"] != launch["launch_id"])
    {
        let event = json!({"sequence":0,"kind":"launch_failed","at":time::OffsetDateTime::now_utc().unix_timestamp(),"state":"failed","expected_stop":false});
        refs.push(reference(
            instance,
            agent,
            "host_launch",
            launch["launch_id"]
                .as_str()
                .ok_or("launch identity missing")?,
            run["run_id"].clone(),
            launch["launch_id"].clone(),
            &event,
        )?);
    }
    // The shared-home record is guest-authored. Check its source binding and
    // project only enumerated transition metadata, never commands or output.
    let command = match crate::guest_commands::read_state(
        &directory.join("home/.safeyolo-command-supervisor.json"),
    ) {
        Ok(command) => command,
        Err(_) => {
            return Ok((refs, true));
        }
    };
    if let Some(command) = command.filter(|command| {
        command["name"] == agent.name
            && command["generation"] == run["run_id"]
            && command["supervision_id"] == launch["launch_id"]
            && !launch["launch_id"].is_null()
    }) {
        for event in command["operational_events"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let Ok(kind) = serde_json::from_value::<Notification>(event["kind"].clone()) else {
                source_unavailable = true;
                continue;
            };
            if !matches!(
                kind,
                Notification::CommandExit
                    | Notification::CommandRestart
                    | Notification::CommandFailed
                    | Notification::SupervisorExit
                    | Notification::SupervisorRestart
            ) {
                source_unavailable = true;
                continue;
            }
            let source = if kind == Notification::SupervisorExit {
                "guest_pid1"
            } else {
                "guest_command_supervisor"
            };
            let event = guest_event(event);
            let r = reference(
                instance,
                agent,
                source,
                launch["launch_id"]
                    .as_str()
                    .ok_or("launch identity missing")?,
                run["run_id"].clone(),
                launch["launch_id"].clone(),
                &event,
            );
            match r {
                Ok(r) => refs.push(r),
                Err(_) => source_unavailable = true,
            }
        }
    }
    Ok((refs, source_unavailable))
}

pub(crate) fn evidence(root: &Path, reference: &Reference) -> Result<Value, Error> {
    let directory = root.join("agents").join(&reference.target.name);
    let event = match reference.source.as_str() {
        "host_runtime" => crate::guest_commands::read_state(&observation_path(root,&reference.target.name))?
            .filter(|saved| saved["agent_id"] == reference.target.agent_id && saved["source_id"] == reference.source_id)
            .and_then(|saved| saved["events"].as_array()?.iter().find(|event| event["sequence"] == reference.sequence).cloned()),
        "host_start" => crate::guest_commands::read_state(&directory.join("last-start-failure.json"))?
            .filter(|saved| saved["agent_id"] == reference.target.agent_id && saved["event_id"] == reference.source_id),
        "host_launch" => crate::guest_commands::read_state(&directory.join("current-launch.json"))?
            .filter(|saved| saved["agent_id"] == reference.target.agent_id && saved["launch_id"] == reference.launch_id)
            .map(|saved|json!({"launch_id":saved["launch_id"],"state":saved["state"],"exit_code":saved["exit_code"],"started_at":saved["started_at"]})),
        "guest_pid1" | "guest_command_supervisor" => crate::guest_commands::read_state(&directory.join("home/.safeyolo-command-supervisor.json"))?
            .filter(|saved| saved["name"] == reference.target.name && saved["generation"] == reference.run_id && saved["supervision_id"] == reference.launch_id)
            .and_then(|saved| saved["operational_events"].as_array()?.iter().find(|event| event["sequence"] == reference.sequence).cloned()),
        _ => return Err("unknown operational evidence owner".into()),
    };
    // Return the enumerated guest fields only. Even a forged guest event may
    // not smuggle command text or arbitrary source keys into host observations.
    let event = event.map(|event| match reference.source.as_str() {
        "guest_pid1" | "guest_command_supervisor" => guest_event(&event),
        _ => event,
    });
    Ok(
        json!({"source_status":if event.is_some(){"retained"}else{"details_unavailable"},"event":event,
        "message":"Source details can be replaced or pruned. A retained reference is not proof of complete audit history. Inspect the current target separately before any authorized action."}),
    )
}

fn guest_event(event: &Value) -> Value {
    let state = event["state"]
        .as_str()
        .filter(|state| {
            matches!(
                *state,
                "starting" | "running" | "restarting" | "stopped" | "failed" | "exited"
            )
        })
        .unwrap_or("unknown");
    let reason = event["reason"]
        .as_str()
        .filter(|reason| {
            matches!(
                *reason,
                "intentional-stop"
                    | "command-exit-clean"
                    | "command-exit-nonzero"
                    | "command-signal"
                    | "supervisor-restarted"
                    | "supervisor-error"
            )
        })
        .unwrap_or("unknown");
    json!({"sequence":event["sequence"].as_u64(),"kind":event["kind"].as_str().filter(|kind|matches!(*kind,"command_exit"|"command_restart"|"command_failed"|"supervisor_exit"|"supervisor_restart")),
        "at":event["at"].as_f64(),"state":state,"reason":reason,"exit_code":event["exit_code"].as_i64(),
        "exit_signal":event["exit_signal"].as_i64(),"wait_status":event["wait_status"].as_i64(),
        "restart_count":event["restart_count"].as_u64(),"expected_stop":event["expected_stop"] == true})
}
