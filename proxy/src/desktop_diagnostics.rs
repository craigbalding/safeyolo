//! Read-only observations for one desktop preview. Never return guest output or secrets.

use serde_json::{Value, json};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;

use crate::{host_platform, host_runs};

pub(crate) async fn guest_check(name: &str) -> Value {
    let started = Instant::now();
    let check = async {
        let mut child = host_platform::spawn_desktop_probe(name).await?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("missing output"))?
            .take(4097);
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("missing error output"))?
            .take(4097);
        let mut bytes = Vec::new();
        let mut errors = Vec::new();
        let (status, _, _) = tokio::try_join!(
            child.wait(),
            stdout.read_to_end(&mut bytes),
            stderr.read_to_end(&mut errors)
        )?;
        if !status.success() || bytes.len() > 4096 || errors.len() > 4096 {
            return Err(std::io::Error::other("guest check failed"));
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
        if value["schema_version"] != 1
            || !matches!(
                value["tcp"].as_str(),
                Some("accepted" | "refused" | "timeout" | "unknown")
            )
            || !matches!(
                value["greeting"].as_str(),
                Some("valid" | "invalid" | "timeout" | "closed" | "unknown" | "not_checked")
            )
        {
            return Err(std::io::Error::other("unverified guest check"));
        }
        Ok::<_, std::io::Error>(json!({"tcp":value["tcp"],"greeting":value["greeting"]}))
    };
    let mut value = match tokio::time::timeout(Duration::from_secs(8), check).await {
        Ok(Ok(value)) => value,
        Ok(Err(_)) => {
            json!({"tcp":"unknown","greeting":"not_checked","transport":"inspection_failed"})
        }
        Err(_) => {
            json!({"tcp":"unknown","greeting":"not_checked","transport":"inspection_timeout"})
        }
    };
    value["duration_ms"] = (started.elapsed().as_millis() as u64).into();
    value
}

pub(crate) async fn snapshot(name: &str, agent_id: &str) -> Value {
    let started = Instant::now();
    let runtime = host_runs::observe(name).await;
    let runtime_ms = started.elapsed().as_millis();
    let saved = host_runs::read(name).ok().flatten();
    let launch = crate::guest_commands::read_state(
        &host_platform::config_dir()
            .join("agents")
            .join(name)
            .join("current-launch.json"),
    )
    .ok()
    .flatten()
    .filter(|value| value["agent_id"] == agent_id && value["name"] == name);
    let recorded = launch
        .as_ref()
        .and_then(|value| value["state"].as_str())
        .filter(|state| {
            matches!(
                *state,
                "running"
                    | "starting"
                    | "launching"
                    | "exited"
                    | "failed"
                    | "stopped"
                    | "stopping"
                    | "finishing"
            )
        })
        .unwrap_or("unknown");
    let observed = if runtime["exec"] == true {
        "running"
    } else {
        match runtime["runtime_state"].as_str() {
            Some("stopped") => "stopped",
            Some("starting") => "starting",
            Some("degraded") => "degraded",
            _ => "unknown",
        }
    };
    // The coding agent can exit while its sandbox and desktop remain live.
    // Only compare the saved sandbox run with independent sandbox evidence.
    let saved_run = match &saved {
        Some(saved) if saved["run_id"] == runtime["run_id"] && !runtime["run_id"].is_null() => {
            "matches_current"
        }
        Some(_) => "different_or_unverified",
        None => "missing_or_unreadable",
    };
    let disagreement = runtime["exec"] == true && saved_run != "matches_current";
    let guest = if runtime["exec"] == true {
        guest_check(name).await
    } else {
        json!({"tcp":"unknown","greeting":"not_checked","transport":"unavailable","duration_ms":0})
    };
    json!({"observed_at":crate::circuit_runtime::now(),"recorded_agent_state":recorded,"saved_run":saved_run,
        "runtime":{"state":observed,"inspection":if observed=="unknown" {"failed"} else {"observed"},
        "control":runtime["control_state"],"disagreement":disagreement,"duration_ms":runtime_ms},
        "guest":guest})
}
