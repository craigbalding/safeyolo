//! The current sandbox incarnation and its independently observed controls.

use crate::{Error, host_platform::config_dir};
use serde_json::{Value, json};
use std::{path::PathBuf, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

pub(crate) fn path(name: &str) -> PathBuf {
    config_dir().join("agents").join(name).join("runtime.json")
}
pub(crate) fn read(name: &str) -> Result<Option<Value>, Error> {
    crate::guest_commands::read_state(&path(name))
}
pub(crate) fn save(name: &str, value: &Value) -> Result<(), Error> {
    crate::guest_commands::write_json(&path(name), value)
}
pub(crate) fn id(name: &str) -> Result<String, Error> {
    let record = crate::guest_commands::read_state(
        &config_dir()
            .join("agents")
            .join(name)
            .join("config-share/host-launch-context.json"),
    )?
    .ok_or("current sandbox identity is missing; run agent status to inspect control health")?;
    let id = record["generation"]
        .as_str()
        .ok_or("current sandbox generation is missing")?;
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid sandbox generation".into());
    }
    Ok(format!("safeyolo-{id}"))
}

pub(crate) fn remember_process(name: &str, key: &str, pid: u32) -> Result<(), Error> {
    let mut run = read(name)?.ok_or("current sandbox record is missing")?;
    let token = crate::host_lifecycle::process_token(i64::from(pid))
        .ok_or("sandbox process identity is unavailable")?;
    run[format!("{key}_pid")] = pid.into();
    run[format!("{key}_token")] = token.into();
    save(name, &run)
}

#[cfg(target_os = "macos")]
fn process_matches(name: &str, run: &Value, key: &str) -> bool {
    run[format!("{key}_pid")]
        .as_i64()
        .zip(run[format!("{key}_token")].as_str())
        .is_some_and(|(pid, token)| {
            i32::try_from(pid)
                .ok()
                .and_then(|pid| crate::host_platform::vm_process_token(name, pid))
                .as_deref()
                == Some(token)
        })
}

#[cfg(target_os = "macos")]
fn saved_vz_helper_is_dead(run: &Value) -> bool {
    let Some(pid) = run["backend_pid"]
        .as_i64()
        .and_then(|pid| i32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
        .filter(|_| run["backend_token"].as_str().is_some())
    else {
        return false;
    };
    // A failed identity lookup can mean denied inspection. Only ESRCH proves
    // absence; a live unrelated PID or an inspection error stays unknown.
    (unsafe { libc::kill(pid, 0) }) != 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

pub(crate) async fn control(name: &str, mut request: Value) -> Result<Value, Error> {
    if !crate::host_platform::valid_agent_name(name) {
        return Err("invalid agent name".into());
    }
    let operation = request["operation"]
        .as_str()
        .ok_or("control operation is required")?
        .to_owned();
    request["operation"] = operation.clone().into();
    let bytes = serde_json::to_vec(&request)?;
    if bytes.len() >= 65536 {
        return Err("VM control request exceeds 64 KiB".into());
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        let socket = tokio::net::UnixStream::connect(
            config_dir()
                .join("data/vm-control")
                .join(format!("{name}.sock")),
        )
        .await?;
        #[cfg(target_os = "macos")]
        let peer_pid = {
            use std::os::fd::AsRawFd;
            let mut pid: libc::pid_t = 0;
            let mut length = std::mem::size_of_val(&pid) as libc::socklen_t;
            // Darwin LOCAL_PEERPID identifies the server independently of
            // the response body and the persisted VM handle.
            if unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    0,
                    2,
                    (&mut pid as *mut libc::pid_t).cast(),
                    &mut length,
                )
            } != 0
                || crate::host_platform::vm_process_token(name, pid).is_none()
            {
                return Err("private control peer is not this agent's installed VZ helper".into());
            }
            pid
        };
        let (reader, mut writer) = socket.into_split();
        writer.write_all(&bytes).await?;
        writer.write_all(b"\n").await?;
        let mut reader = tokio::io::BufReader::new(reader);
        let mut response = Vec::new();
        loop {
            let buffer = reader.fill_buf().await?;
            if buffer.is_empty() {
                return Err("helper closed the control socket before a response".into());
            }
            let count = buffer
                .iter()
                .position(|b| *b == b'\n')
                .map_or(buffer.len(), |i| i + 1);
            let complete = buffer[count - 1] == b'\n';
            response.extend_from_slice(&buffer[..count]);
            reader.consume(count);
            if response.len() > 2 * 1024 * 1024 {
                return Err("VM control response exceeds 2 MiB".into());
            }
            if complete {
                break;
            }
        }
        let response: Value = serde_json::from_slice(&response)?;
        #[cfg(target_os = "macos")]
        if operation == "status" && response["pid"].as_i64() != Some(i64::from(peer_pid)) {
            return Err("private control response has a conflicting helper PID".into());
        }
        if response["schema_version"] != 1
            || response["ok"] != true
            || response["instance"].as_str().is_none_or(str::is_empty)
        {
            return Err(format!(
                "VM control {operation} refused or unverified: {}",
                response["error"]
            )
            .into());
        }
        Ok::<Value, Error>(response)
    })
    .await
    .map_err(|_| "VM control deadline expired; inspect agent diagnostics".to_owned())?
}

/// Backend evidence is separate from the saved host handle. Incomplete or
/// conflicting evidence must hold start rather than permit a replacement.
pub(crate) async fn observe(name: &str) -> Value {
    match observe_checked(name).await {
        Ok(value) => value,
        Err(error) => json!({"runtime_state":"unknown","control_state":"unknown","run_id":null,
            "exec":false,"port_forward":false,"error":error.to_string(),"next_action":"run agent diagnostics; preserve the existing backend before recovery or stop"}),
    }
}

async fn observe_checked(name: &str) -> Result<Value, Error> {
    let saved = read(name);
    let run = saved.as_ref().ok().and_then(|value| value.as_ref());
    #[cfg(target_os = "linux")]
    {
        let holder = crate::host_platform::userns_pid(name).is_some();
        let control = crate::host_platform::control_pid(name).is_some();
        let id = id(name).ok();
        let root = crate::host_platform::runsc_root();
        if control && let Some(id) = &id {
            let output = tokio::time::timeout(
                Duration::from_secs(3),
                crate::host_platform::runsc_command(name)?
                    .args(["state", id])
                    .output(),
            )
            .await??;
            if output.status.success() {
                let state: Value = serde_json::from_slice(&output.stdout)?;
                if state["id"] != id.as_str() {
                    return Err("runsc returned a different sandbox identity".into());
                }
                if state["status"] == "running" || state["status"] == "created" {
                    let run_id = id.trim_start_matches("safeyolo-");
                    let recorded = run.is_some_and(|run| run["run_id"] == run_id);
                    let ready = state["status"] == "running";
                    return Ok(
                        json!({"runtime_state":if !recorded || !holder {"degraded"} else if ready {"running"} else {"starting"},"control_state":if holder {"ready"} else {"recovered"},
                        "run_id":run_id,"exec":ready,"port_forward":ready,"backend":state,
                        "next_action":if !recorded {json!(format!("run agent diagnostics {name} to inspect the live backend; agent stop {name} remains available"))} else if !holder {json!(format!("run agent diagnostics {name} to inspect recovered namespace control; agent stop {name} remains available"))} else {Value::Null},
                        "error":if !recorded {json!("current-run record is missing or corrupt; backend remains live")} else if !holder {json!("namespace holder is missing; control uses the verified surviving backend namespaces")} else {Value::Null}}),
                    );
                }
                if state["status"] == "stopped" {
                    return Ok(json!({"runtime_state":"stopped","control_state":"ready",
                        "run_id":id.trim_start_matches("safeyolo-"),"exec":false,"port_forward":false,
                        "backend":state}));
                }
            }
            if root.join(id).exists() {
                return Err("runsc backend state is present but could not be reconciled".into());
            }
        }
        if let Some(run) = run
            && crate::host_platform::backend_pid(name).is_some()
        {
            return Ok(
                json!({"runtime_state":"degraded","control_state":"unavailable","run_id":run["run_id"],
                "exec":false,"port_forward":false,"error":"namespace holder is unavailable; workload remains live",
                "next_action":"agent stop uses the verified backend process; exec and port forwarding require the original namespaces"}),
            );
        }
        if id.as_ref().is_some_and(|id| root.join(id).exists()) || control {
            return Err("sandbox backend or namespace exists without verified runtime evidence; start is held".into());
        }
        if let Some(run) = run
            && run["backend_pid"].as_i64().is_some_and(|pid| {
                crate::host_lifecycle::process_token(pid).as_deref()
                    == run["backend_token"].as_str()
            })
        {
            return Err("saved backend PID identifies an unrelated process; no runtime or signal authority was inferred".into());
        }
    }
    #[cfg(target_os = "macos")]
    {
        if config_dir()
            .join("data/vm-control")
            .join(format!("{name}.sock"))
            .exists()
        {
            match control(name, json!({"operation":"status"})).await {
                Ok(status) => {
                    if status["agent"] != name {
                        return Err("VZ control identifies another agent".into());
                    }
                    let pid = status["pid"]
                        .as_i64()
                        .ok_or("VZ control has no helper PID")?;
                    if crate::host_platform::vm_process_token(name, pid as i32).is_none() {
                        return Err("VZ control PID does not identify the installed helper".into());
                    }
                    let run_id = id(name)?.trim_start_matches("safeyolo-").to_owned();
                    let matched = run.is_some_and(|run| {
                        run["run_id"] == run_id && run["helper_instance"] == status["instance"]
                    });
                    let ready = status["vm"]["state"] == "running";
                    return Ok(
                        json!({"runtime_state":if !matched {"degraded"} else if ready {"running"} else {"unknown"},"control_state":"ready","run_id":run_id,
                        "exec":ready,"port_forward":ready,"backend":status,
                        "next_action":if !matched || !ready {json!(format!("run agent diagnostics {name} to inspect the identified VZ helper; agent stop {name} remains available"))} else {Value::Null},
                        "error":if !matched {json!("saved host handle is incomplete; private control still identifies the live helper")} else if !ready {json!("helper is responsive but its VM is not running")} else {Value::Null}}),
                    );
                }
                Err(error) if run.is_some_and(|run| process_matches(name, run, "backend")) => {
                    return Ok(
                        json!({"runtime_state":"degraded","control_state":"unavailable","run_id":run.unwrap()["run_id"],"exec":false,"port_forward":false,"error":error.to_string(),
                        "next_action":format!("run agent diagnostics {name} to inspect the unavailable private control path; agent stop {name} uses the verified helper identity")}),
                    );
                }
                Err(error)
                    if error.downcast_ref::<std::io::Error>().is_some_and(|error| {
                        error.kind() == std::io::ErrorKind::ConnectionRefused
                    }) && run.is_some_and(saved_vz_helper_is_dead) => {}
                Err(error) => return Err(error),
            }
        }
        if run.is_some_and(|run| process_matches(name, run, "backend")) {
            return Err(
                "VZ helper remains live but its private control path is unavailable".into(),
            );
        }
    }
    if saved.is_err() {
        return Err("current-run record is corrupt; backend absence is unverified".into());
    }
    // A dead identified backend is stopped. Diagnostic observation is read-only;
    // explicit stop/recovery cleans stale handles under the lifecycle lock.
    Ok(
        json!({"runtime_state":"stopped","control_state":"stopped","run_id":run.map(|run|run["run_id"].clone()),"exec":false,"port_forward":false}),
    )
}

#[cfg(target_os = "linux")]
pub(crate) async fn stop_without_holder(name: &str) -> Result<(), Error> {
    let pid = crate::host_platform::backend_pid(name)
        .ok_or("backend process identity is stale or unverified; no process was signalled")?;
    let token =
        crate::host_lifecycle::process_token(i64::from(pid)).ok_or("backend exited before stop")?;
    if unsafe { libc::kill(pid as i32, libc::SIGKILL) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while crate::host_lifecycle::process_token(i64::from(pid)).as_deref() == Some(&token) {
        if tokio::time::Instant::now() >= deadline {
            return Err("owned runsc workload did not stop".into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}
