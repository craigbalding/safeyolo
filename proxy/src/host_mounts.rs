//! Explicit live-only changes to ordinary extra directories.

use crate::{Error, host_agents, host_boot, host_lifecycle, host_platform, host_runs};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};

pub(crate) fn recorded(run: &Value) -> Value {
    #[cfg(target_os = "linux")]
    let shares = &run["linux"]["extra_shares"];
    #[cfg(not(target_os = "linux"))]
    let shares = &run["macos"]["extra_shares"];
    shares.clone()
}

fn validate_writable_source(source: &Path) -> Result<(), Error> {
    let mut scripts = Vec::new();
    for agent in host_agents::list()? {
        if let Some(script) = &agent.host_script {
            scripts.push(script.clone());
        }
        let selected = host_lifecycle::selected_launcher(&agent)?;
        if let Some(script) = selected["script"].as_str() {
            scripts.push(script.into());
        }
        if let Some(current) = crate::guest_commands::read_state(
            &host_platform::config_dir()
                .join("agents")
                .join(&agent.name)
                .join("current-launch.json"),
        )? && let Some(script) = current["launcher"]["script"].as_str()
        {
            scripts.push(script.into());
        }
    }
    for script in scripts {
        if crate::native_config::resolve_protected_directory(Path::new(&script))?
            .starts_with(source)
        {
            return Err(
                "host launcher or setup script is inside the requested writable mount".into(),
            );
        }
    }
    Ok(())
}

pub(crate) async fn guest(name: &str, generation: &str, args: &[&str]) -> Result<Value, Error> {
    #[cfg(target_os = "linux")]
    let child = host_platform::runsc_command(name)?
        .args([
            "exec",
            "--user",
            "0:0",
            "--cwd",
            "/",
            &format!("safeyolo-{generation}"),
            crate::guest_commands::HELPER,
            "extra-mount",
            generation,
        ])
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    #[cfg(not(target_os = "linux"))]
    let child = {
        let command = [
            "sudo",
            "-n",
            crate::guest_commands::HELPER,
            "extra-mount",
            generation,
        ]
        .into_iter()
        .chain(args.iter().copied())
        .map(|part| format!("'{}'", part.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ");
        host_platform::spawn_guest_command_with_output(name, &command, true, false).await?
    };
    let output = tokio::time::timeout(Duration::from_secs(15), child.wait_with_output()).await??;
    if !output.status.success() {
        return Err(format!("guest extra-mount check failed: {}. Live sharing requires the current safeyolo-guest helper; prepare it on an explicit future stop/start if missing. This command did not restart the sandbox", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

pub(crate) async fn operate(
    operation: &str,
    selected: &host_agents::Agent,
    operand: &str,
) -> Result<Value, Error> {
    let before = host_runs::read(&selected.name)?.ok_or("sandbox is not running")?;
    let directory = host_platform::config_dir()
        .join("agents")
        .join(&selected.name);
    let _setup = tokio::task::spawn_blocking(move || {
        host_lifecycle::SetupLock::acquire_in(&directory, None)
    })
    .await??;
    // Configuration already uses this lock for host-script validation. Keep
    // an add's check and publication together across different agents too.
    let _policy = if operation == "mount" {
        let path = host_agents::policy_path()?;
        Some(tokio::task::spawn_blocking(move || crate::approvals::lock_policy(&path)).await??)
    } else {
        None
    };
    let agent = host_agents::refresh(selected)?;
    let run = host_runs::read(&agent.name)?.ok_or("sandbox is not running")?;
    if agent.name != selected.name
        || [
            "run_id",
            "agent_id",
            "backend_pid",
            "backend_token",
            "helper_instance",
        ]
        .iter()
        .any(|key| before[key] != run[key])
    {
        return Err("sandbox incarnation changed while waiting for its lifecycle lock; no mount was changed".into());
    }
    let observed = host_runs::observe(&agent.name).await;
    if observed["runtime_state"] != "running"
        || observed["run_id"] != run["run_id"]
        || run["agent_id"] != agent.id
    {
        return Err("live mounts require this agent's verified running sandbox; inspect agent status. No mount or saved configuration was changed".into());
    }
    let generation = run["run_id"]
        .as_str()
        .ok_or("sandbox generation is missing")?;
    let change = async {
        if operation == "mount" {
            let (source, target, read_only) = host_boot::mount(operand)?;
            // Preserve the existing host-launcher boundary when a live share
            // introduces another directory that the guest can write.
            if !read_only {
                validate_writable_source(&source)?;
            }
            guest(&agent.name, generation, &["inspect", &target]).await?;
            #[cfg(target_os = "linux")]
            return crate::linux_host::shares::attach(&agent.name, generation, operand).await;
            #[cfg(target_os = "macos")]
            return crate::macos_mounts::attach(&agent.name, generation, operand).await;
        }
        let target = Path::new(operand);
        if !target.is_absolute()
            || target
                .components()
                .any(|part| part == std::path::Component::ParentDir)
        {
            return Err("unmount requires an absolute guest path without '..'".into());
        }
        let target = target.components().collect::<std::path::PathBuf>();
        let target = target.to_str().ok_or("invalid guest path")?;
        guest(&agent.name, generation, &["inspect", target]).await?;
        #[cfg(target_os = "linux")]
        return crate::linux_host::shares::remove(&agent.name, generation, target).await;
        #[cfg(target_os = "macos")]
        return crate::macos_mounts::remove(&agent.name, generation, target).await;
        #[allow(unreachable_code)]
        Err("live extra mounts are unsupported on this platform".into())
    }
    .await;
    let (ok, share, error) = match change {
        Ok(share) => (true, share, Value::Null),
        Err(error) => (false, Value::Null, json!(error.to_string())),
    };
    let current = host_runs::read(&agent.name)?;
    Ok(
        json!({"ok":ok,"operation":operation,"agent":agent.name,"run_id":generation,
        "share":share,"error":error,"live_mounts":current.as_ref().map(recorded),
        "saved_mounts":agent.mounts,"saved_configuration_changed":false,
        "scope":"current sandbox only; saved mounts are unchanged. The next start uses saved mounts.",
        "recovery":if ok {Value::Null} else {json!(format!("Inspect agent status {}. Retry the same action when safe. An uncertain backend outcome retains its owned resources and can require an explicit stop/start; no restart was performed.",agent.name))}}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn live_rw_shares_preserve_other_agents_host_script_boundary() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        host_platform::in_instance(fixture.path().to_owned(), async {
            let workspace = fixture.path().join("workspace");
            let scripts = fixture.path().join("scripts");
            std::fs::create_dir(&workspace).unwrap();
            std::fs::create_dir(&scripts).unwrap();
            let script = scripts.join("launch.sh");
            std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
            let options = [("folder".into(),workspace.to_string_lossy().into_owned()),
                ("launcher".into(),"supervisor".into())];
            let alice = host_agents::configure("alice", &options, true, None).await.unwrap();
            host_agents::configure("bob", &options, true, None).await.unwrap();
            host_agents::configure("bob", &[("launcher".into(),script.to_string_lossy().into_owned())],false,None).await.unwrap();
            assert!(validate_writable_source(&scripts).unwrap_err().to_string().contains("host launcher"));
            // An absent built-in or future script outside the new source is
            // not a prerequisite for adding an unrelated live directory.
            assert!(validate_writable_source(&workspace).is_ok());
            host_agents::configure("bob", &[("launcher".into(),"supervisor".into())],false,None).await.unwrap();
            let mut run = json!({"agent_id":alice.id,"run_id":"a".repeat(32),
                "backend_pid":std::process::id(),
                "backend_token":host_lifecycle::process_token(i64::from(std::process::id())).unwrap()});
            #[cfg(target_os="linux")]
            let backend = "linux";
            #[cfg(target_os="macos")]
            let backend = "macos";
            run[backend] = json!({"extra_shares":[{"host_path":scripts,"read_only":false,"state":"exporting"}]});
            host_runs::save("alice",&run).unwrap();
            let policy = std::fs::read(host_agents::policy_path().unwrap()).unwrap();
            assert!(host_lifecycle::validate_host_script(&script).unwrap_err().to_string().contains("agent-writable"));
            assert!(host_agents::configure("bob", &[("launcher".into(),script.to_string_lossy().into_owned())],false,None).await.is_err());
            assert_eq!(std::fs::read(host_agents::policy_path().unwrap()).unwrap(),policy);
            for (state,read_only) in [("mounted",true),("removed",false)] {
                run[backend]["extra_shares"][0]["state"] = state.into();
                run[backend]["extra_shares"][0]["read_only"] = read_only.into();
                host_runs::save("alice",&run).unwrap();
                assert!(host_lifecycle::validate_host_script(&script).is_ok());
            }
            let mut stopped = std::process::Command::new("sleep").arg("30").spawn().unwrap();
            run["backend_pid"] = stopped.id().into();
            run["backend_token"] = host_lifecycle::process_token(i64::from(stopped.id())).unwrap().into();
            run[backend]["extra_shares"][0]["state"] = "mounted".into();
            stopped.kill().unwrap();
            stopped.wait().unwrap();
            host_runs::save("alice",&run).unwrap();
            assert!(host_lifecycle::validate_host_script(&script).is_ok());
        }).await;
    }

    #[tokio::test]
    async fn live_actions_preserve_saved_intent_and_unverified_run_receipts() {
        let fixture = tempfile::tempdir().unwrap();
        host_platform::in_instance(fixture.path().to_owned(), async {
            let source = fixture.path().join("source");
            std::fs::create_dir(&source).unwrap();
            let agent = host_agents::configure("alice", &[("folder".into(), source.to_string_lossy().into_owned()),
                ("mounts".into(),format!("{}:/reference:ro",source.display()))],true,None).await.unwrap();
            let policy = std::fs::read(fixture.path().join("policy.toml")).unwrap();
            let receipt = json!({"agent_id":agent.id,"run_id":"a".repeat(32),"state":"stopped",
                "linux":{"extra_shares":[{"id":"old","guest_path":"/reference","state":"removed"}]}});
            host_runs::save("alice", &receipt).unwrap();
            for (operation,operand) in [("mount",format!("{}:/new",source.display())),("unmount","/reference".into())] {
                assert!(operate(operation,&agent,&operand).await.is_err());
                assert_eq!(host_runs::read("alice").unwrap().unwrap(),receipt);
                assert_eq!(std::fs::read(fixture.path().join("policy.toml")).unwrap(),policy);
            }
            let lock = host_lifecycle::SetupLock::acquire_in(&fixture.path().join("agents/alice"),None).unwrap();
            let pending = operate("unmount",&agent,"/reference");
            tokio::pin!(pending);
            assert!(futures_util::poll!(pending.as_mut()).is_pending());
            let mut replacement = receipt.clone();
            replacement["run_id"] = "b".repeat(32).into();
            host_runs::save("alice",&replacement).unwrap();
            drop(lock);
            assert!(pending.await.unwrap_err().to_string().contains("incarnation changed"));
            assert_eq!(host_runs::read("alice").unwrap().unwrap(),replacement);
            assert_eq!(std::fs::read(fixture.path().join("policy.toml")).unwrap(),policy);
        }).await;
    }
}
