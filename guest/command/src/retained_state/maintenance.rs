//! An adopted Debian maintenance recipe, with retained requirements and recovery.
//! Commands run only in the selected guest. A receipt never grants authority.
use super::{GuestState, configuration, coverage, packages};
use crate::{Error, live_token, now, read_json, write_json};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    os::{fd::AsRawFd, unix::process::CommandExt},
    path::Path,
    process::{Command, Stdio},
};

fn operation(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 120
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(
            "maintenance operation needs 1..120 letters, digits, hyphens or underscores".into(),
        );
    }
    Ok(())
}

fn directory(store: &GuestState, id: &str) -> std::path::PathBuf {
    store.directory.join("maintenance").join(id)
}

pub(super) fn status(store: &GuestState, id: &str) -> Result<i32, Error> {
    operation(id)?;
    let path = directory(store, id).join("result.json");
    let mut record = read_json(&path, 16 * 1024 * 1024)?;
    let owner = record["pid"].as_i64().ok_or("maintenance owner missing")? as i32;
    record["owner_alive"] = json!(live_token(owner)?.as_deref() == record["owner"].as_str());
    record["record_path"] = json!(path);
    record["command_activity"] = match active_commands(&record) {
        Ok(groups) => {
            json!({"state":if groups.is_empty() {"quiescent"} else {"active"},"groups":groups})
        }
        Err(error) => json!({"state":"unknown","diagnostic":error.to_string()}),
    };
    for field in ["request", "before", "after", "recovered_state"] {
        record
            .as_object_mut()
            .ok_or("invalid maintenance receipt")?
            .remove(field);
    }
    if let Some(commands) = record["commands"].as_object_mut() {
        for command in commands.values_mut() {
            if let Some(command) = command.as_object_mut() {
                command.remove("output_prefix");
            }
        }
    }
    println!("{record}");
    Ok(0)
}

fn save(path: &Path, record: &mut Value, phase: &str) -> Result<(), Error> {
    record["phase"] = json!(phase);
    record["updated_at"] = json!(now());
    write_json(path, record)
}

fn command<'a>(request: &'a Value, field: &str) -> Result<&'a str, Error> {
    request[field]
        .as_str()
        .filter(|s| !s.trim().is_empty() && s.len() <= 16384)
        .ok_or_else(|| format!("maintenance needs an adopted {field} of 1..16384 bytes").into())
}

// File-backed output avoids collecting package-manager output in memory. The
// retained receipt has a bounded diagnostic; the private log keeps the detail.
fn execute(
    store: &GuestState,
    request: &Value,
    stage: &str,
    path: &Path,
    record: &mut Value,
) -> Result<(), Error> {
    let script = command(request, stage)?;
    save(path, record, stage)?;
    let log = path
        .parent()
        .ok_or("maintenance directory missing")?
        .join(format!("{stage}.log"));
    let output = fs::File::create(&log)?;
    let spawned = Command::new("/bin/sh")
        .args([
            "-eu",
            "-c",
            "IFS= read -r permit; [ \"$permit\" = start ]; exec /bin/sh -eu -c \"$1\"",
            "safeyolo-maintenance",
            script,
        ])
        .env("LC_ALL", "C")
        .env("SAFEYOLO_GUEST_ROOT", &store.root)
        .env(
            "SAFEYOLO_MAINTENANCE_OPERATION",
            request["operation_id"]
                .as_str()
                .ok_or("missing operation")?,
        )
        .env(
            "SAFEYOLO_MAINTENANCE_DIRECTORY",
            path.parent().ok_or("maintenance directory missing")?,
        )
        .stdout(output.try_clone()?)
        .stderr(output)
        .stdin(Stdio::piped())
        .process_group(0)
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            record["commands"][stage] = json!({"state":"not_started","log":log});
            write_json(path, record)?;
            return Err(error.into());
        }
    };
    record["commands"][stage] = json!({"pid":child.id(),"owner":live_token(child.id() as i32)?,
        "group":child.id(),"finished":false,"log":log});
    write_json(path, record)?;
    fs::File::open(path.parent().ok_or("maintenance directory missing")?)?.sync_all()?;
    // The script cannot execute before its identity is durable. If this
    // helper exits first, EOF releases the waiting child without running it.
    child
        .stdin
        .take()
        .ok_or("maintenance start pipe missing")?
        .write_all(b"start\n")?;
    let result = child.wait()?;
    let mut diagnostic = Vec::new();
    fs::File::open(&log)?
        .take(4096)
        .read_to_end(&mut diagnostic)?;
    record["commands"][stage]["exit_code"] = json!(result.code());
    record["commands"][stage]["finished"] = json!(true);
    record["commands"][stage]["output_prefix"] = json!(String::from_utf8_lossy(&diagnostic));
    record["commands"][stage]["output_bytes"] = json!(fs::metadata(&log)?.len());
    write_json(path, record)?;
    if !result.success() {
        return Err(format!("guest maintenance {stage} failed; inspect its retained log").into());
    }
    if matches!(
        stage,
        "checkpoint_command" | "patch_command" | "recover_command"
    ) && !active_commands(record)?.is_empty()
    {
        return Err(format!(
            "guest maintenance {stage} left an active command group; inspect its retained identity"
        )
        .into());
    }
    Ok(())
}

fn active_commands(record: &Value) -> Result<Vec<Value>, Error> {
    let mut groups = Vec::new();
    for stage in [
        "checkpoint_command",
        "patch_command",
        "restart_command",
        "health_command",
        "recover_command",
        "recovery_health_command",
    ] {
        let command = &record["commands"][stage];
        if command.is_null() {
            // No identity means the start pipe was never released.
            continue;
        }
        if command["state"] == "not_started" {
            continue;
        }
        if matches!(
            stage,
            "restart_command" | "health_command" | "recovery_health_command"
        ) && command["finished"] == true
        {
            continue;
        }
        let group = i32::try_from(
            command["group"]
                .as_i64()
                .ok_or("maintenance command group missing")?,
        )?;
        if let Some((owner, _, _)) = crate::process(group)?
            && command["owner"]
                .as_str()
                .is_some_and(|original| original != owner)
        {
            continue;
        } // The original group ended and this PID now belongs to another process.
        let mut members = Vec::new();
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|pid| pid.parse::<i32>().ok())
            else {
                continue;
            };
            if let Some((owner, state, current_group)) = crate::process(pid)?
                && current_group == group
                && !matches!(state, 'Z' | 'X')
            {
                members.push(json!({"pid":pid,"owner":owner}));
            }
        }
        if !members.is_empty() {
            groups.push(json!({"stage":stage,"group":group,"members":members}));
        }
    }
    Ok(groups)
}

fn observed(store: &GuestState, value: &Value) -> Result<Value, Error> {
    Ok(
        json!({"distribution":packages::distribution(store)?,"packages":packages::snapshot(store)?,
        "configuration":configuration::inventory(&store.root, &coverage(value)?)?}),
    )
}

fn record_summary(store: &GuestState, path: &Path, record: &Value) -> Result<(), Error> {
    let _lock = store.lock()?;
    let mut value = store.initialize()?;
    value["maintenance"] = json!({"operation_id":record["operation_id"],"outcome":record["outcome"],
        "result_path":path,"phase":record["phase"],"updated_at":record["updated_at"]});
    store.save(&value)
}

fn recover(
    store: &GuestState,
    request: &Value,
    path: &Path,
    record: &mut Value,
) -> Result<(), Error> {
    if !active_commands(record)?.is_empty() {
        return Err("original maintenance command group is still active; stop and inspect that exact group before selecting recovery".into());
    }
    execute(store, request, "recover_command", path, record)?;
    let value = {
        let _lock = store.lock()?;
        store.read()?
    };
    let after = observed(store, &value)?;
    record["recovered_state"] = after.clone();
    if after != record["before"] {
        return Err("recovery does not match the previous package and covered-file state".into());
    }
    let mut recovery_request = request.clone();
    recovery_request["recovery_health_command"] = request["health_command"].clone();
    execute(
        store,
        &recovery_request,
        "recovery_health_command",
        path,
        record,
    )?;
    record["recovery_deleted_package_mappings"] = json!(deleted_mappings(store, &value)?);
    if record["recovery_deleted_package_mappings"]
        .as_array()
        .is_some_and(|mappings| !mappings.is_empty())
    {
        return Err("recovery left old package files mapped; restart the affected processes before claiming restoration".into());
    }
    Ok(())
}

pub(super) fn recover_selected(store: &GuestState, id: &str) -> Result<i32, Error> {
    operation(id)?;
    if unsafe { libc::geteuid() } != 0 {
        return Err("use guest sudo for selected maintenance recovery".into());
    }
    let lock = fs::File::create(store.directory.join("maintenance.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("maintenance is still active; inspect its original result".into());
    }
    let path = directory(store, id).join("result.json");
    let mut record = read_json(&path, 16 * 1024 * 1024)?;
    if record["checkpoint_completed"] != true
        || !matches!(
            record["outcome"].as_str(),
            Some("uncertain" | "recovery_failed")
        )
        || !record["commands"]["recover_command"].is_null()
    {
        return Err("no unused completed checkpoint for this uncertain operation; inspect the reached state and original recovery result".into());
    }
    if !active_commands(&record)?.is_empty() {
        return Err("original maintenance command group is still active; stop and inspect that exact group before selecting recovery".into());
    }
    let request = record["request"].clone();
    let result = recover(store, &request, &path, &mut record);
    record["outcome"] = json!(if result.is_ok() {
        "recovered"
    } else {
        "recovery_failed"
    });
    if let Err(error) = result {
        record["recovery_diagnostic"] = json!(error.to_string());
    }
    save(&path, &mut record, "complete")?;
    record_summary(store, &path, &record)?;
    status(store, id)
}

fn requirements_satisfied(value: &Value, actual: &Value) -> Result<bool, Error> {
    let architecture = packages::architecture()?;
    for (name, requirement) in value["requirements"]
        .as_object()
        .ok_or("invalid retained requirements")?
    {
        let package = packages::package(&actual["packages"], name, &architecture);
        if actual["distribution"] != requirement["distribution"]
            || !packages::installed(package)
            || !packages::satisfies(
                package["version"]
                    .as_str()
                    .ok_or("installed version missing")?,
                requirement,
            )?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn adopt(store: &GuestState, request: &Value) -> Result<Value, Error> {
    let _lock = store.lock()?;
    let mut value = store.initialize()?;
    let requirements = request["requirements"]
        .as_array()
        .ok_or("maintenance requirements must be an array")?;
    for requirement in requirements {
        let field = |name: &str| {
            requirement[name]
                .as_str()
                .ok_or("invalid maintenance requirement")
        };
        let (package, version, distro, advisory) = (
            field("package")?,
            field("version")?,
            field("distribution")?,
            field("advisory")?,
        );
        let old = value["requirements"][package].clone();
        if !old.is_null() && (old["distribution"] != distro || old["operator"] != "ge") {
            return Err("maintenance conflicts with an existing requirement; review it through retained-state require/forget".into());
        }
        // One advisory cannot silently weaken another already adopted fix.
        let version = if !old.is_null() && packages::satisfies(version, &old)? {
            version
        } else {
            old["version"].as_str().unwrap_or(version)
        };
        packages::require(&mut value, package, "ge", version, distro, advisory)?;
        let mut advisories = old["advisories"].as_array().cloned().unwrap_or_default();
        if let Some(previous) = old["advisory"].as_str()
            && !advisories.contains(&json!(previous))
        {
            advisories.push(json!(previous));
        }
        if !advisories.contains(&json!(advisory)) {
            advisories.push(json!(advisory));
        }
        value["requirements"][package]["advisories"] = json!(advisories);
        value["requirements"][package]["maintenance_operation"] = request["operation_id"].clone();
    }
    store.save(&value)?;
    Ok(value)
}

// A selected package database alone cannot detect a copied-up old executable.
// dpkg checks the actual payload. Declared configuration changes may differ
// from the vendor hash only when they match the retained customization.
fn verify_files(store: &GuestState, value: &Value) -> Result<Value, Error> {
    let names = value["requirements"]
        .as_object()
        .ok_or("invalid requirements")?;
    if names.is_empty() {
        return Ok(json!({"packages":[],"modified_configuration":[]}));
    }
    let output = Command::new("dpkg")
        .arg(format!("--root={}", store.root.display()))
        .arg("--verify")
        .args(names.keys())
        .env("LC_ALL", "C")
        .output()?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err("effective package-file verification failed or was unavailable".into());
    }
    let actual = configuration::inventory(&store.root, &coverage(value)?)?;
    let text = String::from_utf8(output.stdout)?;
    let mut retained = Vec::new();
    for line in text.lines() {
        let (flags, path) = line
            .split_once(" /")
            .ok_or("unrecognized dpkg verification output")?;
        let path = format!("/{path}");
        if flags.split_whitespace().last() != Some("c")
            || actual[&path].is_null()
            || actual[&path] != value["configuration"][&path]
        {
            return Err(format!(
                "effective package file differs from vendor and retained configuration: {path}"
            )
            .into());
        }
        retained.push(path);
    }
    Ok(json!({"packages":names.keys().collect::<Vec<_>>(),"modified_configuration":retained}))
}

fn deleted_mappings(store: &GuestState, value: &Value) -> Result<Vec<String>, Error> {
    let mut files = std::collections::BTreeSet::new();
    for name in value["requirements"]
        .as_object()
        .ok_or("invalid requirements")?
        .keys()
    {
        let output = super::output(
            Command::new("dpkg-query")
                .arg(format!(
                    "--admindir={}",
                    store.actual("/var/lib/dpkg").display()
                ))
                .args(["-L", name]),
        )?;
        files.extend(
            output
                .lines()
                .map(|path| store.actual(path).display().to_string()),
        );
    }
    let mut pending = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|pid| pid.parse::<u32>().ok())
        else {
            continue;
        };
        // This verifier exits after its receipt. Its own old mappings do not
        // describe a continuing workload.
        if pid == std::process::id() {
            continue;
        }
        let text = match fs::read_to_string(entry.path().join("maps")) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for line in text.lines().filter(|line| line.ends_with(" (deleted)")) {
            if let Some(index) = line.find('/') {
                let file = line[index..].trim_end_matches(" (deleted)");
                if files.contains(file)
                    || files.contains(file.trim_end_matches(".dpkg-tmp"))
                    || files.contains(file.trim_end_matches(".dpkg-old"))
                {
                    pending.push(format!("{pid}:{file}"));
                }
            }
        }
    }
    Ok(pending)
}

pub(super) fn run(store: &GuestState) -> Result<i32, Error> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("run maintenance with guest sudo so package files and protected process mappings can be verified".into());
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(128 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 128 * 1024 {
        return Err("maintenance request exceeds 128 KiB".into());
    }
    let request: Value = serde_json::from_slice(&bytes)?;
    for stage in [
        "checkpoint_command",
        "patch_command",
        "health_command",
        "recover_command",
    ] {
        command(&request, stage)?;
    }
    if !request["restart_command"].is_null() {
        command(&request, "restart_command")?;
    }
    let id = request["operation_id"]
        .as_str()
        .ok_or("maintenance operation missing")?;
    operation(id)?;
    let directory = directory(store, id);
    let path = directory.join("result.json");
    if path.try_exists()? {
        let record = read_json(&path, 16 * 1024 * 1024)?;
        if record["request"] != request {
            return Err("maintenance operation already has different inputs".into());
        }
        // Even a lost reply or dead owner cannot select a retry.
        return status(store, id);
    }
    let lock = fs::File::create(store.directory.join("maintenance.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(
            "another guest maintenance operation is active; inspect its original receipt".into(),
        );
    }
    if path.try_exists()? {
        let record = read_json(&path, 16 * 1024 * 1024)?;
        if record["request"] != request {
            return Err("maintenance operation already has different inputs".into());
        }
        return status(store, id);
    }
    {
        let _lock = store.lock()?;
        let value = store.initialize()?;
        if let Some(previous) = value["maintenance"]["operation_id"].as_str()
            && previous != id
        {
            let original = read_json(
                &self::directory(store, previous).join("result.json"),
                16 * 1024 * 1024,
            )?;
            if original["outcome"] == "uncertain" || !active_commands(&original)?.is_empty() {
                return Err(format!("original maintenance {previous} is uncertain; inspect maintenance-status and select its recovery before another operation").into());
            }
        }
    }
    fs::create_dir_all(&directory)?;
    let mut record = json!({"operation_id":id,"request":request,"pid":std::process::id(),
        "owner":live_token(std::process::id() as i32)?,"outcome":"uncertain","commands":{},"started_at":now()});
    save(&path, &mut record, "adopting_requirements")?;
    record_summary(store, &path, &record)?;
    let result = (|| -> Result<(), Error> {
        let value = adopt(store, &request)?;
        let before = observed(store, &value)?;
        if value["requirements"]
            .as_object()
            .ok_or("invalid requirements")?
            .values()
            .any(|requirement| requirement["distribution"] != before["distribution"])
        {
            return Err("retained remediation belongs to another guest distribution; inspect its explicit update path".into());
        }
        record["before"] = before.clone();
        record["requirements"] = value["requirements"].clone();
        let needed =
            !requirements_satisfied(&value, &before)? || value["reconcile_required"] == true;
        if needed {
            execute(store, &request, "checkpoint_command", &path, &mut record)?;
            record["checkpoint_completed"] = json!(true);
            execute(store, &request, "patch_command", &path, &mut record)?;
        }
        let current = {
            let _lock = store.lock()?;
            store.read()?
        };
        let after = observed(store, &current)?;
        record["after"] = after.clone();
        if !requirements_satisfied(&current, &after)? {
            return Err(
                "effective packages do not satisfy adopted remediation requirements".into(),
            );
        }
        record["package_files"] = verify_files(store, &current)?;
        if needed && !request["restart_command"].is_null() {
            execute(store, &request, "restart_command", &path, &mut record)?;
        }
        execute(store, &request, "health_command", &path, &mut record)?;
        record["deleted_package_mappings"] = json!(deleted_mappings(store, &current)?);
        record["outcome"] = json!(if record["deleted_package_mappings"]
            .as_array()
            .is_some_and(|p| !p.is_empty())
        {
            "pending_restart"
        } else {
            "verified"
        });
        record["changed"] = json!(needed);
        Ok(())
    })();
    if let Err(error) = result {
        record["diagnostic"] = json!(error.to_string());
        if record["checkpoint_completed"] == true {
            let recovery = recover(store, &request, &path, &mut record);
            record["outcome"] = json!(if recovery.is_ok() {
                "recovered"
            } else {
                "recovery_failed"
            });
            if let Err(error) = recovery {
                record["recovery_diagnostic"] = json!(error.to_string());
            }
        } else {
            record["outcome"] = json!("failed");
        }
    }
    record["coverage"] = json!(
        "Debian package versions, vendor payload verification, retained configuration coverage, deleted package mappings and the adopted health/recovery recipe; host runtime and separately supplied boot kernel are outside this operation"
    );
    save(&path, &mut record, "complete")?;
    record_summary(store, &path, &record)?;
    status(store, id)
}
