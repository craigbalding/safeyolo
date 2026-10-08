//! Native guest boot inputs shared by host lifecycle and the installed CLI.

use crate::Error;
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufWriter, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub const HELPER: &str = "/safeyolo/safeyolo-guest";
pub const WRAPPER: &[u8] = b"#!/bin/sh\n# SafeYolo configured-command observation\nif [ ! -x /safeyolo/safeyolo-guest ]; then\n    echo 'Required native guest helper is missing: /safeyolo/safeyolo-guest; restage the installed guest assets' >&2\n    exit 127\nfi\nexec /safeyolo/safeyolo-guest observe exec -- \"$0.payload\" \"$@\"\n";

pub(crate) fn payload_identity(path: &Path) -> Result<Value, Error> {
    let info = fs::symlink_metadata(path)?;
    if !info.is_file() && !info.file_type().is_symlink() {
        return Err(format!("preserving unrecognized command payload {}", path.display()).into());
    }
    Ok(json!([
        info.dev(),
        info.ino(),
        i128::from(info.mtime()) * 1_000_000_000 + i128::from(info.mtime_nsec()),
        i128::from(info.ctime()) * 1_000_000_000 + i128::from(info.ctime_nsec())
    ]))
}

pub(crate) fn write_json(path: &Path, value: &Value) -> Result<(), Error> {
    write_json_with_mode(path, value, 0o600)
}

pub(crate) fn write_json_with_mode(path: &Path, value: &Value, mode: u32) -> Result<(), Error> {
    let parent = path.parent().ok_or("state has no parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    {
        let mut output = BufWriter::new(&mut temporary);
        serde_json::to_writer(&mut output, value)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn read_state(path: &Path) -> Result<Option<Value>, Error> {
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !file.metadata()?.is_file() {
        return Err("command state must be a regular file; completion is unverified".into());
    }
    let mut source = Vec::new();
    file.take(128 * 1024 + 1).read_to_end(&mut source)?;
    if source.len() > 128 * 1024 {
        return Err("command state exceeds the diagnostic limit".into());
    }
    Ok(Some(serde_json::from_slice(&source)?))
}

fn copy_executable(source: &Path, destination: &Path) -> Result<(), Error> {
    let parent = destination.parent().ok_or("guest asset has no parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    std::io::copy(&mut fs::File::open(source)?, &mut temporary)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o755))?;
    temporary.as_file().sync_all()?;
    temporary.persist(destination)?;
    Ok(())
}

/// Stage only while the selected sandbox is stopped. The caller owns that
/// lifecycle check and supplies the actual host launch context for this run.
pub fn stage(home: &Path, share: &Path, assets: &Path, mut context: Value) -> Result<Value, Error> {
    if context["generation"].as_str().is_none_or(str::is_empty) {
        return Err("guest staging requires a current-run generation".into());
    }
    let helper = assets.join("safeyolo-guest");
    let mut header = [0; 20];
    fs::File::open(&helper)
        .map_err(|error| {
            format!(
                "required native guest helper is missing or unreadable: {}: {error}",
                helper.display()
            )
        })?
        .read_exact(&mut header)?;
    if &header[..4] != b"\x7fELF" {
        return Err(
            "guest helper must be a Linux ELF executable; use the installed Linux guest artifact"
                .into(),
        );
    }
    let mut identities = context
        .get("command_payloads")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut pending = Vec::new();
    for name in [".safeyolo-command", ".safeyolo-interactive-command"] {
        let entrypoint = home.join(name);
        let info = match fs::metadata(&entrypoint) {
            Ok(info) => info,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !info.is_file() || info.permissions().mode() & 0o111 == 0 {
            continue;
        }
        let payload = home.join(format!("{name}.payload"));
        if info.len() == WRAPPER.len() as u64 && fs::read(&entrypoint)? == WRAPPER {
            if !identities.contains_key(name) {
                identities.insert(name.into(), payload_identity(&payload)?);
            }
            continue;
        }
        if fs::symlink_metadata(&payload).is_ok()
            && identities.get(name) != Some(&payload_identity(&payload)?)
        {
            return Err(format!(
                "cannot stage {name}: preserving unrecognized payload {}",
                payload.display()
            )
            .into());
        }
        pending.push((entrypoint, payload));
    }
    fs::create_dir_all(share)?;
    // Precheck all assets before replacing either command entrypoint.
    for asset in [
        "guest-init",
        "guest-init-static",
        "guest-init-per-run",
        "guest-proxy-forwarder",
        "guest-shell-bridge",
        "guest-desktop",
        "safeyolo-guest",
    ] {
        if !assets.join(asset).is_file() {
            return Err(format!(
                "required guest asset is missing: {}",
                assets.join(asset).display()
            )
            .into());
        }
    }
    for asset in [
        "guest-init",
        "guest-init-static",
        "guest-init-per-run",
        "guest-proxy-forwarder",
        "guest-shell-bridge",
        "guest-desktop",
        "safeyolo-guest",
    ] {
        copy_executable(&assets.join(asset), &share.join(asset))?;
    }
    for (entrypoint, payload) in pending {
        fs::rename(&entrypoint, &payload)?;
        let name = entrypoint
            .file_name()
            .ok_or("entrypoint has no name")?
            .to_string_lossy()
            .into_owned();
        identities.insert(name, payload_identity(&payload)?);
        let mut temporary = tempfile::NamedTempFile::new_in(home)?;
        temporary.write_all(WRAPPER)?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))?;
        temporary.persist(entrypoint)?;
    }
    context["command_payloads"] = json!(identities);
    write_json(&share.join("host-launch-context.json"), &context)?;
    Ok(context)
}

/// Publish an idle supervisor command. Callers serialize host setup/launch and
/// never use a guest PID from this shared file as authority for a host signal.
pub fn publish(
    home: &Path,
    share: &Path,
    name: &str,
    command: &str,
    id: &str,
    generation: &str,
) -> Result<(), Error> {
    if command.trim().is_empty() || id.is_empty() || generation.is_empty() {
        return Err("guest command, supervision ID and current-run generation are required".into());
    }
    let state = home.join(".safeyolo-command-supervisor.json");
    if let Some(previous) = read_state(&state)? {
        if previous["schema_version"] != 1
            || previous["name"] != name
            || previous["command"].as_str().is_none()
        {
            return Err(
                "command supervisor state is invalid or unverified; active work was left intact"
                    .into(),
            );
        }
        if !matches!(
            previous["state"].as_str(),
            Some("stopped" | "failed" | "exited")
        ) || !previous["command_pid"].is_null()
            || !previous["command_start_token"].is_null()
        {
            return Err(
                "command supervisor is occupied or unverified; active work was left intact".into(),
            );
        }
    }
    let stop = home.join(".safeyolo-command-supervisor.stop");
    match fs::remove_file(stop) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    write_json(
        &state,
        &json!({"schema_version":1,"name":name,"command":command,"supervision_id":id,"generation":generation,"state":"starting","runtime_owner":"guest-pid1","started_at":time::OffsetDateTime::now_utc().unix_timestamp_nanos().to_string(),"restart_count":0,"consecutive_failures":0,"heartbeat_at":null,"last_stderr":"","last_exit_code":null,"next_restart_at":null}),
    )?;
    fs::write(share.join("command-supervisor-enabled"), b"")?;
    Ok(())
}

/// Fence only the selected command. The guest owner acknowledges termination;
/// publishing a stop request alone does not prove that a command has stopped.
pub fn request_stop(home: &Path, share: &Path, id: &str) -> Result<(), Error> {
    let state = read_state(&home.join(".safeyolo-command-supervisor.json"))?
        .ok_or("command supervisor state is missing; completion is unverified")?;
    if state["supervision_id"] != id {
        return Err("supervisor ownership changed; replacement state was left intact".into());
    }
    write_json(
        &home.join(".safeyolo-command-supervisor.stop"),
        &json!({"supervision_id":id}),
    )?;
    match fs::remove_file(share.join("command-supervisor-enabled")) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assets(directory: &Path) {
        fs::create_dir(directory).unwrap();
        for name in [
            "guest-init",
            "guest-init-static",
            "guest-init-per-run",
            "guest-proxy-forwarder",
            "guest-shell-bridge",
            "guest-desktop",
        ] {
            fs::write(directory.join(name), b"#!/bin/sh\n").unwrap();
        }
        // This fixture challenges staging, not execution of the guest binary.
        let mut header = [0_u8; 20];
        header[..4].copy_from_slice(b"\x7fELF");
        fs::write(directory.join("safeyolo-guest"), header).unwrap();
    }

    #[test]
    fn native_staging_preserves_arguments_payloads_context_and_modes() {
        let fixture = tempfile::tempdir().unwrap();
        let home = fixture.path().join("home");
        let share = fixture.path().join("share");
        let source = fixture.path().join("assets");
        fs::create_dir(&home).unwrap();
        assets(&source);
        for name in [".safeyolo-command", ".safeyolo-interactive-command"] {
            fs::write(home.join(name), b"#!/bin/sh\nexec marker \"$@\"\n").unwrap();
            fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let context = json!({"generation":"fresh-run","workspace":"/selected/workspace"});
        let first = stage(&home, &share, &source, context).unwrap();
        assert_eq!(stage(&home, &share, &source, first.clone()).unwrap(), first);
        for name in [".safeyolo-command", ".safeyolo-interactive-command"] {
            assert_eq!(fs::read(home.join(name)).unwrap(), WRAPPER);
            assert_eq!(
                fs::read(home.join(format!("{name}.payload"))).unwrap(),
                b"#!/bin/sh\nexec marker \"$@\"\n"
            );
            assert_eq!(
                fs::metadata(home.join(name)).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        assert_eq!(
            read_state(&share.join("host-launch-context.json"))
                .unwrap()
                .unwrap(),
            first
        );
        assert_eq!(
            fs::metadata(share.join("host-launch-context.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn missing_asset_and_unrecognized_payload_leave_commands_intact() {
        let fixture = tempfile::tempdir().unwrap();
        let home = fixture.path().join("home");
        let source = fixture.path().join("assets");
        let share = fixture.path().join("share");
        fs::create_dir(&home).unwrap();
        assets(&source);
        fs::write(home.join(".safeyolo-command"), "#!/bin/sh\nexec marker").unwrap();
        fs::set_permissions(
            home.join(".safeyolo-command"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::remove_file(source.join("safeyolo-guest")).unwrap();
        assert!(
            stage(&home, &share, &source, json!({"generation":"run"}))
                .unwrap_err()
                .to_string()
                .contains("required native guest helper")
        );
        assert!(!home.join(".safeyolo-command.payload").exists());
        fs::write(home.join(".safeyolo-command.payload"), "operator payload").unwrap();
        fs::write(source.join("safeyolo-guest"), b"\x7fELF0000000000000000").unwrap();
        assert!(
            stage(&home, &share, &source, json!({"generation":"run"}))
                .unwrap_err()
                .to_string()
                .contains("preserving unrecognized payload")
        );
        assert_eq!(
            fs::read_to_string(home.join(".safeyolo-command.payload")).unwrap(),
            "operator payload"
        );
    }

    #[test]
    fn publication_and_stop_preserve_a_different_owner() {
        let fixture = tempfile::tempdir().unwrap();
        let home = fixture.path().join("home");
        let share = fixture.path().join("share");
        fs::create_dir(&home).unwrap();
        fs::create_dir(&share).unwrap();
        publish(
            &home,
            &share,
            "marker",
            "exec marker 'literal argv'",
            "one",
            "run",
        )
        .unwrap();
        let state = home.join(".safeyolo-command-supervisor.json");
        let original = fs::read(&state).unwrap();
        assert!(publish(&home, &share, "marker", "exec replacement", "two", "run").is_err());
        assert!(request_stop(&home, &share, "two").is_err());
        assert_eq!(fs::read(&state).unwrap(), original);
        request_stop(&home, &share, "one").unwrap();
        assert!(home.join(".safeyolo-command-supervisor.stop").is_file());
        assert!(!share.join("command-supervisor-enabled").exists());
        assert_eq!(read_state(&state).unwrap().unwrap()["state"], "starting");
    }
}
