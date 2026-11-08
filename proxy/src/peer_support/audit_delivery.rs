//! Retry metadata for support mutations. Successful delivery removes the staged
//! envelope; the configured JSONL writer remains the canonical audit owner.

use std::{fs, path::PathBuf};

use serde_json::{Value, json};

use crate::{Error, audit};

pub(crate) const PENDING: &str = "pending; the result is saved. Canonical audit delivery will retry without repeating the operation.";

pub(super) fn directory(name: &str) -> Result<PathBuf, Error> {
    use std::os::unix::fs::PermissionsExt;
    let root = crate::host_platform::config_dir();
    let path = root.join("data").join(name);
    fs::create_dir_all(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    // The receipt writer syncs its containing directory. Also persist newly
    // created directory entries back to the existing owning instance root.
    for parent in path
        .ancestors()
        .take_while(|parent| parent.starts_with(&root))
    {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(path)
}

pub(super) fn lock_grants() -> Result<fs::File, Error> {
    let directory = directory("support-grant-audit")?;
    Ok(crate::host_platform::lock_host_state(
        &directory.join("change.lock"),
    )?)
}

/// Stage before the policy transaction can save authority. Until the transaction
/// returns, termination leaves an honest unknown outcome, never a replay request.
pub(super) fn prepare_grant(name: &str, operation: &str, view: &Value) -> Result<String, Error> {
    let id = format!("evt-{}", uuid::Uuid::new_v4().simple());
    let mut event = audit::Event::new(
        "admin.support_grant_changed",
        audit::Kind::Admin,
        audit::Severity::High,
        "Operator support authority transaction",
    );
    event.event_id = Some(id.clone());
    event.details = json!({"instance_id":super::instance_id()?,
        "initiator":{"kind":"operator","authentication":"admin_bearer"},
        "grant":name,"operation":operation,"revision":view["revision"],
        "previous_revision":view["previous_revision"],"authority":view["after"],
        "phase":"policy_transaction","state":"outcome_unknown"})
    .into();
    let value: Value = serde_json::from_str(&event.encode_at(time::OffsetDateTime::now_utc())?)?;
    crate::guest_commands::write_json(&grant_path(&id)?, &value)?;
    Ok(id)
}

fn grant_path(id: &str) -> Result<PathBuf, Error> {
    if !id
        .strip_prefix("evt-")
        .is_some_and(|id| id.len() == 32 && id.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        return Err("invalid support audit event identity".into());
    }
    Ok(crate::host_platform::config_dir()
        .join("data/support-grant-audit")
        .join(format!("{id}.json")))
}

pub(super) fn grant_saved(id: &str) -> Result<(), Error> {
    let path = grant_path(id)?;
    let mut event = crate::guest_commands::read_state_bounded(&path, 1024 * 1024)?
        .ok_or("support authority audit obligation unavailable")?;
    event["details"]["state"] = json!("completed");
    crate::guest_commands::write_json(&path, &event)
}

/// The same lock covers staging, the native policy transaction and its saved
/// outcome. A recovery worker cannot publish an in-progress transaction.
pub(crate) async fn deliver_grant(writer: &audit::Writer, id: &str) -> Result<(), Error> {
    let path = grant_path(id)?;
    let _lock = crate::host_platform::try_lock_host_state(&path.with_file_name("change.lock"))?;
    let Some(event) = crate::guest_commands::read_state_bounded(&path, 1024 * 1024)? else {
        return Ok(());
    };
    writer.deliver_coord(&event.to_string()).await?;
    fs::remove_file(&path)?;
    fs::File::open(path.parent().ok_or("support audit directory missing")?)?.sync_all()?;
    Ok(())
}

#[derive(Default)]
pub(crate) struct Recovery {
    grants: Option<fs::ReadDir>,
    operations: Option<fs::ReadDir>,
}

fn next_file(files: &mut Option<fs::ReadDir>, name: &str) -> Result<Option<PathBuf>, Error> {
    if files.is_none() {
        let path = crate::host_platform::config_dir().join("data").join(name);
        *files = match fs::read_dir(path) {
            Ok(files) => Some(files),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
    }
    if let Some(entry) = files.as_mut().and_then(Iterator::next) {
        return Ok(Some(entry?.path()));
    }
    *files = None;
    Ok(None)
}

impl Recovery {
    /// Reuse the startup delivery owner. The bounded directory walk retains no
    /// second queue, and an unavailable sink does not prevent the next receipt
    /// from being considered on the next pass.
    pub(crate) async fn reconcile(&mut self, writer: &audit::Writer) -> Result<(), Error> {
        let mut failed = false;
        for (files, name) in [
            (&mut self.grants, "support-grant-audit"),
            (&mut self.operations, "support-operations"),
        ] {
            for _ in 0..16 {
                let Some(path) = next_file(files, name)? else {
                    break;
                };
                if path.extension().and_then(|part| part.to_str()) != Some("json") {
                    continue;
                }
                let result = if name == "support-grant-audit" {
                    let id = path
                        .file_stem()
                        .and_then(|part| part.to_str())
                        .ok_or("support audit identity missing")?;
                    deliver_grant(writer, id).await
                } else {
                    super::operations::recover_audit(writer, &path).await
                };
                if let Err(error) = result
                    && error
                        .downcast_ref::<std::io::Error>()
                        .is_none_or(|error| error.kind() != std::io::ErrorKind::WouldBlock)
                {
                    failed = true;
                    break;
                }
            }
        }
        if failed {
            Err("support canonical audit delivery unavailable".into())
        } else {
            Ok(())
        }
    }
}
