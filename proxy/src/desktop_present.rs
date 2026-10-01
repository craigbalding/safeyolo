//! Native owner of operator desktop presentations.

use std::{collections::BTreeMap, io::Write, os::unix::fs::PermissionsExt, sync::LazyLock};

use serde_json::{Value, json};
use tokio::sync::Mutex;
use yaml_rust2::YamlLoader;

use crate::{desktop_preview::Preview, host_agents, host_platform};

#[derive(Debug)]
pub(crate) enum Error {
    Unavailable,
    NotFound,
    Failed,
}

struct Presentation {
    preview: Preview,
}

static PRESENTATIONS: LazyLock<Mutex<BTreeMap<String, Presentation>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

pub(crate) fn valid_agent_id(agent_id: &str) -> bool {
    !agent_id.is_empty()
        && agent_id.len() <= 128
        && agent_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(crate) fn available() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
}

fn settings() -> Result<(String, u16), Error> {
    let path = host_platform::config_dir().join("config.yaml");
    let source = match std::fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(_) => return Err(Error::Failed),
    };
    let documents = YamlLoader::load_from_str(&source).map_err(|_| Error::Failed)?;
    let desktop = documents.first().map(|document| &document["desktop"]);
    let size = desktop
        .and_then(|desktop| desktop["size"].as_str())
        .unwrap_or("auto")
        .to_owned();
    let port = desktop
        .and_then(|desktop| desktop["present_host_port"].as_i64())
        .unwrap_or(0);
    let port = u16::try_from(port).map_err(|_| Error::Failed)?;
    Ok((size, port))
}

fn parse_geometry(value: &str) -> Result<(u32, u32), Error> {
    let (width, height) = value.split_once('x').ok_or(Error::Failed)?;
    if !(3..=5).contains(&width.len())
        || !(3..=5).contains(&height.len())
        || !width.bytes().all(|byte| byte.is_ascii_digit())
        || !height.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Error::Failed);
    }
    let width = width.parse::<u32>().map_err(|_| Error::Failed)?;
    let height = height.parse::<u32>().map_err(|_| Error::Failed)?;
    if width < 640 || height < 480 {
        return Err(Error::Failed);
    }
    Ok((width, height))
}

fn geometry(size: &str) -> Result<String, Error> {
    let size = size.trim().to_ascii_lowercase();
    if size != "auto" {
        let (width, height) = parse_geometry(&size)?;
        return Ok(format!("{width}x{height}"));
    }
    let display = std::env::var("SAFEYOLO_PREVIEW_SCREEN_SIZE").ok();
    let Some(display) = display else {
        return Ok("1280x800".into());
    };
    let (width, height) = parse_geometry(&display)?;
    Ok(format!(
        "{}x{}",
        width.saturating_sub(160).clamp(640, 2560),
        height.saturating_sub(180).clamp(480, 1440)
    ))
}

fn stage_guest_desktop(name: &str, preferred_size: &str) -> Result<(), Error> {
    let share = host_platform::config_dir()
        .join("agents")
        .join(name)
        .join("config-share");
    std::fs::create_dir_all(&share).map_err(|_| Error::Failed)?;
    let mut temporary = tempfile::NamedTempFile::new_in(&share).map_err(|_| Error::Failed)?;
    temporary
        .write_all(include_bytes!("../../cli/src/safeyolo/guest-desktop.sh"))
        .map_err(|_| Error::Failed)?;
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o755))
        .map_err(|_| Error::Failed)?;
    temporary
        .persist(share.join("guest-desktop"))
        .map_err(|_| Error::Failed)?;
    std::fs::write(share.join("desktop-size"), format!("{preferred_size}\n"))
        .map_err(|_| Error::Failed)?;
    Ok(())
}

fn response(id: &str, name: &str, preview: &Preview, code: String, reused: bool) -> Value {
    json!({"agent_id":id, "agent":name, "url":preview.url, "unlock_code":code, "reused":reused})
}

pub(crate) async fn present(listener_name: String) -> Result<Value, Error> {
    if !valid_agent_id(&listener_name) {
        return Err(Error::Failed);
    }
    if !available() {
        return Err(Error::Unavailable);
    }
    let agents = tokio::task::spawn_blocking(host_agents::list)
        .await
        .map_err(|_| Error::Failed)?
        .map_err(|_| Error::Failed)?;
    let agent = agents
        .iter()
        .find(|agent| agent.id == listener_name)
        .or_else(|| agents.iter().find(|agent| agent.name == listener_name))
        .cloned()
        .ok_or(Error::NotFound)?;
    let id = agent.id;
    let name = agent.name;
    let mut presentations = PRESENTATIONS.lock().await;
    if let Some(presentation) = presentations.get_mut(&id) {
        if presentation.preview.is_running() {
            let code = presentation.preview.issue_unlock_code().await;
            return Ok(response(&id, &name, &presentation.preview, code, true));
        }
    }
    if let Some(mut presentation) = presentations.remove(&id) {
        presentation.preview.close().await;
    }
    if !host_platform::is_sandbox_running(&name).await {
        return Err(Error::Failed);
    }
    let (preferred_size, host_port) = settings()?;
    let geometry = geometry(&preferred_size)?;
    stage_guest_desktop(&name, &preferred_size)?;
    let tailnet = if std::env::var("SAFEYOLO_COMMAND_CENTRE_SHARE").as_deref() == Ok("tailnet") {
        let name = name.clone();
        Some(
            tokio::task::spawn_blocking(move || host_agents::reserve_tailnet_port(&name))
                .await
                .map_err(|_| Error::Failed)?
                .map_err(|_| Error::Failed)?,
        )
    } else {
        None
    };
    let already_ready = matches!(
        host_platform::exec_guest_command(&name, "/safeyolo/guest-desktop status >/dev/null 2>&1")
            .await,
        Ok(0)
    );
    let started = host_platform::exec_guest_command(
        &name,
        &format!("SAFEYOLO_PREVIEW_MANAGED=1 /safeyolo/guest-desktop start {geometry}"),
    )
    .await;
    let preview = if matches!(started, Ok(0)) {
        Preview::start(&name, host_port, tailnet.map(|(port, _)| port))
            .await
            .map_err(|_| Error::Failed)
    } else {
        Err(Error::Failed)
    };
    let preview = match preview {
        Ok(preview) => preview,
        Err(error) => {
            // Preserve an already-running desktop. Only the guest newly
            // started by this attempt needs rollback when preview setup fails.
            if !already_ready {
                let _ = host_platform::exec_guest_command(
                    &name,
                    "/safeyolo/guest-desktop stop >/dev/null 2>&1",
                )
                .await;
            }
            if let Some((port, previous)) = tailnet
                && previous != Some(port)
            {
                let name = name.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    host_agents::restore_tailnet_port(&name, port, previous)
                })
                .await;
            }
            return Err(error);
        }
    };
    let code = preview.unlock_code().await;
    let result = response(&id, &name, &preview, code, false);
    presentations.insert(id, Presentation { preview });
    Ok(result)
}

pub(crate) async fn shutdown() {
    let sessions = std::mem::take(&mut *PRESENTATIONS.lock().await);
    for (_, mut presentation) in sessions {
        presentation.preview.close().await;
    }
}

pub(crate) fn abort() {
    if let Ok(mut presentations) = PRESENTATIONS.try_lock() {
        presentations.clear();
    }
}
