//! Native owner of operator desktop presentations.

use std::{collections::BTreeMap, io::Write, os::unix::fs::PermissionsExt, sync::LazyLock};

use regex::Regex;
use serde_json::{Value, json};
use tokio::sync::Mutex;

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
    let desktop = crate::native_config::host_settings()
        .map_err(|_| Error::Failed)?
        .desktop;
    Ok((desktop.size, desktop.present_host_port))
}

fn parse_geometry(value: &str) -> Result<(u32, u32), Error> {
    let (width, height) = value.split_once('x').ok_or(Error::Failed)?;
    if !(3..=5).contains(&width.len())
        || !(3..=5).contains(&height.len())
        || !width.bytes().all(|byte| byte.is_ascii_digit())
        || !height.bytes().all(|byte| byte.is_ascii_digit())
        || width.starts_with('0')
        || height.starts_with('0')
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

fn geometry_in_text(value: &str) -> Option<(u32, u32)> {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"([1-9][0-9]{2,4})\s*x\s*([1-9][0-9]{2,4})").expect("valid display pattern")
    });
    PATTERN
        .captures_iter(value)
        .filter_map(|captures| {
            Some((
                captures.get(1)?.as_str().parse::<u32>().ok()?,
                captures.get(2)?.as_str().parse::<u32>().ok()?,
            ))
        })
        .max_by_key(|(width, height)| width * height)
}

#[cfg(target_os = "macos")]
fn main_display_size() -> Option<(u32, u32)> {
    #[repr(C)]
    struct Point {
        x: f64,
        y: f64,
    }
    #[repr(C)]
    struct Size {
        width: f64,
        height: f64,
    }
    #[repr(C)]
    struct Rect {
        origin: Point,
        size: Size,
    }
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGMainDisplayID() -> u32;
        fn CGDisplayBounds(display: u32) -> Rect;
    }
    let bounds = unsafe { CGDisplayBounds(CGMainDisplayID()) };
    let width = bounds.size.width as u32;
    let height = bounds.size.height as u32;
    (width >= 640 && height >= 480).then_some((width, height))
}

async fn display_size() -> Option<(u32, u32)> {
    #[cfg(target_os = "macos")]
    if let Some(size) = main_display_size() {
        return Some(size);
    }
    #[cfg(target_os = "macos")]
    let commands: &[(&str, &[&str], u64)] =
        &[("system_profiler", &["SPDisplaysDataType", "-json"], 8)];
    #[cfg(target_os = "linux")]
    let commands: &[(&str, &[&str], u64)] = &[("xdpyinfo", &[], 3), ("xrandr", &["--current"], 3)];
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let commands: &[(&str, &[&str], u64)] = &[];
    for (program, args, seconds) in commands {
        let Some(output) = tokio::time::timeout(
            std::time::Duration::from_secs(*seconds),
            tokio::process::Command::new(program).args(*args).output(),
        )
        .await
        .ok()
        .and_then(Result::ok) else {
            continue;
        };
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            if let Some(size) = geometry_in_text(&text) {
                return Some(size);
            }
        }
    }
    None
}

async fn geometry(size: &str) -> Result<String, Error> {
    let size = size.trim().to_ascii_lowercase();
    if size != "auto" {
        let (width, height) = parse_geometry(&size)?;
        return Ok(format!("{width}x{height}"));
    }
    let display = if let Ok(value) = std::env::var("SAFEYOLO_PREVIEW_SCREEN_SIZE") {
        Some(parse_geometry(&value)?)
    } else {
        display_size().await
    };
    let Some((width, height)) = display else {
        return Ok("1280x800".into());
    };
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

pub(crate) async fn present(agent_id: String, allow_listener_name: bool) -> Result<Value, Error> {
    if !valid_agent_id(&agent_id) {
        return Err(Error::Failed);
    }
    if !available() {
        return Err(Error::Unavailable);
    }
    let agents = host_agents::list().map_err(|_| Error::Failed)?;
    let agent = host_agents::by_id(&agents, &agent_id)
        .map_err(|_| Error::Failed)?
        .or_else(|| {
            allow_listener_name
                .then(|| agents.iter().find(|agent| agent.name == agent_id))
                .flatten()
        })
        .cloned()
        .ok_or(Error::NotFound)?;
    host_agents::by_id(&agents, &agent.id).map_err(|_| Error::Failed)?;
    let id = agent.id;
    let name = agent.name;
    let mut presentations = PRESENTATIONS.lock().await;
    if let Some(presentation) = presentations.get_mut(&id)
        && presentation.preview.is_running()
    {
        let code = presentation.preview.issue_unlock_code().await;
        return Ok(response(&id, &name, &presentation.preview, code, true));
    }
    if let Some(mut presentation) = presentations.remove(&id) {
        presentation.preview.close().await;
    }
    if !host_platform::guest_exec_available(&name).await {
        return Err(Error::Failed);
    }
    let (preferred_size, host_port) = settings()?;
    let geometry = geometry(&preferred_size).await?;
    stage_guest_desktop(&name, &preferred_size)?;
    let tailnet = if crate::native_config::host_settings()
        .map_err(|_| Error::Failed)?
        .command_centre
        .share
        == "tailnet"
    {
        let name = name.clone();
        let config = host_platform::config_path();
        Some(
            tokio::task::spawn_blocking(move || {
                host_platform::with_config(config, || host_agents::reserve_tailnet_port(&name))
            })
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
                let config = host_platform::config_path();
                let _ = tokio::task::spawn_blocking(move || {
                    host_platform::with_config(config, || {
                        host_agents::restore_tailnet_port(&name, port, previous)
                    })
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
