//! Native owner of operator desktop presentations.

use std::{collections::BTreeMap, io::Write, os::unix::fs::PermissionsExt, sync::LazyLock};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::{desktop_preview::Preview, host_agents, host_platform};

#[derive(Debug)]
pub(crate) enum Error {
    Unavailable,
    NotFound,
    Failed,
    Preview(crate::Error),
}

/// Only guest browser navigation and preview lifetime are agent-selectable.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Parameters {
    pub(crate) browser_url: Option<String>,
    pub(crate) ttl_seconds: u32,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            browser_url: None,
            ttl_seconds: 900,
        }
    }
}

impl Parameters {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if !(1..=86400).contains(&self.ttl_seconds) {
            return Err("ttl_seconds must be an integer from 1 to 86400");
        }
        if let Some(url) = &self.browser_url {
            if url == "about:blank" {
                return Ok(());
            }
            let parsed = url.parse::<hyper::Uri>();
            if url.len() > 8192
                || url.chars().any(|c| c.is_control() || c.is_whitespace())
                || url.contains('\\')
                || parsed.as_ref().is_err()
                || parsed.as_ref().is_ok_and(|uri| {
                    !matches!(uri.scheme_str(), Some("http" | "https"))
                        || uri.host().is_none_or(str::is_empty)
                        || uri.authority().is_some_and(|a| a.as_str().contains('@'))
                })
            {
                return Err(
                    "browser_url must be an absolute HTTP or HTTPS URL without credentials, or about:blank",
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Route {
    Local,
    Tailnet,
}

#[derive(Debug)]
pub(crate) struct Diagnostic {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
}

impl Diagnostic {
    pub(crate) fn json(&self) -> Value {
        json!({"code":self.code,"message":self.message,"graph":"triage-desktop-preview"})
    }
}

fn diagnostic(code: &'static str, message: &'static str) -> Diagnostic {
    Diagnostic { code, message }
}

fn executable(program: &str) -> bool {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).any(|path| {
        std::fs::metadata(path.join(program))
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    })
}

pub(crate) async fn action_route() -> Result<Route, Diagnostic> {
    let settings = crate::native_config::host_settings().map_err(|_| {
        diagnostic(
            "host_settings_unavailable",
            "The host desktop settings are unavailable.",
        )
    })?;
    if settings.command_centre.share == "tailnet" {
        crate::tailnet::available()
            .await
            .map_err(|error| tailnet_diagnostic(&error.to_string()))?;
        return Ok(Route::Tailnet);
    }
    #[cfg(target_os = "linux")]
    let local = executable("xdg-open") && display_size().await.is_some();
    #[cfg(target_os = "macos")]
    let local = executable("open") && main_display_size().is_some();
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let local = false;
    if local {
        Ok(Route::Local)
    } else {
        Err(diagnostic(
            "operator_preview_path_unavailable",
            "No usable local display/opener or configured tailnet preview path is available. The operator must configure a presentation path on the SafeYolo host.",
        ))
    }
}

fn tailnet_diagnostic(error: &str) -> Diagnostic {
    let error = error.to_ascii_lowercase();
    if error.contains("permission")
        || error.contains("access denied")
        || error.contains("not permitted")
    {
        diagnostic(
            "tailnet_serve_permission",
            "This host user cannot manage Tailscale Serve. The operator must configure Serve permission; SafeYolo did not run privileged setup.",
        )
    } else if error.contains("no such file") {
        diagnostic(
            "tailscale_missing",
            "Tailscale is not installed on the SafeYolo host. Configure the existing tailnet preview route before requesting it.",
        )
    } else if error.contains("not connected") {
        diagnostic(
            "tailscale_disconnected",
            "Tailscale is not connected on the SafeYolo host.",
        )
    } else {
        diagnostic(
            "tailnet_preview_unavailable",
            "Tailscale Serve could not provide the preview. Check the host's Tailscale connection, HTTPS configuration, Serve permission and assigned HTTPS port.",
        )
    }
}

pub(crate) async fn action_prerequisites(name: &str) -> Result<Route, Diagnostic> {
    let route = action_route().await?;
    if !host_platform::guest_exec_available(name).await {
        return Err(diagnostic(
            "sandbox_unavailable",
            "The requesting agent's sandbox is not ready. Inspect its desktop/runtime diagnostics.",
        ));
    }
    if !matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(8),
            desktop_command_status(name, "/safeyolo/guest-desktop check >/dev/null 2>&1")
        )
        .await,
        Ok(Ok(0))
    ) {
        return Err(diagnostic(
            "desktop_missing",
            "The guest desktop capability is missing or not ready. Run /safeyolo/guest-desktop check in this agent and use the desktop preview graph.",
        ));
    }
    Ok(route)
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

fn stage_guest_desktop(name: &str, geometry: &str) -> Result<(), Error> {
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
    std::fs::write(share.join("desktop-size"), format!("{geometry}\n"))
        .map_err(|_| Error::Failed)?;
    Ok(())
}

fn response(id: &str, name: &str, preview: &Preview, code: String, reused: bool) -> Value {
    json!({"agent_id":id, "agent":name, "url":preview.url, "unlock_code":code, "reused":reused})
}

async fn desktop_command_status(name: &str, command: &str) -> std::io::Result<i32> {
    // Captured commands have kill-on-drop on both supported host platforms.
    // Discard their output without accumulating guest-controlled bytes.
    let mut child =
        host_platform::spawn_guest_command_with_output(name, command, true, false).await?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("missing desktop output"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("missing desktop error output"))?;
    let mut output_sink = tokio::io::sink();
    let mut error_sink = tokio::io::sink();
    let (status, _, _) = tokio::try_join!(
        child.wait(),
        tokio::io::copy(&mut stdout, &mut output_sink),
        tokio::io::copy(&mut stderr, &mut error_sink)
    )?;
    Ok(status.code().unwrap_or(1))
}

pub(crate) async fn present(agent_id: String, allow_listener_name: bool) -> Result<Value, Error> {
    let mut presentations = PRESENTATIONS.lock().await;
    present_locked(agent_id, allow_listener_name, &mut presentations, None)
        .await
        .map(|(result, _)| result)
}

async fn present_locked(
    agent_id: String,
    allow_listener_name: bool,
    presentations: &mut BTreeMap<String, Presentation>,
    route: Option<Route>,
) -> Result<(Value, bool), Error> {
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
    if let Some(presentation) = presentations.get_mut(&id)
        && presentation.preview.is_running()
    {
        if route.is_some_and(|route| (route == Route::Tailnet) != presentation.preview.is_tailnet())
        {
            return Err(Error::Failed);
        }
        let code = presentation.preview.issue_unlock_code().await;
        return Ok((
            response(&id, &name, &presentation.preview, code, true),
            false,
        ));
    }
    if let Some(mut presentation) = presentations.remove(&id) {
        presentation.preview.close().await;
    }
    let guest_available = host_platform::guest_exec_available(&name).await;
    let (preferred_size, host_port) = settings()?;
    let geometry = geometry(&preferred_size).await?;
    stage_guest_desktop(&name, &geometry)?;
    let share_tailnet = match route {
        Some(route) => route == Route::Tailnet,
        None => {
            crate::native_config::host_settings()
                .map_err(|_| Error::Failed)?
                .command_centre
                .share
                == "tailnet"
        }
    };
    let tailnet = if share_tailnet {
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
    let already_ready = guest_available
        && matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                desktop_command_status(&name, "/safeyolo/guest-desktop status >/dev/null 2>&1")
            )
            .await,
            Ok(Ok(0))
        );
    // The explicit presentation action retains initial desktop startup. The
    // diagnostic page and later retries never start or repair an agent/service.
    let desktop_absent = guest_available
        && !already_ready
        && crate::desktop_diagnostics::guest_check(&name).await["tcp"] == "refused";
    let started = if desktop_absent {
        tokio::time::timeout(
            std::time::Duration::from_secs(35),
            desktop_command_status(
                &name,
                &format!("SAFEYOLO_PREVIEW_MANAGED=1 /safeyolo/guest-desktop start {geometry}"),
            ),
        )
        .await
    } else {
        Ok(Err(std::io::Error::other("runtime unavailable")))
    };
    let preview = Preview::start(&name, &id, host_port, tailnet.map(|(port, _)| port))
        .await
        .map_err(Error::Preview);
    let preview = match preview {
        Ok(preview) => preview,
        Err(error) => {
            // Preserve an already-running desktop. Only the guest newly
            // started by this attempt needs rollback when preview setup fails.
            if !already_ready && matches!(started, Ok(Ok(0))) {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(8),
                    desktop_command_status(&name, "/safeyolo/guest-desktop stop >/dev/null 2>&1"),
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
    Ok((result, !already_ready && matches!(started, Ok(Ok(0)))))
}

/// The approved action uses the same preview, guest launcher and access gate.
pub(crate) async fn present_action(
    agent_id: &str,
    parameters: &Parameters,
    route: Route,
    approval_id: &str,
) -> Result<Value, Diagnostic> {
    parameters
        .validate()
        .map_err(|message| diagnostic("invalid_parameters", message))?;
    if action_route().await? != route {
        return Err(diagnostic(
            "presentation_changed",
            "The host presentation path changed. Request a new preview approval.",
        ));
    }
    let agents = host_agents::list().map_err(|_| {
        diagnostic(
            "agent_unavailable",
            "The host agent registry is unavailable.",
        )
    })?;
    let agent = host_agents::by_id(&agents, agent_id)
        .ok()
        .flatten()
        .ok_or_else(|| {
            diagnostic(
                "agent_unavailable",
                "The requesting agent was removed or replaced.",
            )
        })?;
    action_prerequisites(&agent.name).await?;
    let mut presentations = PRESENTATIONS.lock().await;
    let (result, guest_started) = present_locked(agent_id.to_owned(), false, &mut presentations, Some(route)).await.map_err(|error| match error {
        Error::Preview(error) if route == Route::Tailnet => tailnet_diagnostic(&error.to_string()),
        _ => diagnostic("desktop_presentation_failed", "The managed desktop preview could not start. Inspect this agent's desktop diagnostics."),
    })?;
    let name = &agent.name;
    let operation = async {
        if !matches!(tokio::time::timeout(std::time::Duration::from_secs(8), desktop_command_status(name, "/safeyolo/guest-desktop status >/dev/null 2>&1")).await, Ok(Ok(0))) {
            return Err(diagnostic("desktop_not_ready", "The guest desktop did not become ready. Run /safeyolo/guest-desktop status and use the desktop preview graph."));
        }
        if let Some(url) = &parameters.browser_url {
            let command = format!("/safeyolo/guest-desktop browser '{}'", url.replace('\'', "'\\''"));
            if !matches!(tokio::time::timeout(std::time::Duration::from_secs(8), desktop_command_status(name, &command)).await, Ok(Ok(0))) {
                return Err(diagnostic("browser_unavailable", "The guest browser could not start. Check the browser capability and /tmp/chrome.log in this agent."));
            }
        }
        if route == Route::Local {
            #[cfg(target_os = "macos")]
            let program = "open";
            #[cfg(not(target_os = "macos"))]
            let program = "xdg-open";
            let opened = tokio::time::timeout(std::time::Duration::from_secs(8),
                tokio::process::Command::new(program).arg(result["url"].as_str().unwrap_or_default())
                    .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
                    .kill_on_drop(true).status()).await;
            if !matches!(opened, Ok(Ok(status)) if status.success()) {
                return Err(diagnostic("local_opener_failed", "The local browser opener failed. Check the SafeYolo host's desktop and default browser."));
            }
        }
        Ok(())
    }.await;
    if let Err(error) = operation {
        if result["reused"] == false
            && let Some(mut presentation) = presentations.remove(agent_id)
        {
            presentation.preview.close().await;
        }
        if guest_started {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(8),
                desktop_command_status(name, "/safeyolo/guest-desktop stop >/dev/null 2>&1"),
            )
            .await;
        }
        return Err(error);
    }
    let presentation = presentations.get_mut(agent_id).ok_or_else(|| {
        diagnostic(
            "preview_closed",
            "The preview closed before the action completed.",
        )
    })?;
    presentation.preview.expire_after(
        std::time::Duration::from_secs(parameters.ttl_seconds.into()),
        approval_id,
    );
    let expires_at = (time::OffsetDateTime::now_utc()
        + time::Duration::seconds(parameters.ttl_seconds.into()))
    .format(&time::format_description::well_known::Rfc3339)
    .expect("valid preview expiry");
    let mut result = result;
    result["expires_at"] = json!(expires_at);
    result["presentation"] = json!(route);
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
