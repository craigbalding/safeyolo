//! Installed host identity, agent operations, and explicit Tailnet publication.
//! The native Admin listener authenticates and validates requests before these
//! fixed host commands can run. None of these helpers handles proxy traffic.

use std::{path::PathBuf, process::Stdio};

use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, ChildStdin, Command},
};

use crate::Error;

#[derive(Clone)]
pub(crate) struct Host {
    python: PathBuf,
    user: Option<String>,
    instance_file: PathBuf,
    events_port: Option<u16>,
    tailnet: Option<Tailnet>,
}

#[derive(Clone)]
struct Tailnet {
    admin_port: u16,
    events_port: u16,
    state_file: PathBuf,
}

fn env_port(name: &str) -> Result<Option<u16>, Error> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let port = value.to_string_lossy().parse::<u16>()?;
    if port == 0 {
        return Err(format!("{name} must be a nonzero port").into());
    }
    Ok(Some(port))
}

fn env_path(name: &str) -> Result<PathBuf, Error> {
    let path = std::env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{name} is required for the installed Command Centre"))?;
    if !path.is_absolute() {
        return Err(format!("{name} must be an absolute path").into());
    }
    Ok(path)
}

impl Host {
    pub(crate) fn from_env() -> Result<Option<Self>, Error> {
        let Some(python) = std::env::var_os("SAFEYOLO_OPERATOR_HOST_PYTHON") else {
            if std::env::var_os("SAFEYOLO_COMMAND_CENTRE_EVENTS_PORT").is_some()
                || std::env::var_os("SAFEYOLO_COMMAND_CENTRE_TAILNET_ADMIN_PORT").is_some()
            {
                return Err("Command Centre events require the installed host helper".into());
            }
            return Ok(None);
        };
        let python = PathBuf::from(python);
        if !python.is_absolute() || !python.is_file() {
            return Err("SAFEYOLO_OPERATOR_HOST_PYTHON must name an installed interpreter".into());
        }
        let user = std::env::var("SAFEYOLO_OPERATOR_HOST_USER")
            .ok()
            .filter(|value| !value.is_empty());
        let instance_file = env_path("SAFEYOLO_OPERATOR_INSTANCE_ID_FILE")?;
        let events_port = env_port("SAFEYOLO_COMMAND_CENTRE_EVENTS_PORT")?;
        let tailnet = match env_port("SAFEYOLO_COMMAND_CENTRE_TAILNET_ADMIN_PORT")? {
            Some(admin_port) => {
                let events_port = env_port("SAFEYOLO_COMMAND_CENTRE_TAILNET_EVENTS_PORT")?
                    .ok_or("Tailnet event port is required")?;
                if admin_port == events_port {
                    return Err("Command Centre Tailnet ports must differ".into());
                }
                Some(Tailnet {
                    admin_port,
                    events_port,
                    state_file: env_path("SAFEYOLO_COMMAND_CENTRE_TAILNET_STATUS_FILE")?,
                })
            }
            None => None,
        };
        if tailnet.is_some() && events_port.is_none() {
            return Err("Command Centre events must be enabled for Tailnet publication".into());
        }
        Ok(Some(Self {
            python,
            user,
            instance_file,
            events_port,
            tailnet,
        }))
    }

    pub(crate) fn events_port(&self) -> Option<u16> {
        self.events_port
    }

    pub(crate) fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    pub(crate) fn python(&self) -> &str {
        self.python.to_str().unwrap_or_default()
    }

    pub(crate) fn instance_id(&self) -> Result<String, Error> {
        let source = std::fs::read_to_string(&self.instance_file)?;
        let id = source.trim();
        if id.len() != 35
            || !id.starts_with("sy-")
            || !id[3..].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("durable SafeYolo instance identity is invalid".into());
        }
        Ok(id.to_owned())
    }

    pub(crate) async fn agents(
        &self,
        operation: &str,
        agent_id: Option<&str>,
    ) -> Result<Value, Error> {
        let python = self.python.clone();
        let arguments = match agent_id {
            Some(agent_id) => vec![operation.to_owned(), agent_id.to_owned()],
            None => vec![operation.to_owned()],
        };
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(python)
                .args(["-m", "safeyolo.command_centre_agent_host"])
                .args(arguments)
                .stdin(Stdio::null())
                .stderr(Stdio::inherit())
                .output()
        })
        .await??;
        if !output.status.success() || output.stdout.len() > 1024 * 1024 {
            return Err("Command Centre agent host helper failed".into());
        }
        let value: Value = serde_json::from_slice(&output.stdout)?;
        if let Some(agent_id) = agent_id {
            if value.get("status_code").is_none()
                && value.get("agent_id").and_then(Value::as_str) != Some(agent_id)
            {
                return Err("Command Centre agent helper returned another identity".into());
            }
        } else if !value.get("agents").is_some_and(Value::is_array)
            && value.get("status_code").is_none()
        {
            return Err("Command Centre agent helper returned an invalid inventory".into());
        }
        Ok(value)
    }
}

pub(crate) struct Publication {
    child: Child,
    input: Option<ChildStdin>,
}

impl Publication {
    pub(crate) async fn start(
        host: &Host,
        admin_local: u16,
        events_local: u16,
    ) -> Result<Option<Self>, Error> {
        let Some(tailnet) = &host.tailnet else {
            return Ok(None);
        };
        let mut child = Command::new(&host.python)
            .args(["-m", "safeyolo.command_centre_tailnet_host"])
            .args([
                admin_local.to_string(),
                events_local.to_string(),
                tailnet.admin_port.to_string(),
                tailnet.events_port.to_string(),
                tailnet.state_file.to_string_lossy().into_owned(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = child
            .stdin
            .take()
            .ok_or("Tailnet publisher has no stop channel")?;
        let output = child
            .stdout
            .take()
            .ok_or("Tailnet publisher has no readiness channel")?;
        let mut output = BufReader::new(output);
        let mut line = String::new();
        let ready = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            output.read_line(&mut line),
        )
        .await;
        let result = match ready {
            Ok(Ok(size)) if size > 0 && line.len() <= 4096 => {
                serde_json::from_str::<Value>(&line).ok()
            }
            _ => None,
        };
        if result
            .as_ref()
            .and_then(|value| value.get("state"))
            .and_then(Value::as_str)
            != Some("healthy")
        {
            drop(input);
            let _ = tokio::time::timeout(std::time::Duration::from_secs(12), child.wait()).await;
            return Err(format!(
                "Command Centre Tailnet publication failed: {}",
                result
                    .as_ref()
                    .and_then(|value| value.get("detail"))
                    .and_then(Value::as_str)
                    .unwrap_or("publisher did not confirm both mappings")
            )
            .into());
        }
        Ok(Some(Self {
            child,
            input: Some(input),
        }))
    }

    pub(crate) async fn stop(mut self) {
        self.input.take();
        if tokio::time::timeout(std::time::Duration::from_secs(15), self.child.wait())
            .await
            .is_err()
        {
            let _ = self.child.kill().await;
        }
    }
}
