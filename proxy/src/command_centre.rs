//! Installed host identity, agent operations, and explicit Tailnet publication.
//! The native Admin listener authenticates and validates requests before these
//! fixed host commands can run. None of these helpers handles proxy traffic.

use std::path::PathBuf;

use serde_json::Value;
use tokio::sync::oneshot;

use crate::Error;

#[derive(Clone)]
pub(crate) struct Host {
    cli_python: Option<PathBuf>,
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
    pub(crate) fn from_config(config: &crate::Config) -> Result<Option<Self>, Error> {
        let Some(settings) = &config.native_settings else {
            return Self::from_env();
        };
        let centre = &settings.command_centre;
        if !centre.enabled {
            return Ok(None);
        }
        if centre.events_port == 0 {
            return Err("command_centre.events_port must be nonzero".into());
        }
        let tailnet = match centre.share.as_str() {
            "local" => None,
            "tailnet" => {
                if centre.tailnet_admin_port == 0
                    || centre.tailnet_events_port == 0
                    || centre.tailnet_admin_port == centre.tailnet_events_port
                {
                    return Err("command_centre Tailnet ports must be nonzero and distinct".into());
                }
                Some(Tailnet {
                    admin_port: centre.tailnet_admin_port,
                    events_port: centre.tailnet_events_port,
                    state_file: config.data_dir().join("command-centre-tailnet-status.json"),
                })
            }
            _ => return Err("command_centre.share must be local or tailnet".into()),
        };
        let host = Self {
            cli_python: None,
            user: std::env::var("USER").ok(),
            instance_file: config.data_dir().join("instance_id"),
            events_port: Some(centre.events_port),
            tailnet,
        };
        host.instance_id()?;
        Ok(Some(host))
    }

    pub(crate) fn from_env() -> Result<Option<Self>, Error> {
        let Some(_) = std::env::var_os("SAFEYOLO_OPERATOR_INSTANCE_ID_FILE") else {
            if std::env::var_os("SAFEYOLO_COMMAND_CENTRE_EVENTS_PORT").is_some()
                || std::env::var_os("SAFEYOLO_COMMAND_CENTRE_TAILNET_ADMIN_PORT").is_some()
            {
                return Err("Command Centre events require an installed instance identity".into());
            }
            return Ok(None);
        };
        // This is only an informational field for clients that explicitly
        // launch the separate Python CLI. Native proxy operations never use it.
        let cli_python = std::env::var_os("SAFEYOLO_CLI_PYTHON").map(PathBuf::from);
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
            cli_python,
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
        self.cli_python
            .as_ref()
            .and_then(|path| path.to_str())
            .unwrap_or_default()
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
        crate::host_lifecycle::operate(operation, agent_id).await
    }
}

pub(crate) struct Publication {
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
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
        let state_file = tailnet.state_file.clone();
        let mut admin = match crate::tailnet::Session::start(admin_local, tailnet.admin_port).await
        {
            Ok(admin) => admin,
            Err(error) => {
                let _ = crate::tailnet::write_state(
                    &state_file,
                    &serde_json::json!({
                        "state":"error", "enabled":true, "detail":error.to_string()
                    }),
                );
                return Err(error);
            }
        };
        let mut events =
            match crate::tailnet::Session::start(events_local, tailnet.events_port).await {
                Ok(events) => events,
                Err(error) => {
                    admin.stop().await;
                    let _ = crate::tailnet::write_state(
                        &state_file,
                        &serde_json::json!({
                            "state":"error", "enabled":true, "detail":error.to_string()
                        }),
                    );
                    return Err(error);
                }
            };
        let admin_url = admin.url("/");
        let events_url = events
            .url("/admin/events")
            .replacen("https://", "wss://", 1);
        if let Err(error) = crate::tailnet::write_state(
            &state_file,
            &serde_json::json!({
                "state":"healthy", "enabled":true,
                "admin_port":tailnet.admin_port, "events_port":tailnet.events_port,
                "admin_url":admin_url, "events_url":events_url,
                "admin_pid":admin.pid(), "events_pid":events.pid()
            }),
        ) {
            events.stop().await;
            admin.stop().await;
            return Err(error);
        }
        let (shutdown, receiver) = oneshot::channel();
        let watched_state = state_file.clone();
        let task = tokio::spawn(async move {
            tokio::select! {
                _ = receiver => {
                    events.stop().await;
                    admin.stop().await;
                    let _ = std::fs::remove_file(&watched_state);
                }
                result = admin.child_mut().wait() => {
                    events.stop().await;
                    let _ = crate::tailnet::write_state(&watched_state, &serde_json::json!({
                        "state":"error", "enabled":true,
                        "detail":format!("Command Centre admin Tailnet mapping exited: {result:?}")
                    }));
                }
                result = events.child_mut().wait() => {
                    admin.stop().await;
                    let _ = crate::tailnet::write_state(&watched_state, &serde_json::json!({
                        "state":"error", "enabled":true,
                        "detail":format!("Command Centre events Tailnet mapping exited: {result:?}")
                    }));
                }
            }
        });
        Ok(Some(Self {
            shutdown: Some(shutdown),
            task,
        }))
    }

    pub(crate) async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = (&mut self.task).await;
    }
}

impl Drop for Publication {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}
