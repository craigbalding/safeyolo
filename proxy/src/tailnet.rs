//! One foreground Tailscale Serve mapping owned by the native proxy.

use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use tokio::process::{Child, Command};

use crate::Error;

fn contains_exact(value: &Value, target: &str) -> bool {
    match value {
        Value::String(value) => value == target,
        Value::Array(values) => values.iter().any(|value| contains_exact(value, target)),
        Value::Object(values) => values.values().any(|value| contains_exact(value, target)),
        _ => false,
    }
}

fn configurations(status: &Value) -> Vec<&Value> {
    let mut values = vec![status];
    if let Some(foreground) = status.get("Foreground").and_then(Value::as_object) {
        values.extend(foreground.values().filter(|value| value.is_object()));
    }
    values
}

fn port_in_use(status: &Value, port: u16) -> bool {
    configurations(status).iter().any(|config| {
        config
            .get("TCP")
            .and_then(Value::as_object)
            .is_some_and(|tcp| tcp.contains_key(&port.to_string()))
    })
}

fn mapping_ready(status: &Value, port: u16, target: &str) -> bool {
    configurations(status).iter().any(|config| {
        config
            .get("TCP")
            .and_then(Value::as_object)
            .is_some_and(|tcp| tcp.contains_key(&port.to_string()))
            && config
                .get("Web")
                .is_some_and(|web| contains_exact(web, target))
    })
}

async fn tailscale_json(args: &[&str]) -> Result<Value, Error> {
    let output = tokio::time::timeout(
        Duration::from_secs(8),
        Command::new("tailscale").args(args).output(),
    )
    .await
    .map_err(|_| format!("tailscale {} timed out", args.join(" ")))??;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(if output.stderr.is_empty() {
            &output.stdout
        } else {
            &output.stderr
        });
        return Err(format!("tailscale {} failed: {}", args.join(" "), detail.trim()).into());
    }
    let value: Value = serde_json::from_slice(&output.stdout)?;
    if value.is_null() && args == ["serve", "status", "--json"] {
        return Ok(json!({}));
    }
    if !value.is_object() {
        return Err(format!("tailscale {} returned unexpected JSON", args.join(" ")).into());
    }
    Ok(value)
}

pub(crate) async fn preflight(port: u16) -> Result<String, Error> {
    if port == 0 {
        return Err("tailnet HTTPS port must be 1-65535".into());
    }
    let status = tailscale_json(&["status", "--json"]).await?;
    if status.get("BackendState").and_then(Value::as_str) != Some("Running") {
        return Err("Tailscale is not connected".into());
    }
    let name = status
        .get("Self")
        .and_then(|value| value.get("DNSName"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim_end_matches('.');
    if name.is_empty() {
        return Err("Tailscale status did not report a MagicDNS name".into());
    }
    let serve = tailscale_json(&["serve", "status", "--json"]).await?;
    if port_in_use(&serve, port) {
        return Err(format!(
            "tailnet HTTPS port {port} already has a Tailscale Serve mapping; choose another port"
        )
        .into());
    }
    Ok(name.to_owned())
}

pub(crate) struct Session {
    child: Child,
    dns_name: String,
    exposed_port: u16,
}

impl Session {
    pub(crate) async fn start(local_port: u16, exposed_port: u16) -> Result<Self, Error> {
        let dns_name = preflight(exposed_port).await?;
        let target = format!("http://127.0.0.1:{local_port}");
        let output = tempfile::tempfile()?;
        let mut child = Command::new("tailscale")
            .args([
                "serve",
                "--yes",
                &format!("--https={exposed_port}"),
                &target,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(output.try_clone()?))
            .kill_on_drop(true)
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(15);
        let result = loop {
            if let Some(status) = child.try_wait()? {
                let mut diagnostic = output.try_clone()?;
                diagnostic.seek(SeekFrom::Start(0))?;
                let mut detail = String::new();
                diagnostic.take(4096).read_to_string(&mut detail)?;
                break Err(format!(
                    "Tailscale Serve exited with code {status}: {}",
                    detail.trim()
                )
                .into());
            }
            let status = match tailscale_json(&["serve", "status", "--json"]).await {
                Ok(status) => status,
                Err(error) => break Err(error),
            };
            if mapping_ready(&status, exposed_port, &target) {
                break Ok(());
            }
            if Instant::now() >= deadline {
                break Err(format!(
                    "Tailscale Serve did not publish HTTPS port {exposed_port} within 15s"
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        };
        if let Err(error) = result {
            stop_child(&mut child).await;
            return Err(error);
        }
        Ok(Self {
            child,
            dns_name,
            exposed_port,
        })
    }

    pub(crate) fn url(&self, path: &str) -> String {
        let authority = if self.exposed_port == 443 {
            self.dns_name.clone()
        } else {
            format!("{}:{}", self.dns_name, self.exposed_port)
        };
        format!("https://{authority}{path}")
    }

    pub(crate) fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    pub(crate) fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    pub(crate) fn is_running(&mut self) -> bool {
        self.child.try_wait().ok().flatten().is_none()
    }

    pub(crate) async fn stop(&mut self) {
        stop_child(&mut self.child).await;
    }
}

async fn stop_child(child: &mut Child) {
    if let Some(pid) = child.id() {
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        if tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .is_ok()
        {
            return;
        }
        let _ = child.kill().await;
    }
}

pub(crate) fn write_state(path: &Path, state: &Value) -> Result<(), Error> {
    let parent = path.parent().ok_or("Tailnet status path has no parent")?;
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(&mut temporary, state)?;
    temporary.write_all(b"\n")?;
    temporary.persist(path)?;
    Ok(())
}
