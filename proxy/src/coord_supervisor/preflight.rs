//! Harness checks retained from the supervised Codex/Pi launch contract.
use super::*;
use std::{os::unix::fs::PermissionsExt, process::Stdio};
use toml_edit::{DocumentMut, Item};

fn argument<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().enumerate().find_map(|(index, arg)| {
        if arg == name {
            args.get(index + 1).map(String::as_str)
        } else {
            arg.strip_prefix(&format!("{name}="))
        }
    })
}
fn config_override(args: &[String], key: &str) -> Result<Option<Item>, Error> {
    let mut selected = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        let value = if matches!(arg.as_str(), "-c" | "--config") {
            index += 1;
            args.get(index).map(String::as_str)
        } else {
            arg.strip_prefix("--config=")
        };
        if let Some(value) = value
            && let Some((name, text)) = value.split_once('=')
            && name == key
        {
            let mut document = format!("value={text}").parse::<DocumentMut>().map_err(
                |_| "invalid Codex config; repair the selected configuration or override",
            )?;
            selected = Some(document.remove("value").ok_or("invalid Codex override")?);
        }
        index += 1;
    }
    Ok(selected)
}
async fn output(
    program: &std::ffi::OsStr,
    args: &[&str],
    seconds: u64,
) -> Result<std::process::Output, Error> {
    let mut command = tokio::process::Command::new(program);
    command.args(args).stdin(Stdio::null()).kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(seconds), command.output())
        .await
        .map_err(|_| "harness preflight deadline expired")?
        .map_err(Into::into)
}

pub(super) async fn check(config: &Config, args: &[String]) -> Result<(), Error> {
    let home = PathBuf::from(std::env::var_os("HOME").ok_or("HOME is missing")?);
    if config.harness == "pi" {
        for arg in args {
            let name = arg.split('=').next().unwrap_or("");
            if [
                "--mode",
                "--print",
                "-p",
                "--session",
                "--session-id",
                "--no-session",
                "--continue",
                "-c",
                "--resume",
                "-r",
                "--fork",
                "--no-extensions",
                "-ne",
                "--no-tools",
                "--tools",
                "--exclude-tools",
            ]
            .contains(&name)
            {
                return Err(format!("Pi option {name} is owned by the supervisor").into());
            }
        }
        let pi = std::env::var_os("SAFEYOLO_PI_BIN").unwrap_or_else(|| "pi".into());
        if !output(&pi, &["--version"], 20).await?.status.success() {
            return Err("Pi installation is not runnable".into());
        }
        let provider = argument(args, "--provider");
        let model = argument(args, "--model");
        if provider.is_some() && model.is_none() {
            return Err("Pi --provider requires --model".into());
        }
        if let Some((flag, value)) = provider
            .map(|p| ("--provider", p))
            .or_else(|| model.map(|m| ("--model", m)))
        {
            if !output(&pi, &["auth", "check", flag, value, "--json"], 30)
                .await?
                .status
                .success()
            {
                return Err("Pi is not logged in for its selected provider or model".into());
            }
        } else {
            let metadata = fs::metadata(home.join(".pi/agent/auth.json"))?;
            if !metadata.is_file()
                || metadata.len() == 0
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(
                    "Pi agent-local login file is missing or has unsafe permissions".into(),
                );
            }
        }
        return Ok(());
    }
    let codex_home = std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".codex"));
    let document = fs::read_to_string(codex_home.join("config.toml"))?
        .parse::<DocumentMut>()
        .map_err(|_| "invalid Codex config; repair the selected configuration or override")?;
    let registration = document
        .get("mcp_servers")
        .and_then(|s| s.get("safeyolo-coord"))
        .ok_or("Codex safeyolo-coord MCP registration is missing")?;
    let launcher = Path::new(
        registration
            .get("command")
            .and_then(Item::as_str)
            .ok_or("Codex MCP command is missing")?,
    );
    let metadata = fs::metadata(launcher)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err("Codex Coord MCP launcher is not executable".into());
    }
    if let Some(timeout) = registration.get("tool_timeout_sec") {
        let timeout = timeout
            .as_integer()
            .map(|i| i as f64)
            .or_else(|| timeout.as_float())
            .ok_or("invalid Codex MCP timeout")?;
        if !timeout.is_finite() || timeout <= 0. {
            return Err("Codex MCP timeout must be positive".into());
        }
    }
    if document.get("forced_chatgpt_auth").and_then(Item::as_bool) == Some(false) {
        let profile = if let Some(name) = argument(args, "--profile") {
            if !simple_name(name) {
                return Err("invalid Codex provider profile".into());
            }
            fs::read_to_string(codex_home.join(format!("{name}.config.toml")))?
                .parse::<DocumentMut>()
                .map_err(
                    |_| "invalid Codex config; repair the selected configuration or override",
                )?
        } else {
            DocumentMut::new()
        };
        let provider = config_override(args, "model_provider")?.or_else(|| {
            profile
                .get("model_provider")
                .or_else(|| document.get("model_provider"))
                .cloned()
        });
        let model = config_override(args, "model")?
            .or_else(|| argument(args, "--model").map(toml_edit::value))
            .or_else(|| {
                profile
                    .get("model")
                    .or_else(|| document.get("model"))
                    .cloned()
            });
        let provider = provider
            .as_ref()
            .and_then(Item::as_str)
            .filter(|s| !s.is_empty())
            .ok_or("external Codex launch requires explicit provider and model")?;
        if model
            .as_ref()
            .and_then(Item::as_str)
            .is_none_or(str::is_empty)
        {
            return Err("external Codex launch requires explicit provider and model".into());
        }
        let selected = profile
            .get("model_providers")
            .and_then(|p| p.get(provider))
            .or_else(|| {
                document
                    .get("model_providers")
                    .and_then(|p| p.get(provider))
            });
        let auth = selected
            .and_then(|p| p.get("auth"))
            .ok_or("Codex external provider has no command authentication")?;
        if auth
            .get("command")
            .and_then(Item::as_str)
            .is_none_or(str::is_empty)
            || auth
                .get("args")
                .and_then(Item::as_array)
                .is_none_or(|a| a.iter().any(|v| !v.is_str()))
        {
            return Err("Codex external provider has no command authentication".into());
        }
    } else {
        let codex = std::env::var_os("SAFEYOLO_CODEX_BIN").unwrap_or_else(|| "codex".into());
        let login = output(&codex, &["login", "status"], 20).await?;
        let status = format!(
            "{}{}",
            String::from_utf8_lossy(&login.stdout),
            String::from_utf8_lossy(&login.stderr)
        );
        if !login.status.success() || !status.contains("Logged in using ChatGPT") {
            return Err("Codex is not logged in with a ChatGPT subscription".into());
        }
    }
    Ok(())
}
