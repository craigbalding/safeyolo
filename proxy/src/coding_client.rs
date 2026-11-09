//! Native client configuration and fresh, agent-bound gateway authentication.

use std::{ffi::OsString, os::unix::process::CommandExt, path::Path, time::Duration};

use serde_json::{Value, json};
use toml_edit::{DocumentMut, Item, Table, value};

use crate::{
    Error,
    coord_setup::{directory, read_text, safe},
};

pub const HELP: &str = "safeyolo-coord client-auth HOME codex|claude client|host-vault [--remove-guest-auth]\nsafeyolo-coord client-exec codex|claude -- COMMAND [ARGS...]\nConfiguration runs on the host for a stopped agent. Host-vault selection stores no tokens in configuration. Retained client authentication requires explicit removal or continued client-held use. client-exec fetches a fresh scoped token through the guest's existing Agent API at each launch. It does not retry model requests or unlock storage.";

fn check_client(client: &str) -> Result<(), Error> {
    if !matches!(client, "codex" | "claude") {
        return Err("select codex or claude".into());
    }
    Ok(())
}

fn codex_config(home: &Path) -> Result<DocumentMut, Error> {
    if !safe(&home.join(".codex"), true, None)? {
        return Ok(DocumentMut::new());
    }
    let path = home.join(".codex/config.toml");
    if !safe(&path, false, None)? {
        return Ok(DocumentMut::new());
    }
    read_text(&path)?
        .parse()
        .map_err(|_| "invalid Codex config.toml; repair it before changing authentication".into())
}

fn claude_config(home: &Path) -> Result<Value, Error> {
    if !safe(&home.join(".claude"), true, None)? {
        return Ok(json!({}));
    }
    let path = home.join(".claude/settings.json");
    if !safe(&path, false, None)? {
        return Ok(json!({}));
    }
    let document: Value = serde_json::from_str(&read_text(&path)?)
        .map_err(|_| "invalid Claude settings.json; repair it before changing authentication")?;
    if !document.is_object() || document.get("env").is_some_and(|env| !env.is_object()) {
        return Err("Claude settings and env must be objects".into());
    }
    Ok(document)
}

const CLAUDE_AUTH_ENV: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
];

/// Read names only for diagnostics. Never return authentication contents.
pub fn conflicts(home: &Path, client: &str) -> Result<Vec<String>, Error> {
    check_client(client)?;
    if !safe(
        &home.join(if client == "codex" {
            ".codex"
        } else {
            ".claude"
        }),
        true,
        None,
    )? {
        return Ok(Vec::new());
    }
    let path = if client == "codex" {
        ".codex/auth.json"
    } else {
        ".claude/.credentials.json"
    };
    let mut found = Vec::new();
    match std::fs::symlink_metadata(home.join(path)) {
        Ok(_) => found.push(path.into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if client == "claude" {
        let config = claude_config(home)?;
        if config.get("apiKeyHelper").is_some() {
            found.push("settings.json:apiKeyHelper".into());
        }
        for name in CLAUDE_AUTH_ENV {
            if config["env"].get(name).is_some() {
                found.push(format!("settings.json:env.{name}"));
            }
        }
    }
    Ok(found)
}

pub fn selected(home: &Path, client: &str) -> Result<bool, Error> {
    check_client(client)?;
    Ok(if client == "codex" {
        let config = codex_config(home)?;
        config.get("model_provider").and_then(Item::as_str) == Some("safeyolo")
    } else {
        claude_config(home)?["env"]["SAFEYOLO_CLIENT_AUTH"] == "host-vault"
    })
}

/// Compose the existing configuration owners. An explicit removal applies only
/// to the listed client authentication; other settings and denies survive.
pub fn configure(home: &Path, client: &str, mode: &str, remove: bool) -> Result<(), Error> {
    check_client(client)?;
    if !matches!(mode, "client" | "host-vault") {
        return Err("authentication must be client or host-vault".into());
    }
    safe(home, true, None)?
        .then_some(())
        .ok_or("agent home is missing")?;
    let directory_path = home.join(if client == "codex" {
        ".codex"
    } else {
        ".claude"
    });
    directory(&directory_path)?;
    let conflicts = conflicts(home, client)?;
    if mode == "host-vault" && !conflicts.is_empty() && !remove {
        return Err(format!("retained {client} authentication: {}; keep client-held authentication or explicitly select --remove-guest-auth to remove these inputs", conflicts.join(", ")).into());
    }
    // Validate the whole document before any removal. Never follow a guest
    // authentication symlink or delete a directory while running on the host.
    let auth = directory_path.join(if client == "codex" {
        "auth.json"
    } else {
        ".credentials.json"
    });
    if remove {
        safe(&auth, false, None)?;
    }
    if client == "codex" {
        let mut config = codex_config(home)?;
        if mode == "host-vault" {
            config["forced_chatgpt_auth"] = value(false);
            config["model_provider"] = value("safeyolo");
            if config.get("model_providers").is_none() {
                config["model_providers"] = Item::Table(Table::new());
            }
            let inline = config["model_providers"].as_inline_table().is_some();
            let providers = config["model_providers"]
                .as_table_like_mut()
                .ok_or("Codex model_providers must be a table")?;
            if providers.get("safeyolo").is_none() {
                providers.insert(
                    "safeyolo",
                    if inline {
                        value(toml_edit::InlineTable::new())
                    } else {
                        Item::Table(Table::new())
                    },
                );
            }
            let provider = providers
                .get_mut("safeyolo")
                .unwrap()
                .as_table_like_mut()
                .ok_or("Codex safeyolo provider must be a table")?;
            for (key, text) in [
                ("name", "SafeYolo ChatGPT subscription"),
                ("base_url", "https://chatgpt.com/backend-api/codex"),
                ("env_key", "SAFEYOLO_CODEX_GATEWAY_TOKEN"),
                ("wire_api", "responses"),
            ] {
                provider.insert(key, value(text));
            }
            provider.insert("requires_openai_auth", value(false));
            provider.insert("supports_websockets", value(false));
        } else if config.get("model_provider").and_then(Item::as_str) == Some("safeyolo") {
            config["model_provider"] = value("openai");
            config["forced_chatgpt_auth"] = value(true);
        }
        if remove && mode == "host-vault" && auth.try_exists()? {
            std::fs::remove_file(&auth)?;
        }
        let path = directory_path.join("config.toml");
        crate::coord_supervisor::atomic_write(&path, config.to_string().as_bytes(), 0o600)?;
        // Keep the existing provenance/MCP setup owner authoritative.
        codex_state_after_selection(home, mode)?;
    } else {
        let mut config = claude_config(home)?;
        if config.get("env").is_none() {
            config["env"] = json!({});
        }
        if mode == "host-vault" {
            config.as_object_mut().unwrap().remove("apiKeyHelper");
            let env = config["env"].as_object_mut().unwrap();
            for name in CLAUDE_AUTH_ENV {
                env.remove(*name);
            }
            env.insert("SAFEYOLO_CLIENT_AUTH".into(), json!("host-vault"));
        } else {
            config["env"]
                .as_object_mut()
                .unwrap()
                .remove("SAFEYOLO_CLIENT_AUTH");
        }
        if remove && mode == "host-vault" && auth.try_exists()? {
            std::fs::remove_file(&auth)?;
        }
        crate::guest_commands::write_json(&directory_path.join("settings.json"), &config)?;
    }
    Ok(())
}

fn codex_state_after_selection(home: &Path, mode: &str) -> Result<(), Error> {
    // Explicitly selecting host-vault custody supersedes an old provenance
    // marker, without reading or copying the removed login.
    if mode == "host-vault" {
        crate::coord_setup::codex_state(home, None, false, Some("reset"))?;
    }
    crate::coord_setup::codex_state(home, None, false, None)
}

pub async fn exec(client: &str, command: &[OsString]) -> Result<(), Error> {
    let executable = command
        .first()
        .ok_or("client-exec needs a command after --")?;
    let mut process = std::process::Command::new(executable);
    process.args(&command[1..]);
    authenticate(&mut process, client).await?;
    Err(process.exec().into())
}

/// Both an interactive client launch and a bounded native Codex invocation
/// obtain their own current token. Nothing is delivered into a running client.
pub(crate) async fn authenticate(
    process: &mut std::process::Command,
    client: &str,
) -> Result<(), Error> {
    let home = std::path::PathBuf::from(std::env::var_os("HOME").ok_or("HOME is missing")?);
    if selected(&home, client)? {
        if !conflicts(&home, client)?.is_empty() {
            return Err("retained client authentication needs an explicit host decision; stop the agent and run agent auth NAME, then relaunch".into());
        }
        let mut services = crate::coord_tools::Client::default().request(
            hyper::Method::GET, "/gateway/services", Value::Null, Duration::from_secs(15),
        ).await.map_err(|_| "gateway token unavailable; inspect agent auth NAME --json and pending approvals on the host, then relaunch; no client request was sent")?;
        let token = services["authorized"][client]["token"]
            .as_str()
            .filter(|token| token.starts_with("sgw_") && !token.chars().any(char::is_whitespace))
            .map(crate::credentials::Secret::new);
        crate::credentials::wipe_json(&mut services);
        let token = token.ok_or("selected client service is not authorized; run agent auth NAME on the host, then relaunch")?;
        if client == "codex" {
            for name in ["OPENAI_API_KEY", "CODEX_API_KEY", "OPENAI_BASE_URL"] {
                process.env_remove(name);
            }
            process.env("SAFEYOLO_CODEX_GATEWAY_TOKEN", token.expose_secret());
        } else {
            for name in CLAUDE_AUTH_ENV {
                process.env_remove(name);
            }
            process.env("CLAUDE_CODE_OAUTH_TOKEN", token.expose_secret());
        }
        eprintln!(
            "SafeYolo: current scoped {client} token loaded. Provider validity is unknown until a request succeeds. If access changes, stop/relaunch the client to fetch a new token. Inspect each pending network, credential or route approval separately; requests are never replayed."
        );
    }
    Ok(())
}
