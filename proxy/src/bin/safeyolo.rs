//! Installed operator commands use the native policy library and Admin API.

use std::{
    ffi::OsString,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use hyper::Method;
use safeyolo_proxy::{
    Error,
    native_client::{admin, send_json},
    native_config,
    policy::Policy,
    test_context::{self, Context},
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

#[path = "safeyolo/credential_commands.rs"]
mod credential_commands;

fn check(path: &Path) -> Result<(), Error> {
    // The shared loader compiles the policy without evaluating a request or
    // persisting expiry changes. It therefore does not spend a live quota.
    Policy::from_native_path(path)?;
    println!("Policy is valid: {}", path.display());
    Ok(())
}

fn initialize(root: &Path, config: &Path) -> Result<(), Error> {
    if config
        .extension()
        .is_none_or(|extension| extension != "toml")
    {
        return Err("native configuration requires a TOML file".into());
    }
    if config.exists() || root.join("policy.toml").exists() {
        return Err("instance already has configuration; choose a fresh root".into());
    }
    std::fs::create_dir_all(root.join("data"))?;
    std::fs::create_dir_all(root.join("logs"))?;
    std::fs::create_dir_all(root.join("certs"))?;
    let write_new = |name: &str, source: &str| -> Result<(), Error> {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(root.join(name))?;
        file.write_all(source.as_bytes())?;
        file.sync_all()?;
        Ok(())
    };
    write_new(
        "data/admin_token",
        &format!(
            "{}{}\n",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        ),
    )?;
    write_new(
        "data/agent_token",
        &format!(
            "{}{}\n",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        ),
    )?;
    write_new(
        "policy.toml",
        include_str!("../../config/native/policy.toml"),
    )?;
    write_new(
        "data/instance_id",
        &format!("sy-{}\n", uuid::Uuid::new_v4().simple()),
    )?;
    let (private, public) = safeyolo_proxy::tls::CertificateAuthority::create()?;
    write_new("certs/mitmproxy-ca.pem", &private)?;
    write_new("certs/mitmproxy-ca-cert.pem", &public)?;
    write_new(
        config
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("config has no filename")?,
        &format!(
            "{}\ntls_ca_file = \"certs/mitmproxy-ca.pem\"\nagent_map_file = \"data/agent_map.json\"\n",
            include_str!("../../config/native/config.toml")
        ),
    )?;
    println!("Initialized native instance: {}", root.display());
    Ok(())
}

async fn context_command(arguments: &[String]) -> Result<(), Error> {
    if arguments == ["--help"] {
        println!(
            "safeyolo test-context --run ID --agent NAME [--role VALUE] [--suite VALUE] [--subject VALUE] [--step VALUE] [--test VALUE] [--intent VALUE] [--expect VALUE] [--field KEY=VALUE] [--header] [--write FILE]\nsafeyolo test-context declare --socket SOCKET --token-file FILE --run ID --agent NAME [--ttl SECONDS]\nsafeyolo test-context current|clear --socket SOCKET --token-file FILE\n\nrun and agent are required annotations. The trusted listener owns identity.\nFields use [A-Za-z0-9_.:-], at most 20 pairs, with no duplicates.\n--write atomically replaces a watched file. Declare uses an Agent API token; the policy controls injection and maximum TTL (default 900 seconds)."
        );
        return Ok(());
    }
    let mut pairs = Vec::new();
    let mut header = false;
    let mut write = None;
    let mut socket = None;
    let mut token_file = None;
    let mut ttl = None;
    let operation = arguments
        .first()
        .filter(|value| matches!(value.as_str(), "declare" | "current" | "clear"))
        .map(String::as_str);
    let mut arguments = arguments[usize::from(operation.is_some())..].iter();
    while let Some(argument) = arguments.next() {
        if argument == "--header" {
            header = true;
            continue;
        }
        let value = arguments
            .next()
            .ok_or_else(|| format!("{argument} requires a value"))?;
        match argument.as_str() {
            "--write" => write = Some(PathBuf::from(value)),
            "--socket" => socket = Some(PathBuf::from(value)),
            "--token-file" => token_file = Some(PathBuf::from(value)),
            "--ttl" => ttl = Some(value.parse::<u64>()?),
            "--field" => {
                let (key, value) = value.split_once('=').ok_or("--field requires KEY=VALUE")?;
                if test_context::CANONICAL_KEYS.contains(&key) {
                    return Err(format!("use --{key} for a named context field").into());
                }
                pairs.push((key.to_owned(), value.to_owned()));
            }
            key if key
                .strip_prefix("--")
                .is_some_and(|key| test_context::CANONICAL_KEYS.contains(&key)) =>
            {
                pairs.push((key[2..].to_owned(), value.to_owned()));
            }
            _ => return Err(format!("unknown test-context option: {argument}").into()),
        }
    }
    if let Some(operation) = operation {
        if header || write.is_some() {
            return Err("--header and --write are formatter options".into());
        }
        let socket = socket.ok_or("--socket is required for declared context")?;
        let token = Zeroizing::new(std::fs::read_to_string(
            token_file.ok_or("--token-file is required for declared context")?,
        )?);
        let body = if operation == "declare" {
            let context = Context::from_pairs(pairs)?;
            let mut body = json!({"context": context.format()});
            if let Some(ttl) = ttl {
                body["ttl"] = json!(ttl);
            }
            body
        } else {
            if !pairs.is_empty() || ttl.is_some() {
                return Err("context fields and --ttl require declare".into());
            }
            Value::Null
        };
        let method = match operation {
            "declare" => Method::POST,
            "clear" => Method::DELETE,
            _ => Method::GET,
        };
        let socket = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::UnixStream::connect(socket),
        )
        .await??;
        let response = send_json(
            socket,
            "_safeyolo.proxy.internal",
            "/api/test-context/current",
            token.trim(),
            method,
            body,
            Duration::from_secs(5),
        )
        .await?;
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        if socket.is_some() || token_file.is_some() || ttl.is_some() {
            return Err("--socket, --token-file and --ttl require declare/current/clear".into());
        }
        let context = Context::from_pairs(pairs)?;
        if let Some(path) = write {
            test_context::atomic_write(&path, &context)?;
        }
        println!(
            "{}",
            if header {
                context.header_line()
            } else {
                context.format()
            }
        );
    }
    Ok(())
}

async fn run() -> Result<(), Error> {
    let mut arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let explicit_config = arguments.first().is_some_and(|value| value == "--config");
    let explicit_root = arguments.first().is_some_and(|value| value == "--root");
    let selected = if explicit_config || explicit_root {
        if arguments.len() < 2 {
            return Err("--root requires a directory; --config requires a TOML file".into());
        }
        let selected = PathBuf::from(arguments.remove(1));
        arguments.remove(0);
        Some(selected)
    } else {
        std::env::var_os("SAFEYOLO_NATIVE_CONFIG_PATH")
            .map(PathBuf::from)
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "toml")
            })
    };
    let root = if explicit_root {
        selected.clone().unwrap()
    } else if selected.is_some() {
        selected
            .as_ref()
            .unwrap()
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_owned()
    } else {
        std::env::var_os("SAFEYOLO_CONFIG_DIR")
            .or_else(|| std::env::var_os("SAFEYOLO_HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".safeyolo")
            })
    };
    let config = if let Some(selected) = selected.filter(|_| !explicit_root) {
        selected
    } else {
        root.join("config.toml")
    };
    // Proposal file options retain Unix filename bytes through the shared
    // parser, as do the native guest CLI's existing path-taking commands.
    if matches!(arguments.as_slice(), [coord, kind, ..] if coord == "coord" && (kind == "completion-notes" || kind == "proposals"))
    {
        return safeyolo_proxy::factory_proposals::run_operator(&config, &arguments[1..]).await;
    }
    let arguments: Vec<String> = arguments
        .into_iter()
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| "command arguments must be UTF-8 text")
        })
        .collect::<Result<_, _>>()?;
    if arguments.first().is_some_and(|value| value == "lab") {
        let code = safeyolo_proxy::lab::run(config, &arguments[1..]).await?;
        if code != 0 {
            std::process::exit(code);
        }
        return Ok(());
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "factory")
    {
        return safeyolo_proxy::factory::run(&config, &arguments[1..]).await;
    }
    if safeyolo_proxy::operator_commands::handles(&arguments) {
        return safeyolo_proxy::operator_commands::run(&config, &arguments).await;
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "dispatch")
    {
        return safeyolo_proxy::dispatch::run(&arguments[1..]);
    }
    if safeyolo_proxy::host_commands::handles(&arguments) {
        let code = safeyolo_proxy::host_commands::run(config, &arguments).await?;
        if code != 0 {
            std::process::exit(code);
        }
        return Ok(());
    }
    match arguments.as_slice() {
        [command, help] if command == "ssh-proxy" && help == "--help" => {
            println!("{}", safeyolo_proxy::ssh_proxy::HELP);
            Ok(())
        }
        [command, host, port] if command == "ssh-proxy" => {
            safeyolo_proxy::ssh_proxy::run(host, port.parse()?).await
        }
        [command] if command == "init" => initialize(&root, &config),
        [help] if matches!(help.as_str(), "--help" | "help") => {
            println!("{}", credential_commands::CREDENTIAL_HELP);
            println!("{}", credential_commands::SERVICE_HELP);
            println!("{}", safeyolo_proxy::factory::HELP);
            println!("{}", safeyolo_proxy::operator_commands::HELP);
            println!("{}", safeyolo_proxy::ssh_proxy::HELP);
            println!("{}", safeyolo_proxy::lab::HELP);
            println!("{}", safeyolo_proxy::coord_operator::HELP);
            println!("{}", safeyolo_proxy::factory_proposals::HELP);
            println!("{}", safeyolo_proxy::dispatch::request::HELP);
            println!("{}", safeyolo_proxy::dispatch::HELP);
            println!("{}", safeyolo_proxy::mattermost::HELP);
            println!(
                "safeyolo [--root ROOT | --config FILE] init\nsafeyolo [--root ROOT | --config FILE] start|stop|status|doctor\nsafeyolo [--root ROOT] agent --help\nsafeyolo [--root ROOT] coord start [--binary PATH]|stop|status\nsafeyolo [--root ROOT] coord room create NAME|list\nsafeyolo [--root ROOT] coord grant ROOM AGENT [send receive]|revoke ROOM AGENT\nstart and stop control the proxy. Agent runtimes have separate start and stop commands. status and doctor inspect each runtime and control dimension without changing state."
            );
            println!(
                "safeyolo [--root ROOT] agent recover NAME [--timeout SECONDS]\nsafeyolo guest-command stage HOME SHARE ASSETS CONTEXT_JSON\nRecovery requires an already booted guest with idle command supervision. Staging is for a stopped guest; the caller supplies this run's context."
            );
            println!(
                "safeyolo [--root ROOT] policy check FILE\nsafeyolo [--root ROOT] policy show\nsafeyolo [--root ROOT] policy apply FILE\nsafeyolo config check FILE\nsafeyolo test-context --run ID --agent NAME [--role VALUE] [--suite VALUE] [--subject VALUE] [--step VALUE] [--test VALUE] [--intent VALUE] [--expect VALUE] [--field KEY=VALUE] [--header] [--write FILE]\nsafeyolo test-context declare --socket SOCKET --token-file FILE --run ID --agent NAME [--ttl SECONDS]\nsafeyolo test-context current|clear --socket SOCKET --token-file FILE\n\ncheck validates without saving or spending quotas.\nshow reads effective policy and its source from the running process.\napply saves and activates through the operator Admin API.\nROOT contains config.toml and policy.toml. Named controls: network, credentials, patterns, test_context, circuits.\nContext agent is annotation; the trusted listener owns identity. --write atomically replaces a watched file.\n\nsafeyolo --version"
            );
            Ok(())
        }
        [version] if version == "--version" => {
            println!(
                "safeyolo {} commit={} profile={}",
                env!("CARGO_PKG_VERSION"),
                env!("SAFEYOLO_BUILD_REVISION"),
                env!("SAFEYOLO_BUILD_PROFILE"),
            );
            Ok(())
        }
        [policy, command, path] if policy == "policy" && command == "check" => {
            check(Path::new(path))
        }
        [config, command, path] if config == "config" && command == "check" => {
            native_config::read(Path::new(path))?;
            println!("Configuration is valid: {path}");
            Ok(())
        }
        [command, rest @ ..] if command == "credentials" => {
            credential_commands::credentials(&config, rest).await
        }
        [command, rest @ ..] if command == "services" => {
            credential_commands::services(&config, rest).await
        }
        [command, rest @ ..] if command == "test-context" => context_command(rest).await,
        [command, rest @ ..] if command == "coord" => {
            safeyolo_proxy::coord_rooms::run(&config, rest).await
        }
        [guest, stage, home, share, assets, context]
            if guest == "guest-command" && stage == "stage" =>
        {
            let context = serde_json::from_slice(&std::fs::read(context)?)?;
            let result = safeyolo_proxy::guest_commands::stage(
                Path::new(home),
                Path::new(share),
                Path::new(assets),
                context,
            )?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        [policy, command] if policy == "policy" && command == "show" => {
            let result = admin(
                &config,
                "/admin/policy/baseline",
                Method::GET,
                Value::Null,
                Duration::from_secs(5),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        [policy, command, path] if policy == "policy" && command == "apply" => {
            Policy::from_native_path(Path::new(path))?;
            let source = Policy::read_native_candidate(Path::new(path))?;
            match admin(&config, "/admin/policy/baseline", Method::PUT, json!({"source":source.as_str()}), Duration::from_secs(5)).await {
                Ok(result) if result["status"] == "active" => {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                    Ok(())
                }
                Ok(_) => Err("Admin API did not confirm activation; run policy show to inspect saved and active state".into()),
                Err(error) => {
                    eprintln!("Policy apply failed: {error}");
                    match admin(&config, "/admin/policy/baseline", Method::GET, Value::Null, Duration::from_secs(5)).await {
                        Ok(status) => {
                            eprintln!("Policy status: {}; saved source matches active: {}", status["status"], status["saved_matches_active"]);
                            if let Some(repair) = status.get("repair").and_then(Value::as_str) { eprintln!("{repair}"); }
                        }
                        Err(error) => eprintln!("Cannot read active policy: {error}. Restore the Admin API connection, then run policy show."),
                    }
                    Err("policy was not confirmed active".into())
                }
            }
        }
        _ => Err("usage: safeyolo --help".into()),
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("safeyolo: {error}");
        std::process::exit(1);
    }
}
