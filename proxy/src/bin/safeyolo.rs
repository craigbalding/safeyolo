//! Installed operator commands use the native policy library and Admin API.

use std::{
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use hyper::Method;
use safeyolo_proxy::{
    Error, native_client, native_config,
    policy::Policy,
    test_context::{self, Context},
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

fn check(path: &Path) -> Result<(), Error> {
    // The shared loader compiles the policy without evaluating a request or
    // persisting expiry changes. It therefore does not spend a live quota.
    Policy::from_native_path(path)?;
    println!("Policy is valid: {}", path.display());
    Ok(())
}

fn initialize(root: &Path) -> Result<(), Error> {
    if root.join("config.toml").exists() || root.join("policy.toml").exists() {
        return Err("instance already has configuration; choose a fresh root".into());
    }
    std::fs::create_dir_all(root.join("data"))?;
    std::fs::create_dir_all(root.join("logs"))?;
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
    write_new(
        "config.toml",
        include_str!("../../config/native/config.toml"),
    )?;
    println!("Initialized native instance: {}", root.display());
    Ok(())
}

async fn admin(config_path: &Path, method: Method, body: Value) -> Result<Value, Error> {
    native_client::admin(config_path, "/admin/policy/baseline", method, body).await
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
        let response = native_client::send_json(
            socket,
            "_safeyolo.proxy.internal",
            "/api/test-context/current",
            token.trim(),
            method,
            body,
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
    let mut arguments: Vec<String> = std::env::args().skip(1).collect();
    let root = if arguments.first().is_some_and(|value| value == "--root") {
        if arguments.len() < 2 {
            return Err("--root requires a directory".into());
        }
        let root = PathBuf::from(arguments.remove(1));
        arguments.remove(0);
        root
    } else {
        std::env::var_os("SAFEYOLO_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".safeyolo")
            })
    };
    let config = root.join("config.toml");
    if safeyolo_proxy::operator_commands::handles(&arguments) {
        return safeyolo_proxy::operator_commands::run(&root, &arguments).await;
    }
    match arguments.as_slice() {
        [command] if command == "init" => initialize(&root),
        [help] if matches!(help.as_str(), "--help" | "help") => {
            println!("{}", safeyolo_proxy::operator_commands::HELP);
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
        [command, rest @ ..] if command == "test-context" => context_command(rest).await,
        [agent, recover, name] if agent == "agent" && recover == "recover" => {
            let result = safeyolo_proxy::recover_guest_probe(&root, name, Duration::from_secs(15))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        [agent, recover, name, option, seconds]
            if agent == "agent" && recover == "recover" && option == "--timeout" =>
        {
            let seconds: f64 = seconds.parse()?;
            if !seconds.is_finite() || seconds <= 0.0 {
                return Err("--timeout must be positive seconds".into());
            }
            let result = safeyolo_proxy::recover_guest_probe(
                &root,
                name,
                Duration::try_from_secs_f64(seconds)?,
            )?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
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
            let result = admin(&config, Method::GET, Value::Null).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        [policy, command, path] if policy == "policy" && command == "apply" => {
            Policy::from_native_path(Path::new(path))?;
            let source = Policy::read_native_candidate(Path::new(path))?;
            match admin(&config, Method::PUT, json!({"source":source.as_str()})).await {
                Ok(result) if result["status"] == "active" => {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                    Ok(())
                }
                Ok(_) => Err("Admin API did not confirm activation; run policy show to inspect saved and active state".into()),
                Err(error) => {
                    eprintln!("Policy apply failed: {error}");
                    match admin(&config, Method::GET, Value::Null).await {
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
