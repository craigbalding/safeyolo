//! Installed operator commands use the native policy library and Admin API.

use std::{
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use safeyolo_proxy::{Error, native_config, policy::Policy};
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
        "policy.toml",
        include_str!("../../config/native/policy.toml"),
    )?;
    write_new(
        "config.toml",
        include_str!("../../config/native/config.toml"),
    )?;
    println!("Initialized native instance: {}", root.display());
    Ok(())
}

async fn admin(config_path: &Path, method: Method, body: Value) -> Result<Value, Error> {
    let config = native_config::read(config_path)?;
    let configured_port = config.admin_port.ok_or("Admin API is disabled")?;
    let port = if configured_port == 0 {
        let readiness: Value = serde_json::from_slice(&std::fs::read(&config.readiness_file)?)?;
        readiness
            .get("admin_port")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
            .ok_or("readiness does not name an Admin API port")?
    } else {
        configured_port
    };
    let token = Zeroizing::new(std::fs::read_to_string(
        config
            .admin_api_token_file
            .ok_or("Admin API token path is missing")?,
    )?);
    let token = token.trim();
    if token.is_empty() {
        return Err("Admin API token is empty".into());
    }
    let socket = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await??;
    let (mut client, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(socket)).await?;
    let driver = tokio::spawn(connection);
    let request = Request::builder()
        .method(method)
        .uri("/admin/policy/baseline")
        .header("host", format!("127.0.0.1:{port}"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("connection", "close")
        .body(Full::new(Bytes::from(serde_json::to_vec(&body)?)))?;
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let response = client.send_request(request).await?;
        let status = response.status();
        let bytes = response.into_body().collect().await?.to_bytes();
        let value: Value = serde_json::from_slice(&bytes)?;
        if !status.is_success() {
            return Err(format!(
                "Admin API {status}: {}",
                value
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("request failed")
            )
            .into());
        }
        Ok::<_, Error>(value)
    })
    .await;
    driver.abort();
    let _ = driver.await;
    result?
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
    match arguments.as_slice() {
        [command] if command == "init" => initialize(&root),
        [help] if matches!(help.as_str(), "--help" | "help") => {
            println!("safeyolo [--root ROOT] policy check FILE\nsafeyolo [--root ROOT] policy show\nsafeyolo [--root ROOT] policy apply FILE\n\ncheck validates without saving or spending quotas.\nshow reads effective policy and its source from the running process.\napply saves and activates through the operator Admin API.\nROOT contains config.toml and policy.toml.\n\nsafeyolo --version");
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
        _ => Err("usage: safeyolo [--root ROOT] policy check FILE | policy show | policy apply FILE | --version".into()),
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("safeyolo: {error}");
        std::process::exit(1);
    }
}
