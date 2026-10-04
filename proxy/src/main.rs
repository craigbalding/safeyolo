use std::{io::Write, path::PathBuf};

use safeyolo_proxy::{Config, Error, Proxy};
use tokio::signal::unix::{SignalKind, signal};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        Some("--version") => {
            println!(
                "safeyolo-proxy {} commit={} profile={}",
                env!("CARGO_PKG_VERSION"),
                env!("SAFEYOLO_BUILD_REVISION"),
                env!("SAFEYOLO_BUILD_PROFILE"),
            );
            return Ok(());
        }
        Some("--config") => {}
        Some("--host-agent-entrypoint") => {
            let name = arguments.next().ok_or("agent name is required")?;
            let launch_id = arguments.next().ok_or("launch ID is required")?;
            if arguments.next().is_some() {
                return Err("unexpected command argument".into());
            }
            let code = safeyolo_proxy::run_host_agent_entrypoint(&name, &launch_id).await?;
            std::process::exit(code);
        }
        _ => return Err("usage: safeyolo-proxy --config CONFIG.json".into()),
    }
    let config_path = PathBuf::from(arguments.next().ok_or("--config needs a path")?);
    if arguments.next().is_some() {
        return Err("unexpected command argument".into());
    }
    // Register before readiness so a launcher can signal immediately after observing it.
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut reload = signal(SignalKind::hangup())?;
    let mut proxy = Proxy::start(Config::read(&config_path)?).await?;
    loop {
        tokio::select! {
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            _ = reload.recv() => match Config::read(&config_path) {
                Ok(config) => if let Err(error) = proxy.reload(config).await { eprintln!("configuration reload failed: {error}"); },
                Err(error) => eprintln!("configuration reload failed: {error}"),
            },
            _ = proxy.wait_for_service_catalog_check() => {
                if let Err(error) = proxy.reload_services_if_changed().await {
                    let _ = writeln!(
                        std::io::stderr().lock(),
                        "Service watcher reload failed: {}",
                        safeyolo_proxy::network_guard::sanitize(&error.to_string()),
                    );
                }
            },
            _ = proxy.wait_for_policy_check() => {
                if let Err(error) = proxy.reload_policy_if_changed().await {
                    let _ = writeln!(
                        std::io::stderr().lock(),
                        "Policy watcher reload failed: {}",
                        safeyolo_proxy::network_guard::sanitize(&error.to_string()),
                    );
                }
            },
        }
    }
    proxy.shutdown().await;
    Ok(())
}
