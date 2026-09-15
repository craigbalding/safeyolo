use std::path::PathBuf;

use safeyolo_proxy::{Config, Error, Proxy};
use tokio::signal::unix::{SignalKind, signal};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        Some("--version") => {
            println!(
                "safeyolo-proxy {} (development M2)",
                env!("CARGO_PKG_VERSION")
            );
            return Ok(());
        }
        Some("--config") => {}
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
            }
        }
    }
    proxy.shutdown().await;
    Ok(())
}
