//! Owned pinned NATS server for operator-event producer and consumer tests.
use serde_json::{Value, json};
use std::{os::unix::fs::PermissionsExt, path::Path, time::Duration};

pub(crate) struct Nats(std::process::Child);
impl Drop for Nats {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Nats {
    #[allow(dead_code, reason = "Approval-result tests require JetStream instead.")]
    pub(crate) async fn start(root: &Path) -> Self {
        Self::start_config(root, false).await
    }

    #[allow(
        dead_code,
        reason = "Live-event tests use core NATS without retention."
    )]
    pub(crate) async fn start_jetstream(root: &Path) -> Self {
        Self::start_config(root, true).await
    }

    async fn start_config(root: &Path, jetstream: bool) -> Self {
        let binary =
            std::env::var_os("SAFEYOLO_COORD_NATS_BINARY").expect("set the pinned NATS binary");
        let directory = root.join("data/coord/nats");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("creds"), "synthetic-operator-events").unwrap();
        std::fs::set_permissions(
            directory.join("creds"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let config = directory.join("nats.conf");
        std::fs::write(&config, format!("listen: 127.0.0.1:-1\nhttp: 127.0.0.1:-1\nmax_payload: 2097152\nports_file_dir: {directory:?}\nauthorization {{ user: safeyolo, password: synthetic-operator-events }}\n")).unwrap();
        if jetstream {
            use std::io::Write;
            writeln!(
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&config)
                    .unwrap(),
                "jetstream {{ store_dir: {:?} }}",
                directory.join("jetstream")
            )
            .unwrap();
        }
        let server = Self(
            std::process::Command::new(binary)
                .arg("-c")
                .arg(config)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let ports = directory.join(format!("nats-server_{}.ports", server.0.id()));
        let (port, monitor) = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(bytes) = std::fs::read(&ports)
                    && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
                    && let Some(address) = value["nats"]
                        .as_array()
                        .and_then(|a| a.first())
                        .and_then(Value::as_str)
                {
                    let monitor = value["monitoring"][0]
                        .as_str()
                        .unwrap()
                        .rsplit(':')
                        .next()
                        .unwrap()
                        .parse::<u16>()
                        .unwrap();
                    break (
                        address.rsplit(':').next().unwrap().parse::<u16>().unwrap(),
                        monitor,
                    );
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        std::fs::write(
            directory.join("test-endpoints.json"),
            json!({"client_port":port, "monitor_port":monitor}).to_string(),
        )
        .unwrap();
        server
    }

    pub(crate) async fn publisher(root: &Path) -> async_nats::Client {
        let endpoint: Value = serde_json::from_slice(
            &std::fs::read(root.join("data/coord/nats/test-endpoints.json")).unwrap(),
        )
        .unwrap();
        async_nats::ConnectOptions::new()
            .user_and_password("safeyolo".into(), "synthetic-operator-events".into())
            .connect(format!("nats://127.0.0.1:{}", endpoint["client_port"]))
            .await
            .unwrap()
    }
}
