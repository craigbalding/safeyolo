//! Guest-owned HTTP/TLS uses bounded byte I/O to one delegated proxy socket.
//! No guest argument selects a host path, IP address or upstream connection.

use super::{network, now};
use crate::Error;
use crate::credentials::Secret;
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::PathBuf};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

const MESSAGE_BYTES: usize = 48 * 1024;
const CHUNK_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Call {
    ProxyConfig {},
    GatewayToken { service: String },
    ProxyOpen {},
    ProxyRead { id: u64, length: usize },
    ProxyWrite { id: u64, data_base64: String },
    ProxyClose { id: u64 },
    Random { length: usize },
    Time {},
}

pub(super) struct Bridge {
    listener: UnixListener,
    proxy: PathBuf,
    config: Value,
    tokens: BTreeMap<String, Secret>,
    streams: BTreeMap<u64, UnixStream>,
    next_id: u64,
}

impl Bridge {
    pub(super) fn new(
        listener: UnixListener,
        client: &network::Client,
        ca_pem: String,
    ) -> Result<Self, Error> {
        let (proxy, tokens) = client.service_access()?;
        Ok(Self {
            listener,
            proxy,
            config: json!({"ca_pem":ca_pem}),
            tokens,
            streams: BTreeMap::new(),
            next_id: 0,
        })
    }

    // The caller aborts and joins this task before revoking the delegation.
    // Dropping it closes every stream, including a blocked read/write.
    pub(super) async fn serve(mut self) -> Result<(), Error> {
        loop {
            let (mut stream, _) = self.listener.accept().await?;
            let result = async {
                let size = stream.read_u32().await? as usize;
                if size > MESSAGE_BYTES {
                    return Err::<Value, Error>("host-call message limit exceeded".into());
                }
                let mut bytes = vec![0; size];
                stream.read_exact(&mut bytes).await?;
                self.call(serde_json::from_slice(&bytes)?).await
            }
            .await;
            let reply = match result {
                Ok(value) => json!({"ok":true,"value":value}),
                Err(error) => json!({"ok":false,"error":error.to_string()}),
            };
            let bytes = serde_json::to_vec(&reply)?;
            if bytes.len() > MESSAGE_BYTES {
                return Err("host-call reply limit exceeded".into());
            }
            if stream.write_u32(bytes.len().try_into()?).await.is_ok() {
                let _ = stream.write_all(&bytes).await;
            }
        }
    }

    async fn call(&mut self, call: Call) -> Result<Value, Error> {
        match call {
            Call::ProxyConfig {} => Ok(self.config.clone()),
            Call::GatewayToken { service } => {
                let token = self
                    .tokens
                    .get(&service)
                    .ok_or("service grant unavailable")?;
                Ok(json!({"token":token.expose_secret()}))
            }
            Call::ProxyOpen {} => {
                let id = self
                    .next_id
                    .checked_add(1)
                    .ok_or("proxy handle exhausted")?;
                let stream = UnixStream::connect(&self.proxy).await?;
                self.next_id = id;
                self.streams.insert(id, stream);
                Ok(json!({"id":id}))
            }
            Call::ProxyClose { id } => {
                self.streams.remove(&id).ok_or("unknown proxy stream")?;
                Ok(json!({}))
            }
            Call::ProxyRead { id, length } => {
                chunk(length)?;
                let stream = self.streams.get_mut(&id).ok_or("unknown proxy stream")?;
                let mut bytes = vec![0; length];
                let count = stream.read(&mut bytes).await?;
                Ok(json!({"data_base64":STANDARD.encode(&bytes[..count])}))
            }
            Call::ProxyWrite { id, data_base64 } => {
                let bytes = STANDARD.decode(data_base64)?;
                chunk(bytes.len())?;
                let stream = self.streams.get_mut(&id).ok_or("unknown proxy stream")?;
                let count = stream.write(&bytes).await?;
                Ok(json!({"written":count}))
            }
            Call::Random { length } => {
                chunk(length)?;
                let mut bytes = vec![0; length];
                SystemRandom::new()
                    .fill(&mut bytes)
                    .map_err(|_| "randomness unavailable")?;
                Ok(json!({"data_base64":STANDARD.encode(bytes)}))
            }
            Call::Time {} => Ok(json!({"unix_seconds":now()? / 1000})),
        }
    }
}

fn chunk(length: usize) -> Result<(), Error> {
    if !(1..=CHUNK_BYTES).contains(&length) {
        return Err("proxy I/O needs 1..16384 bytes".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_cannot_select_host_transport_or_forge_authority() {
        for value in [
            json!({"kind":"proxy_open","path":"/host/socket"}),
            json!({"kind":"proxy_open","url":"https://example.com"}),
            json!({"kind":"proxy_open","gate_id":"other","run_id":"other"}),
            json!({"kind":"proxy_config","path":"/host/certificate"}),
            json!({"kind":"time","unix_seconds":0}),
            json!({"kind":"service","service":"github","method":"GET","url":"https://example.com"}),
        ] {
            assert!(
                serde_json::from_value::<Call>(value.clone()).is_err(),
                "{value}"
            );
        }
        assert!(chunk(0).is_err());
        assert!(chunk(CHUNK_BYTES + 1).is_err());
        assert!(chunk(CHUNK_BYTES).is_ok());
    }

    #[tokio::test]
    async fn public_egress_needs_only_gate_policy_and_revocation_closes_streams() {
        use std::time::Duration;
        use tokio::net::TcpListener;
        let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let origin = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = origin.local_addr().unwrap().port();
        for directory in ["data", "services", "builtin-services"] {
            std::fs::create_dir(root.path().join(directory)).unwrap();
        }
        std::fs::write(root.path().join("data/admin_token"), "test-host-token").unwrap();
        std::fs::write(
            root.path().join("policy.toml"),
            format!(
                r#"
[hosts.'*']
egress = 'deny'
[agents.'gate:proof'.hosts.'127.0.0.1:{port}']
egress = 'allow'
[controls.credentials]
enabled = false
[controls.patterns]
enabled = false
[controls.test_context]
action = 'warn'
"#
            ),
        )
        .unwrap();
        let config = root.path().join("config.toml");
        std::fs::write(
            &config,
            "admin_port=0\nlisteners=[]\nflow_store_enabled=false\n",
        )
        .unwrap();
        let proxy = crate::Proxy::start(crate::native_config::read(&config).unwrap())
            .await
            .unwrap();
        let mut spec = super::super::tests::spec();
        spec.gate_id = "proof".into();
        spec.network = true;
        let client = network::Client::connect_mediated(
            &config,
            root.path(),
            &spec,
            &"1".repeat(32),
            &["parent-check".into()],
        )
        .await
        .unwrap();
        let socket = root.path().join("bridge.sock");
        let mut bridge = Bridge::new(
            UnixListener::bind(socket).unwrap(),
            &client,
            "test CA".into(),
        )
        .unwrap();
        assert!(
            bridge
                .call(Call::GatewayToken {
                    service: "github".into()
                })
                .await
                .is_err()
        );
        let id = bridge.call(Call::ProxyOpen {}).await.unwrap()["id"]
            .as_u64()
            .unwrap();
        let request = format!(
            "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-SafeYolo-Agent: other\r\n\r\n"
        );
        let mut bytes = request.as_bytes();
        while !bytes.is_empty() {
            let count = bridge
                .call(Call::ProxyWrite {
                    id,
                    data_base64: STANDARD.encode(bytes),
                })
                .await
                .unwrap()["written"]
                .as_u64()
                .unwrap() as usize;
            bytes = &bytes[count..];
        }
        let (mut upstream, _) = tokio::time::timeout(Duration::from_secs(5), origin.accept())
            .await
            .unwrap()
            .unwrap();
        let reply = bridge
            .call(Call::ProxyRead {
                id,
                length: CHUNK_BYTES,
            })
            .await
            .unwrap();
        let reply = STANDARD
            .decode(reply["data_base64"].as_str().unwrap())
            .unwrap();
        assert!(reply.starts_with(b"HTTP/1.1 200"), "{reply:?}");
        client.close().await.unwrap();
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), upstream.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(bridge.call(Call::ProxyOpen {}).await.is_err());
        bridge.call(Call::ProxyClose { id }).await.unwrap();
        assert!(
            bridge
                .call(Call::ProxyRead { id, length: 1 })
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), origin.accept())
                .await
                .is_err()
        );
        proxy.shutdown().await;
    }
}
