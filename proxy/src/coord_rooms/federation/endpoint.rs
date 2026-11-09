//! The selected NATS endpoint and its protection, including reconnects.
use super::*;
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mode {
    #[default]
    Tls,
    Tailscale,
    Loopback,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Endpoint {
    #[serde(default)]
    pub mode: Mode,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tailscale_node: Option<String>,
}

impl Endpoint {
    pub fn origin(&self) -> Result<hyper::Uri, Error> {
        let uri: hyper::Uri = self.url.parse()?;
        if uri.authority().is_none_or(|a| a.as_str().contains('@'))
            || uri.path_and_query().is_some_and(|p| p.as_str() != "/")
            || uri
                .port()
                .is_some_and(|_| uri.port_u16().is_none_or(|port| port == 0))
        {
            return Err("NATS endpoint needs an origin without credentials, path or query and a valid port (default 4222)".into());
        }
        match self.mode {
            Mode::Tls => {
                if uri.scheme_str() != Some("tls")
                    || self.ca_file.is_none()
                    || self.tailscale_node.is_some()
                {
                    return Err("TLS NATS requires tls://, a CA file and no Tailscale node".into());
                }
                tls_material::roots(self.ca_file.as_ref().expect("checked CA"))?;
                if let Some(expected) = &self.ca_sha256
                    && &tls_material::trust_hash(self.ca_file.as_ref().expect("checked CA"))?
                        != expected
                {
                    return Err("NATS CA material changed; verify and explicitly apply the new trust with --rotate-trust before connecting".into());
                }
            }
            Mode::Loopback | Mode::Tailscale => {
                if uri.scheme_str() != Some("nats")
                    || self.ca_file.is_some()
                    || self.ca_sha256.is_some()
                {
                    return Err(
                        "loopback and Tailscale NATS require nats:// without TLS material".into(),
                    );
                }
                let ip = endpoint_ip(&uri)?;
                if self.mode == Mode::Loopback {
                    if !ip.is_loopback() || self.tailscale_node.is_some() {
                        return Err("loopback NATS requires a literal loopback address and no Tailscale node".into());
                    }
                } else if self.tailscale_node.as_deref().is_none_or(str::is_empty) {
                    return Err("Tailscale NATS requires the selected node's stable ID".into());
                }
            }
        }
        Ok(uri)
    }

    pub async fn verify(&self) -> Result<Value, Error> {
        let uri = self.origin()?;
        if self.mode == Mode::Tailscale {
            let mut result = tailscale::verify(
                endpoint_ip(&uri)?,
                self.tailscale_node.as_deref().expect("checked node"),
                false,
            )
            .await?;
            result["mode"] = json!(self.mode);
            return Ok(result);
        }
        Ok(json!({"mode":self.mode,"configuration_verified":true,
            "verified":self.mode == Mode::Loopback,"server_name":uri.host(),
            "trust_sha256":self.ca_sha256}))
    }

    pub async fn options(
        &self,
        username: String,
        token_file: PathBuf,
    ) -> Result<async_nats::ConnectOptions, Error> {
        let mut options = self.credential_options(username, token_file)?;
        if self.mode == Mode::Tailscale {
            let protected = tailscale::verify(
                endpoint_ip(&self.origin()?)?,
                self.tailscale_node.as_deref().expect("checked node"),
                false,
            )
            .await?;
            let address: IpAddr = protected["local_address"]
                .as_str()
                .ok_or("Tailscale local address missing")?
                .parse()?;
            // Reconnects cannot adopt an ordinary LAN source address.
            options = options.local_address(std::net::SocketAddr::new(address, 0));
        }
        Ok(options)
    }

    fn credential_options(
        &self,
        username: String,
        token_file: PathBuf,
    ) -> Result<async_nats::ConnectOptions, Error> {
        self.origin()?;
        let endpoint = self.clone();
        // async-nats calls this immediately before CONNECT on every connection,
        // including automatic reconnects. No credentials exist in its static auth.
        let mut options = async_nats::ConnectOptions::with_auth_callback(move |_| {
            let (endpoint, username, token_file) =
                (endpoint.clone(), username.clone(), token_file.clone());
            async move {
                endpoint.verify().await.map_err(|_| {
                    async_nats::AuthError::new(
                        "selected NATS protection unavailable; credentials withheld",
                    )
                })?;
                let password = token(&token_file).map_err(|_| {
                    async_nats::AuthError::new("host-held NATS credential unavailable")
                })?;
                let mut auth = async_nats::Auth::new();
                auth.username = Some(username);
                auth.password = Some(password.trim().to_owned());
                Ok(auth)
            }
        })
        .ignore_discovered_servers();
        // A broker's INFO advertisement cannot widen the operator's endpoint.
        if self.mode == Mode::Tls {
            options = options
                .require_tls(true)
                .tls_client_config(tls_material::client_config(
                    self.ca_file.as_ref().expect("checked CA"),
                )?);
        }
        Ok(options.connection_timeout(Duration::from_secs(8)))
    }

    pub fn security(&self) -> Result<Value, Error> {
        Ok(json!([
            self,
            self.ca_file
                .as_ref()
                .map(|path| tls_material::trust_hash(path))
                .transpose()?
        ]))
    }
}

pub(crate) fn endpoint_ip(uri: &hyper::Uri) -> Result<IpAddr, Error> {
    uri.host()
        .ok_or("NATS host missing")?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .map_err(|_| "selected NATS mode requires a literal IP address".into())
}

pub(crate) fn url(mode: Mode, host: &str, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    format!(
        "{}://{host}:{port}",
        if mode == Mode::Tls { "tls" } else { "nats" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_requires_a_literal_origin_and_cannot_be_an_unrestricted_tls_false() {
        for origin in ["nats://127.0.0.1:4222", "nats://[::1]:4222"] {
            let endpoint: Endpoint =
                serde_json::from_value(json!({"mode":"loopback","url":origin})).unwrap();
            endpoint.origin().unwrap();
        }
        for origin in [
            "nats://localhost:4222",
            "nats://192.168.0.1:4222",
            "nats://100.64.0.1:4222",
            "nats://0.0.0.0:4222",
            "nats://127.0.0.1:0",
            "nats://user:secret@127.0.0.1:4222",
            "nats://127.0.0.1:4222/path",
            "nats://127.0.0.1:4222?token=x",
        ] {
            let endpoint: Endpoint =
                serde_json::from_value(json!({"mode":"loopback","url":origin})).unwrap();
            assert!(endpoint.origin().is_err(), "{origin}");
        }
        assert!(
            serde_json::from_value::<Endpoint>(json!({"url":"nats://127.0.0.1","tls":false}))
                .is_err()
        );
        assert!(
            serde_json::from_value::<Endpoint>(json!({"url":"nats://127.0.0.1"}))
                .unwrap()
                .origin()
                .is_err()
        );
    }

    #[tokio::test]
    async fn failed_node_verification_withholds_credentials_after_server_info() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint: Endpoint = serde_json::from_value(json!({"mode":"tailscale","url":format!("nats://{}",listener.local_addr().unwrap()),"tailscale_node":"not-a-tailnet-node"})).unwrap();
        let root = tempfile::tempdir().unwrap();
        let secret = root.path().join("secret");
        fs::write(&secret, "must-not-be-sent").unwrap();
        let trap = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"INFO {\"server_id\":\"trap\",\"server_name\":\"trap\",\"version\":\"2.14.5\",\"proto\":1,\"max_payload\":1048576,\"headers\":true}\r\n").await.unwrap();
            let mut bytes = Vec::new();
            tokio::time::timeout(Duration::from_secs(10), socket.read_to_end(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert!(
                bytes.is_empty(),
                "no CONNECT or credentials may reach an unverified node"
            );
        });
        assert!(
            endpoint
                .credential_options("peer".into(), secret)
                .unwrap()
                .connect(&endpoint.url)
                .await
                .is_err()
        );
        trap.await.unwrap();
    }

    #[tokio::test]
    async fn reconnect_ignores_broker_advertised_endpoints() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let advertised = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint: Endpoint = serde_json::from_value(
            json!({"mode":"loopback","url":format!("nats://{}",listener.local_addr().unwrap())}),
        )
        .unwrap();
        let info = format!(
            "INFO {}\r\n",
            json!({"server_id":"selected","server_name":"selected","version":"2.14.5","proto":1,"max_payload":1048576,"headers":true,"connect_urls":[advertised.local_addr().unwrap().to_string()]})
        );
        let (cut, mut interrupted) = tokio::sync::oneshot::channel();
        let (returned, recovered) = tokio::sync::oneshot::channel();
        let selected = tokio::spawn(async move {
            let mut returned = Some(returned);
            for attempt in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                socket.write_all(info.as_bytes()).await.unwrap();
                if attempt == 1 {
                    returned.take().unwrap().send(()).unwrap();
                }
                let mut socket = BufReader::new(socket);
                loop {
                    let mut line = String::new();
                    tokio::select! {
                        _ = &mut interrupted, if attempt == 0 => break,
                        read = socket.read_line(&mut line) => {
                            if read.unwrap() == 0 { break; }
                            if line.starts_with("PING") {
                                socket.get_mut().write_all(b"PONG\r\n").await.unwrap();
                            }
                        }
                    }
                }
            }
        });
        let root = tempfile::tempdir().unwrap();
        let secret = root.path().join("credential");
        fs::write(&secret, "host-held-credential").unwrap();
        let client = endpoint
            .options("peer".into(), secret)
            .await
            .unwrap()
            .connect(&endpoint.url)
            .await
            .unwrap();
        client.flush().await.unwrap();
        cut.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), recovered)
            .await
            .unwrap()
            .unwrap();
        client.flush().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), advertised.accept())
                .await
                .is_err(),
            "reconnect must never dial a broker-advertised destination"
        );
        selected.abort();
    }
}
