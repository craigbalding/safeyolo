//! Host-held NATS setup. The federation account has no imports from SY_LOCAL.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Broker {
    #[serde(default)]
    pub mode: endpoint::Mode,
    pub listen: std::net::IpAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_server_name: Option<String>,
    #[serde(default)]
    pub server_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tailscale_node: Option<String>,
    pub peers: Vec<Peer>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Peer {
    pub instance_id: String,
    pub credential_file: PathBuf,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct TransportPeer {
    pub instance_id: String,
    pub credential_hash: String,
}

pub(crate) fn broker(root: &Path) -> Result<Option<Broker>, Error> {
    let path = root.join("coord-federation.json");
    if !path.try_exists()? {
        return Ok(None);
    }
    read_broker(root, &path, false).map(Some)
}

pub(crate) fn read_broker(root: &Path, path: &Path, rotate_trust: bool) -> Result<Broker, Error> {
    let mut value: Broker = serde_json::from_slice(&fs::read(path)?)?;
    if rotate_trust {
        value.ca_sha256 = None;
    }
    for path in [
        &mut value.cert_file,
        &mut value.key_file,
        &mut value.ca_file,
    ]
    .into_iter()
    .flatten()
    {
        if path.is_relative() {
            *path = root.join(&*path);
        }
    }
    let mut instances = std::collections::HashSet::new();
    for peer in &mut value.peers {
        if peer.instance_id.is_empty() || !instances.insert(&peer.instance_id) {
            return Err("federation peers need distinct durable instance IDs".into());
        }
        if peer.credential_file.is_relative() {
            peer.credential_file = root.join(&peer.credential_file);
        }
        token(&peer.credential_file)?;
    }
    value.validate(root)?;
    Ok(value)
}

impl Broker {
    pub fn endpoint(&self, port: u16) -> endpoint::Endpoint {
        endpoint::Endpoint {
            mode: self.mode,
            url: endpoint::url(
                self.mode,
                self.local_server_name
                    .as_deref()
                    .filter(|_| self.mode == endpoint::Mode::Tls)
                    .unwrap_or(&self.listen.to_string()),
                port,
            ),
            ca_file: self.ca_file.clone(),
            ca_sha256: self.ca_sha256.clone(),
            tailscale_node: self.tailscale_node.clone(),
        }
    }

    pub fn validate(&self, root: &Path) -> Result<Value, Error> {
        self.endpoint(4222).origin()?;
        match self.mode {
            endpoint::Mode::Tls => {
                let cert = self
                    .cert_file
                    .as_ref()
                    .ok_or("TLS broker certificate file missing")?;
                let key = self
                    .key_file
                    .as_ref()
                    .ok_or("TLS broker key file missing")?;
                let ca = self.ca_file.as_ref().ok_or("TLS broker CA file missing")?;
                let local = self
                    .local_server_name
                    .as_ref()
                    .ok_or("TLS broker local_server_name missing")?;
                // Broker keys must not reuse the interception signing identity.
                let config = read_config(root)?;
                if let Some(interception) = config.tls_ca_file {
                    let interception_cert = tls_material::certificates(&interception).ok();
                    let same_key = interception_cert.as_ref().is_some_and(|interception| {
                        [cert, ca].iter().any(|path| {
                            tls_material::certificates(path).is_ok_and(|certs| {
                                certs.iter().any(|cert| {
                                    interception.iter().any(|interception| {
                                        tls_material::same_public_key(cert, interception)
                                    })
                                })
                            })
                        })
                    });
                    if same_key {
                        return Err("use dedicated broker TLS material, separate from the interception CA and key".into());
                    }
                }
                let mut names = self.server_names.clone();
                if !names.contains(local) {
                    names.push(local.clone());
                }
                tls_material::validate(cert, key, ca, &names)
            }
            endpoint::Mode::Loopback | endpoint::Mode::Tailscale => {
                if self.cert_file.is_some()
                    || self.key_file.is_some()
                    || self.local_server_name.is_some()
                    || !self.server_names.is_empty()
                {
                    return Err(
                        "remove TLS-only broker fields when selecting loopback or Tailscale".into(),
                    );
                }
                Ok(json!({"verified":true,"mode":self.mode}))
            }
        }
    }

    pub async fn verify_listener(&self) -> Result<(), Error> {
        if self.mode == endpoint::Mode::Tailscale {
            tailscale::verify(
                self.listen,
                self.tailscale_node
                    .as_deref()
                    .ok_or("Tailscale node missing")?,
                true,
            )
            .await?;
        }
        Ok(())
    }
}

pub(crate) fn subject_token(instance: &str) -> String {
    hash(instance.as_bytes())
}

pub(crate) fn request_subject(destination: &str, source: &str) -> String {
    format!(
        "SY_FED.request.{}.{}",
        subject_token(destination),
        subject_token(source)
    )
}

pub(crate) fn notice_subject(destination: &str, source: &str, principal: &str) -> String {
    format!(
        "SY_FED.notice.{}.{}.{principal}",
        subject_token(destination),
        subject_token(source)
    )
}

pub(crate) fn reply_prefix(source: &str) -> String {
    format!("SY_FED.reply.{}", subject_token(source))
}

/// The operator explicitly selects listener protection. Every peer user can only
/// publish its own source path and receive its own replies and wake hints.
pub(crate) fn server_config(
    setup: Option<&Broker>,
    instance: &str,
    local_password: &str,
    owner_password: &str,
) -> Result<(String, Vec<TransportPeer>), Error> {
    // Keep one explicit private account both before and after federation setup.
    // No imports or exports connect it to the federation account.
    let local =
        json!({"jetstream":"enabled","users":[{"user":"safeyolo","password":local_password}]});
    let mut accounts = json!({"SY_LOCAL":local});
    let mut tls = String::new();
    let mut peers = Vec::new();
    if let Some(setup) = setup {
        let mut users = vec![json!({"user":"safeyolo-federation","password":owner_password})];
        for peer in &setup.peers {
            let credential = token(&peer.credential_file)?;
            peers.push(TransportPeer {
                instance_id: peer.instance_id.clone(),
                credential_hash: hash(credential.trim().as_bytes()),
            });
            let stream = notice_stream(&peer.instance_id);
            users.push(json!({"user":subject_token(&peer.instance_id),"password":credential.trim(),
                "permissions":{"publish":{"allow":[request_subject(instance,&peer.instance_id),
                    format!("$JS.API.STREAM.INFO.{stream}"),format!("$JS.API.CONSUMER.INFO.{stream}.*"),format!("$JS.API.CONSUMER.MSG.NEXT.{stream}.*")]},
                    "subscribe":{"allow":[format!("{}.>",reply_prefix(&peer.instance_id)),
                        notice_subject(instance,&peer.instance_id,"*")]}}}));
        }
        accounts["SY_FED"] = json!({"users":users,"jetstream":"enabled"});
        if setup.mode == endpoint::Mode::Tls {
            tls = format!(
                "tls {{ cert_file: {}, key_file: {}, ca_file: {}, timeout: 2 }}\n",
                serde_json::to_string(&setup.cert_file)?,
                serde_json::to_string(&setup.key_file)?,
                serde_json::to_string(&setup.ca_file)?
            );
        }
    }
    Ok((format!("accounts: {accounts}\n{tls}"), peers))
}

/// Move the previous generated configuration's private account while its broker
/// is stopped and the runtime lock is held. Moving the entire account preserves
/// stream/consumer sequences; SQLite references must not be rewritten.
pub(crate) fn upgrade_local_store(jetstream: &Path) -> Result<(), Error> {
    // NATS appends its own jetstream directory to the configured store_dir.
    let accounts = jetstream.join("jetstream");
    if !accounts.try_exists()? {
        return Ok(());
    }
    let previous = accounts.join("$G");
    let current = accounts.join("SY_LOCAL");
    if previous.try_exists()? {
        if current.try_exists()? {
            return Err("Coord found both previous ($G) and current (SY_LOCAL) NATS account stores; neither was changed. Preserve both stores and v0.db; see Coord upgrade recovery in docs/coord-reference.md".into());
        }
        // Both paths have the same parent/filesystem. A process interruption
        // leaves the complete account at one name, never a partially copied set
        // of streams. The next start resumes using the current configuration.
        fs::rename(&previous, &current)?;
    }
    // Also sync on a resumed start: a prior process may have exited immediately
    // after rename and before persisting the directory entry.
    fs::File::open(accounts)?.sync_all()?;
    Ok(())
}

pub(crate) fn notice_stream(source: &str) -> String {
    format!("SY_FED_{}", subject_token(source))
}

pub(crate) const MAX_WAIT_CONSUMERS: i32 = 64;

pub(crate) async fn retained_notices(
    connection: &async_nats::Client,
    destination: &str,
    source: &str,
) -> Result<async_nats::jetstream::stream::Stream, Error> {
    Ok(async_nats::jetstream::new(connection.clone())
        .get_or_create_stream(async_nats::jetstream::stream::Config {
            name: notice_stream(source),
            subjects: vec![notice_subject(destination, source, "*")],
            max_messages_per_subject: 1,
            max_consumers: MAX_WAIT_CONSUMERS,
            ..Default::default()
        })
        .await?)
}

pub(crate) async fn local_options(
    data: &Path,
    url: String,
    username: String,
    token_file: PathBuf,
) -> Result<(String, async_nats::ConnectOptions), Error> {
    let endpoint = local_endpoint(data, url)?;
    let options = endpoint.options(username, token_file).await?;
    Ok((endpoint.url, options))
}

pub(crate) fn local_endpoint(data: &Path, fallback: String) -> Result<endpoint::Endpoint, Error> {
    let path = data.join("nats/local-endpoint.json");
    if path.try_exists()? {
        return Ok(serde_json::from_slice(&fs::read(path)?)?);
    }
    // An existing TLS broker can remain live during the source upgrade. Read
    // its old active record until its next controlled Coord start replaces it.
    let previous = data.join("nats/local-tls.json");
    if previous.try_exists()? {
        #[derive(Deserialize)]
        struct Previous {
            server_name: String,
            ca_file: PathBuf,
        }
        let tls: Previous = serde_json::from_slice(&fs::read(previous)?)?;
        let address: async_nats::ServerAddr = fallback.parse()?;
        return Ok(endpoint::Endpoint {
            mode: endpoint::Mode::Tls,
            url: endpoint::url(endpoint::Mode::Tls, &tls.server_name, address.port()),
            ca_sha256: Some(tls_material::trust_hash(&tls.ca_file)?),
            ca_file: Some(tls.ca_file),
            tailscale_node: None,
        });
    }
    Ok(endpoint::Endpoint {
        mode: endpoint::Mode::Loopback,
        url: fallback,
        ca_file: None,
        ca_sha256: None,
        tailscale_node: None,
    })
}

pub(crate) async fn connect_with_options(
    home: &Home,
    source: &str,
    configure: impl FnOnce(async_nats::ConnectOptions) -> async_nats::ConnectOptions,
) -> Result<async_nats::Client, Error> {
    let endpoint = home.endpoint();
    Ok(configure(
        endpoint
            .options(subject_token(source), home.token_file.clone())
            .await?,
    )
    .custom_inbox_prefix(reply_prefix(source))
    // A request is submitted once. The library reconnects subscriptions,
    // but SafeYolo never retries a possibly executed request.
    .request_timeout(Some(Duration::from_secs(60)))
    .connect(&home.url)
    .await?)
}

#[cfg(test)]
mod upgrade_tests {
    use super::*;

    #[test]
    fn local_account_move_preserves_both_stores_on_conflict() {
        let root = tempfile::tempdir().unwrap();
        upgrade_local_store(root.path()).unwrap();
        assert!(!root.path().join("jetstream").exists());
        let previous = root.path().join("jetstream/$G/streams/ROOM_original");
        let current = root.path().join("jetstream/SY_LOCAL/streams/ROOM_other");
        fs::create_dir_all(&previous).unwrap();
        fs::create_dir_all(&current).unwrap();
        fs::write(previous.join("meta.inf"), "original").unwrap();
        fs::write(current.join("meta.inf"), "other").unwrap();
        let error = upgrade_local_store(root.path()).unwrap_err().to_string();
        assert!(error.contains("neither was changed"));
        assert_eq!(fs::read(previous.join("meta.inf")).unwrap(), b"original");
        assert_eq!(fs::read(current.join("meta.inf")).unwrap(), b"other");
    }

    #[test]
    fn local_account_move_resumes_after_process_exit_before_activation() {
        const CHILD_ROOT: &str = "SAFEYOLO_TEST_LOCAL_ACCOUNT_MOVE";
        if let Some(path) = std::env::var_os(CHILD_ROOT) {
            upgrade_local_store(Path::new(&path)).unwrap();
            std::process::exit(73);
        }
        let root = tempfile::tempdir().unwrap();
        let relative = "streams/ROOM_original/obs/reader/o.dat";
        let previous = root.path().join("jetstream/$G").join(relative);
        fs::create_dir_all(previous.parent().unwrap()).unwrap();
        fs::write(&previous, "retained-consumer-position").unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "coord_rooms::federation::nats::upgrade_tests::local_account_move_resumes_after_process_exit_before_activation"])
            .env(CHILD_ROOT, root.path())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(73));
        assert!(!root.path().join("jetstream/$G").exists());
        upgrade_local_store(root.path()).unwrap();
        assert_eq!(
            fs::read(root.path().join("jetstream/SY_LOCAL").join(relative)).unwrap(),
            b"retained-consumer-position"
        );
    }
}
