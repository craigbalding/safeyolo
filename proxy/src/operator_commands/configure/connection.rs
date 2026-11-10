//! Guided, directional handoffs using the existing protected NATS operations.
use super::*;
use crate::coord_rooms::federation::{
    self,
    endpoint::{self, Mode},
    nats, tls_material,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rusqlite::OptionalExtension as _;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Handoff {
    schema: String,
    owner: Identity,
    source: Identity,
    mode: Mode,
    url: String,
    tailscale_node: Option<String>,
    // Public certificates only; private broker/CA keys never enter a handoff.
    ca_pem: Option<String>,
}

async fn federation(root: &Path, args: &[String]) -> Result<Value, Error> {
    federation::run(root, args).await
}

fn private_directory(path: &Path) -> Result<(), Error> {
    if !path.try_exists()? {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    crate::coord_setup::safe(path, true, Some(0o700))?;
    Ok(())
}

fn saved_broker(root: &Path) -> Result<Option<nats::Broker>, Error> {
    let path = root.join("coord-federation.json");
    if !path.try_exists()? {
        return Ok(None);
    }
    // Expired TLS input must remain editable. Validation belongs to broker check.
    let mut broker: nats::Broker = serde_json::from_value(read_json_file(&path)?)?;
    for path in [
        &mut broker.cert_file,
        &mut broker.key_file,
        &mut broker.ca_file,
    ]
    .into_iter()
    .flatten()
    {
        if path.is_relative() {
            *path = root.join(&*path);
        }
    }
    for peer in &mut broker.peers {
        if peer.credential_file.is_relative() {
            peer.credential_file = root.join(&peer.credential_file);
        }
    }
    Ok(Some(broker))
}

fn days(label: &str, default: &str) -> Result<i64, Error> {
    let days = ask(label, default)?.parse::<i64>()?;
    if days <= 0 {
        return Err("certificate lifetime must be positive".into());
    }
    Ok(days)
}

fn expiry(days: i64) -> Result<time::OffsetDateTime, Error> {
    let seconds = days
        .checked_mul(86400)
        .ok_or("certificate lifetime exceeds the supported timestamp range")?;
    time::OffsetDateTime::now_utc()
        .checked_add(time::Duration::seconds(seconds))
        .ok_or_else(|| "certificate lifetime exceeds the supported timestamp range".into())
}

fn material(root: &Path, broker: &mut nats::Broker) -> Result<(), Error> {
    let names = words(&ask(
        "Broker certificate names/IP addresses, comma-separated (include the local endpoint name)",
        &broker
            .local_server_name
            .clone()
            .unwrap_or_else(|| broker.listen.to_string()),
    )?);
    broker.local_server_name = Some(ask(
        "Local broker endpoint name",
        names.first().ok_or("select a certificate name")?,
    )?);
    broker.server_names = names.clone();
    let action = ask(
        "TLS material: generate dedicated CA, renew with current CA, import supplied material, or reuse saved material",
        if broker.cert_file.is_some() {
            "reuse"
        } else {
            "generate"
        },
    )?;
    match action.as_str() {
        "reuse" => {}
        "import" => {
            println!(
                "Select files on this broker's host. Keep the certificate's private key here. The interception CA/key cannot be used."
            );
            broker.cert_file =
                Some(PathBuf::from(ask("Broker certificate chain PEM", "")?).canonicalize()?);
            broker.key_file =
                Some(PathBuf::from(ask("Broker private key PEM", "")?).canonicalize()?);
            broker.ca_file = Some(PathBuf::from(ask("Trusted broker CA PEM", "")?).canonicalize()?);
        }
        "generate" | "renew" => {
            let parent = root.join("data/broker-tls");
            private_directory(&parent)?;
            let staging = tempfile::Builder::new()
                .prefix("material-")
                .tempdir_in(&parent)?;
            let ca_key;
            let mut ca_params = None;
            let mut ca_der = None;
            let mut old_ca = None;
            if action == "generate" {
                let mut params = CertificateParams::default();
                params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
                params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
                params.not_after = expiry(days("Dedicated CA lifetime in days", "3650")?)?;
                params
                    .distinguished_name
                    .push(rcgen::DnType::CommonName, "SafeYolo dedicated broker CA");
                let key = KeyPair::generate()?;
                let ca = params.self_signed(&key)?;
                write_new(&staging.path().join("ca.pem"), ca.pem().as_bytes())?;
                write_new(
                    &staging.path().join("ca.key"),
                    key.serialize_pem().as_bytes(),
                )?;
                ca_key = key;
                ca_params = Some(params);
            } else {
                let ca = broker
                    .ca_file
                    .as_ref()
                    .ok_or("no saved broker CA; select import or generate")?
                    .canonicalize()?;
                let default_key = ca.with_extension("key");
                let key = PathBuf::from(ask(
                    "Owner-held CA signing key (organizational renewal can use import instead)",
                    &default_key.to_string_lossy(),
                )?);
                ca_der = tls_material::certificates(&ca)?.into_iter().next();
                ca_key = KeyPair::from_pem(&fs::read_to_string(key)?)?;
                old_ca = Some(ca);
            }
            let issuer = if let Some(params) = &ca_params {
                Issuer::from_params(params, &ca_key)
            } else {
                Issuer::from_ca_cert_der(ca_der.as_ref().ok_or("missing CA certificate")?, &ca_key)?
            };
            let key = KeyPair::generate()?;
            let mut params = CertificateParams::new(names)?;
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
            params.not_after = expiry(days("Broker leaf lifetime in days", "365")?)?;
            write_new(
                &staging.path().join("broker.pem"),
                params.signed_by(&key, &issuer)?.pem().as_bytes(),
            )?;
            write_new(
                &staging.path().join("broker.key"),
                key.serialize_pem().as_bytes(),
            )?;
            let directory = staging.keep();
            broker.cert_file = Some(directory.join("broker.pem"));
            broker.key_file = Some(directory.join("broker.key"));
            broker.ca_file = Some(old_ca.unwrap_or_else(|| directory.join("ca.pem")));
            println!(
                "Dedicated material retained on this owner at {}. If interrupted before apply, select import and these files on return. Private keys were not exported.",
                safe(&directory.to_string_lossy())
            );
        }
        _ => return Err("select generate, renew, import or reuse".into()),
    }
    // Existing validation checks current expiry, names, key matching and separation.
    let mut names = broker.server_names.clone();
    names.push(
        broker
            .local_server_name
            .clone()
            .ok_or("local TLS name missing")?,
    );
    let result = tls_material::validate(
        broker
            .cert_file
            .as_deref()
            .ok_or("broker certificate missing")?,
        broker.key_file.as_deref().ok_or("broker key missing")?,
        broker.ca_file.as_deref().ok_or("broker CA missing")?,
        &names,
    )?;
    println!(
        "Certificate valid from {} until {}",
        safe(text(&result["not_before"])),
        safe(text(&result["not_after"]))
    );
    Ok(())
}

async fn broker(root: &Path) -> Result<(), Error> {
    let owner = identity(root)?;
    println!(
        "Destination owner: {} at {}",
        safe(&owner.instance_id),
        safe(&owner.root.to_string_lossy())
    );
    let source = choose_identity(
        root,
        "Source instance root or authenticated public identity file",
    )?;
    if source.instance_id == owner.instance_id {
        return Err("select a different, independently initialized source instance".into());
    }
    let before = saved_broker(root)?;
    let current_mode = before
        .as_ref()
        .map(|b| match b.mode {
            Mode::Tls => "tls",
            Mode::Tailscale => "tailscale",
            Mode::Loopback => "loopback",
        })
        .unwrap_or("tls");
    let mode = match ask(
        "Endpoint protection: tls, tailscale or loopback",
        current_mode,
    )?
    .as_str()
    {
        "tls" => Mode::Tls,
        "tailscale" => Mode::Tailscale,
        "loopback" => Mode::Loopback,
        _ => return Err("select tls, tailscale or loopback".into()),
    };
    let mut broker = before.clone().unwrap_or(nats::Broker {
        mode,
        listen: "127.0.0.1".parse()?,
        cert_file: None,
        key_file: None,
        ca_file: None,
        ca_sha256: None,
        local_server_name: None,
        server_names: Vec::new(),
        tailscale_node: None,
        peers: Vec::new(),
    });
    broker.mode = mode;
    let tailscale = if mode == Mode::Tailscale {
        let status = crate::tailnet::tailscale_json(&["status", "--json"]).await?;
        let node = status["Self"]["ID"]
            .as_str()
            .ok_or("this host's Tailscale identity is unavailable")?
            .to_owned();
        let addresses = strings(&status["Self"]["TailscaleIPs"]);
        println!(
            "This host's Tailscale node: {} ({}). Assigned addresses: {}",
            safe(&node),
            safe(text(&status["Self"]["DNSName"])),
            safe(&addresses)
        );
        Some((
            node,
            words(&addresses)
                .into_iter()
                .next()
                .ok_or("no assigned Tailscale address")?,
        ))
    } else {
        None
    };
    broker.listen = ask(
        "Broker listen IP address (only this explicit selection changes the listener)",
        &tailscale
            .as_ref()
            .map(|(_, address)| address.clone())
            .unwrap_or_else(|| broker.listen.to_string()),
    )?
    .parse()?;
    broker.tailscale_node = tailscale.map(|(node, _)| node);
    if mode == Mode::Tls {
        material(root, &mut broker)?;
    } else {
        broker.cert_file = None;
        broker.key_file = None;
        broker.ca_file = None;
        broker.ca_sha256 = None;
        broker.local_server_name = None;
        broker.server_names.clear();
    }
    let data = root.join("data/federation");
    private_directory(&data)?;
    let old_peer = broker
        .peers
        .iter()
        .find(|p| p.instance_id == source.instance_id)
        .cloned();
    let rotate_credential = old_peer.is_some()
        && yes(
            "Rotate this source's broker credential? Old support/approval grants then need an explicit new grant",
            false,
        )?;
    let credential = if !rotate_credential {
        old_peer.as_ref().map(|p| p.credential_file.clone())
    } else {
        None
    }
    .unwrap_or_else(|| data.join(format!("peer-{}.token", uuid::Uuid::new_v4().simple())));
    if !credential.try_exists()? {
        federation(
            root,
            &[
                "credential".into(),
                credential.to_string_lossy().into_owned(),
            ],
        )
        .await?;
        println!(
            "Scoped peer credential created on this owner. Rerunning setup reuses the saved peer credential."
        );
    }
    broker.peers.retain(|p| p.instance_id != source.instance_id);
    broker.peers.push(nats::Peer {
        instance_id: source.instance_id.clone(),
        credential_file: credential.clone(),
    });
    let status = crate::coord_rooms::status(root).await?;
    let port = ask(
        "Owned broker client port (repeat on activation)",
        &status["process"]["client_port"]
            .as_u64()
            .unwrap_or(4222)
            .to_string(),
    )?
    .parse::<u16>()?;
    if port == 0 {
        return Err("select a nonzero port".into());
    }
    let url = ask("Source-visible broker URL", &broker.endpoint(port).url)?;
    let endpoint = endpoint::Endpoint {
        mode,
        url: url.clone(),
        ca_file: broker.ca_file.clone(),
        ca_sha256: None,
        tailscale_node: broker.tailscale_node.clone(),
    };
    endpoint.origin()?;
    if mode == Mode::Tls {
        tls_material::validate(
            broker.cert_file.as_deref().unwrap(),
            broker.key_file.as_deref().unwrap(),
            broker.ca_file.as_deref().unwrap(),
            &[endpoint
                .origin()?
                .host()
                .ok_or("endpoint name missing")?
                .trim_matches(['[', ']'])
                .to_owned()],
        )?;
    }
    let changed_ca = before
        .as_ref()
        .and_then(|b| b.ca_sha256.as_deref())
        .zip(
            broker
                .ca_file
                .as_ref()
                .map(|p| tls_material::trust_hash(p))
                .transpose()?,
        )
        .is_some_and(|(old, new)| old != new);
    println!(
        "Direction: source {} ({}) → destination {} ({})\nListener before: {}\nListener after: {}:{} ({:?})\nSource endpoint: {}",
        safe(&source.instance_id),
        safe(&source.root.to_string_lossy()),
        safe(&owner.instance_id),
        safe(&owner.root.to_string_lossy()),
        before.as_ref().map_or_else(
            || "local default".into(),
            |b| format!("{} ({:?})", b.listen, b.mode)
        ),
        broker.listen,
        port,
        mode,
        safe(&url)
    );
    println!(
        "Trust changes: destination trusts only this source's scoped credential. No reverse route or room/support/approval authority is added.\nActivation: restart this owner's proxy and Coord; existing requests/agents can be interrupted. Tailnet policy is unchanged.\nCA trust changed: {changed_ca}; peer credential rotated: {rotate_credential}. Other source home routes need the new CA after CA rotation. Old grants stay invalid after credential rotation."
    );
    let mut input = tempfile::NamedTempFile::new_in(&data)?;
    input.write_all(&serde_json::to_vec(&broker)?)?;
    let mut check = vec![
        "broker".into(),
        "check".into(),
        input.path().to_string_lossy().into_owned(),
    ];
    if changed_ca {
        check.push("--rotate-trust".into());
    }
    let preview = federation(root, &check).await?;
    println!(
        "Backend validation: {}",
        context_json(&preview["protection"])?
    );
    if !yes(
        "Save this directional broker configuration and trust?",
        false,
    )? {
        println!(
            "No broker configuration or trust applied. Generated material remains on its owner for reuse."
        );
        return Ok(());
    }
    check[1] = "apply".into();
    let saved = federation(root, &check).await?;
    println!(
        "Owner broker configuration saved. Active: {}. Restart required: {}.",
        saved["active"], saved["restart_required"]
    );
    // Separate durable steps are intentionally observable after interruption.
    // Reusing the same token is idempotent and does not advance trust epochs.
    let trust = federation(
        root,
        &[
            "trust".into(),
            source.instance_id.clone(),
            credential.to_string_lossy().into_owned(),
        ],
    )
    .await?;
    println!(
        "Owner trust saved, generation {}. Source route has not been installed.",
        trust["epoch"]
    );
    let output = PathBuf::from(ask(
        "New private connection handoff directory to send through your authenticated administrative channel",
        &data
            .join(format!("handoff-{}", uuid::Uuid::new_v4().simple()))
            .to_string_lossy(),
    )?);
    if output.try_exists()? {
        return Err("handoff directory already exists; choose a new path. Saved owner steps remain; do not overwrite another handoff".into());
    }
    private_directory(&output)?;
    fs::copy(&credential, output.join("credential"))?;
    fs::set_permissions(output.join("credential"), fs::Permissions::from_mode(0o600))?;
    let ca_pem = broker
        .ca_file
        .as_ref()
        .map(fs::read_to_string)
        .transpose()?;
    let handoff = Handoff {
        schema: "safeyolo.connection-handoff/v1".into(),
        owner,
        source,
        mode,
        url,
        tailscale_node: broker.tailscale_node,
        ca_pem,
    };
    write_new(
        &output.join("connection.json"),
        &serde_json::to_vec_pretty(&handoff)?,
    )?;
    println!(
        "Private handoff saved at {}. It contains the scoped broker credential and public CA only. Keep broker and CA private keys here. On the source, run configure connection and select import. This is a partial cross-host setup until that source installs its route and verification succeeds.",
        safe(&output.to_string_lossy())
    );
    println!(
        "On this owner, return to configure connection and select activate. Select client port {port} and the existing distinct monitor port. Then verify here and on each source. Saved configuration is not activation."
    );
    Ok(())
}

async fn import(root: &Path) -> Result<(), Error> {
    let local = identity(root)?;
    println!(
        "Use only a handoff received through an authenticated administrative channel. This pins its destination identity and owning root; filenames do not authenticate it."
    );
    let directory = PathBuf::from(ask("Received private connection handoff directory", "")?);
    let handoff: Handoff =
        serde_json::from_value(read_json_file(&directory.join("connection.json"))?)?;
    validate_identity(&handoff.owner)?;
    validate_identity(&handoff.source)?;
    if handoff.schema != "safeyolo.connection-handoff/v1"
        || handoff.source.instance_id != local.instance_id
    {
        return Err("handoff is not addressed to this durable source instance".into());
    }
    let name = ask("Saved home route name", "primary")?;
    let data = root.join("data/federation");
    private_directory(&data)?;
    let staging = tempfile::Builder::new()
        .prefix("received-")
        .tempdir_in(&data)?;
    let credential = zeroize::Zeroizing::new(fs::read(directory.join("credential"))?);
    write_new(&staging.path().join("credential"), &credential)?;
    if let Some(pem) = &handoff.ca_pem {
        write_new(&staging.path().join("ca.pem"), pem.as_bytes())?;
    }
    let endpoint = endpoint::Endpoint {
        mode: handoff.mode,
        url: handoff.url.clone(),
        ca_file: handoff
            .ca_pem
            .as_ref()
            .map(|_| staging.path().join("ca.pem")),
        ca_sha256: None,
        tailscale_node: handoff.tailscale_node.clone(),
    };
    endpoint.origin()?;
    let conn = crate::coord_rooms::open(root)?;
    let old: Option<(String, String, Option<String>)> = conn
        .query_row(
            "SELECT instance_id,url,trust_hash FROM coord_federation_homes WHERE name=?1",
            [&name],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let trust = endpoint
        .ca_file
        .as_ref()
        .map(|p| tls_material::trust_hash(p))
        .transpose()?;
    let rotate = old
        .as_ref()
        .and_then(|v| v.2.as_ref())
        .zip(trust.as_ref())
        .is_some_and(|(a, b)| a != b);
    println!(
        "Source: {} ({})\nDestination: {} ({})\nRoute {} before: {}\nAfter: {} ({:?})\nCA trust rotation: {}\nActivation: next request; no local listener change or reverse connectivity. Route removal, trust revocation, credential rotation and grant revocation are separate operations.",
        safe(&local.instance_id),
        safe(&local.root.to_string_lossy()),
        safe(&handoff.owner.instance_id),
        safe(&handoff.owner.root.to_string_lossy()),
        safe(&name),
        old.as_ref()
            .map_or_else(|| "none".into(), |v| format!("{} at {}", v.0, v.1)),
        safe(&handoff.url),
        handoff.mode,
        rotate
    );
    if !yes(
        "Install this exact destination and trust from the authenticated handoff?",
        false,
    )? {
        return Ok(());
    }
    let staged = staging.keep();
    let mut args = vec![
        "home".into(),
        name.clone(),
        handoff.owner.instance_id,
        match handoff.mode {
            Mode::Tls => "tls",
            Mode::Tailscale => "tailscale",
            Mode::Loopback => "loopback",
        }
        .into(),
        handoff.url,
    ];
    match handoff.mode {
        Mode::Tls => args.push(staged.join("ca.pem").to_string_lossy().into_owned()),
        Mode::Tailscale => args.push(
            handoff
                .tailscale_node
                .ok_or("missing stable Tailscale node")?,
        ),
        Mode::Loopback => {}
    }
    args.push(staged.join("credential").to_string_lossy().into_owned());
    if rotate {
        args.push("--rotate-trust".into());
    }
    let result = federation(root, &args).await?;
    println!(
        "Source route saved for {}. Activation: {}",
        safe(&name),
        safe(text(&result["activation"]))
    );
    show_check(&federation(root, &["check".into(), name]).await?)
}

fn show_check(value: &Value) -> Result<(), Error> {
    for (label, key) in [
        ("Configuration", "configured"),
        ("Configured settings active", "configuration_active"),
        ("Endpoint protection", "protection"),
        ("Broker authentication", "broker_authentication"),
        ("Owning instance / Core request-reply", "owner"),
        ("Notification availability", "notifications"),
        ("Applicable operation authority", "operation_permission"),
        ("Owner observation/transport diagnostics", "runtime"),
        ("Recovery", "recovery"),
    ] {
        if let Some(value) = value.get(key) {
            println!(
                "{label}: {}",
                if value.is_null() {
                    "unknown; not verified".into()
                } else {
                    context_json(value)?
                }
            );
        }
    }
    println!(
        "A saved route or authenticated broker does not establish operation authority, retained event delivery or model progress. Use the selected support agent's authorized inspection to verify access; no repair operation was manufactured."
    );
    Ok(())
}

pub(super) async fn run(root: &Path) -> Result<(), Error> {
    println!(
        "Selected instance: {} at {}",
        safe(&identity(root)?.instance_id),
        safe(&root.canonicalize()?.to_string_lossy())
    );
    println!(
        "broker: prepare/update the destination listener, trust and authenticated handoff; also renew/import/rotate TLS or peer credentials.\nimport: install a handoff on its addressed source.\nactivate: restart this owner's proxy and Coord with selected ports.\nverify: check the local endpoint or a saved source home route.\nBroker setup never claims an atomic cross-host transaction."
    );
    match ask("Connection action", "verify")?.as_str() {
        "broker" => broker(root).await,
        "import" => import(root).await,
        "activate" => activate(root).await,
        "verify" => {
            let home = ask("Saved home route, or local", "local")?;
            let mut args = vec!["check".into()];
            if home != "local" {
                args.push(home);
            }
            show_check(&federation(root, &args).await?)
        }
        _ => Err("select broker, import, activate or verify".into()),
    }
}

async fn activate(root: &Path) -> Result<(), Error> {
    let state = crate::coord_rooms::status(root).await?;
    let client = ask(
        "Broker client port",
        &state["process"]["client_port"]
            .as_u64()
            .unwrap_or(4222)
            .to_string(),
    )?
    .parse::<u16>()?;
    let monitor = ask(
        "Loopback monitor port (distinct for each instance)",
        &state["process"]["monitor_port"]
            .as_u64()
            .unwrap_or(8222)
            .to_string(),
    )?
    .parse::<u16>()?;
    if client == 0 || monitor == 0 || client == monitor {
        return Err("select distinct nonzero client and monitor ports".into());
    }
    println!(
        "This stops only this owner's proxy and owned Coord broker, starts Coord on client port {client} and loopback monitor port {monitor}, then starts this proxy. Running guests remain. Requests and feeds can be interrupted. A failed step leaves earlier steps in effect; rerun verify and inspect the reported owner before recovery."
    );
    if !yes(
        "Activate this owner's saved broker configuration now?",
        false,
    )? {
        return Ok(());
    }
    let config = root.join("config.toml");
    let code = crate::host_commands::run(config.clone(), &["stop".into()]).await?;
    if code != 0 {
        return Err("proxy stop failed; activation stopped before changing Coord".into());
    }
    crate::coord_rooms::stop(root).await?;
    println!("Owner proxy and Coord stopped.");
    crate::coord_rooms::start(root, None, Some(client), Some(monitor)).await?;
    println!("Owner Coord started; proxy activation is next.");
    let code = crate::host_commands::run(config, &["start".into()]).await?;
    if code != 0 {
        return Err(
            "Coord started but proxy start failed; inspect this owner's proxy log before recovery"
                .into(),
        );
    }
    show_check(&federation(root, &["check".into()]).await?)
}
