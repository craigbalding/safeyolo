//! Operator trust and room grants for explicitly federated SafeYolo agents.
use super::*;
use crate::agent_api::coord::{public_name_part, valid_agent_id};
use rustls::pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};
pub(crate) mod configuration;
pub(crate) mod endpoint;
pub(crate) mod nats;
mod tailscale;
pub(crate) mod tls_material;

pub(crate) const HELP: &str = "safeyolo [--root ROOT] coord federation peers\nsafeyolo [--root ROOT] coord federation credential PATH\nsafeyolo [--root ROOT] coord federation trust INSTANCE TOKEN_FILE\nsafeyolo [--root ROOT] coord federation revoke INSTANCE\nsafeyolo [--root ROOT] coord federation member ROOM INSTANCE AGENT_ID DISPLAY_NAME [send] [receive] [page_operator] [--operation-id ID]\nsafeyolo [--root ROOT] coord federation unmember ROOM INSTANCE AGENT_ID [--operation-id ID]\nsafeyolo [--root ROOT] coord federation home NAME INSTANCE [tls] TLS_NATS_URL CA_FILE TOKEN_FILE [--rotate-trust]\nsafeyolo [--root ROOT] coord federation home NAME INSTANCE tailscale NATS_IP_URL NODE_ID TOKEN_FILE\nsafeyolo [--root ROOT] coord federation home NAME INSTANCE loopback NATS_IP_URL TOKEN_FILE\nsafeyolo [--root ROOT] coord federation unhome NAME\nsafeyolo [--root ROOT] coord federation broker check|apply FILE [--rotate-trust]\nsafeyolo [--root ROOT] coord federation check [HOME]\n\nConfigure the destination's host-held coord-federation.json before starting its managed NATS and proxy. Select mode tls (default), tailscale or loopback. TLS requires dedicated cert_file, key_file, ca_file and local_server_name; server_names lists additional certificate names to validate. Tailscale requires a literal listen address assigned to this host's selected tailscale_node stable ID. Loopback requires a literal loopback listen address. Remove TLS-only fields for non-TLS modes. Monitoring stays on loopback.\nBroker check validates supplied material without saving. Broker apply saves configuration, reports trust changes and requires an owned Coord/proxy restart; it does not claim activation. Leaf renewal under the same CA retains credentials and grants. CA rotation requires --rotate-trust; update client routes explicitly. Credential rotation through trust advances the existing peer generation; old support and approval grants do not regain authority. Check separates configured/active endpoints, protection, broker authentication, owner reachability and notification stream availability. It does not grant or prove operation permission.\nCredentials stay host-held. Peers have scoped SY_FED subjects; SY_LOCAL has no exports. Selected Tailscale node identity, host route and WireGuard reachability are checked before credentials on initial connections and reconnects. Broker advertisements cannot add destinations. Subnet-router onward legs require TLS. There is no mode fallback. Tailnet membership grants no instance or agent authority. Guests use only their local Agent API. Trust alone grants neither room nor target access. revoke disables the peer and revokes memberships; re-trust restores neither memberships nor old target grants. Omitted home remains local. NATS remains the only inter-instance transport.";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RemoteAgent {
    pub instance_id: String,
    pub agent_id: String,
    pub principal_id: String,
    pub display_name: String,
    pub epoch: i64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Home {
    pub instance_id: String,
    pub url: String,
    pub ca_file: PathBuf,
    pub token_file: PathBuf,
    pub revision: String,
    #[serde(default)]
    pub mode: endpoint::Mode,
    #[serde(default)]
    pub tailscale_node: Option<String>,
    pub ca_sha256: Option<String>,
}

impl Home {
    pub fn endpoint(&self) -> endpoint::Endpoint {
        endpoint::Endpoint {
            mode: self.mode,
            url: self.url.clone(),
            ca_file: (self.mode == endpoint::Mode::Tls).then(|| self.ca_file.clone()),
            ca_sha256: self.ca_sha256.clone(),
            tailscale_node: self.tailscale_node.clone(),
        }
    }
}

pub(crate) fn principal(instance: &str, agent: &str) -> String {
    // Length-prefix both operands: a peer cannot select a local principal or
    // collide with another peer by choosing an ambiguous concatenation.
    format!(
        "ag-fed-{}",
        hash(format!("{}:{instance}{agent}", instance.len()).as_bytes())
    )
}

pub(crate) fn token(path: &Path) -> Result<zeroize::Zeroizing<String>, Error> {
    let token = zeroize::Zeroizing::new(fs::read_to_string(path)?);
    if token.trim().is_empty() || token.trim().bytes().any(|b| !b.is_ascii_graphic()) {
        return Err("federation credential must contain printable non-space bytes".into());
    }
    Ok(token)
}

pub(crate) fn authenticate_transport(
    conn: &Connection,
    instance: &str,
    credential_hash: &str,
    agent: &str,
) -> Result<RemoteAgent, Error> {
    if !valid_agent_id(agent) {
        return Err("invalid remote agent identity".into());
    }
    let epoch = conn.query_row("SELECT epoch FROM coord_federation_peers WHERE instance_id=?1 AND token_hash=?2 AND enabled=1",params![instance,credential_hash],|row|row.get(0))?;
    let principal_id = principal(instance, agent);
    let display_name=conn.query_row("SELECT display_name FROM coord_federation_agents WHERE principal_id=?1 AND instance_id=?2 AND agent_id=?3",params![principal_id,instance,agent],|row|row.get(0))?;
    Ok(RemoteAgent {
        instance_id: instance.into(),
        agent_id: agent.into(),
        principal_id,
        display_name,
        epoch,
    })
}

pub(crate) fn registration_available(
    conn: &Connection,
    policy: &crate::policy::Policy,
    instance: &str,
    agent: &str,
    name: &str,
) -> Result<(), Error> {
    if !valid_agent_id(agent) || !public_name_part(name) || policy.evidence_agent_id(name).is_some()
    {
        return Err("choose a valid remote handle distinct from local agents".into());
    }
    let id = principal(instance, agent);
    let old: Option<String> = conn
        .query_row(
            "SELECT principal_id FROM coord_federation_agents WHERE display_name=?1",
            [name],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(old) = old.filter(|old| old != &id) {
        let member:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM memberships WHERE principal_kind='agent' AND principal_id=?1 AND revoked_at IS NULL)",[&old],|row|row.get(0))?;
        let mut support = false;
        for grant in policy
            .support_grants()
            .values()
            .filter(|grant| grant.active())
        {
            if let Some(instance) = &grant.support_instance_id
                && principal(instance, &grant.support.agent_id) == old
            {
                support|=conn.query_row("SELECT EXISTS(SELECT 1 FROM coord_federation_peers WHERE instance_id=?1 AND enabled=1 AND epoch=?2)",params![instance,grant.support_peer_epoch],|row|row.get::<_,bool>(0))?;
            }
        }
        for delegation in policy
            .delegations()
            .values()
            .filter(|delegation| delegation.current())
        {
            for reviewer in &delegation.reviewers {
                if let Some(instance) = &reviewer.instance_id
                    && principal(instance, &reviewer.agent_id) == old
                {
                    support |= conn.query_row("SELECT EXISTS(SELECT 1 FROM coord_federation_peers WHERE instance_id=?1 AND enabled=1 AND epoch=?2)", params![instance,reviewer.peer_epoch], |row| row.get::<_,bool>(0))?;
                }
            }
        }
        if member || support {
            return Err("remote display handle is held by an identity with active grants".into());
        }
    }
    Ok(())
}

pub(crate) fn register(
    conn: &Connection,
    policy: &crate::policy::Policy,
    instance: &str,
    agent: &str,
    name: &str,
) -> Result<(), Error> {
    registration_available(conn, policy, instance, agent, name)?;
    let id = principal(instance, agent);
    conn.execute(
        "DELETE FROM coord_federation_agents WHERE display_name=?1 AND principal_id<>?2",
        params![name, id],
    )?;
    conn.execute("INSERT INTO coord_federation_agents VALUES(?1,?2,?3,?4) ON CONFLICT(principal_id) DO UPDATE SET display_name=excluded.display_name",params![id,instance,agent,name])?;
    Ok(())
}

#[cfg(test)]
fn authenticate(conn: &Connection, credential: &[u8], agent: &str) -> Result<RemoteAgent, Error> {
    if !valid_agent_id(agent) {
        return Err("invalid remote agent identity".into());
    }
    let token_hash = hash(credential);
    let (instance, epoch): (String, i64) = conn.query_row(
        "SELECT instance_id,epoch FROM coord_federation_peers WHERE token_hash=?1 AND enabled=1",
        [token_hash],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let principal_id = principal(&instance, agent);
    let name: String = conn.query_row(
        "SELECT display_name FROM coord_federation_agents WHERE principal_id=?1 AND instance_id=?2 AND agent_id=?3",
        params![principal_id,instance,agent], |r| r.get(0),
    )?;
    Ok(RemoteAgent {
        instance_id: instance,
        agent_id: agent.into(),
        principal_id,
        display_name: name,
        epoch,
    })
}

pub(crate) fn authorize(conn: &Connection, remote: &RemoteAgent) -> Result<(), Error> {
    if !conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM coord_federation_peers WHERE instance_id=?1 AND enabled=1 AND epoch=?2)",
        params![remote.instance_id, remote.epoch], |r| r.get::<_,bool>(0),
    )? {
        return Err("federation access changed".into());
    }
    Ok(())
}

pub(crate) fn home(conn: &Connection, name: &str) -> Result<Home, Error> {
    conn.query_row(
        "SELECT instance_id,url,ca_file,token_file,revision,mode,tailscale_node,trust_hash FROM coord_federation_homes WHERE name=?1", [name],
        |r| Ok(Home { instance_id:r.get(0)?,url:r.get(1)?,ca_file:PathBuf::from(r.get::<_,String>(2)?),token_file:PathBuf::from(r.get::<_,String>(3)?),revision:r.get(4)?, mode: match r.get::<_,String>(5)?.as_str() { "tls"=>endpoint::Mode::Tls,"tailscale"=>endpoint::Mode::Tailscale,"loopback"=>endpoint::Mode::Loopback,_=>return Err(rusqlite::Error::InvalidQuery) },tailscale_node:r.get(6)?,ca_sha256:r.get(7)? }),
    ).map_err(Into::into)
}

pub(crate) fn names(conn: &Connection) -> Result<Vec<(String, String, String, String)>, Error> {
    Ok(conn.prepare("SELECT a.principal_id,a.display_name,a.instance_id,a.agent_id FROM coord_federation_agents a JOIN coord_federation_peers p USING(instance_id) WHERE p.enabled=1")?
        .query_map([], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?
        .collect::<Result<_,_>>()?)
}

pub(crate) async fn run(root: &Path, arguments: &[String]) -> Result<Value, Error> {
    if arguments.is_empty() || arguments == ["--help"] {
        println!("{HELP}");
        return Ok(Value::Null);
    }
    bootstrap(root)?;
    if let Some(result) = configuration::run(root, arguments).await? {
        return Ok(result);
    }
    let mut conn = open(root)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let (arguments, operation_id) = match arguments {
        [arguments @ .., flag, id] if flag == "--operation-id" => (arguments, id.clone()),
        arguments => (arguments, uuid::Uuid::new_v4().simple().to_string()),
    };
    let result = match arguments {
        [command] if command == "peers" => {
            let peers = tx.prepare("SELECT instance_id,epoch,enabled FROM coord_federation_peers ORDER BY instance_id")?
                .query_map([], |row| Ok(json!({"instance_id":row.get::<_,String>(0)?,"epoch":row.get::<_,i64>(1)?,"trusted":row.get::<_,bool>(2)?})))?
                .collect::<std::result::Result<Vec<_>,_>>()?;
            json!({"peers":peers})
        }
        [command, path] if command == "credential" => {
            use std::io::Write;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            let secret = zeroize::Zeroizing::new(format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ));
            file.write_all(secret.as_bytes())?;
            file.sync_all()?;
            json!({"created":true})
        }
        [command, instance, path] if command == "trust" => {
            if instance.is_empty() || instance.chars().any(char::is_control) {
                return Err("invalid peer instance ID".into());
            }
            let own: String = tx.query_row("SELECT id FROM instance", [], |r| r.get(0))?;
            if instance == &own {
                return Err("a federation peer must be another instance".into());
            }
            let credential = token(Path::new(path))?;
            let digest = hash(credential.trim().as_bytes());
            if tx.query_row("SELECT EXISTS(SELECT 1 FROM coord_federation_peers WHERE token_hash=?1 AND instance_id<>?2)",params![digest,instance],|r|r.get::<_,bool>(0))? {
                return Err("federation peers require distinct credentials".into());
            }
            tx.execute("INSERT INTO coord_federation_peers VALUES(?1,?2,1,1) ON CONFLICT(instance_id) DO UPDATE SET token_hash=excluded.token_hash,epoch=CASE WHEN enabled=1 AND token_hash=excluded.token_hash THEN epoch ELSE epoch+1 END,enabled=1",params![instance,digest])?;
            let epoch: i64 = tx.query_row(
                "SELECT epoch FROM coord_federation_peers WHERE instance_id=?1",
                [instance],
                |row| row.get(0),
            )?;
            json!({"instance_id":instance,"trusted":true,"epoch":epoch,"activation":"If broker credentials changed, restart this instance's Coord and proxy after updating the scoped broker peer file. Support and approval grants from a previous trust generation remain invalid; explicitly grant current authority where required."})
        }
        [command, instance] if command == "revoke" => {
            tx.execute("UPDATE coord_federation_peers SET enabled=0,epoch=epoch+1 WHERE instance_id=?1 AND enabled=1",[instance])?;
            let revoked=tx.execute("UPDATE memberships SET revoked_at=?2 WHERE principal_kind='agent' AND revoked_at IS NULL AND principal_id IN (SELECT principal_id FROM coord_federation_agents WHERE instance_id=?1)", params![instance,now()])?;
            json!({"instance_id":instance,"trusted":false,"revoked_memberships":revoked})
        }
        [command, room, instance, agent, rest @ ..]
            if command == "member" || command == "unmember" =>
        {
            if !valid_agent_id(agent) {
                return Err("invalid remote agent identity".into());
            }
            let id = principal(instance, agent);
            let revoke = command == "unmember";
            let (name, permissions) = if revoke {
                if !rest.is_empty() {
                    return Err(HELP.into());
                }
                (None, Vec::new())
            } else {
                let [name, permissions @ ..] = rest else {
                    return Err(HELP.into());
                };
                if !public_name_part(name) {
                    return Err("remote display name must be a public Coord name".into());
                }
                if !tx.query_row("SELECT EXISTS(SELECT 1 FROM coord_federation_peers WHERE instance_id=?1 AND enabled=1)",[instance],|r|r.get::<_,bool>(0))? {
                    return Err("trust the peer before granting room membership".into());
                }
                let config = crate::native_config::read(&root.join("config.toml"))?;
                let policy =
                    fs::read_to_string(config.policy_file.ok_or("policy path is missing")?)?
                        .parse::<toml_edit::DocumentMut>()?;
                if policy.get("agents").and_then(|a| a.get(name)).is_some() {
                    return Err("remote display name conflicts with a local agent".into());
                }
                (Some(name.as_str()), permissions.to_vec())
            };
            let room_id: String =
                tx.query_row("SELECT room_id FROM rooms WHERE name=?1", [room], |r| {
                    r.get(0)
                })?;
            let replay: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM coord_operations WHERE principal_kind='operator' AND principal_id='operator' AND operation_type=?1 AND operation_id=?2)",params![if revoke {"coord.revoke"} else {"coord.grant"},operation_id],|r|r.get(0))?;
            let result = membership::change(
                &tx,
                &room_id,
                "agent",
                &id,
                &permissions,
                revoke,
                &operation_id,
                name,
            )?;
            if !replay && let Some(name) = name {
                // Reuse a display name after its former principal's last grant
                // ends. The same transaction preserves immutable authorship and
                // prevents replay from restoring the obsolete binding.
                let config = crate::native_config::read(&root.join("config.toml"))?;
                let policy = crate::policy::Policy::from_native_path(
                    &config.policy_file.ok_or("policy path missing")?,
                )?;
                register(&tx, &policy, instance, agent, name)?;
            }
            result
        }
        [command, name, instance, rest @ ..] if command == "home" => {
            if !public_name_part(name) {
                return Err("invalid home name".into());
            }
            let (endpoint, credential, rotate) = configuration::home_arguments(rest)?;
            let url = &endpoint.url;
            let ca = endpoint.ca_file.clone().unwrap_or_default();
            let credential = fs::canonicalize(credential)?;
            token(&credential)?;
            let trust_hash = endpoint
                .ca_file
                .as_ref()
                .map(|path| tls_material::trust_hash(path))
                .transpose()?;
            let old: Option<Option<String>> = tx
                .query_row(
                    "SELECT trust_hash FROM coord_federation_homes WHERE name=?1",
                    [name],
                    |row| row.get(0),
                )
                .optional()?;
            let changed_trust = old.as_ref().is_some_and(|old| {
                old.as_ref()
                    .zip(trust_hash.as_ref())
                    .is_some_and(|(old, new)| old != new)
            });
            if changed_trust && !rotate {
                return Err("home CA trust changed; repeat with --rotate-trust after verifying the owning instance's new CA".into());
            }
            tx.execute("INSERT INTO coord_federation_homes(name,instance_id,url,ca_file,token_file,revision,mode,tailscale_node,trust_hash) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(name) DO UPDATE SET instance_id=excluded.instance_id,url=excluded.url,ca_file=excluded.ca_file,token_file=excluded.token_file,revision=excluded.revision,mode=excluded.mode,tailscale_node=excluded.tailscale_node,trust_hash=excluded.trust_hash",params![name,instance,url.trim_end_matches('/'),ca.to_string_lossy(),credential.to_string_lossy(),uuid::Uuid::new_v4().simple().to_string(),serde_json::to_value(endpoint.mode)?.as_str(),endpoint.tailscale_node,trust_hash])?;
            json!({"home":name,"instance_id":instance,"configured":endpoint,"activation":"next_request","trust_changed":changed_trust,"authority":"route selection grants no room, support or approval authority"})
        }
        [command, name] if command == "unhome" => {
            tx.execute("DELETE FROM coord_federation_homes WHERE name=?1", [name])?;
            json!({"home":name,"removed":true})
        }
        _ => return Err(HELP.into()),
    };
    if arguments
        .first()
        .is_some_and(|command| matches!(command.as_str(), "trust" | "revoke" | "home" | "unhome"))
    {
        let event_id = format!("evt-{}", uuid::Uuid::new_v4().simple());
        let event = json!({"schema_version":crate::audit::SCHEMA_VERSION,"event_id":event_id,
            "ts":time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?,
            "event":"coord.federation_changed","kind":"coord","severity":"low","summary":"Coord federation access changed","addon":"coord",
            "details":{"actor":"operator","action":arguments[0],"result":result}});
        tx.execute("INSERT INTO coord_outbox(event_id,destination,event_type,payload_json,created_at) VALUES(?1,'audit-jsonl','coord.federation_changed',?2,?3)",params![event_id,event.to_string(),now()])?;
    }
    tx.commit()?;
    Ok(result)
}

#[cfg(test)]
mod tests;
