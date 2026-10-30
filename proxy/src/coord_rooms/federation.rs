//! Operator trust and room grants for explicitly federated SafeYolo agents.
use super::*;
use crate::agent_api::coord::{public_name_part, valid_agent_id};
use serde::{Deserialize, Serialize};

pub(crate) const HELP: &str = "safeyolo [--root ROOT] coord federation credential PATH\nsafeyolo [--root ROOT] coord federation trust INSTANCE TOKEN_FILE\nsafeyolo [--root ROOT] coord federation revoke INSTANCE\nsafeyolo [--root ROOT] coord federation member ROOM INSTANCE AGENT_ID DISPLAY_NAME [send] [receive] [page_operator] [--operation-id ID]\nsafeyolo [--root ROOT] coord federation unmember ROOM INSTANCE AGENT_ID [--operation-id ID]\nsafeyolo [--root ROOT] coord federation home NAME INSTANCE HTTPS_URL CA_FILE TOKEN_FILE\nsafeyolo [--root ROOT] coord federation unhome NAME\nsafeyolo [--root ROOT] coord federation serve LISTEN CERT_FILE KEY_FILE\n\nRun serve in the foreground on the room's home instance. Peers use host-held credentials and pinned home TLS trust. Trust alone grants no room access. member grants retained history using the existing room permissions. revoke atomically disables the peer and revokes its room memberships. Re-trust does not restore those memberships. Agents select an explicit home on ordinary Coord tools; omitted home remains local. NATS stays loopback-only and is never connected to a peer.";

#[derive(Clone)]
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

pub(crate) fn authenticate(
    conn: &Connection,
    credential: &[u8],
    agent: &str,
) -> Result<RemoteAgent, Error> {
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
        "SELECT instance_id,url,ca_file,token_file,revision FROM coord_federation_homes WHERE name=?1", [name],
        |r| Ok(Home { instance_id:r.get(0)?,url:r.get(1)?,ca_file:PathBuf::from(r.get::<_,String>(2)?),token_file:PathBuf::from(r.get::<_,String>(3)?),revision:r.get(4)? }),
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
    if let [command, listen, cert, key] = arguments
        && command == "serve"
    {
        return crate::agent_api::coord::federation::serve(
            root,
            listen,
            Path::new(cert),
            Path::new(key),
        )
        .await;
    }
    bootstrap(root)?;
    let mut conn = open(root)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let (arguments, operation_id) = match arguments {
        [arguments @ .., flag, id] if flag == "--operation-id" => (arguments, id.clone()),
        arguments => (arguments, uuid::Uuid::new_v4().simple().to_string()),
    };
    let result = match arguments {
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
            json!({"instance_id":instance,"trusted":true})
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
                tx.execute("INSERT INTO coord_federation_agents VALUES(?1,?2,?3,?4) ON CONFLICT(principal_id) DO UPDATE SET display_name=excluded.display_name",params![id,instance,agent,name])?;
            }
            result
        }
        [command, name, instance, url, ca, credential] if command == "home" => {
            if !public_name_part(name) {
                return Err("invalid home name".into());
            }
            let uri: hyper::Uri = url.parse()?;
            if uri.scheme_str() != Some("https")
                || uri.authority().is_none_or(|a| a.as_str().contains('@'))
                || uri.path_and_query().is_some_and(|p| p.as_str() != "/")
            {
                return Err(
                    "home URL must be an HTTPS origin without credentials, path or query".into(),
                );
            }
            let ca = fs::canonicalize(ca)?;
            let credential = fs::canonicalize(credential)?;
            token(&credential)?;
            // Parse pinned trust before recording a route that cannot start.
            crate::agent_api::coord::federation::pinned_tls(&ca)?;
            tx.execute("INSERT INTO coord_federation_homes VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(name) DO UPDATE SET instance_id=excluded.instance_id,url=excluded.url,ca_file=excluded.ca_file,token_file=excluded.token_file,revision=excluded.revision",params![name,instance,url.trim_end_matches('/'),ca.to_string_lossy(),credential.to_string_lossy(),uuid::Uuid::new_v4().simple().to_string()])?;
            json!({"home":name,"instance_id":instance})
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
