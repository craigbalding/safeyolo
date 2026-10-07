use crate::Error;
use serde_json::json;
use std::{
    collections::BTreeSet,
    net::IpAddr,
    path::{Path, PathBuf},
};
use toml_edit::{DocumentMut, Item};

#[derive(Clone)]
pub(super) struct Room {
    pub name: String,
    pub channel: String,
    pub backfill: bool,
}
#[derive(Clone)]
pub(super) struct Actions {
    pub host: IpAddr,
    pub port: u16,
    pub base: String,
    pub path: String,
    pub ttl: i64,
    pub trusted: Vec<String>,
}
impl Actions {
    pub fn callback_url(&self) -> String {
        format!("{}/mattermost/actions", self.base)
    }
    pub fn callback_path(&self) -> String {
        format!("{}/mattermost/actions", self.path)
    }
    pub fn health_path(&self) -> String {
        format!("{}/mattermost/healthz", self.path)
    }
}
#[derive(Clone)]
pub(super) struct Config {
    pub server: String,
    pub token: PathBuf,
    pub bot: String,
    pub operator: String,
    pub state: PathBuf,
    pub interval: std::time::Duration,
    pub rooms: Vec<Room>,
    pub actions: Option<Actions>,
    pub id: String,
}

pub(super) fn mm_id(value: &str) -> bool {
    value.len() == 26
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}
pub(super) fn coord_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|v| {
        v.len() == 32
            && v.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}
pub(super) fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

// Keep the retained adapter's ipaddress.is_global boundary, including the
// special-purpose ranges and their globally reachable exceptions. Multicast
// and global IPv4-mapped IPv6 are not newly forbidden by the native port.
fn global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, d] = ip.octets();
            !(matches!(a, 0 | 10 | 127 | 240..=255)
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192
                    && ((b == 0 && c == 0 && ![9, 10].contains(&d))
                        || (b == 0 && c == 2)
                        || b == 168))
                || (a == 198 && ([18, 19].contains(&b) || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return global_ip(IpAddr::V4(mapped));
            }
            let s = ip.segments();
            let exception = s[0] == 0x2001
                && ((s[1] == 1 && s[2..7].iter().all(|v| *v == 0) && [1, 2].contains(&s[7]))
                    || s[1] == 3
                    || (s[1] == 4 && s[2] == 0x112)
                    || [0x20, 0x30].contains(&(s[1] & 0xfff0)));
            !(ip.is_loopback()
                || ip.is_unspecified()
                || (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1)
                || (s[0] == 0x100 && s[1..4].iter().all(|v| *v == 0))
                || (s[0] == 0x2001 && s[1] < 0x200 && !exception)
                || (s[0] == 0x2001 && s[1] == 0xdb8)
                || s[0] == 0x2002
                || (s[0] == 0x3fff && s[1] & 0xf000 == 0)
                || s[0] & 0xfe00 == 0xfc00
                || s[0] & 0xffc0 == 0xfe80)
        }
    }
}

fn text<'a>(item: Option<&'a Item>, field: &str) -> Result<&'a str, Error> {
    item.and_then(Item::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("{field} must be a non-empty string").into())
}
fn path(value: &str, parent: &Path) -> Result<PathBuf, Error> {
    let path = if value == "~" || value.starts_with("~/") {
        PathBuf::from(std::env::var_os("HOME").ok_or("operator home is unavailable")?)
            .join(value.strip_prefix("~/").unwrap_or(""))
    } else {
        PathBuf::from(value)
    };
    let path = if path.is_absolute() {
        path
    } else {
        parent.join(path)
    };
    // Normalize lexical dot segments without following a final symlink.
    let mut absolute = PathBuf::new();
    for component in path.components() {
        if component == std::path::Component::ParentDir {
            absolute.pop();
        } else if component != std::path::Component::CurDir {
            absolute.push(component);
        }
    }
    Ok(absolute)
}
pub(super) fn https_url(value: &str, public: bool) -> Result<String, Error> {
    let uri: hyper::Uri = value.parse().map_err(|_| "invalid HTTPS URL")?;
    let authority = uri.authority().ok_or("HTTPS URL requires a host")?;
    let host = authority
        .host()
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    let uri_path = uri.path();
    if uri.scheme_str() != Some("https")
        || authority.as_str().contains('@')
        || value.contains(['?', '#'])
        || authority.as_str().ends_with(':')
        || (authority.port().is_some() && authority.port_u16().is_none())
        || authority.port_u16() == Some(0)
        || (!public && uri_path != "/" && !uri_path.is_empty())
        || (public
            && (uri_path.contains('%')
                || uri_path.contains("//")
                || uri_path.split('/').any(|v| {
                    v == "."
                        || v == ".."
                        || !v
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"._~-".contains(&c))
                })))
    {
        return Err("HTTPS URL has credentials, an invalid origin/path, query or fragment".into());
    }
    if public {
        let local = match host.parse::<IpAddr>() {
            Ok(ip) => !global_ip(ip),
            Err(_) => host == "localhost" || host.ends_with(".localhost"),
        };
        if local {
            return Err("public_callback_base_url host must be publicly routable".into());
        }
    }
    if host.parse::<IpAddr>().is_err()
        && (host.len() > 253
            || host.bytes().all(|c| c.is_ascii_digit() || c == b'.')
            || host.split('.').any(|v| {
                v.is_empty()
                    || v.len() > 63
                    || v.starts_with('-')
                    || v.ends_with('-')
                    || !v.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            }))
    {
        return Err("HTTPS URL has an invalid host".into());
    }
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    Ok(format!(
        "https://{host}{}{}",
        authority
            .port_u16()
            .map_or(String::new(), |v| format!(":{v}")),
        if public {
            uri_path.trim_end_matches('/')
        } else {
            ""
        }
    ))
}

impl Config {
    pub fn load(config_path: &Path) -> Result<Self, Error> {
        let config_path = if let Ok(relative) = config_path.strip_prefix("~") {
            PathBuf::from(std::env::var_os("HOME").ok_or("operator home is unavailable")?)
                .join(relative)
        } else if config_path.is_absolute() {
            config_path.to_owned()
        } else {
            std::env::current_dir()?.join(config_path)
        }
        .canonicalize()?;
        let document = std::fs::read_to_string(&config_path)?
            .parse::<DocumentMut>()
            .map_err(|_| "invalid Mattermost TOML configuration")?;
        let allowed = [
            "version",
            "server_url",
            "bot_token_file",
            "bot_user_id",
            "operator_user_id",
            "state_file",
            "poll_interval_seconds",
            "rooms",
            "action_listener_host",
            "action_listener_port",
            "public_callback_base_url",
            "action_capability_ttl_seconds",
            "trusted_action_agent_ids",
        ];
        if document.iter().any(|(k, _)| !allowed.contains(&k)) {
            return Err("unknown Mattermost configuration key".into());
        }
        if document.get("version").and_then(Item::as_integer) != Some(1) {
            return Err("Mattermost config version must be 1".into());
        }
        let parent = config_path.parent().ok_or("configuration has no parent")?;
        let server = https_url(text(document.get("server_url"), "server_url")?, false)?;
        let token = path(
            text(document.get("bot_token_file"), "bot_token_file")?,
            parent,
        )?;
        let state = path(text(document.get("state_file"), "state_file")?, parent)?;
        let bot = text(document.get("bot_user_id"), "bot_user_id")?.to_owned();
        let operator = text(document.get("operator_user_id"), "operator_user_id")?.to_owned();
        if !mm_id(&bot) || !mm_id(&operator) || bot == operator {
            return Err("bot and operator require distinct 26-character Mattermost IDs".into());
        }
        let interval = match document.get("poll_interval_seconds") {
            None => 2.0,
            Some(v) => v
                .as_float()
                .or_else(|| v.as_integer().map(|v| v as f64))
                .ok_or("poll_interval_seconds must be a number")?,
        };
        if !(0.5..=60.0).contains(&interval) {
            return Err("poll_interval_seconds must be between 0.5 and 60".into());
        }
        let tables = document
            .get("rooms")
            .and_then(Item::as_array_of_tables)
            .filter(|v| !v.is_empty())
            .ok_or("rooms requires at least one [[rooms]] mapping")?;
        let mut rooms = Vec::new();
        let mut names = BTreeSet::new();
        let mut channels = BTreeSet::new();
        for table in tables {
            if table
                .iter()
                .any(|(k, _)| !["coord_room", "channel_id", "backfill"].contains(&k))
            {
                return Err("unknown room mapping key".into());
            }
            let name = text(table.get("coord_room"), "coord_room")?.to_owned();
            let channel = text(table.get("channel_id"), "channel_id")?.to_owned();
            if name.is_empty()
                || name.len() > 128
                || !name.as_bytes()[0].is_ascii_alphanumeric()
                || !name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
                || !mm_id(&channel)
            {
                return Err("invalid room or channel ID".into());
            }
            if !names.insert(name.clone()) || !channels.insert(channel.clone()) {
                return Err("rooms and channels must form a one-to-one mapping".into());
            }
            let backfill = table
                .get("backfill")
                .map_or(Ok(false), |v| v.as_bool().ok_or("backfill must be boolean"))?;
            rooms.push(Room {
                name,
                channel,
                backfill,
            });
        }
        let action_keys = [
            "action_listener_host",
            "action_listener_port",
            "public_callback_base_url",
            "action_capability_ttl_seconds",
            "trusted_action_agent_ids",
        ];
        let actions = if action_keys.iter().any(|k| document.contains_key(k)) {
            let base = https_url(
                text(
                    document.get("public_callback_base_url"),
                    "public_callback_base_url",
                )?,
                true,
            )?;
            let host = document
                .get("action_listener_host")
                .map_or(Ok("127.0.0.1"), |v| text(Some(v), "action_listener_host"))?
                .parse::<IpAddr>()
                .map_err(|_| "listener host must be a loopback IP")?;
            if !host.is_loopback() {
                return Err("listener host must be a loopback IP".into());
            }
            let port = document.get("action_listener_port").map_or(Ok(8765), |v| {
                v.as_integer().ok_or("listener port must be an integer")
            })?;
            let ttl = document
                .get("action_capability_ttl_seconds")
                .map_or(Ok(86400), |v| {
                    v.as_integer().ok_or("capability TTL must be an integer")
                })?;
            if !(1024..=65535).contains(&port) || !(300..=604800).contains(&ttl) {
                return Err(
                    "listener port or capability TTL is outside its supported range".into(),
                );
            }
            let trusted = document
                .get("trusted_action_agent_ids")
                .and_then(Item::as_array)
                .filter(|v| !v.is_empty())
                .ok_or("trusted_action_agent_ids requires a non-empty array")?;
            let mut seen = BTreeSet::new();
            let mut trusted_ids = Vec::new();
            for value in trusted {
                let id = value.as_str().ok_or("invalid trusted canonical agent ID")?;
                if !coord_id(id, "ag-") || !seen.insert(id) {
                    return Err("invalid or duplicate trusted canonical agent ID".into());
                }
                trusted_ids.push(id.to_owned());
            }
            let path = base
                .parse::<hyper::Uri>()?
                .path()
                .trim_end_matches('/')
                .to_owned();
            Some(Actions {
                host,
                port: port as u16,
                base,
                path,
                ttl,
                trusted: trusted_ids,
            })
        } else {
            None
        };
        let identity = json!({"version":1,"server_url":server,"bot_user_id":bot,"operator_user_id":operator,"rooms":rooms.iter().map(|r| json!({"coord_room":r.name,"channel_id":r.channel})).collect::<Vec<_>>(),"actions":actions.as_ref().map(|a| json!({"host":a.host.to_string(),"port":a.port,"base":a.base,"ttl":a.ttl,"trusted":a.trusted}))});
        let id = crate::coord_setup::sha256(&serde_json::to_vec(&identity)?);
        Ok(Self {
            server,
            token,
            bot,
            operator,
            state,
            interval: std::time::Duration::from_secs_f64(interval),
            rooms,
            actions,
            id,
        })
    }
}
