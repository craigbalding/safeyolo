//! File-backed agent discovery reports. Accepted listener identities are supplied
//! explicitly; this component never resolves an identity from an IP address.

use std::{
    fs::{self, File},
    io::{Read, Write},
    os::fd::IntoRawFd,
    path::Path,
    sync::{Mutex, MutexGuard},
    time::UNIX_EPOCH,
};

use indexmap::IndexMap;
use num_bigint::{BigInt, ToBigInt};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    audit::{self, Event, Kind, Severity, Writer},
    circuits::{CircuitValue as C, ErrorKind as JsonError},
    network_guard::sanitize,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Attribute,
    Type,
    UnicodeDecode,
    Value,
    Permission,
    Io,
    Compatibility,
    Poisoned,
    Audit(audit::ErrorKind),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(ErrorKind);
impl Error {
    pub fn kind(self) -> ErrorKind {
        self.0
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("agent discovery operation failed")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

struct Document(C);
impl Drop for Document {
    fn drop(&mut self) {
        audit::wipe(&mut self.0);
    }
}
impl Default for Document {
    fn default() -> Self {
        Self(C::Object(IndexMap::new()))
    }
}

// Only JSON scalar dictionary keys are possible here. Keep their original value
// separately: Python's dict preserves the first equal key but replaces its owner.
#[derive(Hash, PartialEq, Eq)]
enum IpKey {
    Text(String),
    Integer(BigInt),
    Float(u64),
}
impl Drop for IpKey {
    fn drop(&mut self) {
        if let Self::Text(value) = self {
            value.zeroize();
        }
    }
}
impl IpKey {
    fn from_value(value: &C) -> Result<Self> {
        match value {
            C::Other(Value::String(value)) => Ok(Self::Text(value.clone())),
            C::Bool(value) => Ok(Self::Integer(BigInt::from(u8::from(*value)))),
            C::Integer(value) => Ok(Self::Integer(value.clone())),
            C::Float(value) if value.is_finite() && value.fract() == 0. => Ok(Self::Integer(
                value.to_bigint().expect("finite integral float"),
            )),
            // json.loads reuses its NaN constant, so repeated NaN tokens are the
            // same Python dictionary key despite NaN's numeric inequality.
            C::Float(value) => Ok(Self::Float(if value.is_nan() {
                f64::NAN.to_bits()
            } else {
                value.to_bits()
            })),
            C::Array(_) | C::Object(_) => Err(Error(ErrorKind::Type)),
            _ => Err(Error(ErrorKind::Compatibility)),
        }
    }
}
struct IpEntry {
    value: C,
    name: String,
}
impl Drop for IpEntry {
    fn drop(&mut self) {
        audit::wipe(&mut self.value);
        self.name.zeroize();
    }
}
#[derive(Default)]
struct State {
    path: String,
    mtime: f64,
    map: Document,
    reverse: IndexMap<IpKey, IpEntry>,
    last_seen: IndexMap<String, f64>,
}
impl Drop for State {
    fn drop(&mut self) {
        self.path.zeroize();
        for (mut name, _) in self.last_seen.drain(..) {
            name.zeroize();
        }
    }
}

/// One shared report owner, retained across runtime reloads. The reverse index
/// serves reports/discovery events only and is not exposed as an identity API.
#[derive(Default)]
pub struct AgentDiscovery {
    state: Mutex<State>,
}
impl AgentDiscovery {
    pub fn new() -> Self {
        Self::default()
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| Error(ErrorKind::Poisoned))
    }

    /// Call only when the map-file option is updated. Empty paths and failed
    /// loads retain prior map/mtime/last-seen state, as in source configure.
    pub fn configure(&self, path: &str, writer: &Writer) -> Result<()> {
        let mut state = self.lock()?;
        state.path.zeroize();
        state.path = path.into();
        reload(&mut state, writer)
    }
    /// Compare the actual configured path, including changes published before a
    /// failed configure. Runtime snapshots may still carry the preceding path.
    pub fn matches_path(&self, path: &str) -> Result<bool> {
        Ok(self.lock()?.path == path)
    }

    pub fn reload(&self, writer: &Writer) -> Result<()> {
        reload(&mut *self.lock()?, writer)
    }

    /// The caller supplies an already resolved accepted identity. No lookup,
    /// normalization, map refresh or identity validation is performed here.
    pub fn observe_trusted(&self, agent: &str, clock: impl FnOnce() -> f64) -> Result<()> {
        self.lock()?.last_seen.insert(agent.into(), clock());
        Ok(())
    }

    /// Source reads the report clock before refreshing the map. Refresh can
    /// publish state and then fail at event submission; those effects persist.
    pub fn get_agents(&self, writer: &Writer, clock: impl FnOnce() -> f64) -> Result<C> {
        let now = clock();
        let mut state = self.lock()?;
        reload(&mut state, writer)?;
        Ok(agents(&state, now))
    }
    pub fn get_stats(&self, writer: &Writer, clock: impl FnOnce() -> f64) -> Result<C> {
        let mut report = Document(self.get_agents(writer, clock)?);
        let C::Object(report) = &mut report.0 else {
            unreachable!("fixed report")
        };
        let state = self.lock()?;
        Ok(object([
            ("map_file", text(&state.path)),
            ("known_ips", BigInt::from(state.reverse.len()).into()),
            (
                "agents",
                report.shift_remove("agents").expect("fixed report"),
            ),
            (
                "agents_seen",
                report.shift_remove("count").expect("fixed report"),
            ),
        ]))
    }
}

fn agents(state: &State, now: f64) -> C {
    let C::Object(map) = &state.map.0 else {
        unreachable!("published map is an object")
    };
    let mut agents = IndexMap::new();
    for (name, info) in map {
        let C::Object(info) = info else {
            unreachable!("published entries are objects")
        };
        let mut entry = IndexMap::from([(
            "ip".into(),
            info.get("ip")
                .cloned()
                .unwrap_or_else(|| Value::Null.into()),
        )]);
        if let Some(seen) = state.last_seen.get(name) {
            entry.insert("last_seen".into(), C::Float(*seen));
            let elapsed = now - seen;
            let idle = if elapsed.is_finite() {
                format!("{elapsed:.1}").parse().expect("formatted float")
            } else {
                elapsed
            };
            entry.insert("idle_seconds".into(), C::Float(idle));
        }
        agents.insert(name.clone(), C::Object(entry));
    }
    let count = BigInt::from(agents.len()).into();
    object([("agents", C::Object(agents)), ("count", count)])
}

fn reload(state: &mut State, writer: &Writer) -> Result<()> {
    if state.path.is_empty() || !exists(Path::new(&state.path))? {
        return Ok(());
    }
    let Ok(metadata) = fs::metadata(&state.path) else {
        return Ok(());
    };
    let Ok(modified) = metadata.modified() else {
        return Ok(());
    };
    let mtime = match modified.duration_since(UNIX_EPOCH) {
        Ok(value) => value.as_secs_f64(),
        Err(value) => -value.duration().as_secs_f64(),
    };
    if mtime == state.mtime {
        return Ok(());
    }
    let Some(data) = read_map(Path::new(&state.path))? else {
        return Ok(());
    };
    let C::Object(map) = &data.0 else {
        return Err(Error(ErrorKind::Attribute));
    };
    let mut reverse: IndexMap<IpKey, IpEntry> = IndexMap::new();
    for (name, info) in map {
        let C::Object(info) = info else {
            return Err(Error(ErrorKind::Attribute));
        };
        if let Some(ip) = info.get("ip").filter(|value| value.truthy()) {
            let key = IpKey::from_value(ip)?;
            if let Some(previous) = reverse.get_mut(&key) {
                previous.name.zeroize();
                previous.name = name.clone();
            } else {
                reverse.insert(
                    key,
                    IpEntry {
                        value: ip.clone(),
                        name: name.clone(),
                    },
                );
            }
        }
    }
    let old_names: std::collections::HashSet<_> = state
        .reverse
        .values()
        .map(|entry| entry.name.clone())
        .collect();
    state.map = data;
    state.reverse = reverse;
    state.mtime = mtime;
    // Python iterates a set here; the contract is an unordered event group.
    // Native emits one event per final newly represented name in reverse-index insertion order.
    for entry in state
        .reverse
        .values()
        .filter(|entry| !old_names.contains(&entry.name))
    {
        let mut event = Event::new(
            "agent.discovered",
            Kind::Agent,
            Severity::Low,
            format!(
                "Discovered agent {} at {}",
                sanitize(&entry.name),
                scalar_text(&entry.value)?,
            ),
        );
        event.agent = Some(entry.name.clone());
        event.addon = Some("service-discovery".into());
        event.details = object([("ip", entry.value.clone())]);
        match writer.emit(event) {
            Ok(_) => {}
            // Source catches OSError around the whole reload, including emit.
            Err(error) if error.kind() == audit::ErrorKind::Io => {
                warning();
                break;
            }
            Err(error) => return Err(Error(ErrorKind::Audit(error.kind()))),
        }
    }
    Ok(())
}

fn exists(path: &Path) -> Result<bool> {
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Ok(false);
    }
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOENT | libc::ENOTDIR | libc::EBADF | libc::ELOOP)
            ) =>
        {
            Ok(false)
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(Error(ErrorKind::Permission))
        }
        Err(_) => Err(Error(ErrorKind::Io)),
    }
}
fn read_map(path: &Path) -> Result<Option<Document>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => {
            warning();
            return Ok(None);
        }
    };
    let mut bytes = Zeroizing::new(Vec::new());
    let read = file.read_to_end(&mut bytes);
    let fd = file.into_raw_fd();
    // Consume exactly once; never retry close, even after Interrupted.
    let closed = unsafe { libc::close(fd) };
    if read.is_err() || closed != 0 {
        warning();
        return Ok(None);
    }
    let source = std::str::from_utf8(&bytes).map_err(|_| Error(ErrorKind::UnicodeDecode))?;
    match C::parse_api_json(source) {
        Ok(data) => Ok(Some(Document(data))),
        Err(error) if error.kind() == JsonError::Invalid => {
            warning();
            Ok(None)
        }
        Err(error) if error.kind() == JsonError::Value => Err(Error(ErrorKind::Value)),
        Err(_) => Err(Error(ErrorKind::Compatibility)),
    }
}
fn scalar_text(value: &C) -> Result<String> {
    match value {
        C::Other(Value::String(value)) => Ok(value.clone()),
        C::Bool(value) => Ok(if *value { "True" } else { "False" }.into()),
        C::Integer(value) => Ok(value.to_string()),
        C::Float(value) if value.is_nan() => Ok("nan".into()),
        C::Float(value) if *value == f64::INFINITY => Ok("inf".into()),
        C::Float(value) if *value == f64::NEG_INFINITY => Ok("-inf".into()),
        C::Float(_) => value
            .render_json(false)
            .map_err(|_| Error(ErrorKind::Compatibility)),
        _ => Err(Error(ErrorKind::Compatibility)),
    }
}
fn warning() {
    let _ = writeln!(std::io::stderr().lock(), "Agent discovery map load failed");
}
fn text(value: &str) -> C {
    C::Other(Value::String(value.into()))
}
fn object<const N: usize>(fields: [(&str, C); N]) -> C {
    C::Object(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

#[cfg(test)]
mod tests;
