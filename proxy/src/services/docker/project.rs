//! Project membership is bound to observed Docker identities, never client
//! names or Compose labels. Only this Docker integration consumes this state.

use super::enforcement::{Inspection, Resource};
use crate::Error;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

pub(crate) const MARKER: &str = "io.safeyolo.creation";

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    #[serde(default)]
    pub containers: BTreeSet<String>,
    #[serde(default)]
    pub networks: BTreeSet<String>,
    #[serde(default)]
    pub images: BTreeSet<String>,
    #[serde(default)]
    pub image_names: BTreeMap<String, String>,
    #[serde(default)]
    pub volumes: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub name: String,
    /// An operator changes this value to explicitly re-adopt selected state
    /// after an observation gap. It is not a client-supplied ownership label.
    pub adoption: String,
    #[serde(default)]
    pub selected: Selection,
    #[serde(default)]
    pub shared: Selection,
}

impl Project {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        check(
            !self.name.is_empty() && !self.adoption.is_empty(),
            "project name and adoption are required",
        )?;
        for selection in [&self.selected, &self.shared] {
            for id in selection.containers.iter().chain(&selection.networks) {
                check(
                    immutable(id),
                    "select containers and networks by full Docker ID",
                )?;
            }
            for id in &selection.images {
                check(image_id(id), "select images by full sha256 ID")?;
            }
            for (name, id) in &selection.image_names {
                Resource::Image(name.clone()).path()?;
                check(
                    image_id(id),
                    "select image references with their current full image ID",
                )?;
            }
            for (name, created) in &selection.volumes {
                Resource::Volume(name.clone(), false).path()?;
                time::OffsetDateTime::parse(
                    created,
                    &time::format_description::well_known::Rfc3339,
                )?;
            }
        }
        Ok(())
    }
}

pub(crate) fn check(ok: bool, message: &str) -> Result<(), Error> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn immutable(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}
fn image_id(id: &str) -> bool {
    id.strip_prefix("sha256:").is_some_and(immutable)
}
fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Volume {
    pub created: String,
    pub marker: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Pending {
    pub method: String,
    pub path: String,
    pub kind: String,
    pub name: String,
    pub marker: String,
    pub parent: String,
    pub volume_effects: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct State {
    pub adoption: String,
    pub superseded_adoptions: BTreeSet<String>,
    pub containers: BTreeSet<String>,
    pub networks: BTreeSet<String>,
    pub images: BTreeSet<String>,
    pub volumes: BTreeMap<String, Volume>,
    pub execs: BTreeMap<String, String>,
    pub image_names: BTreeMap<String, String>,
    pub pending: Option<Pending>,
    /// A retained daemon event proves continuity for selected name-only volumes.
    /// Its absence is uncertainty, including after a daemon/event-history reset.
    pub anchor: Option<Value>,
    pub uncertain_volumes: BTreeSet<String>,
}

pub(crate) struct Membership {
    pub project: Project,
    pub state: State,
    path: PathBuf,
    pub readopted: bool,
}

impl Membership {
    /// Call while holding the process-wide Docker project mutex. The path is
    /// endpoint-bound so neither a renamed service nor another daemon inherits
    /// a resource grant. Files live in the existing operator-owned data dir.
    pub(crate) fn open(root: &Path, endpoint: &str, project: &Project) -> Result<Self, Error> {
        let key = ring::digest::digest(
            &ring::digest::SHA256,
            &serde_json::to_vec(&(endpoint, &project.name))?,
        );
        let key: String = key.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        let path = root.join("docker-projects").join(format!("{key}.json"));
        let mut state: State = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(error) => return Err(error.into()),
        };
        let readopted = state.adoption != project.adoption;
        if readopted {
            check(
                !state.superseded_adoptions.contains(&project.adoption),
                "project adoption was superseded; use the current operator selection",
            )?;
            if !state.adoption.is_empty() {
                state.superseded_adoptions.insert(state.adoption.clone());
            }
            state.adoption = project.adoption.clone();
            // Only explicit operator selections resolve an unknown creation.
            // Previously recorded immutable creations retain their identities.
            state.pending = None;
            state.uncertain_volumes.clear();
            state.anchor = None;
            // Explicit operator re-adoption replaces a prior automatic volume
            // identity at that name, including a deliberate shared selection.
            state.volumes.retain(|name, _| {
                !project.selected.volumes.contains_key(name)
                    && !project.shared.volumes.contains_key(name)
            });
        }
        let membership = Self {
            project: project.clone(),
            state,
            path,
            readopted,
        };
        if readopted {
            membership.save()?;
        }
        Ok(membership)
    }
    pub(crate) fn save(&self) -> Result<(), Error> {
        use std::{io::Write, os::unix::fs::PermissionsExt};
        let parent = self.path.parent().expect("project state directory");
        std::fs::create_dir_all(parent)?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        temporary.write_all(&serde_json::to_vec(&self.state)?)?;
        temporary.as_file().sync_all()?;
        temporary.persist(&self.path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
    pub(crate) fn owns(&self, kind: &str, id: &str) -> bool {
        match kind {
            "container" => {
                self.project.selected.containers.contains(id) || self.state.containers.contains(id)
            }
            "network" => {
                self.project.selected.networks.contains(id) || self.state.networks.contains(id)
            }
            "image" => {
                self.project.selected.images.contains(id)
                    || self.state.images.contains(id)
                    || self
                        .project
                        .selected
                        .image_names
                        .values()
                        .any(|image| image == id)
            }
            "volume" => {
                !self.state.uncertain_volumes.contains(id)
                    && (self.project.selected.volumes.contains_key(id)
                        || self.state.volumes.contains_key(id))
            }
            "exec" => self
                .state
                .execs
                .get(id)
                .is_some_and(|parent| self.owns("container", parent)),
            _ => false,
        }
    }
    pub(crate) fn uses(&self, kind: &str, id: &str) -> bool {
        self.owns(kind, id)
            || match kind {
                "container" => self.project.shared.containers.contains(id),
                "network" => self.project.shared.networks.contains(id),
                "image" => {
                    self.project.shared.images.contains(id)
                        || self
                            .project
                            .shared
                            .image_names
                            .values()
                            .any(|image| image == id)
                }
                "volume" => {
                    !self.state.uncertain_volumes.contains(id)
                        && self.project.shared.volumes.contains_key(id)
                }
                _ => false,
            }
    }
    pub(crate) fn owns_image_name(&self, name: &str, id: &str) -> bool {
        self.state
            .image_names
            .get(name)
            .or_else(|| self.project.selected.image_names.get(name))
            .is_some_and(|image| image == id)
    }
    pub(crate) fn volume(&self, name: &str, value: &Value) -> bool {
        if self.state.uncertain_volumes.contains(name) {
            return false;
        }
        let created = string(value, "CreatedAt");
        if let Some(volume) = self.state.volumes.get(name) {
            return volume.created == created
                && volume.marker.as_ref().is_some_and(|marker| {
                    value["Labels"][MARKER].as_str() == Some(marker.as_str())
                });
        }
        self.project
            .selected
            .volumes
            .get(name)
            .or_else(|| self.project.shared.volumes.get(name))
            .is_some_and(|expected| expected == created)
    }
    pub(crate) fn events(&mut self, events: &[Value]) -> Result<(), Error> {
        let continuous = self.readopted
            || self
                .state
                .anchor
                .as_ref()
                .is_some_and(|anchor| events.contains(anchor));
        for name in self
            .project
            .selected
            .volumes
            .keys()
            .chain(self.project.shared.volumes.keys())
        {
            let replaced = !self.readopted
                && events
                    .iter()
                    .skip_while(|event| Some(*event) != self.state.anchor.as_ref())
                    .skip(1)
                    .any(|event| {
                        string(event, "Type") == "volume"
                            && string(&event["Actor"], "ID") == name
                            && ["create", "destroy"].contains(&string(event, "Action"))
                    });
            if !continuous || replaced {
                self.state.uncertain_volumes.insert(name.clone());
            }
        }
        self.state.anchor = events.last().cloned();
        self.readopted = false;
        self.save()
    }
    pub(crate) fn authorize(
        &self,
        inspection: &Inspection,
        method: &str,
        path: &str,
    ) -> Result<(), Error> {
        if let Some(id) = &inspection.container_id {
            check(
                self.owns("container", id),
                "shared containers permit references, not direct management",
            )?;
        }
        for (resource, observed) in &inspection.observed {
            match (resource, observed) {
                (Resource::Daemon { .. }, _) => (),
                (Resource::Volume(_, true), None) => (), // checked absent before autonomous creation
                (Resource::Container(_), Some(value)) => check(
                    self.uses("container", string(value, "Id")),
                    "container is outside project",
                )?,
                (Resource::Exec(_), Some(value)) => check(
                    self.owns("container", string(value, "ContainerID")),
                    "exec is outside project",
                )?,
                (Resource::Network(_), Some(value)) => check(
                    self.uses("network", string(value, "Id")),
                    "network is outside project",
                )?,
                (Resource::Image(_), Some(value)) => check(
                    self.uses("image", string(value, "Id")),
                    "image is outside project",
                )?,
                (Resource::Volume(name, _), Some(value)) => check(
                    self.volume(name, value),
                    "volume identity needs explicit re-adoption",
                )?,
                _ => return Err("project resource is unavailable".into()),
            }
        }
        let path = path.split('?').next().unwrap_or(path);
        let pieces: Vec<_> = path
            .trim_start_matches(super::API_PREFIX)
            .split('/')
            .filter(|p| !p.is_empty())
            .collect();
        // A shared dependency may be inspected for client compatibility and used,
        // but may not be deleted, retagged or otherwise administered.
        if method != "GET" && method != "HEAD" {
            match pieces.as_slice() {
                ["networks", name, ..]
                    if !(method == "POST" && pieces == ["networks", "create"]) =>
                {
                    let value = inspection
                        .observed
                        .get(&Resource::Network((*name).into()))
                        .and_then(Option::as_ref)
                        .ok_or("network inspection missing")?;
                    // Attaching the project's container to an adopted shared
                    // network is use; the container reference was checked above.
                    if pieces.len() != 3 || !["connect", "disconnect"].contains(&pieces[2]) {
                        check(
                            self.owns("network", string(value, "Id")),
                            "shared network is use-only",
                        )?;
                    }
                }
                ["volumes", name] if !(method == "POST" && *name == "create") => {
                    check(self.owns("volume", name), "shared volume is use-only")?
                }
                ["images", ..] if method == "DELETE" => {
                    let value = inspection
                        .observed
                        .iter()
                        .find_map(|(r, v)| {
                            matches!(r, Resource::Image(_))
                                .then_some(v.as_ref())
                                .flatten()
                        })
                        .ok_or("image inspection missing")?;
                    check(
                        self.owns("image", string(value, "Id")),
                        "shared image is use-only",
                    )?;
                }
                _ => (),
            }
        }
        Ok(())
    }
    pub(crate) fn record(
        &mut self,
        kind: &str,
        value: &Value,
        marker: Option<&str>,
    ) -> Result<(), Error> {
        let id = if kind == "exec" {
            string(value, "ID")
        } else {
            string(value, "Id")
        };
        if ["container", "network"].contains(&kind) {
            check(
                marker.is_some()
                    && value["Labels"][MARKER]
                        .as_str()
                        .or_else(|| value["Config"]["Labels"][MARKER].as_str())
                        == marker,
                "created resource identity unavailable",
            )?;
        }
        match kind {
            "container" => {
                check(immutable(id), "created container ID unavailable")?;
                self.state.containers.insert(id.into());
            }
            "network" => {
                check(immutable(id), "created network ID unavailable")?;
                self.state.networks.insert(id.into());
            }
            "image" => {
                check(image_id(id), "created image ID unavailable")?;
                self.state.images.insert(id.into());
            }
            "volume" => {
                let name = string(value, "Name");
                let created = string(value, "CreatedAt");
                check(
                    !name.is_empty() && !created.is_empty(),
                    "created volume identity unavailable",
                )?;
                check(
                    marker.is_some() && value["Labels"][MARKER].as_str() == marker,
                    "created volume marker unavailable",
                )?;
                self.state.volumes.insert(
                    name.into(),
                    Volume {
                        created: created.into(),
                        marker: marker.map(str::to_owned),
                    },
                );
            }
            "exec" => {
                let parent = string(value, "ContainerID");
                check(
                    immutable(id) && self.owns("container", parent),
                    "created exec association unavailable",
                )?;
                self.state.execs.insert(id.into(), parent.into());
            }
            _ => return Err("unknown project creation kind".into()),
        }
        self.save()
    }

    /// Project only the fixed management schemas used by the supported client.
    /// Workload logs, tar contents and exec bytes retain their ordinary meaning.
    pub(crate) fn response(&self, path: &str, mut value: Value) -> Result<Value, Error> {
        let path = path
            .split('?')
            .next()
            .unwrap_or(path)
            .trim_start_matches(super::API_PREFIX);
        match path {
            "/_ping" => return Ok(value),
            "/version" => retain(
                &mut value,
                &[
                    "Version",
                    "ApiVersion",
                    "MinAPIVersion",
                    "GitCommit",
                    "GoVersion",
                    "Os",
                    "Arch",
                    "KernelVersion",
                    "BuildTime",
                    "Experimental",
                ],
            ),
            "/info" => retain(
                &mut value,
                &[
                    "ServerVersion",
                    "OSType",
                    "Architecture",
                    "NCPU",
                    "MemTotal",
                    "KernelVersion",
                    "CgroupDriver",
                    "CgroupVersion",
                    "Driver",
                    "DefaultRuntime",
                    "LoggingDriver",
                    "SecurityOptions",
                ],
            ),
            "/containers/json" => {
                let items = value.as_array_mut().ok_or("invalid container list")?;
                items.retain(|v| self.owns("container", string(v, "Id")));
                for item in items {
                    self.container(item, false)?;
                }
            }
            "/networks" => {
                let items = value.as_array_mut().ok_or("invalid network list")?;
                items.retain(|v| self.owns("network", string(v, "Id")));
                for item in items {
                    self.network(item)?;
                }
            }
            "/volumes" => {
                let items = value.get_mut("Volumes").and_then(Value::as_array_mut);
                if let Some(items) = items {
                    items.retain(|v| {
                        self.owns("volume", string(v, "Name")) && self.volume(string(v, "Name"), v)
                    });
                    for item in items {
                        volume_response(item);
                    }
                }
                retain(&mut value, &["Volumes"]);
                value["Warnings"] = json!([]);
            }
            "/images/json" => {
                let items = value.as_array_mut().ok_or("invalid image list")?;
                items.retain(|v| self.owns("image", string(v, "Id")));
                for item in items {
                    self.image(item);
                }
            }
            _ => {
                let pieces: Vec<_> = path.split('/').filter(|p| !p.is_empty()).collect();
                match pieces.as_slice() {
                    ["containers", _, "json"] => self.container(&mut value, true)?,
                    ["networks", _] => self.network(&mut value)?,
                    ["volumes", _] => {
                        check(
                            self.volume(string(&value, "Name"), &value),
                            "volume identity changed during inspection",
                        )?;
                        volume_response(&mut value);
                        if !self.owns("volume", string(&value, "Name")) {
                            value["Labels"] = json!({});
                        }
                    }
                    ["images", ..] => self.image(&mut value),
                    ["exec", _, "json"] => retain(
                        &mut value,
                        &[
                            "ID",
                            "Running",
                            "ExitCode",
                            "ProcessConfig",
                            "OpenStdin",
                            "OpenStdout",
                            "OpenStderr",
                            "ContainerID",
                            "DetachKeys",
                            "CanRemove",
                        ],
                    ),
                    ["containers", _, "top"] => retain(&mut value, &["Titles", "Processes"]),
                    _ => {
                        if value.is_object() {
                            retain(&mut value, &["Id", "ID", "StatusCode", "Error"]);
                        }
                    }
                }
            }
        }
        if value.is_object() {
            value.as_object_mut().unwrap().remove("Warnings");
        }
        Ok(value)
    }
    fn container(&self, value: &mut Value, inspect: bool) -> Result<(), Error> {
        check(
            self.owns("container", string(value, "Id")),
            "unexpected container response",
        )?;
        if inspect {
            retain(
                value,
                &[
                    "Id",
                    "Created",
                    "Path",
                    "Args",
                    "State",
                    "Image",
                    "Name",
                    "RestartCount",
                    "Driver",
                    "Platform",
                    "MountLabel",
                    "ProcessLabel",
                    "AppArmorProfile",
                    "ExecIDs",
                    "HostConfig",
                    "Config",
                    "NetworkSettings",
                    "Mounts",
                    "SizeRw",
                    "SizeRootFs",
                ],
            );
            // Engine State.Error is diagnostic prose, not workload output.
            if let Some(state) = value.get_mut("State").and_then(Value::as_object_mut) {
                state.insert("Error".into(), json!(""));
            }
            let image = value.get("Image").cloned().unwrap_or(Value::Null);
            if let Some(config) = value.get_mut("Config").and_then(Value::as_object_mut) {
                config.insert("Image".into(), image);
            }
            if let Some(host) = value.get_mut("HostConfig").and_then(Value::as_object_mut) {
                host.remove("Links");
                host.remove("VolumesFrom");
            }
        } else {
            retain(
                value,
                &[
                    "Id",
                    "Names",
                    "ImageID",
                    "Command",
                    "Created",
                    "Ports",
                    "Labels",
                    "State",
                    "Status",
                    "NetworkSettings",
                    "Mounts",
                    "SizeRw",
                    "SizeRootFs",
                ],
            );
            if !self.uses("image", string(value, "ImageID")) {
                value.as_object_mut().unwrap().remove("ImageID");
            }
            value["Image"] = value.get("ImageID").cloned().unwrap_or(Value::Null);
            if let Some(mounts) = value.get_mut("Mounts").and_then(Value::as_array_mut) {
                mounts.retain(|mount| {
                    string(mount, "Type") != "volume" || self.uses("volume", string(mount, "Name"))
                });
                for mount in mounts {
                    if string(mount, "Type") == "bind" {
                        mount.as_object_mut().unwrap().remove("Source");
                    }
                }
            }
        }
        if let Some(networks) = value
            .pointer_mut("/NetworkSettings/Networks")
            .and_then(Value::as_object_mut)
        {
            networks.retain(|_, v| self.uses("network", string(v, "NetworkID")));
            for v in networks.values_mut() {
                if let Some(o) = v.as_object_mut() {
                    o.remove("Links");
                }
            }
        }
        hide_marker(value);
        Ok(())
    }
    fn network(&self, value: &mut Value) -> Result<(), Error> {
        check(
            self.uses("network", string(value, "Id")),
            "unexpected network response",
        )?;
        retain(
            value,
            &[
                "Id",
                "Name",
                "Created",
                "Scope",
                "Driver",
                "EnableIPv6",
                "IPAM",
                "Internal",
                "Attachable",
                "Ingress",
                "Containers",
                "Options",
                "Labels",
            ],
        );
        if let Some(containers) = value.get_mut("Containers").and_then(Value::as_object_mut) {
            containers.retain(|id, _| self.owns("container", id));
        }
        if !self.owns("network", string(value, "Id")) {
            value["Labels"] = json!({});
        }
        hide_marker(value);
        Ok(())
    }
    fn image(&self, value: &mut Value) {
        let actual_tags = value
            .get("RepoTags")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        retain(
            value,
            &[
                "Id",
                "Created",
                "Size",
                "SharedSize",
                "VirtualSize",
                "Labels",
                "Config",
                "Architecture",
                "Os",
                "OsVersion",
                "Variant",
                "RootFS",
                "Metadata",
            ],
        );
        let id = string(value, "Id").to_owned();
        value["RepoTags"] = json!(
            self.project
                .selected
                .image_names
                .iter()
                .chain(&self.project.shared.image_names)
                .chain(&self.state.image_names)
                .filter_map(|(name, image)| (*image == id
                    && actual_tags
                        .iter()
                        .any(|tag| tag.as_str() == Some(name.as_str())))
                .then_some(name))
                .collect::<BTreeSet<_>>()
        );
        value["RepoDigests"] = json!([]);
        if let Some(config) = value.get_mut("Config").and_then(Value::as_object_mut) {
            config.insert("Image".into(), json!(id));
        }
        hide_marker(value);
    }
    pub(crate) fn event(&self, value: &Value) -> Option<Value> {
        let kind = string(value, "Type");
        // Volume events contain a reusable name rather than an immutable ID.
        // Keep those in the private reconciliation input, never a client stream.
        if !["container", "network", "image"].contains(&kind) {
            return None;
        }
        let id = string(&value["Actor"], "ID");
        if !self.owns(kind, id) {
            return None;
        }
        let attributes = value["Actor"]["Attributes"]
            .as_object()
            .map(|attrs| {
                attrs
                    .iter()
                    .filter(|(k, _)| k.starts_with("com.docker.compose.") || *k == "name")
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<serde_json::Map<_, _>>()
            })
            .unwrap_or_default();
        Some(
            json!({"Type":kind,"Action":value["Action"],"scope":value["scope"],"Actor":{"ID":id,"Attributes":attributes},"time":value["time"],"timeNano":value["timeNano"]}),
        )
    }
    pub(crate) fn stats(&self, mut value: Value) -> Result<Value, Error> {
        check(
            self.owns("container", string(&value, "id")),
            "unexpected statistics identity",
        )?;
        retain(
            &mut value,
            &[
                "id",
                "name",
                "read",
                "preread",
                "pids_stats",
                "blkio_stats",
                "num_procs",
                "storage_stats",
                "cpu_stats",
                "precpu_stats",
                "memory_stats",
                "networks",
            ],
        );
        Ok(value)
    }
}
fn retain(value: &mut Value, fields: &[&str]) {
    if let Some(object) = value.as_object_mut() {
        object.retain(|key, _| fields.contains(&key.as_str()));
    }
}
fn volume_response(value: &mut Value) {
    retain(
        value,
        &["Name", "Driver", "CreatedAt", "Labels", "Options", "Scope"],
    );
    hide_marker(value);
}
fn hide_marker(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.remove(MARKER);
            for item in object.values_mut() {
                hide_marker(item);
            }
        }
        Value::Array(items) => {
            for item in items {
                hide_marker(item);
            }
        }
        _ => (),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::docker::{DockerAccess, ExecutionBoundary};
    fn project() -> Project {
        serde_json::from_value(json!({"name":"alpha","adoption":"operator-selection-1", "selected":{"containers":["a".repeat(64)],"networks":["b".repeat(64)],"volumes":{"ordinary-data":"2026-11-07T01:02:03Z"}},"shared":{"images":[format!("sha256:{}","c".repeat(64))],"networks":["d".repeat(64)],"volumes":{"shared-data":"2026-11-07T01:02:03Z"}}})).unwrap()
    }
    #[test]
    fn project_selection_loads_without_names_or_labels_as_authority() {
        let mut value = serde_json::to_value(project()).unwrap();
        value["mode"] = json!("project");
        value["bind_mounts"] = json!([]);
        let access: DockerAccess = serde_json::from_value(value.clone()).unwrap();
        access.validate(ExecutionBoundary::External).unwrap();
        value["selected"]["containers"] = json!(["ordinary-name"]);
        assert!(
            serde_json::from_value::<DockerAccess>(value)
                .unwrap()
                .validate(ExecutionBoundary::External)
                .is_err()
        );
    }
    #[test]
    fn shared_dependencies_do_not_grant_destructive_or_container_authority() {
        let root = tempfile::tempdir().unwrap();
        let membership = Membership::open(root.path(), "https://engine", &project()).unwrap();
        let mut inspection = Inspection::default();
        inspection.observed.insert(
            Resource::Network("shared-net".into()),
            Some(json!({"Id":"d".repeat(64)})),
        );
        membership
            .authorize(&inspection, "GET", "/v1.45/networks/shared-net")
            .unwrap();
        assert!(
            membership
                .authorize(&inspection, "DELETE", "/v1.45/networks/shared-net")
                .is_err()
        );
        inspection.observed.insert(Resource::Container("beta".into()),Some(json!({"Id":"e".repeat(64),"Config":{"Labels":{"com.docker.compose.project":"alpha"}}})));
        assert!(
            membership
                .authorize(&inspection, "POST", "/v1.45/networks/shared-net/connect")
                .is_err()
        );
    }
    #[test]
    fn rename_requires_the_inspected_container_to_be_owned() {
        let root = tempfile::tempdir().unwrap();
        let mut selected = project();
        selected.shared.containers.insert("e".repeat(64));
        let membership = Membership::open(root.path(), "https://engine", &selected).unwrap();
        for (id, allowed) in [('a', true), ('e', false), ('f', false)] {
            let mut inspection = Inspection::default();
            inspection.container_id = Some(id.to_string().repeat(64));
            inspection.observed.insert(
                Resource::Container("temporary-name".into()),
                Some(json!({"Id":id.to_string().repeat(64)})),
            );
            assert_eq!(
                membership
                    .authorize(
                        &inspection,
                        "POST",
                        "/v1.45/containers/temporary-name/rename?name=alpha-web-1",
                    )
                    .is_ok(),
                allowed,
                "container {id}",
            );
        }
    }
    #[test]
    fn default_network_alias_requires_the_observed_bridge_to_belong_to_the_project() {
        let root = tempfile::tempdir().unwrap();
        let selected = project();
        let membership = Membership::open(root.path(), "https://engine", &selected).unwrap();
        let access = DockerAccess::Project {
            project: Box::new(selected),
            bind_mounts: Vec::new(),
        };
        for (bridge, allowed) in [('b', true), ('d', true), ('e', false)] {
            let mut inspection = access
                .request(
                    "POST",
                    "/v1.45/containers/create",
                    include_bytes!("../../../tests/fixtures/docker/create-defaults.json"),
                )
                .unwrap();
            while let Some(resource) = inspection.next() {
                let value = match &resource {
                    Resource::Daemon { .. } => {
                        json!({"OSType":"linux","SecurityOptions":["name=cgroupns"],"DefaultRuntime":"runc","LoggingDriver":"json-file"})
                    }
                    Resource::Network(name) => {
                        assert_eq!(name, "bridge");
                        json!({"Id":bridge.to_string().repeat(64),"Name":"bridge","Driver":"bridge","IPAM":{"Driver":"default"}})
                    }
                    Resource::Image(_) => {
                        json!({"Id":format!("sha256:{}", "c".repeat(64)),"Os":"linux"})
                    }
                    _ => panic!("unexpected resource {resource:?}"),
                };
                inspection.observe(&access, &resource, Some(value)).unwrap();
            }
            assert!(
                inspection
                    .observed
                    .contains_key(&Resource::Network("bridge".into()))
            );
            assert_eq!(
                membership
                    .authorize(&inspection, "POST", "/v1.45/containers/create")
                    .is_ok(),
                allowed
            );
        }
    }
    #[test]
    fn shared_container_references_and_reserved_resource_names_keep_their_bounds() {
        let root = tempfile::tempdir().unwrap();
        let mut selected = project();
        selected.shared.containers.insert("e".repeat(64));
        selected
            .shared
            .volumes
            .insert("create".into(), "2026-11-07T01:02:03Z".into());
        let membership = Membership::open(root.path(), "https://engine", &selected).unwrap();
        let mut inspection = Inspection::default();
        inspection.observed.insert(
            Resource::Container("dependency".into()),
            Some(json!({"Id":"e".repeat(64)})),
        );
        membership
            .authorize(&inspection, "POST", "/v1.45/containers/create")
            .unwrap();
        inspection.container_id = Some("e".repeat(64));
        assert!(
            membership
                .authorize(&inspection, "GET", "/v1.45/containers/dependency/json")
                .is_err()
        );
        let mut inspection = Inspection::default();
        inspection.observed.insert(
            Resource::Volume("create".into(), false),
            Some(json!({"CreatedAt":"2026-11-07T01:02:03Z"})),
        );
        assert!(
            membership
                .authorize(&inspection, "DELETE", "/v1.45/volumes/create")
                .is_err()
        );
    }
    #[test]
    fn creation_state_survives_restart_and_reused_names_do_not_adopt_new_ids() {
        let root = tempfile::tempdir().unwrap();
        let selected = project();
        let mut membership = Membership::open(root.path(), "https://engine", &selected).unwrap();
        membership
            .record(
                "container",
                &json!({"Id":"e".repeat(64),"Config":{"Labels":{MARKER:"creation-1"}}}),
                Some("creation-1"),
            )
            .unwrap();
        membership.record("volume",&json!({"Name":"new-data","CreatedAt":"2026-11-07T02:00:00Z","Labels":{MARKER:"creation-2"}}),Some("creation-2")).unwrap();
        let membership = Membership::open(root.path(), "https://engine", &selected).unwrap();
        assert!(membership.owns("container", &"e".repeat(64)));
        assert!(!membership.owns("container", &"f".repeat(64)));
        assert!(membership.volume(
            "new-data",
            &json!({"CreatedAt":"2026-11-07T02:00:00Z","Labels":{MARKER:"creation-2"}})
        ));
        assert!(!membership.volume("new-data",&json!({"CreatedAt":"2026-11-07T02:00:00Z","Labels":{"com.docker.compose.project":"alpha"}})));
        assert!(!membership.volume(
            "other-name",
            &json!({"CreatedAt":"2026-11-07T02:00:00Z","Labels":{MARKER:"creation-2"}})
        ));
        assert!(
            !Membership::open(root.path(), "https://another-engine", &selected)
                .unwrap()
                .owns("container", &"e".repeat(64))
        );
        let mut readopted = selected.clone();
        readopted.adoption = "explicit-volume-readoption-2".into();
        readopted
            .selected
            .volumes
            .insert("new-data".into(), "2026-11-07T03:00:00Z".into());
        let membership = Membership::open(root.path(), "https://engine", &readopted).unwrap();
        assert!(membership.volume(
            "new-data",
            &json!({"CreatedAt":"2026-11-07T03:00:00Z","Labels":{}})
        ));
        assert!(Membership::open(root.path(), "https://engine", &selected).is_err());
    }
    #[test]
    fn volume_event_gap_and_same_timestamp_replacement_require_readoption() {
        let root = tempfile::tempdir().unwrap();
        let mut selected = project();
        let mut membership = Membership::open(root.path(), "https://engine", &selected).unwrap();
        let anchor =
            json!({"Type":"container","Action":"start","Actor":{"ID":"a".repeat(64)},"timeNano":1});
        let volume = json!({"CreatedAt":"2026-11-07T01:02:03Z"});
        membership.events(std::slice::from_ref(&anchor)).unwrap();
        assert!(membership.volume("ordinary-data", &volume));
        let destroy =
            json!({"Type":"volume","Action":"destroy","Actor":{"ID":"ordinary-data"},"timeNano":2});
        membership.events(&[anchor.clone(), destroy]).unwrap();
        assert!(!membership.volume("ordinary-data", &volume));
        selected.adoption = "explicit-operator-readoption-2".into();
        let mut membership = Membership::open(root.path(), "https://engine", &selected).unwrap();
        membership.events(&[anchor]).unwrap();
        assert!(membership.volume("ordinary-data", &volume));
        membership.events(&[]).unwrap();
        assert!(!membership.volume("ordinary-data", &volume));
    }
    #[test]
    fn management_projection_keeps_client_facts_and_excludes_foreign_metadata() {
        let root = tempfile::tempdir().unwrap();
        let mut membership = Membership::open(root.path(), "https://engine", &project()).unwrap();
        let list=membership.response("/v1.45/containers/json",json!([
            {"Id":"a".repeat(64),"Names":["/ordinary-name"],"ImageID":format!("sha256:{}","c".repeat(64)),"Labels":{MARKER:"private-marker"}},
            {"Id":"e".repeat(64),"Names":["/beta-secret"]}
        ])).unwrap().to_string();
        assert!(list.contains("ordinary-name"));
        assert!(!list.contains("beta-secret") && !list.contains("private-marker"));
        let network=membership.response("/v1.45/networks/shared",json!({"Id":"d".repeat(64),"Name":"selected-shared", "Labels":{"com.docker.compose.project":"beta-secret"},"Containers":{"a".repeat(64):{"Name":"ordinary-name"},"e".repeat(64):{"Name":"beta-secret"}}})).unwrap().to_string();
        assert!(network.contains("ordinary-name") && !network.contains("beta-secret"));
        let info=membership.response("/v1.45/info",json!({"OSType":"linux","ServerVersion":"29.1.3","Name":"beta-host","Containers":22,"Images":44})).unwrap();
        assert_eq!(info, json!({"OSType":"linux","ServerVersion":"29.1.3"}));
        let image_id = format!("sha256:{}", "c".repeat(64));
        membership
            .project
            .shared
            .image_names
            .insert("selected:tag".into(), image_id.clone());
        membership
            .state
            .image_names
            .insert("stale:tag".into(), image_id.clone());
        let image=membership.response("/v1.45/images/selected:tag/json",json!({"Id":image_id,"RepoTags":["selected:tag","unrelated:tag"],"Config":{"Image":"unrelated-parent-id"}})).unwrap();
        assert_eq!(image["RepoTags"], json!(["selected:tag"]));
        assert_eq!(image["Config"]["Image"], image_id);
        assert!(
            membership
                .stats(json!({"id":"e".repeat(64),"name":"beta-secret"}))
                .is_err()
        );
        assert!(
            membership
                .event(&json!({"Type":"container","Actor":{"ID":"e".repeat(64)}}))
                .is_none()
        );
        assert!(
            membership
                .event(&json!({"Type":"volume","Actor":{"ID":"ordinary-data"}}))
                .is_none()
        );
    }
}
