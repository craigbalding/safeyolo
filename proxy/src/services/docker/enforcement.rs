//! API 1.45 authority checks. This is a request-local inspection plan, not a
//! resource ownership database. Docker administrators may continue using names.

use crate::{
    Error,
    contracts::{Constraints, check_json_shape, strict_json},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::LazyLock,
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionBoundary {
    External,
    Sandbox,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum DockerAccess {
    Workloads {
        #[serde(default)]
        bind_mounts: Vec<BindMount>,
    },
    Project {
        #[serde(flatten)]
        project: Box<super::project::Project>,
        #[serde(default)]
        bind_mounts: Vec<BindMount>,
    },
    SandboxAdmin,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindMount {
    pub source: String,
    pub read_only: bool,
}

impl DockerAccess {
    pub(crate) fn validate(&self, boundary: ExecutionBoundary) -> Result<(), Error> {
        match self {
            Self::SandboxAdmin if boundary != ExecutionBoundary::Sandbox => {
                Err("sandbox_admin requires an operator-adopted sandbox execution boundary".into())
            }
            Self::Workloads { bind_mounts } | Self::Project { bind_mounts, .. } => {
                if let Self::Project { project, .. } = self {
                    project.validate()?;
                }
                for mount in bind_mounts {
                    require(
                        clean_absolute(&mount.source),
                        "bind source must be a canonical absolute path",
                    )?;
                    require(
                        !daemon_socket(&mount.source),
                        "daemon socket paths cannot be delegated as workload files",
                    )?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Presented by the existing service-authorization challenge. Approval is
    /// capability-wide and never removes these checks or binds an exact payload.
    pub fn authority(&self, boundary: ExecutionBoundary) -> Value {
        json!({"execution_boundary":boundary,"enforced_access":self,
            "authority": match self {
                Self::SandboxAdmin => "Administer the entire hosting sandbox Docker environment. Privileged inner workloads, the provider filesystem, workspace, credentials, mounted host files and other inner workloads may be accessible. This does not confer outer-host privilege or project isolation.",
                Self::Workloads { .. } => "Manage supported Linux Docker workloads. Host privileges, devices, daemon sockets and unsupported drivers are refused. Only the exact listed host-file sources and write modes may be mounted. These files may have site-specific consumers; the operator must inspect them during external onboarding. This does not enforce project visibility or external network policy.",
                Self::Project { .. } => "Manage the selected Docker project and create its resources autonomously. Shared dependencies permit use, not destructive management. Management responses exclude unrelated workloads. Host-file and workload constraints still apply. External workloads use the daemon's network authority; nested workloads retain the hosting sandbox's authority. Name-only volume identity can require explicit operator re-adoption after an observation gap. Docker offers no atomic inspect-and-mutate transaction against another trusted administrator.",
            }, "approval_bounds":"All supported creation arguments within these enforced bounds remain available. Approval is not tied to the attempted payload. Expiry or revocation stops future requests; existing containers, files, volumes and other effects remain."})
    }

    fn bind(&self, source: &str, read_only: bool) -> Result<(), Error> {
        let bind_mounts = match self {
            Self::Workloads { bind_mounts } | Self::Project { bind_mounts, .. } => bind_mounts,
            Self::SandboxAdmin => return Ok(()),
        };
        require(
            clean_absolute(source) && !daemon_socket(source),
            "unsupported bind source or daemon socket",
        )?;
        require(
            bind_mounts
                .iter()
                .any(|bound| bound.source == source && (read_only || !bound.read_only)),
            "bind source or write authority is outside the adopted capability",
        )
    }

    pub(crate) fn request(
        &self,
        method: &str,
        target: &str,
        body: &[u8],
    ) -> Result<Inspection, Error> {
        require(
            !crate::contracts::reject_path_tricks(target),
            "noncanonical Docker path",
        )?;
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let params: BTreeMap<String, String> = crate::contracts::query_params(query)
            .map_err(|_| "invalid or duplicate Docker query fields")?
            .into_iter()
            .map(|(name, value)| (name, value.as_str().expect("query string").to_owned()))
            .collect();
        let mut inspection = Inspection::default();
        if matches!(self, Self::SandboxAdmin) {
            return Ok(inspection);
        }
        let path = path.strip_prefix(super::API_PREFIX).unwrap_or(path);
        let parts: Vec<_> = path.split('/').filter(|p| !p.is_empty()).collect();
        let object = if body.is_empty() {
            Map::new()
        } else if method == "POST" && path != "/build" {
            strict_json(body)?
                .as_object()
                .cloned()
                .ok_or("Docker JSON body must be an object")?
        } else {
            Map::new()
        };
        let mut rules: &[&str] = &[];
        match (method, parts.as_slice()) {
            ("POST", ["containers", "create"]) => {
                rules = &["name", "platform"];
                shape("create", &object)?;
                require(!text(&object, "Image")?.is_empty(), "Image is required")?;
                inspection.add(Resource::Image(text(&object, "Image")?.into()));
                self.config(&object, &mut inspection)?;
                let host = optional_object(&object, "HostConfig")?;
                inspection.add(Resource::Daemon {
                    private_cgroup: text(&host, "CgroupnsMode")?.is_empty(),
                    default_runtime: text(&host, "Runtime")?.is_empty(),
                    default_log: text(&optional_object(&host, "LogConfig")?, "Type")?.is_empty(),
                });
            }
            ("GET", ["containers", "json"]) => (),
            (_, ["containers", id, tail @ ..]) => {
                inspection.primary_container = Some((*id).into());
                inspection.add(Resource::Container((*id).into()));
                rules = match tail {
                    ["json"] => &["size"],
                    ["logs"] => &[
                        "follow",
                        "stdout",
                        "stderr",
                        "since",
                        "until",
                        "timestamps",
                        "tail",
                        "details",
                    ],
                    ["stats"] => &["stream", "one-shot"],
                    ["top"] => &["ps_args"],
                    ["archive"] => &["path", "noOverwriteDirNonDir", "copyUIDGID"],
                    ["start" | "pause" | "unpause" | "attach"] => {
                        &["detachKeys", "logs", "stream", "stdin", "stdout", "stderr"]
                    }
                    ["stop" | "restart"] => &["t", "signal"],
                    ["rename"] => {
                        require(
                            params.get("name").is_some_and(|name| !name.is_empty()),
                            "container rename requires a name",
                        )?;
                        &["name"]
                    }
                    ["kill"] => &["signal"],
                    ["wait"] => &["condition"],
                    ["resize"] => &["h", "w"],
                    [] => &["v", "force", "link"],
                    ["exec" | "update"] => &[],
                    _ => return Err("unsupported container operation".into()),
                };
                match (method, tail) {
                    ("POST", ["exec"]) => {
                        shape("exec_create", &object)?;
                        fields(
                            &object,
                            &[
                                "AttachStdin",
                                "AttachStdout",
                                "AttachStderr",
                                "ConsoleSize",
                                "Detach",
                                "DetachKeys",
                                "Tty",
                                "Env",
                                "Cmd",
                                "Privileged",
                                "User",
                                "WorkingDir",
                            ],
                        )?;
                        require(
                            !boolean(&object, "Privileged")?,
                            "privileged exec is outside workload authority",
                        )?;
                        strings(&object, "Env")?;
                    }
                    ("POST", ["update"]) => {
                        shape("update", &object)?;
                        self.host_config(&object, &mut inspection)?;
                    }
                    ("PUT", ["archive"]) => (),
                    _ => require(
                        body.is_empty(),
                        "this Docker operation has no supported request body",
                    )?,
                }
            }
            (_, ["exec", id, tail @ ..]) => {
                inspection.add(Resource::Exec((*id).into()));
                if *tail == ["resize"] {
                    rules = &["h", "w"]
                } else if *tail == ["start"] {
                    shape("exec_start", &object)?;
                    fields(&object, &["Detach", "Tty", "ConsoleSize"])?;
                    boolean(&object, "Detach")?;
                    boolean(&object, "Tty")?;
                }
            }
            ("POST", ["volumes", "create"]) => {
                shape("volume_create", &object)?;
                fields(&object, &["Name", "Driver", "DriverOpts", "Labels"])?;
                local_driver(&object, "Driver", "DriverOpts")?;
                let name = text(&object, "Name")?;
                if !name.is_empty() {
                    inspection.add(Resource::Volume(name.into(), true));
                }
            }
            (_, ["volumes", id]) => {
                inspection.add(Resource::Volume((*id).into(), false));
                rules = &["force"];
            }
            ("POST", ["networks", "create"]) => {
                shape("network_create", &object)?;
                fields(
                    &object,
                    &[
                        "Name",
                        "CheckDuplicate",
                        "Driver",
                        "Internal",
                        "Attachable",
                        "Ingress",
                        "IPAM",
                        "EnableIPv6",
                        "Options",
                        "Labels",
                        "ConfigOnly",
                        "ConfigFrom",
                        "Scope",
                    ],
                )?;
                require(
                    ["", "bridge"].contains(&text(&object, "Driver")?),
                    "unsupported network driver",
                )?;
                require(
                    ["", "local"].contains(&text(&object, "Scope")?),
                    "unsupported network scope",
                )?;
                require(
                    !boolean(&object, "Ingress")?
                        && !boolean(&object, "ConfigOnly")?
                        && empty(object.get("ConfigFrom")),
                    "unsupported network inheritance",
                )?;
                network_options(&object, false)?;
                let ipam = optional_object(&object, "IPAM")?;
                fields(&ipam, &["Driver", "Config", "Options"])?;
                require(
                    ["", "default"].contains(&text(&ipam, "Driver")?) && empty(ipam.get("Options")),
                    "unsupported IPAM driver or options",
                )?;
            }
            ("POST", ["networks", id, "connect" | "disconnect"]) => {
                fields(&object, &["Container", "EndpointConfig", "Force"])?;
                require(
                    !text(&object, "Container")?.is_empty(),
                    "Container is required",
                )?;
                inspection.primary_container = Some(text(&object, "Container")?.into());
                inspection.add(Resource::Container(text(&object, "Container")?.into()));
                inspection.add(Resource::Network((*id).into()));
                network_endpoint(
                    &optional_object(&object, "EndpointConfig")?,
                    &mut inspection,
                    true,
                )?;
            }
            (_, ["networks", id]) => inspection.add(Resource::Network((*id).into())),
            ("POST", ["build"]) => {
                inspection.add(Resource::Daemon {
                    private_cgroup: true,
                    default_runtime: true,
                    default_log: true,
                });
                rules = &[
                    "dockerfile",
                    "t",
                    "extrahosts",
                    "remote",
                    "q",
                    "nocache",
                    "cachefrom",
                    "pull",
                    "rm",
                    "forcerm",
                    "memory",
                    "memswap",
                    "cpushares",
                    "cpusetcpus",
                    "cpuperiod",
                    "cpuquota",
                    "buildargs",
                    "shmsize",
                    "squash",
                    "labels",
                    "networkmode",
                    "platform",
                    "target",
                    "version",
                    "ulimits",
                ];
                require(
                    params.get("remote").is_none_or(String::is_empty),
                    "remote build contexts are unsupported",
                )?;
                require(
                    params.get("version").is_none_or(|v| v == "1"),
                    "only the classic builder is supported",
                )?;
                let network = params
                    .get("networkmode")
                    .map(String::as_str)
                    .unwrap_or("default");
                self.namespace(network, "network", &mut inspection)?;
            }
            ("POST", ["images", "create"]) => {
                rules = &[
                    "fromImage",
                    "fromSrc",
                    "repo",
                    "tag",
                    "message",
                    "changes",
                    "platform",
                ];
                require(
                    !params.contains_key("fromSrc") && !params.contains_key("changes"),
                    "image import is unsupported; use image pull",
                )?;
                require(body.is_empty(), "image pull cannot upload a body")?;
            }
            ("GET" | "DELETE", ["images", name @ ..]) if name != ["json"] => {
                let mut name = name.join("/");
                if method == "GET" {
                    name = name
                        .strip_suffix("/json")
                        .ok_or("unsupported image operation")?
                        .into();
                }
                if matches!(self, Self::Project { .. }) {
                    inspection.add(Resource::Image(name));
                }
                if method == "DELETE" {
                    rules = &["force", "noprune"];
                }
            }
            _ => {} // Read-only discovery/list/image routes have no execution arguments.
        }
        if method == "POST"
            || method == "PUT"
            || method == "DELETE"
            || inspection.primary_container.is_some()
        {
            for key in params.keys() {
                require(
                    rules.contains(&key.as_str()),
                    format!("unsupported constrained Docker query field {key}"),
                )?;
            }
        }
        Ok(inspection)
    }

    fn config(
        &self,
        config: &Map<String, Value>,
        inspection: &mut Inspection,
    ) -> Result<(), Error> {
        let host = optional_object(config, "HostConfig")?;
        self.host_config(&host, inspection)?;
        let default_network = ["", "default"].contains(&text(&host, "NetworkMode")?);
        let networking = optional_object(config, "NetworkingConfig")?;
        fields(&networking, &["EndpointsConfig"])?;
        for (name, settings) in optional_object(&networking, "EndpointsConfig")? {
            // Moby's create route resolves this alias only for defaulted mode.
            // Explicit network names and endpoint NetworkID keep their identity.
            let name = if default_network && name == "default" {
                "bridge".into()
            } else {
                name
            };
            inspection.add(Resource::Network(name));
            network_endpoint(
                settings
                    .as_object()
                    .ok_or("network endpoint must be an object")?,
                inspection,
                true,
            )?;
        }
        Ok(())
    }

    fn namespace(&self, value: &str, kind: &str, inspection: &mut Inspection) -> Result<(), Error> {
        if matches!(self, Self::Project { .. })
            && kind == "network"
            && ["", "default", "bridge", "none"].contains(&value)
        {
            inspection.add(Resource::Network(
                if value == "none" { "none" } else { "bridge" }.into(),
            ));
        }
        if let Some(id) = value.strip_prefix("container:") {
            require(!id.is_empty(), "empty namespace reference")?;
            inspection.add(Resource::Container(id.into()));
        } else if kind == "network" && !["", "default", "bridge", "none"].contains(&value) {
            require(
                value != "host",
                "host network namespace is outside workload authority",
            )?;
            inspection.add(Resource::Network(value.into()));
        } else {
            let allowed = if kind == "network" {
                &["", "default", "bridge", "none"][..]
            } else if kind == "ipc" {
                &["", "private", "shareable", "none"][..]
            } else {
                &["", "private"][..]
            };
            require(
                allowed.contains(&value),
                format!("unsupported {kind} namespace"),
            )?;
        }
        Ok(())
    }

    fn host_config(
        &self,
        host: &Map<String, Value>,
        inspection: &mut Inspection,
    ) -> Result<(), Error> {
        require(
            !boolean(host, "Privileged")?,
            "privileged containers are outside workload authority",
        )?;
        for field in [
            "Devices",
            "DeviceRequests",
            "DeviceCgroupRules",
            "CapAdd",
            "StorageOpt",
            "Sysctls",
            "Annotations",
        ] {
            require(
                empty(host.get(field)),
                format!("{field} is outside workload authority"),
            )?;
        }
        for (field, kind) in [
            ("NetworkMode", "network"),
            ("PidMode", "pid"),
            ("IpcMode", "ipc"),
            ("UTSMode", "uts"),
            ("CgroupnsMode", "cgroup"),
        ] {
            self.namespace(text(host, field)?, kind, inspection)?;
        }
        require(
            text(host, "UsernsMode")?.is_empty(),
            "user namespace override is unsupported",
        )?;
        require(
            ["", "runc"].contains(&text(host, "Runtime")?),
            "unsupported container runtime",
        )?;
        require(
            ["", "default"].contains(&text(host, "Isolation")?),
            "only Linux workload isolation is supported",
        )?;
        require(
            text(host, "ContainerIDFile")?.is_empty()
                && text(host, "CgroupParent")?.is_empty()
                && text(host, "Cgroup")?.is_empty(),
            "host file or cgroup selection is unsupported",
        )?;
        for value in strings(host, "SecurityOpt")? {
            require(
                [
                    "no-new-privileges",
                    "no-new-privileges=true",
                    "no-new-privileges:true",
                ]
                .contains(&value),
                "unsupported security option",
            )?;
        }
        for field in ["MaskedPaths", "ReadonlyPaths"] {
            if host.get(field).is_some_and(|v| !v.is_null()) {
                // A complete explicit default is safe. Empty arrays disable Docker's defaults.
                let expected = if field == "MaskedPaths" {
                    MASKED
                } else {
                    READONLY
                };
                let actual: BTreeSet<_> = strings(host, field)?.into_iter().collect();
                require(
                    expected.iter().all(|path| actual.contains(path)),
                    format!("unsupported {field} override"),
                )?;
            }
        }
        require(
            ["", "local"].contains(&text(host, "VolumeDriver")?),
            "unsupported volume driver",
        )?;
        let log = optional_object(host, "LogConfig")?;
        require(
            ["", "json-file", "local", "none"].contains(&text(&log, "Type")?),
            "unsupported logging driver",
        )?;
        for key in optional_object(&log, "Config")?.keys() {
            require(
                [
                    "max-size",
                    "max-file",
                    "compress",
                    "mode",
                    "max-buffer-size",
                ]
                .contains(&key.as_str()),
                "unsupported log driver option",
            )?;
        }
        for bind in strings(host, "Binds")? {
            self.legacy_mount(bind, inspection)?;
        }
        for mount in array(host, "Mounts")? {
            self.mount(
                mount.as_object().ok_or("mount must be an object")?,
                inspection,
            )?;
        }
        for share in strings(host, "VolumesFrom")? {
            let mut parts = share.split(':');
            let id = parts.next().unwrap();
            require(
                !id.is_empty()
                    && parts.next().is_none_or(|mode| ["ro", "rw"].contains(&mode))
                    && parts.next().is_none(),
                "unsupported volume sharing reference",
            )?;
            inspection.add(Resource::Container(id.into()));
        }
        for link in strings(host, "Links")? {
            let id = link
                .split(':')
                .next()
                .unwrap_or_default()
                .trim_start_matches('/');
            require(!id.is_empty(), "empty link reference")?;
            inspection.add(Resource::Container(id.into()));
        }
        Ok(())
    }

    fn legacy_mount(&self, bind: &str, inspection: &mut Inspection) -> Result<(), Error> {
        let parts: Vec<_> = bind.split(':').collect();
        require((1..=3).contains(&parts.len()), "unsupported mount encoding")?;
        let (source, target) = if parts.len() == 1 {
            ("", parts[0])
        } else {
            (parts[0], parts[1])
        };
        require(clean_absolute(target), "mount target must be absolute")?;
        let modes: Vec<_> = parts.get(2).unwrap_or(&"rw").split(',').collect();
        require(
            modes
                .iter()
                .all(|m| ["ro", "rw", "nocopy", "consistent", "cached", "delegated"].contains(m)),
            "unsupported bind option or propagation",
        )?;
        let read_only = modes.contains(&"ro");
        require(
            !(read_only && modes.contains(&"rw")),
            "ambiguous mount write mode",
        )?;
        if source.starts_with('/') {
            self.bind(source, read_only)?
        } else if !source.is_empty() {
            volume_name(source)?;
            inspection.add(Resource::Volume(source.into(), true));
        }
        Ok(())
    }

    fn mount(&self, mount: &Map<String, Value>, inspection: &mut Inspection) -> Result<(), Error> {
        let source = text(mount, "Source")?;
        require(
            clean_absolute(text(mount, "Target")?),
            "mount target must be absolute",
        )?;
        match text(mount, "Type")? {
            "bind" => {
                require(
                    empty(mount.get("VolumeOptions")) && empty(mount.get("TmpfsOptions")),
                    "mount options do not match bind type",
                )?;
                self.bind(source, boolean(mount, "ReadOnly")?)?;
                let options = optional_object(mount, "BindOptions")?;
                require(
                    ["", "private", "rprivate"].contains(&text(&options, "Propagation")?),
                    "shared mount propagation is unsupported",
                )?;
                require(
                    !boolean(&options, "CreateMountpoint")?
                        && !boolean(&options, "ReadOnlyNonRecursive")?,
                    "unsupported host mount mutation or partial read-only mode",
                )?;
            }
            "volume" => {
                require(
                    empty(mount.get("BindOptions")) && empty(mount.get("TmpfsOptions")),
                    "mount options do not match volume type",
                )?;
                let options = optional_object(mount, "VolumeOptions")?;
                local_driver(
                    &optional_object(&options, "DriverConfig")?,
                    "Name",
                    "Options",
                )?;
                if !source.is_empty() {
                    volume_name(source)?;
                    inspection.add(Resource::Volume(source.into(), true));
                }
            }
            "tmpfs" => require(
                source.is_empty()
                    && empty(mount.get("BindOptions"))
                    && empty(mount.get("VolumeOptions")),
                "tmpfs cannot reference a host source or another mount type",
            )?,
            _ => return Err("unsupported mount type".into()),
        }
        Ok(())
    }
}

const MASKED: &[&str] = &[
    "/proc/asound",
    "/proc/acpi",
    "/proc/keys",
    "/proc/kcore",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/sys/firmware",
    "/sys/devices/virtual/powercap",
];
const READONLY: &[&str] = &[
    "/proc/bus",
    "/proc/fs",
    "/proc/irq",
    "/proc/sys",
    "/proc/sysrq-trigger",
];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Resource {
    Daemon {
        private_cgroup: bool,
        default_runtime: bool,
        default_log: bool,
    },
    Container(String),
    Exec(String),
    Volume(String, bool),
    Network(String),
    Image(String),
}
impl Resource {
    pub(crate) fn path(&self) -> Result<String, Error> {
        if matches!(self, Self::Daemon { .. }) {
            return Ok(format!("{}/info", super::API_PREFIX));
        }
        let (kind, name, tail) = match self {
            Self::Daemon { .. } => unreachable!(),
            Self::Container(name) => ("containers", name, "/json"),
            Self::Exec(name) => ("exec", name, "/json"),
            Self::Volume(name, _) => ("volumes", name, ""),
            Self::Network(name) => ("networks", name, ""),
            Self::Image(name) => ("images", name, "/json"),
        };
        require(
            !name.is_empty()
                && !name.contains(['?', '#', '%', '\\'])
                && !name.split('/').any(|p| p == "." || p == ".."),
            "unsupported resource identifier",
        )?;
        if kind != "images" {
            require(!name.contains('/'), "unsupported resource identifier")?;
        }
        Ok(format!("{}/{kind}/{name}{tail}", super::API_PREFIX))
    }
}

#[derive(Default)]
pub(crate) struct Inspection {
    pending: BTreeSet<Resource>,
    checked: BTreeSet<Resource>,
    missing: Option<Resource>,
    primary_container: Option<String>,
    pub(crate) container_id: Option<String>,
    pub(crate) observed: BTreeMap<Resource, Option<Value>>,
}
impl Inspection {
    /// A confirmed absence at the client's inspect target is normal Docker
    /// discovery. Absence of a dependency still refuses the requested operation.
    pub(crate) fn missing_target(&self, method: &str, target: &str) -> bool {
        method == "GET"
            && self.missing.as_ref().is_some_and(|resource| {
                resource.path().ok().as_deref() == Some(target.split('?').next().unwrap_or(target))
            })
    }

    fn add(&mut self, resource: Resource) {
        if !self.checked.contains(&resource) {
            self.pending.insert(resource);
        }
    }
    pub(crate) fn next(&mut self) -> Option<Resource> {
        let next = self.pending.pop_first()?;
        self.checked.insert(next.clone());
        Some(next)
    }
    pub(crate) fn observe(
        &mut self,
        access: &DockerAccess,
        resource: &Resource,
        value: Option<Value>,
    ) -> Result<(), Error> {
        if matches!(access, DockerAccess::Project { .. }) {
            self.observed.insert(resource.clone(), value.clone());
        }
        if matches!(resource, Resource::Volume(_, true)) && value.is_none() {
            return Ok(());
        }
        let Some(value) = value else {
            self.missing = Some(resource.clone());
            return Err("required Docker resource inspection unavailable".into());
        };
        let object = value
            .as_object()
            .ok_or("invalid Docker inspection response")?;
        match resource {
            Resource::Daemon {
                private_cgroup,
                default_runtime,
                default_log,
            } => {
                require(
                    text(object, "OSType")? == "linux",
                    "only Linux Engine is supported",
                )?;
                require(
                    !private_cgroup
                        || strings(object, "SecurityOptions")?.contains(&"name=cgroupns"),
                    "the daemon's omitted cgroup namespace must default to private; select CgroupnsMode private explicitly",
                )?;
                require(
                    !default_runtime || text(object, "DefaultRuntime")? == "runc",
                    "the daemon default runtime is outside workload authority",
                )?;
                require(
                    !default_log
                        || ["json-file", "local", "none"].contains(&text(object, "LoggingDriver")?),
                    "the daemon default logging driver is outside workload authority",
                )?;
            }
            Resource::Container(name) => {
                let id = text(object, "Id")?;
                require(
                    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()),
                    "invalid immutable container ID",
                )?;
                if self.primary_container.as_ref() == Some(name) {
                    self.container_id = Some(id.into());
                }
                if matches!(access, DockerAccess::Project { .. }) {
                    self.add(Resource::Image(text(object, "Image")?.into()));
                }
                let host = object
                    .get("HostConfig")
                    .and_then(Value::as_object)
                    .ok_or("HostConfig is required for existing workloads")?;
                require(
                    host.get("Privileged").is_some_and(Value::is_boolean),
                    "existing workload privilege is unknown",
                )?;
                require(
                    host.get("CgroupnsMode").and_then(Value::as_str) == Some("private"),
                    "existing workload cgroup namespace is unsafe or unknown",
                )?;
                access.host_config(host, self)?;
                let networking = object
                    .get("NetworkSettings")
                    .and_then(Value::as_object)
                    .ok_or("effective network settings are unavailable")?;
                for (name, settings) in optional_object(networking, "Networks")? {
                    self.add(Resource::Network(name));
                    network_endpoint(
                        settings
                            .as_object()
                            .ok_or("invalid effective network endpoint")?,
                        self,
                        false,
                    )?;
                }
                let mounts = object
                    .get("Mounts")
                    .and_then(Value::as_array)
                    .ok_or("effective mounts are unavailable")?;
                for mount in mounts {
                    let mount = mount.as_object().ok_or("invalid effective mount")?;
                    match text(mount, "Type")? {
                        "bind" => access.bind(
                            text(mount, "Source")?,
                            !mount
                                .get("RW")
                                .and_then(Value::as_bool)
                                .ok_or("mount write mode unavailable")?,
                        )?,
                        "volume" => {
                            require(
                                text(mount, "Driver")? == "local",
                                "unsupported effective volume driver",
                            )?;
                            self.add(Resource::Volume(text(mount, "Name")?.into(), false));
                        }
                        "tmpfs" => (),
                        _ => return Err("unsupported effective mount".into()),
                    }
                }
            }
            Resource::Exec(_) => {
                let process = object
                    .get("ProcessConfig")
                    .and_then(Value::as_object)
                    .ok_or("exec privilege is unavailable")?;
                require(
                    process.get("privileged") == Some(&json!(false)),
                    "privileged or unknown existing exec",
                )?;
                self.add(Resource::Container(text(object, "ContainerID")?.into()));
            }
            Resource::Volume(_, _) => {
                require(
                    text(object, "Driver")? == "local",
                    "effective volume driver is unknown or unsupported",
                )?;
                local_driver(object, "Driver", "Options")?;
            }
            Resource::Network(_) => {
                require(
                    ["bridge", "null"].contains(&text(object, "Driver")?),
                    "unsafe existing network driver",
                )?;
                network_options(object, true)?;
                let ipam = optional_object(object, "IPAM")?;
                require(
                    ["", "default"].contains(&text(&ipam, "Driver")?) && empty(ipam.get("Options")),
                    "existing network IPAM authority is unsupported",
                )?;
            }
            Resource::Image(_) => require(
                text(object, "Os")? == "linux",
                "only Linux images are supported",
            )?,
        }
        Ok(())
    }
}

static SHAPES: LazyLock<BTreeMap<String, Constraints>> = LazyLock::new(|| {
    serde_json::from_value(
        crate::policy::parse_yaml(include_str!(
            "../../../../contrib/docker/request-shapes.yaml"
        ))
        .expect("authored Docker shapes"),
    )
    .expect("authored Docker constraints")
});
fn shape(name: &str, object: &Map<String, Value>) -> Result<(), Error> {
    check_json_shape(&SHAPES[name], object)
        .map_err(|e| format!("Docker field {:?}: {:?}", e.field, e.code).into())
}
fn require(ok: bool, message: impl Into<String>) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(message.into().into())
    }
}
fn empty(value: Option<&Value>) -> bool {
    value.is_none_or(|v| {
        v.is_null()
            || v.as_array().is_some_and(Vec::is_empty)
            || v.as_object().is_some_and(Map::is_empty)
    })
}
fn text<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, Error> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(""),
        Some(Value::String(v)) => Ok(v),
        _ => Err(format!("{field} must be a string").into()),
    }
}
fn boolean(object: &Map<String, Value>, field: &str) -> Result<bool, Error> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(v)) => Ok(*v),
        _ => Err(format!("{field} must be a boolean").into()),
    }
}
fn array<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a [Value], Error> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(v)) => Ok(v),
        _ => Err(format!("{field} must be an array").into()),
    }
}
fn strings<'a>(object: &'a Map<String, Value>, field: &str) -> Result<Vec<&'a str>, Error> {
    array(object, field)?
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| format!("{field} items must be strings").into())
        })
        .collect()
}
fn optional_object(object: &Map<String, Value>, field: &str) -> Result<Map<String, Value>, Error> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::Object(v)) => Ok(v.clone()),
        _ => Err(format!("{field} must be an object").into()),
    }
}
fn fields(object: &Map<String, Value>, names: &[&str]) -> Result<(), Error> {
    for key in object.keys() {
        require(
            names.contains(&key.as_str()),
            format!("unsupported constrained Docker field {key}"),
        )?;
    }
    Ok(())
}
fn local_driver(object: &Map<String, Value>, driver: &str, options: &str) -> Result<(), Error> {
    require(
        ["", "local"].contains(&text(object, driver)?) && empty(object.get(options)),
        "only local volumes without driver options are supported",
    )
}
fn clean_absolute(path: &str) -> bool {
    path.starts_with('/')
        && path != "/"
        && !path.ends_with('/')
        && !path.contains(['\\', '\0'])
        && !path[1..]
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
}
fn daemon_socket(path: &str) -> bool {
    [
        "/run",
        "/var/run",
        "/var/lib/docker",
        "/proc",
        "/sys",
        "/dev",
    ]
    .iter()
    .any(|root| {
        path == *root
            || root.starts_with(&format!("{path}/"))
            || path.starts_with(&format!("{root}/"))
    }) || [
        "docker.sock",
        "podman.sock",
        "containerd.sock",
        "buildkitd.sock",
    ]
    .contains(&path.rsplit('/').next().unwrap_or_default())
}
fn volume_name(name: &str) -> Result<(), Error> {
    require(
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            && name != "."
            && name != "..",
        "unsupported volume name",
    )
}
fn network_endpoint(
    object: &Map<String, Value>,
    inspection: &mut Inspection,
    request: bool,
) -> Result<(), Error> {
    if request {
        shape("network_endpoint", object)?;
    }
    let id = text(object, "NetworkID")?;
    if !id.is_empty() {
        inspection.add(Resource::Network(id.into()));
    }
    for link in strings(object, "Links")? {
        let container = link
            .split(':')
            .next()
            .unwrap_or_default()
            .trim_start_matches('/');
        require(!container.is_empty(), "empty endpoint link reference")?;
        inspection.add(Resource::Container(container.into()));
    }
    require(
        empty(object.get("DriverOpts")),
        "endpoint driver options are unsupported",
    )
}

fn network_options(object: &Map<String, Value>, existing: bool) -> Result<(), Error> {
    let options = optional_object(object, "Options")?;
    for (key, value) in &options {
        let ordinary = [
            "com.docker.network.driver.mtu",
            "com.docker.network.bridge.enable_icc",
            "com.docker.network.bridge.enable_ip_masquerade",
            "com.docker.network.bridge.host_binding_ipv4",
        ]
        .contains(&key.as_str());
        let daemon_bridge = existing
            && options
                .get("com.docker.network.bridge.default_bridge")
                .and_then(Value::as_str)
                == Some("true")
            && [
                "com.docker.network.bridge.default_bridge",
                "com.docker.network.bridge.name",
            ]
            .contains(&key.as_str());
        require(
            value.is_string() && (ordinary || daemon_bridge),
            "unsupported network driver option",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn access() -> DockerAccess {
        DockerAccess::Workloads {
            bind_mounts: Vec::new(),
        }
    }
    fn create(body: Value) -> Result<Inspection, Error> {
        access().request(
            "POST",
            "/v1.45/containers/create",
            &serde_json::to_vec(&body).unwrap(),
        )
    }

    #[test]
    fn ordinary_defaults_and_nested_shapes_remain_usable() {
        for config in [
            // Docker CLI 26.1.5 create payload captured before any daemon effect.
            serde_json::from_str(include_str!(
                "../../../tests/fixtures/docker/create-defaults.json"
            ))
            .unwrap(),
            json!({"Image":"busybox"}),
            json!({"Image":"busybox","HostConfig":null}),
            json!({"Image":"busybox","Cmd":"sh","HostConfig":{"Privileged":null,"Memory":6291456,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"Mounts":[{"Type":"volume","Target":"/data","Source":"existing-name"}]}}),
            json!({"Image":"busybox","StopTimeout":-1,"HostConfig":{"BlkioWeight":0,"ShmSize":0}}),
        ] {
            assert!(create(config.clone()).is_ok(), "{config}");
        }
        for config in [
            json!({}),
            json!({"Image":7}),
            json!({"Image":"busybox","HostConfig":{"Memory":-1}}),
            json!({"Image":"busybox","HostConfig":{"Mounts":[{"Type":"volume","Target":"/data"},true]}}),
            json!({"Image":"busybox","hostconfig":{"privileged":true}}),
        ] {
            assert!(create(config.clone()).is_err(), "{config}");
        }
    }
    #[test]
    fn compose_exec_defaults_require_existing_resource_inspection() {
        // Compose v2.40.3 at API 1.45, captured against a local synthetic Engine.
        // Attached, detached and 24x80 terminal sessions all send Detach on create.
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/docker/compose-exec-defaults.json"
        ))
        .unwrap();
        for fixture in fixtures.as_array().unwrap() {
            for (field, path, resource) in [
                (
                    "create",
                    "/v1.45/containers/existing-name/exec",
                    Resource::Container("existing-name".into()),
                ),
                (
                    "start",
                    "/v1.45/exec/exec-id/start",
                    Resource::Exec("exec-id".into()),
                ),
            ] {
                let mut plan = access()
                    .request("POST", path, &serde_json::to_vec(&fixture[field]).unwrap())
                    .unwrap();
                assert_eq!(plan.next(), Some(resource.clone()));
                assert!(plan.observe(&access(), &resource, None).is_err());
            }
        }
    }
    #[test]
    fn exec_create_and_start_keep_typed_fields_and_privilege_bounds() {
        for (body, allowed) in [
            (json!({}), true),
            (json!({"Detach":false,"Tty":false}), true),
            (
                json!({"Detach":true,"Tty":true,"ConsoleSize":[24,80]}),
                true,
            ),
            (json!({"Detach":null,"Tty":null,"ConsoleSize":null}), true),
            (json!({"ConsoleSize":[0,0]}), true),
            (json!({"Detach":"false"}), false),
            (json!({"Detach":0}), false),
            (json!({"Detach":[]}), false),
            (json!({"Tty":"true"}), false),
            (json!({"ConsoleSize":[-1,80]}), false),
            (json!({"ConsoleSize":[24,80.0]}), false),
            (json!({"ConsoleSize":[24,"80"]}), false),
            (json!({"ConsoleSize":[24,true]}), false),
            (json!({"ConsoleSize":24}), false),
            (json!({"ConsoleSize":{}}), false),
            (json!({"Detach":false,"detach":true}), false),
            (
                json!({"Detach":false,"ConsoleSize":[24,80],"FutureOption":false}),
                false,
            ),
            (
                json!({"Detach":false,"ConsoleSize":[24,80],"Privileged":true}),
                false,
            ),
        ] {
            for path in [
                "/v1.45/containers/existing-name/exec",
                "/v1.45/exec/exec-id/start",
            ] {
                assert_eq!(
                    access()
                        .request("POST", path, &serde_json::to_vec(&body).unwrap())
                        .is_ok(),
                    allowed,
                    "{path}: {body}"
                );
            }
        }
    }
    #[test]
    fn resource_defaults_and_sentinels_apply_to_create_and_update() {
        for (resources, allowed) in [
            (json!({}), true),
            (json!({"MemorySwappiness":null}), true),
            (json!({"MemorySwappiness":-1}), true),
            (json!({"MemorySwappiness":0}), true),
            (json!({"MemorySwappiness":100}), true),
            (json!({"MemorySwappiness":-2}), false),
            (json!({"MemorySwappiness":101}), false),
            (json!({"MemorySwappiness":"-1"}), false),
            (json!({"MemorySwappiness":-1.0}), false),
            (json!({"MemorySwappiness":true}), false),
            (json!({"Memory":null}), true),
            (json!({"Memory":0}), true),
            (json!({"Memory":6291456}), true),
            (json!({"Memory":-1}), false),
            // These distinct resource fields retain their own unlimited sentinels.
            (
                json!({"Memory":6291456,"MemorySwap":-1,"CpuQuota":-1,"PidsLimit":-1,"Ulimits":[{"Name":"nofile","Soft":-1,"Hard":-1}]}),
                true,
            ),
        ] {
            assert_eq!(
                create(json!({"Image":"busybox","HostConfig":resources})).is_ok(),
                allowed,
                "create {resources}"
            );
            assert_eq!(
                access()
                    .request(
                        "POST",
                        "/v1.45/containers/existing-name/update",
                        &serde_json::to_vec(&resources).unwrap(),
                    )
                    .is_ok(),
                allowed,
                "update {resources}"
            );
        }
    }
    #[test]
    fn endpoint_defaults_types_and_bounds_apply_to_create_and_connect() {
        // Compose v2.40.3 createEndpointSettings sets GwPriority even when unset.
        // Moby docker-v29.1.3 defines it as int64; create at API 1.45 resets it
        // to zero, while network connect passes the decoded value through.
        for (endpoint, allowed) in [
            (json!({}), true),
            (
                json!({"IPAMConfig":null,"Links":null,"Aliases":["ordinary-worker-1","worker"],"MacAddress":"","DriverOpts":null,"GwPriority":0,"NetworkID":"","EndpointID":"","Gateway":"","IPAddress":"","IPPrefixLen":0,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"DNSNames":null}),
                true,
            ),
            (json!({"GwPriority":null}), true),
            (json!({"GwPriority":0}), true),
            (json!({"GwPriority":-1}), true),
            (json!({"GwPriority":1}), true),
            (json!({"GwPriority":i64::MIN}), true),
            (json!({"GwPriority":i64::MAX}), true),
            (json!({"GwPriority":9223372036854775808_u64}), false),
            (
                serde_json::from_str(r#"{"GwPriority":-9223372036854775809}"#).unwrap(),
                false,
            ),
            (json!({"GwPriority":"0"}), false),
            (json!({"GwPriority":0.0}), false),
            (json!({"GwPriority":0.5}), false),
            (json!({"GwPriority":true}), false),
            (json!({"GwPriority":[]}), false),
            (json!({"GwPriority":{}}), false),
            (json!({"GwPriority":0,"gwpriority":1}), false),
            (json!({"GwPriority":0,"FutureOption":false}), false),
            (json!({"GwPriority":0,"Aliases":[true]}), false),
            (
                json!({"GwPriority":0,"IPAMConfig":{"IPv4Address":7}}),
                false,
            ),
            (
                json!({"GwPriority":0,"IPAMConfig":{"Driver":"host"}}),
                false,
            ),
            (
                json!({"GwPriority":0,"DriverOpts":{"com.docker.network.endpoint.sysctls":"net.ipv4.conf.IFNAME.forwarding=1"}}),
                false,
            ),
        ] {
            assert_eq!(
                create(json!({"Image":"busybox","NetworkingConfig":{"EndpointsConfig":{"ordinary-net":endpoint}}})).is_ok(),
                allowed,
                "create {endpoint}"
            );
            assert_eq!(
                access()
                    .request(
                        "POST",
                        "/v1.45/networks/ordinary-net/connect",
                        &serde_json::to_vec(
                            &json!({"Container":"existing-name","EndpointConfig":endpoint})
                        )
                        .unwrap(),
                    )
                    .is_ok(),
                allowed,
                "connect {endpoint}"
            );
        }
    }
    #[test]
    fn endpoint_priority_preserves_indirect_inspection() {
        let endpoint =
            json!({"GwPriority":1,"NetworkID":"unsafe-network","Links":["unsafe-container:alias"]});
        for mut plan in [
            create(json!({"Image":"busybox","NetworkingConfig":{"EndpointsConfig":{"ordinary-net":endpoint}}})).unwrap(),
            access().request(
                "POST",
                "/v1.45/networks/ordinary-net/connect",
                &serde_json::to_vec(&json!({"Container":"existing-name","EndpointConfig":endpoint})).unwrap(),
            ).unwrap(),
        ] {
            let mut seen = Vec::new();
            while let Some(resource) = plan.next() {
                seen.push(resource);
            }
            assert!(seen.contains(&Resource::Network("ordinary-net".into())));
            assert!(seen.contains(&Resource::Network("unsafe-network".into())));
            assert!(seen.contains(&Resource::Container("unsafe-container".into())));
        }
    }
    #[test]
    fn endpoint_default_network_alias_depends_on_create_network_mode() {
        for (host, expected_network) in [
            (Value::Null, "bridge"),
            (json!({}), "bridge"),
            (json!({"NetworkMode":null}), "bridge"),
            (json!({"NetworkMode":""}), "bridge"),
            (json!({"NetworkMode":"default"}), "bridge"),
            (json!({"NetworkMode":"bridge"}), "default"),
            (json!({"NetworkMode":"none"}), "default"),
            (json!({"NetworkMode":"ordinary-net"}), "default"),
        ] {
            let mut plan = create(json!({"Image":"busybox","HostConfig":host,
                "NetworkingConfig":{"EndpointsConfig":{"default":{"NetworkID":"referenced-net","Links":["linked-container:alias"]}}}})).unwrap();
            let mut networks = BTreeSet::new();
            let mut containers = BTreeSet::new();
            while let Some(resource) = plan.next() {
                match resource {
                    Resource::Network(name) => {
                        networks.insert(name);
                    }
                    Resource::Container(name) => {
                        containers.insert(name);
                    }
                    _ => (),
                }
            }
            assert!(networks.contains(expected_network), "{host}");
            assert_eq!(
                networks.contains("default"),
                expected_network == "default",
                "{host}"
            );
            assert!(networks.contains("referenced-net"));
            assert!(containers.contains("linked-container"));
        }

        // The alias belongs to create configuration, not every network ID.
        for (method, target, body, expected_networks) in [
            ("GET", "/v1.45/networks/default", json!({}), vec!["default"]),
            (
                "POST",
                "/v1.45/networks/default/connect",
                json!({"Container":"ordinary"}),
                vec!["default"],
            ),
            (
                "POST",
                "/v1.45/containers/create",
                json!({"Image":"busybox","HostConfig":{"NetworkMode":"default"},"NetworkingConfig":{"EndpointsConfig":{"default":{"NetworkID":"default"}}}}),
                vec!["bridge", "default"],
            ),
        ] {
            let mut plan = access()
                .request(method, target, &serde_json::to_vec(&body).unwrap())
                .unwrap();
            let mut networks = Vec::new();
            while let Some(resource) = plan.next() {
                if let Resource::Network(name) = resource {
                    networks.push(name);
                }
            }
            assert_eq!(networks, expected_networks, "{target}");
        }
    }
    #[test]
    fn normalized_resource_defaults_preserve_existing_workload_checks() {
        // Engine normalizes the request's -1 swappiness sentinel to null.
        // Inspection is a response, so it does not use the request-only shape.
        for resources in [
            json!({}),
            json!({"MemorySwappiness":null,"MemorySwap":-1,"PidsLimit":null}),
            json!({"MemorySwappiness":0,"PidsLimit":-1}),
            json!({"MemorySwappiness":100,"PidsLimit":0}),
        ] {
            for privileged in [false, true] {
                let mut host = resources.as_object().unwrap().clone();
                host.extend(
                    json!({"Privileged":privileged,"CgroupnsMode":"private","NetworkMode":"bridge"})
                        .as_object()
                        .unwrap()
                        .clone(),
                );
                let mut plan = access()
                    .request("POST", "/v1.45/containers/existing-name/start", b"")
                    .unwrap();
                let resource = plan.next().unwrap();
                assert_eq!(
                    plan.observe(
                        &access(),
                        &resource,
                        Some(json!({"Id":"b".repeat(64),"HostConfig":host,"NetworkSettings":{"Networks":{}},"Mounts":[]})),
                    )
                    .is_ok(),
                    !privileged,
                    "existing workload {resources}, privileged={privileged}"
                );
            }
        }
    }
    #[test]
    fn known_host_routes_and_alternate_mount_encodings_are_refused() {
        for mut host in [
            json!({"Privileged":true}),
            json!({"NetworkMode":"host"}),
            json!({"PidMode":"host"}),
            json!({"IpcMode":"host"}),
            json!({"UTSMode":"host"}),
            json!({"CgroupnsMode":"host"}),
            json!({"UsernsMode":"host"}),
            json!({"Devices":[{"PathOnHost":"/dev/kvm","PathInContainer":"/dev/kvm","CgroupPermissions":"rwm"}]}),
            json!({"DeviceCgroupRules":["a *:* rwm"]}),
            json!({"DeviceRequests":[{"Count":-1,"Capabilities":[["gpu"]]}]}),
            json!({"CapAdd":["SYS_ADMIN"]}),
            json!({"SecurityOpt":["seccomp=unconfined"]}),
            json!({"SecurityOpt":["apparmor=unconfined"]}),
            json!({"MaskedPaths":[]}),
            json!({"ReadonlyPaths":[]}),
            json!({"ContainerIDFile":"/operator-file"}),
            json!({"Binds":["/var/run/docker.sock:/s"]}),
            json!({"Binds":["/etc:/data:ro"]}),
            json!({"Mounts":[{"Type":"bind","Source":"/etc","Target":"/data","ReadOnly":true}]}),
            json!({"Mounts":[{"Type":"volume","Target":"/data","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","device":"/","o":"bind"}}}}]}),
            json!({"NetworkMode":"host","CapDrop":["ALL"],"ReadonlyRootfs":true}),
        ] {
            host.as_object_mut()
                .unwrap()
                .insert("MemorySwappiness".into(), json!(-1));
            assert!(
                create(json!({"Image":"busybox","HostConfig":host})).is_err(),
                "{host}"
            );
        }
        assert!(
            access()
                .request(
                    "POST",
                    "/v1.45/build?version=2&entitlements=security.insecure",
                    b"tar"
                )
                .is_err()
        );
        assert!(
            access()
                .request("POST", "/v1.45/build?networkmode=host", b"tar")
                .is_err()
        );
        assert!(
            access()
                .request(
                    "POST",
                    "/v1.45/volumes/create",
                    br#"{"Driver":"local","driver":"evil"}"#
                )
                .is_err()
        );
        assert!(
            access()
                .request(
                    "POST",
                    "/v1.45/networks/create",
                    br#"{"Name":"n","IPAM":{"Driver":"default","driver":"evil"}}"#
                )
                .is_err()
        );
    }
    #[test]
    fn indirect_volume_and_workload_references_are_checked() {
        let mut plan = create(json!({"Image":"busybox","HostConfig":{"VolumesFrom":["unsafe:ro"],"NetworkMode":"container:unsafe","Binds":["named:/data"]}})).unwrap();
        let mut seen = Vec::new();
        while let Some(resource) = plan.next() {
            seen.push(resource);
        }
        assert!(seen.contains(&Resource::Container("unsafe".into())));
        assert!(seen.contains(&Resource::Volume("named".into(), true)));
        let mut plan = access()
            .request("POST", "/v1.45/containers/unsafe/start", b"")
            .unwrap();
        let resource = plan.next().unwrap();
        assert!(
            plan.observe(
                &access(),
                &resource,
                Some(json!({"Id":"a".repeat(64),"HostConfig":{"Privileged":true},"Mounts":[]}))
            )
            .is_err()
        );
        let mut plan = Inspection::default();
        assert!(
            plan.observe(
                &access(),
                &Resource::Volume("named".into(), false),
                Some(json!({"Driver":"local","Options":{"device":"/","o":"bind","type":"none"}}))
            )
            .is_err()
        );
        assert!(
            plan.observe(
                &access(),
                &Resource::Exec("exec-id".into()),
                Some(json!({"ContainerID":"safe","ProcessConfig":{"privileged":true}}))
            )
            .is_err()
        );
    }
    #[test]
    fn missing_inspection_fails_closed_and_existing_names_resolve_without_labels() {
        let mut plan = access()
            .request("POST", "/v1.45/containers/existing-name/start", b"")
            .unwrap();
        let resource = plan.next().unwrap();
        assert!(plan.observe(&access(), &resource, None).is_err());
        plan.observe(&access(),&resource,Some(json!({"Id":"b".repeat(64),"HostConfig":{"Privileged":false,"CgroupnsMode":"private","NetworkMode":"bridge"},"NetworkSettings":{"Networks":{}},"Mounts":[]}))).unwrap();
        assert_eq!(plan.container_id, Some("b".repeat(64)));
    }
    #[test]
    fn rename_requires_one_name_and_inspects_the_existing_container() {
        for (query, allowed) in [
            ("?name=syproof21cd528538cf-web-1", true),
            ("?name=%2Fweb-1", true),
            ("", false),
            ("?name=", false),
            ("?name=web-1&name=other", false),
            ("?name=web-1&force=true", false),
        ] {
            let result = access().request(
                "POST",
                &format!("/v1.45/containers/temporary-name/rename{query}"),
                b"",
            );
            assert_eq!(result.is_ok(), allowed, "{query}");
            if let Ok(mut inspection) = result {
                assert_eq!(
                    inspection.next(),
                    Some(Resource::Container("temporary-name".into()))
                );
                assert!(
                    inspection
                        .observe(
                            &access(),
                            &Resource::Container("temporary-name".into()),
                            None
                        )
                        .is_err()
                );
            }
        }
    }
    #[test]
    fn confirmed_absence_is_not_found_only_for_the_direct_inspect_target() {
        for resource in [
            Resource::Container("ordinary".into()),
            Resource::Exec("exec-id".into()),
            Resource::Network("ordinary-net".into()),
            Resource::Volume("ordinary-data".into(), false),
            Resource::Image("registry.example/project:current".into()),
        ] {
            let mut plan = Inspection::default();
            let target = resource.path().unwrap();
            assert!(plan.observe(&access(), &resource, None).is_err());
            assert!(plan.missing_target("GET", &target));
            assert!(plan.missing_target("GET", &format!("{target}?size=false")));
            assert!(!plan.missing_target("POST", &target));
            assert!(!plan.missing_target("DELETE", &target));
            assert!(!plan.missing_target("GET", "/v1.45/containers/another/json"));
        }
        let mut plan = Inspection::default();
        assert!(
            plan.observe(&access(), &Resource::Volume("new-data".into(), true), None)
                .is_ok()
        );
        assert!(!plan.missing_target("GET", "/v1.45/volumes/new-data"));
    }
    #[test]
    fn effective_daemon_defaults_are_checked_before_defaulted_creation() {
        let resource = Resource::Daemon {
            private_cgroup: true,
            default_runtime: true,
            default_log: true,
        };
        for (facts, allowed) in [
            (
                json!({"OSType":"linux","CgroupVersion":"2","SecurityOptions":["name=cgroupns"],"DefaultRuntime":"runc","LoggingDriver":"json-file"}),
                true,
            ),
            (
                json!({"OSType":"linux","CgroupVersion":"1","SecurityOptions":["name=cgroupns"],"DefaultRuntime":"runc","LoggingDriver":"local"}),
                true,
            ),
            (
                json!({"OSType":"linux","CgroupVersion":"2","SecurityOptions":[],"DefaultRuntime":"runc","LoggingDriver":"json-file"}),
                false,
            ),
            (
                json!({"OSType":"linux","CgroupVersion":"2","SecurityOptions":["name=cgroupns"],"DefaultRuntime":"custom","LoggingDriver":"json-file"}),
                false,
            ),
            (
                json!({"OSType":"linux","CgroupVersion":"2","SecurityOptions":["name=cgroupns"],"DefaultRuntime":"runc","LoggingDriver":"fluentd"}),
                false,
            ),
        ] {
            assert_eq!(
                Inspection::default()
                    .observe(&access(), &resource, Some(facts))
                    .is_ok(),
                allowed
            );
        }
    }
    #[test]
    fn explicit_file_bounds_apply_to_both_mount_encodings() {
        let access = DockerAccess::Workloads {
            bind_mounts: vec![BindMount {
                source: "/srv/project-data".into(),
                read_only: true,
            }],
        };
        for mount in [
            json!({"Binds":["/srv/project-data:/data:ro"]}),
            json!({"Mounts":[{"Type":"bind","Source":"/srv/project-data","Target":"/data","ReadOnly":true}]}),
        ] {
            assert!(
                access
                    .request(
                        "POST",
                        "/v1.45/containers/create",
                        &serde_json::to_vec(&json!({"Image":"busybox","HostConfig":mount}))
                            .unwrap()
                    )
                    .is_ok()
            );
        }
        for host in [
            json!({"Binds":["/srv/project-data:/data"]}),
            json!({"Mounts":[{"Type":"bind","Source":"/srv/project-data","Target":"/data","ReadOnly":false}]}),
        ] {
            assert!(
                access
                    .request(
                        "POST",
                        "/v1.45/containers/create",
                        &serde_json::to_vec(&json!({"Image":"busybox","HostConfig":host})).unwrap()
                    )
                    .is_err()
            );
        }
        assert!(
            DockerAccess::SandboxAdmin
                .validate(ExecutionBoundary::External)
                .is_err()
        );
        assert!(
            DockerAccess::SandboxAdmin
                .validate(ExecutionBoundary::Sandbox)
                .is_ok()
        );
    }
}
