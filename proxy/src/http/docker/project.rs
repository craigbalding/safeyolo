//! Docker-specific admission, successful-effect recording and response projection.

use super::super::{AllowedRequest, Body, full};
use crate::{
    Error, Runtime,
    services::docker::{
        API_PREFIX, DockerAccess,
        enforcement::{Inspection, Resource},
        project::{MARKER, Membership, Pending, check},
    },
};
use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::{
    HeaderMap, Response, StatusCode,
    body::{Body as HttpBody, Frame, Incoming},
    header,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    pin::Pin,
    task::{Context, Poll},
};

pub(in crate::http) struct ProjectRequest {
    pub membership: Membership,
    method: String,
    path: String,
    references: BTreeMap<Resource, String>,
    _serial: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl ProjectRequest {
    pub(in crate::http) fn switched(
        mut self,
        upstream: &mut Response<Incoming>,
    ) -> Result<(), Error> {
        sanitize_headers(upstream.headers_mut(), false);
        upstream
            .extensions_mut()
            .remove::<hyper::ext::ReasonPhrase>();
        self.membership.state.pending = None;
        self.membership.save()
    }
    pub(in crate::http) async fn open(
        runtime: &Runtime,
        access: &DockerAccess,
        endpoint: &str,
        method: &str,
        path: &str,
    ) -> Result<Option<Self>, Error> {
        let DockerAccess::Project { project, .. } = access else {
            return Ok(None);
        };
        let serial = runtime.docker_projects.clone().lock_owned().await;
        Ok(Some(Self {
            membership: Membership::open(&runtime.config.data_dir(), endpoint, project)?,
            method: method.into(),
            path: path.into(),
            references: BTreeMap::new(),
            _serial: Some(serial),
        }))
    }
    pub(in crate::http) async fn prepare(
        &mut self,
        runtime: &Runtime,
        allowed: &AllowedRequest<'_>,
        provider: Option<&str>,
        headers: &HeaderMap,
        inspection: &Inspection,
        body: &[u8],
    ) -> Result<(String, Option<Vec<u8>>), Error> {
        let membership = &mut self.membership;
        if membership.state.pending.is_some() {
            self.reconcile(runtime, allowed, provider, headers).await?;
        }
        let membership = &mut self.membership;
        if !membership.project.selected.volumes.is_empty()
            || !membership.project.shared.volumes.is_empty()
        {
            let events = events(runtime, allowed, provider, headers).await?;
            membership.events(&events)?;
        }
        membership.authorize(inspection, &self.method, &self.path)?;
        let (path, query) = self.path.split_once('?').unwrap_or((&self.path, ""));
        let params = crate::contracts::query_params(query).map_err(|_| "invalid project query")?;
        let parts: Vec<_> = path
            .trim_start_matches(API_PREFIX)
            .split('/')
            .filter(|p| !p.is_empty())
            .collect();
        // Classic build contexts can name arbitrary local images in FROM and
        // COPY --from. That API has no inspectable request-local image set.
        // Workload mode retains classic build; project mode uses explicit pulls.
        check(
            path != format!("{API_PREFIX}/build"),
            "classic build cannot enforce project image references",
        )?;
        let mut object = if body.is_empty() {
            json!({})
        } else if self.method == "POST" && !path.ends_with("/archive") {
            crate::contracts::strict_json(body)?
        } else {
            Value::Null
        };
        let mut forwarded_path = self.path.clone();
        // Pin every resolvable direct address, including image tags and networks.
        match parts.as_slice() {
            ["networks", name, tail @ ..]
                if !(self.method == "POST" && *name == "create" && tail.is_empty()) =>
            {
                if let Some(Some(value)) =
                    inspection.observed.get(&Resource::Network((*name).into()))
                {
                    forwarded_path = address("networks", string(value, "Id"), tail, query);
                }
            }
            ["images", tail @ ..] if *tail != ["create"] && *tail != ["json"] => {
                if let Some((_, Some(value))) = inspection
                    .observed
                    .iter()
                    .find(|(r, _)| matches!(r, Resource::Image(_)))
                {
                    forwarded_path = address(
                        "images",
                        string(value, "Id"),
                        if self.method == "GET" { &["json"] } else { &[] },
                        query,
                    );
                    if self.method == "DELETE" {
                        let tags = value
                            .get("RepoTags")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        check(
                            tags.iter().all(|tag| {
                                tag.as_str().is_some_and(|tag| {
                                    membership.owns_image_name(tag, string(value, "Id"))
                                })
                            }),
                            "image has aliases outside this project",
                        )?;
                        // Do not let image deletion recursively prune parent images.
                        forwarded_path =
                            address("images", string(value, "Id"), &[], "noprune=true");
                    }
                }
            }
            ["exec", name, tail @ ..] => {
                if let Some(Some(value)) = inspection.observed.get(&Resource::Exec((*name).into()))
                {
                    forwarded_path = address("exec", string(value, "ID"), tail, query);
                }
            }
            ["containers", _, tail @ ..] => {
                if let Some(id) = &inspection.container_id {
                    forwarded_path = address("containers", id, tail, query);
                }
            }
            _ => (),
        }
        self.references = inspection
            .observed
            .iter()
            .filter_map(|(resource, value)| {
                let value = value.as_ref()?;
                let id = value
                    .get("Id")
                    .or_else(|| value.get("ID"))
                    .and_then(Value::as_str)?;
                Some((resource.clone(), id.to_owned()))
            })
            .collect();
        rewrite_references(&mut object, &self.references);
        if self.method == "DELETE"
            && parts.first() == Some(&"containers")
            && params.get("v").is_some_and(|v| v == "1" || v == "true")
        {
            for (resource, value) in &inspection.observed {
                if let (Resource::Volume(name, _), Some(_)) = (resource, value) {
                    check(
                        membership.owns("volume", name),
                        "container removal cannot delete a shared volume",
                    )?;
                }
            }
        }
        let mutation = !["GET", "HEAD"].contains(&self.method.as_str());
        if !mutation {
            return Ok((forwarded_path, None));
        }
        let marker = uuid::Uuid::new_v4().to_string();
        let mut pending = Pending {
            method: self.method.clone(),
            path: forwarded_path.clone(),
            kind: "operation".into(),
            name: String::new(),
            marker: marker.clone(),
            parent: inspection.container_id.clone().unwrap_or_default(),
            volume_effects: false,
        };
        match parts.as_slice() {
            ["containers", "create"] if self.method == "POST" => {
                pending.kind = "container".into();
                pending.name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .into();
                insert_marker(&mut object, &marker);
                prepare_volumes(
                    &mut object,
                    inspection,
                    &marker,
                    &mut pending.volume_effects,
                )?;
                if !pending.name.is_empty() {
                    absent(
                        runtime,
                        allowed,
                        provider,
                        headers,
                        &Resource::Container(pending.name.clone()),
                    )
                    .await?;
                }
            }
            ["networks", "create"] if self.method == "POST" => {
                pending.kind = "network".into();
                pending.name = string(&object, "Name").into();
                check(!pending.name.is_empty(), "network name required")?;
                absent(
                    runtime,
                    allowed,
                    provider,
                    headers,
                    &Resource::Network(pending.name.clone()),
                )
                .await?;
                insert_marker(&mut object, &marker);
            }
            ["volumes", "create"] if self.method == "POST" => {
                pending.kind = "volume".into();
                if string(&object, "Name").is_empty() {
                    object["Name"] = json!(format!("safeyolo-{}", uuid::Uuid::new_v4()));
                }
                pending.name = string(&object, "Name").into();
                let existing = super::get(
                    runtime,
                    allowed,
                    provider,
                    headers,
                    &Resource::Volume(pending.name.clone(), false).path()?,
                )
                .await?;
                if let Some(existing) = existing {
                    check(
                        membership.volume(&pending.name, &existing)
                            && membership.owns("volume", &pending.name),
                        "volume create would adopt an existing dependency",
                    )?;
                    // Engine volume-create is idempotent for an already selected
                    // volume. Preserve its identity rather than relabelling it.
                    pending.kind = "operation".into();
                } else {
                    insert_marker(&mut object, &marker);
                }
            }
            ["images", "create"] if self.method == "POST" => {
                pending.kind = "image".into();
                let from = params
                    .get("fromImage")
                    .and_then(Value::as_str)
                    .ok_or("fromImage required")?;
                let tag = params
                    .get("tag")
                    .and_then(Value::as_str)
                    .unwrap_or("latest");
                pending.name =
                    if from.contains('@') || from.rsplit('/').next().unwrap_or("").contains(':') {
                        from.into()
                    } else {
                        format!("{from}:{tag}")
                    };
                let existing = super::get(
                    runtime,
                    allowed,
                    provider,
                    headers,
                    &Resource::Image(pending.name.clone()).path()?,
                )
                .await?;
                if let Some(existing) = existing {
                    check(
                        membership.owns_image_name(&pending.name, string(&existing, "Id")),
                        "pull would replace an unrelated or shared image reference",
                    )?;
                }
            }
            ["containers", _, "exec"] => {
                pending.kind = "exec".into();
            }
            _ => (),
        }
        // Journal before dispatch. Cancellation, parser failure or process exit
        // leaves this intent for reconciliation, without replaying the mutation.
        if pending.kind != "operation" {
            membership.state.pending = Some(pending);
            membership.save()?;
        }
        // Wait does not create identities. Each subsequent operation already
        // inspects the affected container's current state. Holding the creation
        // mutex here would prevent another client from stopping that container.
        if parts.last() == Some(&"wait") {
            self._serial.take();
        }
        let rewritten = if body.is_empty() && object == json!({}) {
            None
        } else if object.is_object() {
            Some(serde_json::to_vec(&object)?)
        } else {
            None
        };
        Ok((forwarded_path, rewritten))
    }

    async fn reconcile(
        &mut self,
        runtime: &Runtime,
        allowed: &AllowedRequest<'_>,
        provider: Option<&str>,
        headers: &HeaderMap,
    ) -> Result<(), Error> {
        let pending = self
            .membership
            .state
            .pending
            .clone()
            .expect("pending project operation");
        match pending.kind.as_str() {
            "container" | "network" | "volume" => {
                let resource = match pending.kind.as_str() {
                    "container" if !pending.name.is_empty() => {
                        Some(Resource::Container(pending.name.clone()))
                    }
                    "network" => Some(Resource::Network(pending.name.clone())),
                    "volume" => Some(Resource::Volume(pending.name.clone(), false)),
                    _ => None,
                };
                let value = if let Some(resource) = resource {
                    super::get(runtime, allowed, provider, headers, &resource.path()?).await?
                } else {
                    let list = super::get(
                        runtime,
                        allowed,
                        provider,
                        headers,
                        &format!("{API_PREFIX}/containers/json?all=true"),
                    )
                    .await?
                    .ok_or("container list unavailable")?;
                    let found: Vec<_> = list
                        .as_array()
                        .ok_or("invalid container list")?
                        .iter()
                        .filter(|v| v["Labels"][MARKER].as_str() == Some(&pending.marker))
                        .collect();
                    check(found.len() <= 1, "ambiguous container creation")?;
                    if let Some(value) = found.first() {
                        super::get(
                            runtime,
                            allowed,
                            provider,
                            headers,
                            &Resource::Container(string(value, "Id").into()).path()?,
                        )
                        .await?
                    } else {
                        None
                    }
                };
                let created = value.is_some();
                if let Some(value) = value {
                    check(
                        value["Labels"][MARKER]
                            .as_str()
                            .or_else(|| value["Config"]["Labels"][MARKER].as_str())
                            == Some(&pending.marker),
                        "unknown creation requires explicit operator re-adoption",
                    )?;
                    self.membership
                        .record(&pending.kind, &value, Some(&pending.marker))?;
                }
                let volumes_recorded = self
                    .record_volumes(runtime, allowed, provider, headers, &pending)
                    .await?;
                check(
                    !created || volumes_recorded,
                    "created volume effects remain uncertain",
                )?;
            }
            "image" => {
                return Err(
                    "interrupted image creation requires explicit operator re-adoption".into(),
                );
            }
            "exec" => {
                let parent = super::get(
                    runtime,
                    allowed,
                    provider,
                    headers,
                    &Resource::Container(pending.parent.clone()).path()?,
                )
                .await?
                .ok_or("exec parent is unavailable; explicitly re-adopt current state")?;
                check(
                    string(&parent, "Id") == pending.parent
                        && self.membership.owns("container", &pending.parent),
                    "exec parent identity changed",
                )?;
                if let Some(execs) = parent.get("ExecIDs").and_then(Value::as_array) {
                    for id in execs.iter().filter_map(Value::as_str) {
                        if let Some(value) = super::get(
                            runtime,
                            allowed,
                            provider,
                            headers,
                            &Resource::Exec(id.into()).path()?,
                        )
                        .await?
                        {
                            check(
                                string(&value, "ContainerID") == pending.parent,
                                "exec parent association changed",
                            )?;
                            self.membership.record("exec", &value, None)?;
                        }
                    }
                }
            }
            _ => return Err("unknown Docker mutation".into()),
        }
        self.membership.state.pending = None;
        self.membership.save()?;
        runtime.audit.emit(allowed.identity.request_event("gateway.docker_reconciled",crate::audit::Kind::Gateway,allowed.request_id,
            "Reconciled the current state after an interrupted Docker mutation; no mutation was replayed",json!({"project":self.membership.project.name,"prior_method":pending.method,"prior_path":pending.path,"replayed":false})))?;
        Ok(())
    }

    async fn record_volumes(
        &mut self,
        runtime: &Runtime,
        allowed: &AllowedRequest<'_>,
        provider: Option<&str>,
        headers: &HeaderMap,
        pending: &Pending,
    ) -> Result<bool, Error> {
        if !pending.volume_effects {
            return Ok(true);
        }
        let filters =
            serde_json::to_string(&json!({"label":[format!("{MARKER}={}",pending.marker)]}))?;
        let filters =
            percent_encoding::utf8_percent_encode(&filters, percent_encoding::NON_ALPHANUMERIC);
        let values = super::get(
            runtime,
            allowed,
            provider,
            headers,
            &format!("{API_PREFIX}/volumes?filters={filters}"),
        )
        .await?
        .ok_or("created volumes unavailable")?;
        let volumes = values.get("Volumes").and_then(Value::as_array);
        if let Some(volumes) = volumes {
            for volume in volumes {
                self.membership
                    .record("volume", volume, Some(&pending.marker))?;
            }
        }
        Ok(volumes.is_some_and(|volumes| !volumes.is_empty()))
    }

    pub(in crate::http) async fn response(
        mut self,
        runtime: &Runtime,
        allowed: &AllowedRequest<'_>,
        provider: Option<&str>,
        headers: &HeaderMap,
        upstream: Response<Incoming>,
    ) -> Result<Response<Body>, Error> {
        let status = upstream.status();
        let (mut parts, body) = upstream.into_parts();
        sanitize_headers(&mut parts.headers, self.path.contains("/archive"));
        parts.extensions.remove::<hyper::ext::ReasonPhrase>();
        if !status.is_success() && status != StatusCode::SWITCHING_PROTOCOLS {
            // Even daemon conflict and driver messages can contain other names.
            // A completed error can still leave partial creation effects; reconcile
            // those before dependent work instead of treating it as rollback.
            return Ok(Response::from_parts(
                parts,
                full(Bytes::from_static(
                    b"{\"message\":\"Docker project operation failed\"}",
                )),
            ));
        }
        let path = self
            .path
            .split('?')
            .next()
            .unwrap_or(&self.path)
            .trim_start_matches(API_PREFIX)
            .to_owned();
        let raw = path.ends_with("/logs")
            || path.ends_with("/archive")
            || path.ends_with("/attach")
            || path.ends_with("/start") && path.starts_with("/exec/");
        if raw || status == StatusCode::SWITCHING_PROTOCOLS {
            self.membership.state.pending = None;
            self.membership.save()?;
            return Ok(Response::from_parts(
                parts,
                body.map_err(|e| Box::new(e) as Error).boxed(),
            ));
        }
        if path == "/events" || path.ends_with("/stats") {
            return Ok(Response::from_parts(
                parts,
                Lines {
                    body,
                    buffer: BytesMut::new(),
                    membership: self.membership,
                    events: path == "/events",
                    done: false,
                }
                .boxed(),
            ));
        }
        let bytes =
            http_body_util::Limited::new(body, crate::http_content::BUFFERED_BODY_THRESHOLD)
                .collect()
                .await?
                .to_bytes();
        let mut result = if bytes.is_empty() || path == "/_ping" {
            None
        } else if path == "/images/create" {
            let records = parse_lines(&bytes)?;
            check(
                !records
                    .iter()
                    .any(|v| v.get("error").is_some() || v.get("errorDetail").is_some()),
                "image pull failed; inspect or re-adopt before retrying",
            )?;
            let pending = self
                .membership
                .state
                .pending
                .clone()
                .ok_or("image pull intent missing")?;
            let digest = records
                .iter()
                .find_map(|record| {
                    record
                        .get("status")
                        .and_then(Value::as_str)
                        .and_then(|status| status.strip_prefix("Digest: "))
                })
                .ok_or("image pull did not establish a content digest")?;
            let repository = pending.name.split('@').next().unwrap_or(&pending.name);
            let repository = repository
                .rsplit_once(':')
                .filter(|(_, tag)| !tag.contains('/'))
                .map_or(repository, |(repository, _)| repository);
            let value = super::get(
                runtime,
                allowed,
                provider,
                headers,
                &Resource::Image(format!("{repository}@{digest}")).path()?,
            )
            .await?
            .ok_or("pulled image unavailable")?;
            self.membership.record("image", &value, None)?;
            self.membership
                .state
                .image_names
                .insert(pending.name, string(&value, "Id").into());
            Some(json!({"status":"Image pull completed"}))
        } else {
            Some(crate::contracts::strict_json(&bytes)?)
        };
        if let Some(pending) = self.membership.state.pending.clone() {
            if ["container", "network", "volume", "exec"].contains(&pending.kind.as_str()) {
                let value = result.as_ref().ok_or("creation response missing")?;
                let id = string(value, "Id");
                let resource = match pending.kind.as_str() {
                    "container" => Resource::Container(id.into()),
                    "network" => Resource::Network(id.into()),
                    "volume" => Resource::Volume(string(value, "Name").into(), false),
                    "exec" => Resource::Exec(id.into()),
                    _ => unreachable!(),
                };
                let observed = super::get(runtime, allowed, provider, headers, &resource.path()?)
                    .await?
                    .ok_or("created resource unavailable")?;
                self.membership
                    .record(&pending.kind, &observed, Some(&pending.marker))?;
                check(
                    self.record_volumes(runtime, allowed, provider, headers, &pending)
                        .await?,
                    "created volume effects remain uncertain",
                )?;
            }
            self.membership.state.pending = None;
            self.membership.save()?;
        }
        if self._serial.is_some()
            && (!self.membership.project.selected.volumes.is_empty()
                || !self.membership.project.shared.volumes.is_empty())
        {
            self.membership
                .events(&events(runtime, allowed, provider, headers).await?)?;
        }
        let bytes = if let Some(value) = result.take() {
            if self.method == "DELETE" && path.starts_with("/images/") {
                serde_json::to_vec(&json!([]))?
            } else if path == "/images/create" {
                let mut out = serde_json::to_vec(&value)?;
                out.push(b'\n');
                out
            } else {
                let mut value = value;
                rewrite_references(&mut value, &self.references);
                serde_json::to_vec(&self.membership.response(&self.path, value)?)?
            }
        } else {
            bytes.to_vec()
        };
        parts
            .headers
            .insert(header::CONTENT_LENGTH, bytes.len().to_string().parse()?);
        Ok(Response::from_parts(parts, full(Bytes::from(bytes))))
    }
}
fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}
fn address(kind: &str, id: &str, tail: &[&str], query: &str) -> String {
    let tail = if tail.is_empty() {
        String::new()
    } else {
        format!("/{}", tail.join("/"))
    };
    format!(
        "{API_PREFIX}/{kind}/{id}{tail}{}",
        if query.is_empty() {
            String::new()
        } else {
            format!("?{query}")
        }
    )
}
async fn absent(
    runtime: &Runtime,
    allowed: &AllowedRequest<'_>,
    provider: Option<&str>,
    headers: &HeaderMap,
    resource: &Resource,
) -> Result<(), Error> {
    check(
        super::get(runtime, allowed, provider, headers, &resource.path()?)
            .await?
            .is_none(),
        "creation cannot adopt an existing resource",
    )
}
async fn events(
    runtime: &Runtime,
    allowed: &AllowedRequest<'_>,
    provider: Option<&str>,
    headers: &HeaderMap,
) -> Result<Vec<Value>, Error> {
    let now = time::OffsetDateTime::now_utc();
    let path = format!(
        "{API_PREFIX}/events?since=0&until={}.{:09}",
        now.unix_timestamp(),
        now.nanosecond()
    );
    let (status, bytes) = super::read(runtime, allowed, provider, headers, &path).await?;
    check(
        status == StatusCode::OK,
        "volume identity reconciliation unavailable",
    )?;
    parse_lines(&bytes)
}
fn parse_lines(bytes: &[u8]) -> Result<Vec<Value>, Error> {
    bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
        .map(crate::contracts::strict_json)
        .collect()
}
fn insert_marker(value: &mut Value, marker: &str) {
    if !value["Labels"].is_object() {
        value["Labels"] = json!({});
    }
    value["Labels"][MARKER] = json!(marker);
}
fn rewrite_references(value: &mut Value, references: &BTreeMap<Resource, String>) {
    fn pin(references: &BTreeMap<Resource, String>, resource: Resource) -> Option<String> {
        references.get(&resource).cloned()
    }
    fn pin_containers(value: &mut Value, references: &BTreeMap<Resource, String>) {
        if let Some(values) = value.as_array_mut() {
            for value in values {
                if let Some(name) = value.as_str() {
                    let (name, suffix) = name.split_once(':').unwrap_or((name, ""));
                    if let Some(id) = pin(
                        references,
                        Resource::Container(name.trim_start_matches('/').into()),
                    ) {
                        *value = json!(if suffix.is_empty() {
                            id
                        } else {
                            format!("{id}:{suffix}")
                        });
                    }
                }
            }
        }
    }
    if let Some(object) = value.as_object_mut() {
        if let Some(image) = object.get_mut("Image") {
            if let Some(id) = image
                .as_str()
                .and_then(|name| pin(references, Resource::Image(name.into())))
            {
                *image = json!(id);
            }
        }
        if let Some(container) = object.get_mut("Container") {
            if let Some(id) = container
                .as_str()
                .and_then(|name| pin(references, Resource::Container(name.into())))
            {
                *container = json!(id);
            }
        }
        if let Some(host) = object.get_mut("HostConfig").and_then(Value::as_object_mut) {
            for key in [
                "NetworkMode",
                "PidMode",
                "IpcMode",
                "UTSMode",
                "CgroupnsMode",
            ] {
                if let Some(value) = host.get_mut(key) {
                    if let Some(name) = value.as_str() {
                        if let Some(name) = name.strip_prefix("container:") {
                            if let Some(id) = pin(references, Resource::Container(name.into())) {
                                *value = json!(format!("container:{id}"));
                            }
                        } else if key == "NetworkMode" {
                            if let Some(id) = pin(references, Resource::Network(name.into())) {
                                *value = json!(id);
                            }
                        }
                    }
                }
            }
            for key in ["VolumesFrom", "Links"] {
                if let Some(values) = host.get_mut(key) {
                    pin_containers(values, references);
                }
            }
        }
        if let Some(links) = object
            .get_mut("EndpointConfig")
            .and_then(|v| v.get_mut("Links"))
        {
            pin_containers(links, references);
        }
        if let Some(endpoints) = object
            .get_mut("NetworkingConfig")
            .and_then(|v| v.get_mut("EndpointsConfig"))
            .and_then(Value::as_object_mut)
        {
            let original = std::mem::take(endpoints);
            for (name, mut value) in original {
                let id = pin(references, Resource::Network(name.clone())).unwrap_or(name);
                value["NetworkID"] = json!(id);
                if let Some(links) = value.get_mut("Links") {
                    pin_containers(links, references);
                }
                endpoints.insert(id, value);
            }
        }
    }
}
fn prepare_volumes(
    object: &mut Value,
    inspection: &Inspection,
    marker: &str,
    planned: &mut bool,
) -> Result<(), Error> {
    let mut targets = object
        .get("Volumes")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (resource, value) in &inspection.observed {
        if let (Resource::Image(_), Some(image)) = (resource, value) {
            if let Some(volumes) = image.pointer("/Config/Volumes").and_then(Value::as_object) {
                targets.extend(volumes.clone());
            }
        }
    }
    if !object["HostConfig"].is_object() {
        object["HostConfig"] = json!({});
    }
    let host = object["HostConfig"].as_object_mut().unwrap();
    let mut mounts = host
        .remove("Mounts")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let mut binds = Vec::new();
    if let Some(original) = host.remove("Binds").and_then(|v| v.as_array().cloned()) {
        for bind in original {
            let text = bind.as_str().ok_or("invalid bind")?;
            let parts: Vec<_> = text.split(':').collect();
            let (source, target) = if parts.len() == 1 {
                ("", parts[0])
            } else {
                (parts[0], parts[1])
            };
            targets.remove(target);
            if source.starts_with('/')
                || !source.is_empty()
                    && inspection
                        .observed
                        .get(&Resource::Volume(source.into(), true))
                        .is_some_and(Option::is_some)
            {
                binds.push(bind);
            } else {
                let modes: Vec<_> = parts.get(2).unwrap_or(&"rw").split(',').collect();
                mounts.push(json!({"Type":"volume","Source":source,"Target":target,"ReadOnly":modes.contains(&"ro"),"VolumeOptions":{"NoCopy":modes.contains(&"nocopy")}}));
            }
        }
    }
    for mount in &mounts {
        if let Some(target) = mount.get("Target").and_then(Value::as_str) {
            targets.remove(target);
        }
    }
    for (target, _) in targets {
        mounts.push(json!({"Type":"volume","Source":"","Target":target}));
    }
    for mount in &mut mounts {
        if string(mount, "Type") == "volume" {
            let name = string(mount, "Source").to_owned();
            if !inspection
                .observed
                .get(&Resource::Volume(name.clone(), true))
                .is_some_and(Option::is_some)
            {
                if !mount["VolumeOptions"].is_object() {
                    mount["VolumeOptions"] = json!({});
                }
                insert_marker(&mut mount["VolumeOptions"], marker);
                *planned = true;
            }
        }
    }
    host.insert("Binds".into(), json!(binds));
    host.insert("Mounts".into(), json!(mounts));
    Ok(())
}
fn sanitize_headers(headers: &mut HeaderMap, archive: bool) {
    let allowed = [
        "content-type",
        "api-version",
        "docker-experimental",
        "ostype",
        "upgrade",
        "connection",
    ];
    let names: Vec<_> = headers
        .keys()
        .filter(|key| {
            !allowed.contains(&key.as_str())
                && !(archive && key.as_str() == "x-docker-container-path-stat")
        })
        .cloned()
        .collect();
    for name in names {
        headers.remove(name);
    }
}
struct Lines {
    body: Incoming,
    buffer: BytesMut,
    membership: Membership,
    events: bool,
    done: bool,
}
impl HttpBody for Lines {
    type Data = Bytes;
    type Error = Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        loop {
            let line = if let Some(end) = self.buffer.iter().position(|b| *b == b'\n') {
                Some(self.buffer.split_to(end + 1).freeze())
            } else if self.done && !self.buffer.is_empty() {
                Some(self.buffer.split().freeze())
            } else {
                None
            };
            if let Some(line) = line {
                let value = match crate::contracts::strict_json(line.trim_ascii()) {
                    Ok(value) => value,
                    Err(_) => {
                        return Poll::Ready(Some(Err("invalid Docker management stream".into())));
                    }
                };
                let value = if self.events {
                    self.membership.event(&value)
                } else {
                    match self.membership.stats(value) {
                        Ok(value) => Some(value),
                        Err(error) => return Poll::Ready(Some(Err(error))),
                    }
                };
                if let Some(value) = value {
                    let mut bytes = match serde_json::to_vec(&value) {
                        Ok(bytes) => bytes,
                        Err(error) => return Poll::Ready(Some(Err(error.into()))),
                    };
                    bytes.push(b'\n');
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from(bytes)))));
                }
                continue;
            }
            if self.done {
                return Poll::Ready(None);
            }
            match Pin::new(&mut self.body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => self.done = true,
                Poll::Ready(Some(Err(_))) => {
                    self.done = true;
                    return Poll::Ready(Some(Err("Docker management stream interrupted".into())));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(bytes) = frame.into_data() {
                        if self.buffer.len() + bytes.len()
                            > crate::http_content::BUFFERED_BODY_THRESHOLD
                        {
                            self.done = true;
                            return Poll::Ready(Some(Err(
                                "Docker management record exceeds inspection capacity".into(),
                            )));
                        }
                        self.buffer.extend_from_slice(&bytes);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn anonymous_volume_markers_preserve_anonymous_sources_and_existing_binds() {
        let mut inspection = Inspection::default();
        inspection.observed.insert(
            Resource::Image("image".into()),
            Some(json!({"Config":{"Volumes":{"/anonymous":{}}}})),
        );
        inspection.observed.insert(
            Resource::Volume("existing".into(), true),
            Some(json!({"Driver":"local"})),
        );
        let mut object = json!({"Image":"image","HostConfig":{"Binds":["existing:/existing:ro","new-data:/new:rw"]}});
        let mut planned = false;
        prepare_volumes(&mut object, &inspection, "private-creation", &mut planned).unwrap();
        assert!(planned);
        assert_eq!(
            object["HostConfig"]["Binds"],
            json!(["existing:/existing:ro"])
        );
        let mounts = object["HostConfig"]["Mounts"].as_array().unwrap();
        let anonymous = mounts
            .iter()
            .find(|mount| mount["Target"] == "/anonymous")
            .unwrap();
        assert_eq!(anonymous["Source"], "");
        assert_eq!(
            anonymous["VolumeOptions"]["Labels"][MARKER],
            "private-creation"
        );
        let named = mounts
            .iter()
            .find(|mount| mount["Target"] == "/new")
            .unwrap();
        assert_eq!(named["Source"], "new-data");
    }
    #[test]
    fn mutable_container_network_and_image_references_are_pinned() {
        let container = "a".repeat(64);
        let network = "b".repeat(64);
        let image = format!("sha256:{}", "c".repeat(64));
        let references = BTreeMap::from([
            (Resource::Container("ordinary".into()), container.clone()),
            (Resource::Network("ordinary-net".into()), network.clone()),
            (Resource::Image("mutable:tag".into()), image.clone()),
        ]);
        let mut object = json!({"Image":"mutable:tag","Container":"ordinary","HostConfig":{"NetworkMode":"container:ordinary","VolumesFrom":["ordinary:ro"]},"NetworkingConfig":{"EndpointsConfig":{"ordinary-net":{"Links":["ordinary:alias"]}}},"EndpointConfig":{"Links":["ordinary:alias"]}});
        rewrite_references(&mut object, &references);
        assert_eq!(object["Image"], image);
        assert_eq!(object["Container"], container);
        assert_eq!(
            object["HostConfig"]["NetworkMode"],
            format!("container:{container}")
        );
        assert_eq!(
            object["HostConfig"]["VolumesFrom"],
            json!([format!("{container}:ro")])
        );
        assert_eq!(
            object["NetworkingConfig"]["EndpointsConfig"][&network]["NetworkID"],
            network
        );
        assert_eq!(
            object["EndpointConfig"]["Links"],
            json!([format!("{container}:alias")])
        );
    }
}
