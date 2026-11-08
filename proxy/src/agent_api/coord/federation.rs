//! Scoped Core NATS requests. Canonical owners retain identity and effects.
use super::*;
use crate::{Error, coord_rooms::federation as trust};
use serde::{Deserialize, Serialize};

// DOC: docs/peer-support.md
const MAX_WIRE_REQUEST: usize = crate::coord_rooms::COLLABORATION_MAX_ENVELOPE_BYTES;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerRequest {
    destination_instance_id: String,
    source_run: crate::host_runs::AgentRun,
    method: String,
    path: String,
    body: Option<Value>,
}

impl CoordClient {
    pub(super) async fn check_remote(&self) -> Result<(), CoordError> {
        let Some(remote) = self.remote.clone() else {
            return Ok(());
        };
        let db = self.owner.data_dir.join("v0.db");
        tokio::task::spawn_blocking(move || {
            trust::authorize(&open_db(&db, false)?, &remote).map_err(|_| CoordError::Forbidden)
        })
        .await
        .map_err(|_| CoordError::Unavailable)?
    }
}

fn without_home(path: &str) -> Result<String, CoordError> {
    let Some((path, query)) = path.split_once('?') else {
        return Err(CoordError::Invalid);
    };
    let mut homes = 0;
    let mut retained = Vec::new();
    for part in query.split('&') {
        let key =
            percent_encoding::percent_decode_str(part.split_once('=').map_or(part, |(key, _)| key))
                .decode_utf8()
                .map_err(|_| CoordError::Invalid)?;
        if key == "home" {
            homes += 1;
        } else {
            retained.push(part);
        }
    }
    if homes != 1 {
        return Err(CoordError::Invalid);
    }
    Ok(if retained.is_empty() {
        path.into()
    } else {
        format!("{path}?{}", retained.join("&"))
    })
}

fn support_route(request: Request<'_>) -> bool {
    let path = super::super::route(request);
    (request.method == "GET" && path == "/support/grants")
        || (request.method == "POST" && path == "/support/operations")
        || (request.method == "GET"
            && path
                .strip_prefix("/support/operations/")
                .is_some_and(|id| !id.is_empty() && !id.contains('/')))
}

fn approval_route(request: Request<'_>) -> bool {
    let path = super::super::route(request);
    (request.method == "GET" && path == "/approvals")
        || path.strip_prefix("/approvals/").is_some_and(|suffix| {
            let (id, resolve) = suffix
                .strip_suffix("/resolve")
                .map_or((suffix, false), |id| (id, true));
            crate::approvals::pending::valid_id(id)
                && !id.contains('/')
                && ((request.method == "GET" && !resolve) || (request.method == "POST" && resolve))
        })
}

fn allowed(request: Request<'_>) -> bool {
    request.path_and_query.len() <= 16384
        && query_parameter(request.path_and_query, "home").is_ok_and(|home| home.is_none())
        && (route_parts(request).is_some()
            || attention_wait_route(request)
            || attention_object_route(request).is_some()
            || support_route(request)
            || approval_route(request)
            || (request.method == "POST"
                && super::super::route(request) == "/api/coord/attention/subscribe"))
}

fn unavailable(request: Request<'_>) -> Outcome<'static> {
    response(
        503,
        json!({"error":"owning instance unreachable; inspect the original operation_id or canonical history before retrying. A lost reply does not prove cancellation or target death.",
        "mutation_outcome":if request.method == "POST" {"unknown"} else {"not_requested"},
        "availability":"unreachable"}),
    )
}

fn local_run_current(context: &CoordContext<'_>, run: &crate::host_runs::AgentRun) -> bool {
    context
        .runtime
        .and_then(|runtime| crate::peer_support::current_policy(runtime).ok())
        .is_some_and(|policy| run.current(&policy))
}

pub(super) async fn forward(
    request: Request<'_>,
    context: &CoordContext<'_>,
    payload: Option<&[u8]>,
    _agent_name: &str,
    principal: &str,
    home_name: &str,
) -> Outcome<'static> {
    if !public_name_part(home_name) {
        return error_response(CoordError::Invalid);
    }
    let Some(run) = request.identity.run() else {
        return response(
            403,
            json!({"error":"trusted current source-agent run required"}),
        );
    };
    if run.agent_id != principal || !local_run_current(context, run) {
        return error_response(CoordError::Forbidden);
    }
    let path = match without_home(request.path_and_query) {
        Ok(path) => path,
        Err(error) => return error_response(error),
    };
    if !allowed(Request {
        path_and_query: &path,
        ..request
    }) {
        return error_response(CoordError::NotFound);
    }
    let source = match std::fs::read_to_string(context.client.owner.data_dir.join("instance_id")) {
        Ok(id) => id.trim().to_owned(),
        Err(_) => return error_response(CoordError::Unavailable),
    };
    let db = context.client.owner.data_dir.join("v0.db");
    let home = match open_db(&db, false)
        .and_then(|conn| trust::home(&conn, home_name).map_err(|_| CoordError::Forbidden))
    {
        Ok(home) => home,
        Err(error) => return error_response(error),
    };
    if query_parameter(request.path_and_query, "instance_id")
        .ok()
        .flatten()
        .is_some_and(|selected| selected != home.instance_id)
    {
        return response(
            409,
            json!({"error":"source cursor belongs to another instance; inspect the current route","instance_id":home.instance_id}),
        );
    }
    let body = match payload
        .filter(|_| request.method == "POST")
        .map(serde_json::from_slice::<Value>)
        .transpose()
    {
        Ok(body) => body,
        Err(_) => return response(400, json!({"error":"invalid JSON body"})),
    };
    let peer = PeerRequest {
        destination_instance_id: home.instance_id.clone(),
        source_run: run.clone(),
        method: request.method.into(),
        path,
        body,
    };
    if serde_json::to_vec(&peer).is_ok_and(|wire| wire.len() > MAX_WIRE_REQUEST) {
        return response(
            413,
            json!({"error":"request exceeds the managed NATS payload limit; no remote operation attempted"}),
        );
    }
    let result = async {
        let connection = trust::nats::connect(&home, &source).await?;
        if attention_wait_route(Request {
            path_and_query: &peer.path,
            ..request
        }) {
            wait_remote(&connection, &home, &source, &peer).await
        } else {
            exchange(&connection, &home, &source, &peer).await
        }
    };
    let mut cancellation = context.cancellation.clone();
    let result = tokio::select! {
        value=result=>value,
        _=wait_cancelled(&mut cancellation)=>return unavailable(request),
    };
    if !local_run_current(context, run)
        || open_db(&db, false)
            .ok()
            .and_then(|conn| trust::home(&conn, home_name).ok())
            .as_ref()
            != Some(&home)
    {
        return error_response(CoordError::Forbidden);
    }
    match result {
        Ok(reply) if reply["home_instance_id"] == home.instance_id => {
            let Some(status) = reply["status"]
                .as_u64()
                .and_then(|s| u16::try_from(s).ok())
                .filter(|s| (200..600).contains(s))
            else {
                return error_response(CoordError::Data);
            };
            match reply.get("body") {
                Some(body) => response(status, body.clone()),
                None => error_response(CoordError::Data),
            }
        }
        Ok(_) => response(
            503,
            json!({"error":"response identity differs from selected owning instance","availability":"unknown"}),
        ),
        Err(error)
            if error
                .downcast_ref::<async_nats::ConnectError>()
                .is_some_and(|error| {
                    matches!(
                        error.kind(),
                        async_nats::ConnectErrorKind::AuthorizationViolation
                            | async_nats::ConnectErrorKind::Authentication
                    )
                }) =>
        {
            response(
                403,
                json!({"error":"peer broker authentication denied; reconcile any prior in-flight operation before retrying"}),
            )
        }
        Err(_) => unavailable(request),
    }
}

async fn exchange(
    connection: &async_nats::Client,
    home: &trust::Home,
    source: &str,
    peer: &PeerRequest,
) -> Result<Value, Error> {
    let timeout = if peer.path.starts_with("/api/coord/attention/") {
        Duration::from_secs(2)
    } else {
        Duration::from_secs(330)
    };
    let message = connection
        .send_request(
            trust::nats::request_subject(&home.instance_id, source),
            async_nats::Request::new()
                .payload(serde_json::to_vec(peer)?.into())
                .timeout(Some(timeout)),
        )
        .await?;
    if message.payload.len() > 8 * 1024 * 1024 {
        return Err("federation response exceeds limit".into());
    }
    Ok(serde_json::from_slice(&message.payload)?)
}

/// Subscribe before reading B's retained position. There is no network poll
/// and no global cross-instance position.
async fn wait_remote(
    connection: &async_nats::Client,
    home: &trust::Home,
    source: &str,
    peer: &PeerRequest,
) -> Result<Value, Error> {
    let seconds = query_parameter(&peer.path, "timeout")
        .map_err(|_| "invalid wait timeout")?
        .map_or(Ok(60.0), |value| value.parse::<f64>())
        .map_err(|_| "invalid wait timeout")?;
    if !seconds.is_finite() || !(0.0..=300.0).contains(&seconds) {
        return Err("invalid wait timeout".into());
    }
    if seconds == 0.0 {
        return exchange(connection, home, source, peer).await;
    }
    let subscription = exchange(
        connection,
        home,
        source,
        &PeerRequest {
            method: "POST".into(),
            path: "/api/coord/attention/subscribe".into(),
            body: None,
            ..peer.clone()
        },
    )
    .await?;
    if subscription["status"] != 200 {
        return Ok(subscription);
    }
    let stream = async_nats::jetstream::new(connection.clone())
        .get_stream(trust::nats::notice_stream(source))
        .await?;
    let consumer = stream
        .get_consumer::<pull::Config>(
            subscription["body"]["consumer"]
                .as_str()
                .ok_or("invalid notification consumer")?,
        )
        .await?;
    let mut hints = consumer.messages().await?;
    let path = peer
        .path
        .split_once('?')
        .map_or(peer.path.as_str(), |(path, _)| path);
    let since = query_parameter(&peer.path, "since")
        .map_err(|_| "invalid cursor")?
        .unwrap_or_else(|| "0".into());
    let limit = query_parameter(&peer.path, "limit")
        .map_err(|_| "invalid limit")?
        .unwrap_or_else(|| "1".into());
    let read = PeerRequest {
        path: format!("{path}?since={since}&limit={limit}&timeout=0"),
        ..peer.clone()
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(seconds);
    loop {
        let reply = exchange(connection, home, source, &read).await?;
        if reply["status"] != 200
            || reply["body"]["edges"]
                .as_array()
                .is_none_or(|edges| !edges.is_empty())
            || reply["body"]["next_cursor"]
                .as_u64()
                .is_some_and(|next| Some(next) != since.parse::<u64>().ok())
            || tokio::time::Instant::now() >= deadline
        {
            return Ok(reply);
        }
        tokio::select! {
            _=tokio::time::sleep_until(deadline)=>return exchange(connection,home,source,&read).await,
            hint=hints.next()=>if hint.is_none(){return Err("remote notification subscription unavailable".into());},
        }
    }
}

pub(crate) async fn forward_support(
    request: Request<'_>,
    state: &crate::RuntimeState,
    payload: Option<&[u8]>,
    home: &str,
) -> Outcome<'static> {
    let Some(run) = request.identity.run() else {
        return error_response(CoordError::Forbidden);
    };
    let client = match state.read() {
        Ok(runtime) => runtime.coord.clone(),
        Err(_) => return error_response(CoordError::Unavailable),
    };
    let (_cancel, cancellation) = tokio::sync::watch::channel(false);
    forward(
        request,
        &CoordContext {
            client: &client,
            cancellation,
            runtime: Some(state),
        },
        payload,
        &run.agent,
        &run.agent_id,
        home,
    )
    .await
}

fn reply(instance: &str, status: u16, body: Value) -> Value {
    json!({"home_instance_id":instance,"status":status,"body":body})
}

async fn receive(
    client: &CoordClient,
    runtime: &crate::RuntimeState,
    instance: &str,
    source: &str,
    credential_hash: &str,
    bytes: &[u8],
) -> Value {
    if bytes.len() > MAX_WIRE_REQUEST {
        return reply(instance, 413, json!({"error":"request body too large"}));
    }
    let Ok(peer) = serde_json::from_slice::<PeerRequest>(bytes) else {
        return reply(instance, 400, json!({"error":"invalid federation request"}));
    };
    // DOC: docs/coord-reference.md, docs/coord-trust-boundary.md
    if peer.destination_instance_id != instance {
        return reply(
            instance,
            403,
            json!({"error":"destination instance mismatch; no operation attempted"}),
        );
    }
    let remote = match open_db(&client.owner.data_dir.join("v0.db"), false).and_then(|conn| {
        trust::authenticate_transport(&conn, source, credential_hash, &peer.source_run.agent_id)
            .map_err(|_| CoordError::Forbidden)
    }) {
        Ok(remote) => remote,
        Err(_) => {
            return reply(
                instance,
                403,
                json!({"error":"peer or qualified agent is not authorized"}),
            );
        }
    };
    let request = Request {
        method: &peer.method,
        path_and_query: &peer.path,
        authorization: None,
        identity: crate::network_guard::Identity::Resolved(&remote.display_name),
        client_ip: None,
        request_id: "federation",
    };
    if !allowed(request) {
        return reply(
            instance,
            404,
            json!({"error":"remote operation is not available"}),
        );
    }
    let mut scoped = client.clone();
    scoped.remote = Some(remote.clone());
    scoped.request_run = Some(Arc::new(SourceRun::Remote {
        run: peer.source_run.clone(),
    }));
    if scoped.bound_current().is_err() {
        return reply(
            instance,
            403,
            json!({"error":"source binding or peer trust changed"}),
        );
    }
    let payload = peer
        .body
        .map(|body| serde_json::to_vec(&body).expect("JSON value serialization"));
    let max = if support_route(request) {
        MAX_WIRE_REQUEST
    } else {
        match route_parts(request).map(|(_, op)| op) {
            Some("send") => MAX_COORD_REQUEST_BYTES,
            Some("work") => crate::coord_rooms::work::MAX_REQUEST_BYTES,
            Some("signals") => crate::coord_rooms::signals::MAX_REQUEST_BYTES,
            _ => MAX_DECLARATION_REQUEST_BYTES,
        }
    };
    if payload.as_ref().is_some_and(|payload| payload.len() > max) {
        return reply(instance, 413, json!({"error":"request body too large"}));
    }
    let outcome = if peer.method == "POST" && peer.path == "/api/coord/attention/subscribe" {
        match subscribe(client, instance, &remote).await {
            Ok(value) => response(200, value),
            Err(_) => response(503, json!({"error":"retained notifications unavailable"})),
        }
    } else if approval_route(request) {
        crate::agent_api::approvals::remote(
            request,
            runtime,
            crate::peer_support::Caller {
                run: peer.source_run,
                remote: Some(remote.clone()),
            },
            payload.as_deref(),
        )
        .await
    } else if support_route(request) {
        crate::agent_api::support::remote(
            request,
            runtime,
            remote.clone(),
            peer.source_run,
            payload.as_deref(),
        )
        .await
    } else {
        let (_cancel, cancellation) = tokio::sync::watch::channel(false);
        Box::pin(respond_as(
            request,
            CoordContext {
                client: &scoped,
                cancellation,
                runtime: Some(runtime),
            },
            payload.as_deref(),
            &remote.principal_id,
            &remote.display_name,
        ))
        .await
    };
    if scoped.check_remote().await.is_err() {
        return reply(instance, 403, json!({"error":"federation access changed"}));
    }
    let super::super::ResponseBody::Json(body) = &outcome.response.body else {
        return reply(instance, 503, json!({"error":"response unavailable"}));
    };
    reply(instance, outcome.response.status, body.clone())
}

async fn subscribe(
    client: &CoordClient,
    instance: &str,
    remote: &trust::RemoteAgent,
) -> Result<Value, Error> {
    let connection = client
        .owner
        .federation_nats
        .lock()
        .await
        .clone()
        .ok_or("federation notifications unavailable")?;
    let stream = trust::nats::retained_notices(&connection, instance, &remote.instance_id).await?;
    let name = format!("sfw-{}", uuid::Uuid::new_v4().simple());
    stream
        .create_consumer(pull::Config {
            name: Some(name.clone()),
            ack_policy: AckPolicy::None,
            deliver_policy: DeliverPolicy::LastPerSubject,
            filter_subject: trust::nats::notice_subject(
                instance,
                &remote.instance_id,
                &remote.principal_id,
            ),
            inactive_threshold: Duration::from_secs(330),
            ..Default::default()
        })
        .await?;
    Ok(json!({"consumer":name,"instance_id":instance}))
}

pub(crate) struct Running {
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Running {
    pub(crate) fn start(runtime: crate::RuntimeState) -> Option<Self> {
        let root = runtime.read().ok()?.config.native_config_dir.clone()?;
        if !root.join("coord-federation.json").is_file() {
            return None;
        }
        Some(Self {
            task: tokio::spawn(async move {
                loop {
                    if let Err(error) = serve(&root, &runtime).await {
                        eprintln!("NATS federation unavailable: {error}");
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }),
        })
    }
}

async fn serve(root: &Path, runtime: &crate::RuntimeState) -> Result<(), Error> {
    let client = runtime
        .read()
        .map_err(|_| "runtime unavailable")?
        .coord
        .clone();
    let broker: Value = serde_json::from_slice(&std::fs::read(
        client.owner.data_dir.join("nats/process.json"),
    )?)?;
    let peers: Vec<trust::nats::TransportPeer> =
        serde_json::from_value(broker["federation_peers"].clone())?;
    let instance = std::fs::read_to_string(root.join("data/instance_id"))?
        .trim()
        .to_owned();
    let password = trust::token(&client.owner.data_dir.join("nats/federation-creds"))?;
    let (url, options) = trust::nats::local_options(
        &client.owner.data_dir,
        client.nats_url(),
        async_nats::ConnectOptions::new(),
    )?;
    let connection = options
        .user_and_password("safeyolo-federation".into(), password.trim().into())
        .connection_timeout(Duration::from_secs(2))
        .connect(url)
        .await?;
    let mut requests = connection
        .subscribe(format!(
            "SY_FED.request.{}.*",
            trust::nats::subject_token(&instance)
        ))
        .await?;
    connection.flush().await?;
    *client.owner.federation_nats.lock().await = Some(connection.clone());
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            message=requests.next()=>{
                let message=message.ok_or("federation subscription closed")?;
                let Some(source_token)=message.subject.rsplit('.').next() else{continue;};
                let Some(source)=peers.iter().find(|peer|trust::nats::subject_token(&peer.instance_id)==source_token) else{continue;};
                let Some(reply_to)=message.reply else{continue;};
                if !reply_to.starts_with(&format!("{}.",trust::nats::reply_prefix(&source.instance_id))) {continue;}
                let credential_hash=source.credential_hash.clone();
                let (client,runtime,connection,instance,source)=(client.clone(),runtime.clone(),connection.clone(),instance.clone(),source.instance_id.clone());
                let config=root.join("config.toml");
                tasks.spawn(async move {crate::host_platform::in_config(config,async {
                    let value=receive(&client,&runtime,&instance,&source,&credential_hash,&message.payload).await;
                    let _=connection.publish(reply_to,value.to_string().into()).await;
                }).await;});
            },
            _=tasks.join_next(),if !tasks.is_empty()=>{},
        }
    }
}

#[cfg(test)]
mod tests;
