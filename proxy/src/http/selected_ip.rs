//! An explicit endpoint travels with its admitted logical destination. It never
//! becomes a resolver hint or a process-wide hostname override.

use std::{net::IpAddr, sync::Arc};

use serde_json::{Value, json};

use crate::{ConnectionIdentity, Error, Runtime};

use super::Destination;

#[derive(Clone)]
pub(super) struct SelectedIp {
    pub(super) requested_ip: Option<IpAddr>,
    pub(super) ip: IpAddr,
    pub(super) source: &'static str,
}

impl SelectedIp {
    pub(super) fn client(ip: IpAddr) -> Self {
        Self {
            requested_ip: Some(ip),
            ip,
            source: "client_connect",
        }
    }
}

/// A pinned tunnel keeps its selection across reloads. A conflicting new
/// mapping refuses that request instead of moving an existing tunnel.
pub(super) fn apply_mapping(
    destination: &mut Destination,
    runtime: &Runtime,
    identity: &ConnectionIdentity,
) -> Result<(), Error> {
    if let Some(ip) = runtime.config.target_ip_for(
        &destination.host,
        destination.port,
        identity.request_agent(),
    ) {
        if let Some(target) = &destination.selected_ip {
            if target.ip != ip {
                return Err("operator mapping conflicts with the admitted target IP".into());
            }
        } else {
            destination.selected_ip = Some(SelectedIp {
                requested_ip: None,
                ip,
                source: "operator_mapping",
            });
        }
    }
    Ok(())
}

/// Only a numeric outer CONNECT can introduce a logical TLS name. A named
/// CONNECT remains pinned to its original name, as does every later request.
pub(super) fn bind_tls_name(
    destination: &mut Destination,
    name: Option<&str>,
) -> Result<bool, Error> {
    let Some(name) = name else { return Ok(false) };
    if destination.host.parse::<IpAddr>().is_err() {
        return Ok(false);
    }
    super::validate_hostname(name)?;
    if name.parse::<IpAddr>().is_ok() {
        return Err("TLS DNS SNI cannot select another numeric authority".into());
    }
    destination.host = name.to_ascii_lowercase();
    destination.policy_host = super::policy_hostname(name, true, false)?;
    destination.authority = format!("{}:{}", destination.host, destination.port);
    destination.uri_authority = destination.authority.clone();
    Ok(true)
}

pub(super) fn route_needs_name(
    runtime: &Runtime,
    identity: &ConnectionIdentity,
    destination: &Destination,
) -> bool {
    destination.host.parse::<IpAddr>().is_ok()
        && runtime
            .parent
            .as_ref()
            .is_some_and(|parent| !parent.destination_hosts.is_empty())
        && (runtime.config.parent_proxy_agents.is_empty()
            || runtime
                .config
                .parent_proxy_agents
                .contains(&identity.agent_id))
}

pub(super) fn facts(destination: &Destination) -> Value {
    json!({
        "logical_host": destination.host,
        "requested_ip": destination.selected_ip.as_ref().and_then(|target| target.requested_ip).map(|ip| ip.to_string()),
        "requested_port": destination.port,
        "effective_ip": destination.selected_ip.as_ref().map(|target| target.ip.to_string()),
        "effective_port": destination.port,
        "selection_source": destination.selected_ip.as_ref().map(|target| target.source),
        "direct_peer": null,
    })
}

pub(super) fn record(
    runtime: &Runtime,
    identity: &ConnectionIdentity,
    request_id: &str,
    destination: &Destination,
    stage: &str,
    outcome: &str,
    extra: Value,
) {
    if destination.selected_ip.is_none() {
        return;
    }
    let mut details = facts(destination);
    let fields = details.as_object_mut().expect("target facts are an object");
    fields.insert("stage".into(), stage.into());
    fields.insert("outcome".into(), outcome.into());
    fields.extend(
        extra
            .as_object()
            .expect("connection details are an object")
            .clone(),
    );
    let mut event = identity.request_event(
        "traffic.connection",
        crate::audit::Kind::Traffic,
        request_id,
        format!("Connection {stage}: {outcome}"),
        details,
    );
    event.host = Some(destination.policy_host.clone());
    // Traffic observations follow the existing egress-event contract. An
    // observation error cannot undo a request already admitted or delivered.
    if let Err(error) = runtime.audit.emit(event) {
        eprintln!("connection observation failed: {error}");
    }
}

/// A dropped upgrade task must leave a terminal no-contact observation too.
pub(super) struct RouteWaitAudit {
    runtime: Arc<Runtime>,
    identity: ConnectionIdentity,
    request_id: String,
    destination: Destination,
    active: bool,
}

impl RouteWaitAudit {
    pub(super) fn new(
        runtime: Arc<Runtime>,
        identity: &ConnectionIdentity,
        request_id: &str,
        destination: &Destination,
        active: bool,
    ) -> Self {
        if active {
            record(
                &runtime,
                identity,
                request_id,
                destination,
                "route_wait",
                "pending",
                json!({
                "missing_information": "client protocol prefix or a complete TLS ClientHello",
                    "outbound": "not_attempted", "client_connect_status": 200,
                    "wait_seconds": crate::tunnels::ROUTE_WAIT.as_secs(),
                }),
            );
        }
        Self {
            runtime,
            identity: identity.clone(),
            request_id: request_id.into(),
            destination: destination.clone(),
            active,
        }
    }

    pub(super) fn end(&mut self, outcome: &str) {
        if self.active {
            self.active = false;
            record(
                &self.runtime,
                &self.identity,
                &self.request_id,
                &self.destination,
                "route_wait",
                outcome,
                json!({
                    "missing_information": if outcome == "complete" { None } else { Some("client protocol prefix or a complete TLS ClientHello") },
                    "outbound": "not_attempted", "client_connect_status": 200,
                }),
            );
        }
    }
}
impl Drop for RouteWaitAudit {
    fn drop(&mut self) {
        self.end("cancelled");
    }
}
