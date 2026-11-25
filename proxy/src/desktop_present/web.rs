//! HTTP publication through the existing preview, authority and Serve owners.

use super::*;

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[schemars(extend("x-scope" = "Requesting worker run and exact guest HTTP port/audience", "x-lifetime" = "Finite ttl_seconds; stop or expiry disconnects only this publication", "x-effects" = "Open a gated local or tailnet HTTP publication without a desktop", "x-dependencies" = "Existing preview authority, verified guest-port transport and host Tailscale Serve authority for tailnet", "x-gaps" = "A URL is not evidence of app health or operator-device reachability"))]
pub(crate) struct Parameters {
    pub(crate) guest_port: u16,
    pub(crate) audience: Route,
    #[serde(default)]
    pub(crate) tailnet_port: Option<u16>,
    #[serde(default = "default_ttl")]
    pub(crate) ttl_seconds: u32,
}

fn default_ttl() -> u32 {
    900
}

pub(crate) fn invalid_parameters() -> Diagnostic {
    diagnostic(
        "invalid_publication_parameters",
        "The saved publication parameters cannot be read. Inspect this request before a new publication.",
    )
}

impl Parameters {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.guest_port == 0 || self.tailnet_port == Some(0) {
            return Err("guest and tailnet ports must be from 1 to 65535");
        }
        // These are SafeYolo's proxy/control ports, not app listeners. Keep
        // the historical arbitrary-port preview boundary.
        if matches!(self.guest_port, 8080 | 9090) {
            return Err(
                "guest ports 8080 and 9090 are reserved for SafeYolo plumbing; select the app's HTTP port",
            );
        }
        if self.audience == Route::Local && self.tailnet_port.is_some() {
            return Err("tailnet_port requires the tailnet audience");
        }
        if !(1..=86400).contains(&self.ttl_seconds) {
            return Err("ttl_seconds must be from 1 to 86400");
        }
        Ok(())
    }

    pub(crate) fn key(&self, agent_id: &str) -> String {
        format!(
            "web:{agent_id}:{}:{}:{}",
            self.guest_port,
            if self.audience == Route::Tailnet {
                "tailnet"
            } else {
                "local"
            },
            self.tailnet_port.unwrap_or_default()
        )
    }
}

pub(crate) fn configuration_revision() -> Result<String, Diagnostic> {
    Ok(crate::approvals::pending::digest(&json!({
        "action_id":crate::operator_actions::WEB_PRESENT,
        "semantics":1,"instance_id":instance_id()?
    })))
}

pub(crate) async fn prerequisites(
    name: &str,
    parameters: &Parameters,
) -> Result<Route, Diagnostic> {
    parameters.validate().map_err(|_| {
        diagnostic(
            "invalid_web_publication",
            "Select a valid guest port, audience, lifetime and optional tailnet port.",
        )
    })?;
    if !available() {
        return Err(diagnostic(
            "web_publication_unavailable",
            "This host has no native guest-port transport.",
        ));
    }
    let run = crate::host_runs::observe(name).await;
    if run["port_forward"] != true {
        return Err(diagnostic(
            "guest_port_transport_unavailable",
            "The selected agent's current runtime cannot forward a guest port. Inspect agent diagnostics for this same instance and agent; no desktop or peer-support grant is needed.",
        ));
    }
    if parameters.audience == Route::Tailnet {
        crate::tailnet::available()
            .await
            .map_err(|error| tailnet_diagnostic(&error.to_string()))?;
    }
    Ok(parameters.audience)
}

pub(crate) async fn present(
    agent_id: &str,
    parameters: &Parameters,
    authority: Option<PreviewAuthority>,
) -> Result<Value, Diagnostic> {
    let agents = host_agents::list().map_err(|_| {
        diagnostic(
            "agent_registry_unavailable",
            "Cannot inspect the selected instance's agents.",
        )
    })?;
    let agent = host_agents::by_id(&agents, agent_id)
        .map_err(|_| {
            diagnostic(
                "agent_identity_ambiguous",
                "The selected agent's identity is ambiguous.",
            )
        })?
        .ok_or_else(|| {
            diagnostic(
                "agent_not_found",
                "The selected agent is no longer configured.",
            )
        })?;
    prerequisites(&agent.name, parameters).await?;
    let authority = authority.unwrap_or_else(|| {
        PreviewAuthority::OperatorUntil(
            std::time::Instant::now()
                + std::time::Duration::from_secs(u64::from(parameters.ttl_seconds)),
        )
    });
    let key = parameters.key(agent_id);
    let mut presentations = PRESENTATIONS.lock().await;
    let mut reused = false;
    if let Some(presentation) = presentations.get_mut(&key)
        && presentation.preview.is_running()
    {
        presentation.preview.add_authority(authority.clone());
        reused = true;
    }
    if !reused {
        if let Some(mut old) = presentations.remove(&key) {
            old.preview.close().await;
        }
        let tailnet_port = if parameters.audience == Route::Tailnet {
            Some(match parameters.tailnet_port {
                Some(port) => port,
                None => host_agents::reserve_tailnet_port(&agent.name)
                        .map_err(|_| diagnostic("tailnet_port_unavailable", "Cannot reserve this agent's tailnet port. Select an available --tailnet-port explicitly."))?.0,
            })
        } else {
            None
        };
        let preview = Preview::start_web(&agent.name, agent_id, parameters.guest_port, tailnet_port, authority).await
            .map_err(|error| Diagnostic { code:"web_publication_failed", message:"The selected web publication could not start. Inspect the reported transport or Serve error; existing mappings were preserved.",operator_details:Some(json!({"error":error.to_string(),"agent":agent.name,"parameters":parameters})) })?;
        presentations.insert(key.clone(), Presentation { preview });
    }
    let preview = &presentations.get(&key).unwrap().preview;
    let code = if reused {
        preview.issue_unlock_code().await
    } else {
        preview.unlock_code().await
    };
    let mut result = response(agent_id, &agent.name, preview, code, reused);
    result["guest_port"] = json!(parameters.guest_port);
    result["audience"] = json!(parameters.audience);
    result["ttl_seconds"] = json!(parameters.ttl_seconds);
    result["publication_id"] = json!(key);
    Ok(result)
}

pub(crate) async fn stop(agent_id: &str, parameters: &Parameters) -> Value {
    let key = parameters.key(agent_id);
    let mut presentations = PRESENTATIONS.lock().await;
    let removed = presentations.remove(&key);
    let stopped = removed.is_some();
    if let Some(mut presentation) = removed {
        presentation.preview.close().await;
    }
    json!({"agent_id":agent_id,"guest_port":parameters.guest_port,"audience":parameters.audience,"publication_id":key,"stopped":stopped})
}

pub(crate) async fn list(agent_id: &str) -> Value {
    let mut presentations = PRESENTATIONS.lock().await;
    let mut selected = Vec::new();
    for (key, presentation) in presentations
        .iter_mut()
        .filter(|(key, _)| key.starts_with(&format!("web:{agent_id}:")))
    {
        let mut value = presentation
            .preview
            .authority_view(None)
            .unwrap_or(Value::Null);
        value["active"] = json!(presentation.preview.is_running());
        value["publication_id"] = json!(key);
        value["url"] = json!(presentation.preview.url);
        selected.push(value);
    }
    json!({"agent_id":agent_id,"publications":selected})
}
