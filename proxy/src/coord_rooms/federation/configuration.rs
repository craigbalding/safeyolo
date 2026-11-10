//! Lower-level configuration, certificate activation and messaging checks.
use super::*;

pub(crate) fn home_arguments(
    arguments: &[String],
) -> Result<(endpoint::Endpoint, &str, bool), Error> {
    let (arguments, rotate) = match arguments {
        [rest @ .., flag] if flag == "--rotate-trust" => (rest, true),
        rest => (rest, false),
    };
    let (mode, url, ca, node, token_file) = match arguments {
        [mode, url, token] if mode == "loopback" => {
            (endpoint::Mode::Loopback, url, None, None, token)
        }
        [mode, url, ca, token] if mode == "tls" => {
            (endpoint::Mode::Tls, url, Some(ca), None, token)
        }
        [mode, url, node, token] if mode == "tailscale" => (
            endpoint::Mode::Tailscale,
            url,
            None,
            Some(node.clone()),
            token,
        ),
        [url, ca, token] => (endpoint::Mode::Tls, url, Some(ca), None, token),
        _ => return Err(HELP.into()),
    };
    let ca_file = ca.map(fs::canonicalize).transpose()?;
    let endpoint = endpoint::Endpoint {
        mode,
        url: url.trim_end_matches('/').to_owned(),
        ca_sha256: ca_file
            .as_ref()
            .map(|path| tls_material::trust_hash(path))
            .transpose()?,
        ca_file,
        tailscale_node: node,
    };
    endpoint.origin()?;
    Ok((endpoint, token_file, rotate))
}

pub(crate) async fn run(root: &Path, arguments: &[String]) -> Result<Option<Value>, Error> {
    match arguments {
        [command, _, _, rest @ ..] if command == "home" => {
            // Network checks must not hold the room database's writer lock.
            home_arguments(rest)?.0.verify().await?;
            Ok(None)
        }
        [broker, command, file, rest @ ..]
            if broker == "broker" && (command == "check" || command == "apply") =>
        {
            let rotate = rest == ["--rotate-trust"];
            if !rest.is_empty() && !rotate {
                return Err(HELP.into());
            }
            let mut setup = nats::read_broker(root, Path::new(file), rotate)?;
            let protection = setup.validate(root)?;
            setup.verify_listener().await?;
            let previous = directory(root)?.join("nats/local-endpoint.json");
            let previous: Option<endpoint::Endpoint> = if previous.try_exists()? {
                Some(serde_json::from_slice(&fs::read(previous)?)?)
            } else {
                None
            };
            let configured_path = root.join("coord-federation.json");
            // A malformed saved file can be repaired. The last active endpoint
            // still supplies the trust pin when the configured pin is unreadable.
            let configured: Option<Value> = if configured_path.try_exists()? {
                serde_json::from_slice(&fs::read(&configured_path)?).ok()
            } else {
                None
            };
            let previous_trust = configured
                .as_ref()
                .and_then(|setup| setup["ca_sha256"].as_str())
                .or_else(|| {
                    previous
                        .as_ref()
                        .and_then(|endpoint| endpoint.ca_sha256.as_deref())
                });
            let current_trust = setup
                .ca_file
                .as_ref()
                .map(|path| tls_material::trust_hash(path))
                .transpose()?;
            let trust_changed = previous_trust
                .zip(current_trust.as_deref())
                .is_some_and(|(old, new)| old != new);
            if command == "apply" && trust_changed && !rotate {
                return Err("broker CA changed; repeat broker apply with --rotate-trust and distribute the verified CA to clients".into());
            }
            setup.ca_sha256 = current_trust;
            if command == "apply" {
                atomic_write(
                    &root.join("coord-federation.json"),
                    &serde_json::to_vec_pretty(&setup)?,
                    0o600,
                )?;
            }
            let recorded = record(root)?;
            let running = if let Some(saved) = &recorded {
                verified(root, saved).await.unwrap_or(false)
            } else {
                false
            };
            let active = if let Some(saved) = &recorded {
                running
                    && saved["broker_configuration"] == json!(setup)
                    && saved["protection_check"] == protection
                    && peer_credentials_active(Some(&setup), saved)?
            } else {
                false
            };
            Ok(Some(
                json!({"instance_id":fs::read_to_string(root.join("data/instance_id"))?.trim(),
                "configuration_saved":command == "apply","configured":setup,"validated":true,"mode":setup.mode,"protection":protection,
                "active_endpoint":if running { recorded.as_ref().map(|saved|&saved["local_endpoint"]) } else {None},
                "active":active,"activation":"not_attempted","restart_required":command == "apply" && !active,"trust_changed":trust_changed,
                "authority":"certificate renewal preserves instance credentials and grants; CA rotation changes server verification, not peer grants",
                "recovery":"Stop this instance's proxy and Coord, start Coord with the selected ports, then start the proxy. After CA rotation, explicitly update peer home routes with the new CA and --rotate-trust. Existing peer credential rotations use federation trust; old support and approval grants remain bound to their recorded trust generation."}),
            ))
        }
        [command] if command == "check" => Ok(Some(local_check(root).await?)),
        [command, name] if command == "check" => Ok(Some(home_check(root, name).await?)),
        _ => Ok(None),
    }
}

fn peer_credentials_active(setup: Option<&nats::Broker>, saved: &Value) -> Result<bool, Error> {
    let peers = setup
        .into_iter()
        .flat_map(|broker| &broker.peers)
        .map(|peer| {
            Ok(nats::TransportPeer {
                instance_id: peer.instance_id.clone(),
                credential_hash: hash(token(&peer.credential_file)?.trim().as_bytes()),
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(json!(peers) == saved["federation_peers"])
}

pub(crate) fn configuration_active(root: &Path, saved: &Value) -> Result<bool, Error> {
    let setup = nats::broker(root)?;
    let protection = setup
        .as_ref()
        .map(|setup| setup.validate(root))
        .transpose()?;
    let endpoint = nats::local_endpoint(
        &directory(root)?,
        format!("nats://127.0.0.1:{}", saved["client_port"]),
    )?;
    Ok(json!(setup) == saved["broker_configuration"]
        && json!(protection) == saved["protection_check"]
        && endpoint.security()? == saved["protection"]
        && peer_credentials_active(setup.as_ref(), saved)?)
}

pub(crate) async fn local_check(root: &Path) -> Result<Value, Error> {
    let configured = match nats::broker(root) {
        Ok(setup) => json!({"valid":true,"broker":setup}),
        Err(error) => {
            json!({"valid":false,"reason":error.to_string(),"recovery":"Correct coord-federation.json and validate it with federation broker check before restarting this instance."})
        }
    };
    let active = record(root)?;
    let mut result = json!({"instance_id":fs::read_to_string(root.join("data/instance_id"))?.trim(),"configured":configured,
        "recorded":active,"active":null,"configuration_active":false,"broker_authentication":"not_checked","owner":"unavailable","notifications":"not_checked","operation_permission":"not_checked"});
    let Some(saved) = active else {
        result["recovery"] = json!("Start this instance's Coord, then its proxy.");
        return Ok(result);
    };
    if !verified(root, &saved).await.unwrap_or(false) {
        result["recovery"] = json!(
            "Inspect coord status and the owned broker log; process readiness is not authenticated messaging."
        );
        return Ok(result);
    }
    result["active"] = saved.clone();
    result["configuration_active"] = json!(configuration_active(root, &saved).unwrap_or(false));
    let endpoint = nats::local_endpoint(
        &directory(root)?,
        format!("nats://127.0.0.1:{}", saved["client_port"]),
    )?;
    result["active_endpoint"] = json!(endpoint);
    match endpoint.verify().await {
        Ok(protection) => result["protection"] = protection,
        Err(error) => {
            result["protection"] = json!({"verified":false,"reason":error.to_string()});
            return Ok(result);
        }
    }
    match jetstream(root).await {
        Ok(context) => {
            result["protection"]["verified"] = json!(true);
            result["broker_authentication"] = json!("authenticated");
            result["notifications"] = match context.query_account().await {
                Ok(_) => json!({"jetstream":"available","retained_delivery":"not_checked"}),
                Err(_) => json!({"jetstream":"unavailable","retained_delivery":"not_checked"}),
            };
        }
        Err(_) => {
            result["broker_authentication"] =
                json!("unavailable; inspect host-held local credentials and the owned broker log")
        }
    }
    if let Ok(runtime) = crate::native_client::admin(
        &root.join("config.toml"),
        "/admin/coord/diagnostics",
        hyper::Method::GET,
        Value::Null,
        Duration::from_secs(2),
    )
    .await
    {
        result["owner"] = json!("reachable");
        result["runtime"] = runtime;
    }
    Ok(result)
}

async fn home_check(root: &Path, name: &str) -> Result<Value, Error> {
    let home = home(&open(root)?, name)?;
    let endpoint = home.endpoint();
    let source = fs::read_to_string(root.join("data/instance_id"))?
        .trim()
        .to_owned();
    let mut result = json!({"home":name,"instance_id":source,"expected_owner":home.instance_id,"configured":endpoint,
        "protection":{"verified":false},"broker_authentication":"not_checked","owner":"not_checked","notifications":"not_checked","operation_permission":"not_checked"});
    match endpoint.verify().await {
        Ok(protection) => result["protection"] = protection,
        Err(error) => {
            result["protection"]["reason"] = json!(error.to_string());
            result["recovery"] = json!(
                "Restore the selected protected endpoint on its owning host; no alternate mode was selected."
            );
            return Ok(result);
        }
    }
    let connection = match nats::connect_with_options(&home, &source, |options| {
        options.request_timeout(Some(Duration::from_secs(3)))
    })
    .await
    {
        Ok(connection) => connection,
        Err(error) => {
            let kind = error
                .downcast_ref::<async_nats::ConnectError>()
                .map(|error| error.kind());
            let authentication = matches!(
                kind,
                Some(
                    async_nats::ConnectErrorKind::Authentication
                        | async_nats::ConnectErrorKind::AuthorizationViolation
                )
            );
            result["broker_authentication"] = json!(if authentication {
                "denied"
            } else {
                "not_established"
            });
            result["protection"]["verified"] = json!(authentication);
            result["connection_failure"] = json!(
                kind.map(|kind| format!("{kind:?}"))
                    .unwrap_or_else(|| "protected_endpoint_unavailable".into())
            );
            result["recovery"] = json!(
                "On the owner, check its broker log, endpoint certificate, scoped peer credentials and current trust. Restart owned Coord and the responder after broker changes."
            );
            return Ok(result);
        }
    };
    result["active_endpoint"] = json!(endpoint);
    result["protection"]["verified"] = json!(true);
    result["broker_authentication"] = json!("authenticated");
    let request = json!({"destination_instance_id":home.instance_id,"source_run":null,"method":"GET","path":"/federation/check","body":null});
    result["owner"] = match connection
        .request(
            nats::request_subject(&home.instance_id, &source),
            request.to_string().into(),
        )
        .await
    {
        Ok(message) => match serde_json::from_slice::<Value>(&message.payload) {
            Ok(reply)
                if reply["home_instance_id"] == home.instance_id && reply["status"] == 200 =>
            {
                json!({"reachable":true,"identity_verified":true,"result":reply["body"]})
            }
            Ok(reply) if reply["home_instance_id"] == home.instance_id => {
                json!({"reachable":true,"identity_verified":true,"permitted":false,"status":reply["status"]})
            }
            _ => {
                json!({"reachable":"unknown","reason":"unexpected owner reply; no operation attempted"})
            }
        },
        Err(_) => {
            json!({"reachable":false,"recovery":"Check the selected owner's running proxy and federation responder; broker authentication alone does not establish owner reachability."})
        }
    };
    result["notifications"] = match async_nats::jetstream::new(connection)
        .get_stream(nats::notice_stream(&source))
        .await
    {
        Ok(mut stream) => {
            if stream.info().await.is_ok() {
                json!({"stream":"available","retained_delivery":"not_checked"})
            } else {
                json!({"stream":"unavailable","reason":"stream_info_failed","retained_delivery":"not_checked"})
            }
        }
        Err(error) if matches!(error.kind(), async_nats::jetstream::context::GetStreamErrorKind::JetStream(error) if error.code()==404) =>
        {
            json!({"stream":"not_created","retained_delivery":"not_checked","reason":"The owner creates this peer's stream at the first authorized notification or subscription."})
        }
        Err(_) => json!({"stream":"unavailable","retained_delivery":"not_checked",
            "recovery":"On the owner, restore the scoped retained notification stream without repeating uncertain operations."}),
    };
    Ok(result)
}
