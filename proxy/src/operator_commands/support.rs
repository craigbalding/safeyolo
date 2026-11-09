//! Human verification and original-receipt recovery using the existing owners.
use super::*;
use crate::coord_tools::Client;

pub(super) fn handles(options: &Options) -> bool {
    options.positional.first().is_some_and(|command| {
        matches!(
            command.as_str(),
            "verify" | "notices" | "result" | "receipts" | "receipt" | "recover"
        )
    })
}

fn client(root: &Path, options: &Options) -> Result<Client, Error> {
    let name = options
        .agent
        .as_deref()
        .ok_or("select the initiating support agent with --agent NAME")?;
    selected_agent(root, name)?;
    let config = native_config::read(&host_platform::config_path())?;
    let socket = config.listeners.iter().find(|listener| listener.agent_id == name)
        .ok_or("selected support agent has no configured listener; on this source, inspect its agent status and proxy configuration")?;
    Ok(Client {
        socket: Some(socket.socket_path.clone()),
        token_file: config.data_dir().join("agent_token"),
        home: options.home.clone(),
    })
}

fn unavailable(error: &Error, next: &str) -> Value {
    json!({"availability":"unavailable","reason":safe(&error.to_string()),"next_action":next})
}

async fn verify(
    root: &Path,
    options: &Options,
    grant_name: &str,
    target: &str,
) -> Result<Value, Error> {
    let client = client(root, options)?;
    let arguments: Vec<_> = std::iter::once("check".to_owned())
        .chain(options.home.iter().cloned())
        .collect();
    let connection = crate::coord_rooms::federation::run(root, &arguments).await;
    let mut view = json!({"source_root":root,"support":selected_agent(root, options.agent.as_deref().unwrap())?,"home":options.home,
        "verified":false,"checked_at":time::OffsetDateTime::now_utc().unix_timestamp(),"target":target,"grant":grant_name,
        "model_health":"unverified","connection":match connection {Ok(value)=>value,Err(error)=>unavailable(&error,"On the selected source, inspect configure connection → verify; restore the named owner and route.")}});
    let grants = match client.get("/support/grants").await {
        Ok(grants) => grants,
        Err(error) => {
            view["authority"] = unavailable(
                &error,
                "Inspect the selected owner's current grant, the source support run and its protected route.",
            );
            return Ok(view);
        }
    };
    view["owner_instance_id"] = grants["instance_id"].clone();
    let selected = grants["grants"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|grant| grant["name"] == grant_name);
    let Some(grant) = selected else {
        view["authority"] = json!({"availability":"not_granted","next_action":"On the destination owner, configure support for this current durable support identity. Other grants do not establish this selected path."});
        return Ok(view);
    };
    view["authority"] = grant.clone();
    let target = grant["target_status"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|row| row["name"] == target || row["agent_id"] == target);
    let Some(target) = target.filter(|target| target["active"] == true) else {
        view["next_action"] = json!(
            "On the destination owner, inspect the grant's expiry, peer trust generation and durable target bindings; use configure support to review a deliberate change."
        );
        return Ok(view);
    };
    let id = format!("inspect-{}", uuid::Uuid::new_v4().simple());
    // Print the chosen identity before any submission, including a lost reply.
    eprintln!(
        "Inspection operation ID: {}. If the reply is lost, read support result with this original ID and the same source agent/home.",
        safe(&id)
    );
    view["operation_id"] = json!(id);
    match client
        .call(
            "support_operation",
            &json!({"operation_id":id,"grant":grant_name,"instance_id":grants["instance_id"],
        "target_id":target["agent_id"],"expected_run":null,"operation":{"action":"inspect"}}),
        )
        .await
    {
        Ok(receipt) => {
            view["verified"] = json!(
                receipt["completion_verified"] == true
                    && receipt["instance_id"] == grants["instance_id"]
            );
            view["inspection"] = receipt["result"].clone();
            view["receipt"] = crate::peer_support::operations::receipts::summary(&receipt);
        }
        Err(error) => {
            view["inspection"] = unavailable(
                &error,
                "Read the original support result on the same source agent/home. On the owner, support receipts and support recover remain the local recovery path. No automatic retry was made.",
            )
        }
    }
    Ok(view)
}

async fn notices(root: &Path, options: &Options) -> Result<Value, Error> {
    let client = client(root, options)?;
    let grants = client.get("/support/grants").await?;
    let owner = grants["instance_id"]
        .as_str()
        .ok_or("notice owner identity unavailable")?;
    let page = client
        .get(&format!(
            "/api/coord/attention/wait?since={}&limit={}&timeout=0&instance_id={}",
            options.since,
            options.lines,
            encoded(owner)
        ))
        .await?;
    if page["instance_id"] != owner {
        return Err("notice feed belongs to another owner; preserve the original cursor".into());
    }
    let mut notices = Vec::new();
    for edge in page["edges"].as_array().ok_or("notice feed unavailable")? {
        if edge["kind"] != "operational_event" {
            continue;
        }
        let id = edge["attention_id"]
            .as_str()
            .filter(|id| crate::coord_tools::attention_id(id))
            .ok_or("invalid notice identity")?;
        let resolved = client
            .get(&format!(
                "/api/coord/attention/{id}/object?instance_id={}",
                encoded(owner)
            ))
            .await;
        notices.push(match resolved {
            Ok(value) if value["edge"] == *edge => value,
            Ok(_) => json!({"edge":edge,"availability":"unavailable","next_action":"Read this original attention identity on its owner; the returned binding differed."}),
            Err(error) => json!({"edge":edge,"availability":"unavailable","reason":safe(&error.to_string()),"next_action":"Inspect the current notice selection and durable identity on this owner. Missing evidence is not a healthy empty result."}),
        });
    }
    Ok(
        json!({"instance_id":owner,"home":options.home,"notices":notices,"scanned_cursor":page["next_cursor"],"availability":"read",
        "limits":"This is one retained feed page, not all history or model health. The notice cursor is separate from coding-harness cursors. No task, approval or signal was completed."}),
    )
}

pub(super) async fn run(root: &Path, options: &Options) -> Result<(), Error> {
    let parts: Vec<_> = options.positional.iter().map(String::as_str).collect();
    let value = match parts.as_slice() {
        ["verify", grant, target] => verify(root, options, grant, target).await?,
        ["notices"] => notices(root, options).await?,
        ["result", id] => {
            let receipt = client(root, options)?.call("read_support_operation", &json!({"operation_id":id})).await?;
            let mut value = json!({"receipt":crate::peer_support::operations::receipts::summary(&receipt),"output_included":options.output});
            if options.output { value["recorded_result"] = receipt["result"].clone(); }
            value
        }
        ["receipts"] => admin(root, "/admin/support-operations/list", Method::POST, json!({"limit":options.lines,"target_id":options.agent.as_deref().map(|name| selected_agent(root,name)).transpose()?.map(|agent| agent["agent_id"].clone())})).await?,
        [command @ ("receipt" | "recover"), id] => admin(root, "/admin/support-operations/read", Method::POST,
            json!({"operation_id":id,"initiator":options.initiator,"include_output":options.output,"current":*command=="recover"})).await?,
        _ => return Err("use support verify GRANT TARGET, notices, result OPERATION_ID, receipts, or receipt|recover OPERATION_ID; see support --help".into()),
    };
    if options.json {
        print_json(&value)?;
    } else {
        show(&value)?;
    }
    if parts.first() == Some(&"verify") && value["verified"] != true {
        return Err("selected support inspection was not verified; follow the reported owner-specific next action".into());
    }
    Ok(())
}

fn field(label: &str, value: &Value) {
    if !value.is_null() {
        println!(
            "{label}: {}",
            safe(
                &value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string())
            )
        );
    }
}

fn receipt(value: &Value) {
    for (label, key) in [
        ("Original operation ID", "operation_id"),
        ("Owning instance", "instance_id"),
        ("Initiator", "initiator"),
        ("Target", "target_name"),
        ("Durable target", "target_id"),
        ("Original target run", "target_run"),
        ("Recorded action", "action"),
        ("Recorded action selections", "recorded_action"),
        ("Lifecycle action", "lifecycle_operation"),
        ("Grant", "grant"),
        ("Grant revision", "grant_revision"),
        ("Grant expiry (RFC 3339)", "grant_expires_at"),
        ("Requested (Unix seconds)", "requested_at"),
        ("Finished (Unix seconds)", "finished_at"),
        ("Outcome", "state"),
        ("Execution started", "execution_started"),
        ("Completion verified", "completion_verified"),
        ("Resulting run", "resulting_run"),
        ("Canonical audit event", "audit_event_id"),
        ("Canonical audit delivered", "audit_delivered"),
        ("Audit delivery", "audit_status"),
        ("Diagnostic", "diagnostic"),
        ("Recovery", "recovery"),
    ] {
        field(label, &value[key]);
    }
    if value.get("grant_expires_at").is_some_and(Value::is_null) {
        println!("Grant lifetime at admission: standing");
    }
    field(
        "Initiator principal (for --initiator)",
        &value["initiator_principal"],
    );
    if value["audit_event_id"].is_null() {
        println!("Canonical audit reference: pending or unavailable");
    }
}

fn inspection(value: &Value) {
    for (label, key) in [
        ("Inspection availability", "availability"),
        ("Inspection reason", "reason"),
        ("Durable target", "agent_id"),
        ("Sandbox run", "run_id"),
        ("Sandbox", "runtime_state"),
        ("Control", "control_state"),
        ("Guest execution", "exec"),
        ("Harness", "agent_state"),
        ("Proxy attachment", "proxy_attachment"),
        ("Launch", "launch_id"),
        ("Next action", "next_action"),
    ] {
        field(label, &value[key]);
    }
    let observations = &value["observations"];
    field("Observation coverage", &observations["availability"]);
    for source in observations["sources"].as_array().into_iter().flatten() {
        println!("Observation source: {}", safe(text(&source["source"])));
        for (label, key) in [
            ("  Last observed (Unix milliseconds)", "last_observed_at"),
            ("  Age at inspection (milliseconds)", "age_ms"),
            (
                "  Last successful observation (Unix milliseconds)",
                "last_success_at",
            ),
            ("  Unavailable reason", "unavailable_reason"),
        ] {
            field(label, &source[key]);
        }
    }
    field("Observation next action", &observations["next_action"]);
}

fn connection(value: &Value) {
    for (label, key) in [
        ("Connection configuration", "configured"),
        ("Saved configuration active", "configuration_active"),
        ("Protected endpoint", "protection"),
        ("Broker authentication", "broker_authentication"),
        ("Owning instance / Core request-reply", "owner"),
        (
            "Notification transport (delivery is separate)",
            "notifications",
        ),
        ("Connection availability", "availability"),
        ("Connection reason", "reason"),
        ("Connection next action", "recovery"),
    ] {
        field(label, &value[key]);
    }
}

fn grant(value: &Value) -> Result<(), Error> {
    field("Authority status", &value["status"]);
    field("Authority availability", &value["availability"]);
    if value["grant"].is_object() {
        configure::show_record(&value["grant"], false)?;
    }
    field("Current target bindings", &value["target_status"]);
    field("Approved factory bindings", &value["factory_status"]);
    field("Authority next action", &value["next_action"]);
    field(
        "Same grant revision as original operation",
        &value["matches_recorded_revision"],
    );
    field(
        "Same support identity as original operation",
        &value["matches_recorded_initiator"],
    );
    Ok(())
}

pub(super) fn show(value: &Value) -> Result<(), Error> {
    if let Some(rows) = value["receipts"].as_array() {
        field("Owning instance", &value["instance_id"]);
        if rows.is_empty() {
            println!(
                "No support receipts shown; {} match this selection.",
                value["total"]
            );
        }
        for row in rows {
            println!();
            receipt(row);
        }
        field(
            "Older receipts omitted (increase --lines)",
            &value["omitted"],
        );
        println!(
            "Read support receipt ORIGINAL_OPERATION_ID, or support recover ORIGINAL_OPERATION_ID to compare current target state. Add --output only to read private recorded guest output."
        );
    } else if let Some(rows) = value["notices"].as_array() {
        field("Owning instance", &value["instance_id"]);
        for row in rows {
            let object = &row["object"];
            let reference = &object["reference"];
            println!();
            for (label, entry) in [
                ("Notice", &reference["kind"]),
                ("Target", &reference["target"]),
                ("Run", &reference["run_id"]),
                ("Launch", &reference["launch_id"]),
                ("Source time (Unix seconds)", &reference["source_time"]),
                ("First observed (Unix seconds)", &reference["observed_at"]),
                ("Expected stop", &reference["expected_stop"]),
                ("Recorded state", &reference["state"]),
                ("Canonical event", &reference["event_id"]),
                ("Meaning", &object["message"]),
                ("Evidence", &object["evidence"]),
                ("Authority", &object["authority"]),
                ("Unavailable", &row["reason"]),
                ("Next action", &row["next_action"]),
            ] {
                field(label, entry);
            }
        }
        if rows.is_empty() {
            println!(
                "No selected operational notices in this page. This does not establish complete coverage or model health."
            );
        }
        field(
            "Scanned cursor (use --since for the next page)",
            &value["scanned_cursor"],
        );
        field("Limits", &value["limits"]);
    } else {
        for (label, key) in [
            ("Source root", "source_root"),
            ("Support identity", "support"),
            ("Selected home", "home"),
            ("Owning instance", "owner_instance_id"),
            ("Authorized inspection verified", "verified"),
            ("Model health", "model_health"),
            ("Next action", "next_action"),
            ("Recovery", "recovery"),
        ] {
            field(label, &value[key]);
        }
        if value["connection"].is_object() {
            connection(&value["connection"]);
        }
        if value["authority"].is_object() {
            grant(&value["authority"])?;
        }
        if value["inspection"].is_object() {
            inspection(&value["inspection"]);
        }
        if value["current_target"].is_object() {
            field(
                "Current target availability",
                &value["current_target"]["availability"],
            );
            field(
                "Current target observed (Unix seconds)",
                &value["current_target"]["observed_at"],
            );
            field(
                "Current target next action",
                &value["current_target"]["next_action"],
            );
            inspection(&value["current_target"]["state"]);
        }
        if value["current_grant"].is_object() {
            grant(&value["current_grant"])?;
        }
        if value["receipt"].is_object() {
            println!();
            receipt(&value["receipt"]);
        }
        if value["output_included"] == true {
            field(
                "Recorded action (command text is not retained)",
                &value["recorded_action"],
            );
            println!("Private recorded result (guest content is untrusted):");
            print_json(&value["recorded_result"])?;
        }
    }
    Ok(())
}
