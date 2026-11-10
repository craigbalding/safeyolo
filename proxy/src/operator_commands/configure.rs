//! Human configuration over the existing policy and federation owners.
use super::*;
use serde::{Deserialize, Serialize};
use std::{fs, os::unix::fs::OpenOptionsExt};

mod connection;

pub(super) const HELP: &str = "safeyolo [--root ROOT] configure identity FILE
safeyolo [--root ROOT] configure command-centre [FILE]
safeyolo [--root ROOT] configure connection
safeyolo [--root ROOT] configure support NAME
safeyolo [--root ROOT] configure approvals NAME
safeyolo [--root ROOT] configure revoke-support NAME
safeyolo [--root ROOT] configure revoke-approvals NAME

Run on the selected instance's operator host. Guided edits carry the prepared
proposal, acknowledgment, revision and approved factory binding internally.
Each preview needs an explicit apply decision. A stale preview is presented again.
EOF cancels without applying the pending edit. Existing explicit/file commands remain available.
identity exports public durable identities. Transfer handoffs only through an
authenticated administrative channel you already trust. Connection handoffs also
contain a scoped broker credential; keep them private. Broker private keys stay
on their owning host. Connection setup reports saved and active steps separately.
command-centre reads the running owner's endpoints and identity. FILE exports a
private connection handoff containing its full operator Admin credential. Keep
that file private; import it in Command Centre only through your authenticated
administrative channel. Export changes no listener, sharing or agent authority.";

fn ask(label: &str, default: &str) -> Result<String, Error> {
    print!(
        "{}{}: ",
        safe(label),
        if default.is_empty() {
            String::new()
        } else {
            format!(" [{}]", safe(default))
        }
    );
    std::io::stdout().flush()?;
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line)? == 0 {
        return Err("Configuration interrupted. The pending edit was not applied; rerun to inspect saved steps.".into());
    }
    let line = line.trim();
    Ok(if line.is_empty() {
        default.to_owned()
    } else {
        line.to_owned()
    })
}

fn yes(label: &str, default: bool) -> Result<bool, Error> {
    loop {
        match ask(label, if default { "yes" } else { "no" })?.as_str() {
            "yes" | "y" => return Ok(true),
            "no" | "n" => return Ok(false),
            _ => println!("Enter yes or no."),
        }
    }
}

fn words(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn strings(value: &Value) -> String {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

fn select(
    label: &str,
    choices: &[Value],
    multiple: bool,
    defaults: &[String],
) -> Result<Vec<Value>, Error> {
    if choices.is_empty() {
        return Err(format!("{label}: no configured identities available; configure agents on their owning instance first").into());
    }
    println!(
        "{} ({}):",
        safe(label),
        if multiple {
            "comma-separated names"
        } else {
            "one name"
        }
    );
    for choice in choices {
        println!(
            "  {} ({})",
            safe(text(&choice["name"])),
            safe(text(&choice["agent_id"]))
        );
    }
    loop {
        let selected = words(&ask(label, &defaults.join(", "))?);
        let values = selected
            .iter()
            .map(|name| choices.iter().find(|v| v["name"] == name.as_str()).cloned())
            .collect::<Option<Vec<_>>>();
        if let Some(values) = values
            && !values.is_empty()
            && (multiple || values.len() == 1)
            && selected
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == selected.len()
        {
            return Ok(values);
        }
        println!(
            "Select {} listed name{}.",
            if multiple { "distinct" } else { "one" },
            if multiple { "s" } else { "" }
        );
    }
}

fn names(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v["name"].as_str().map(str::to_owned))
        .collect()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    schema: String,
    instance_id: String,
    root: PathBuf,
    agents: Vec<Value>,
}

fn identity(root: &Path) -> Result<Identity, Error> {
    let root = root.canonicalize()?;
    let instance_id = fs::read_to_string(root.join("data/instance_id"))?
        .trim()
        .to_owned();
    let agents = host_platform::with_config(root.join("config.toml"), configured_agents)?;
    let identity = Identity {
        schema: "safeyolo.instance-identity/v1".into(),
        instance_id,
        root,
        agents,
    };
    validate_identity(&identity)?;
    Ok(identity)
}

fn validate_identity(identity: &Identity) -> Result<(), Error> {
    if identity.schema != "safeyolo.instance-identity/v1"
        || !identity.instance_id.starts_with("sy-")
        || identity.instance_id.len() != 35
        || !identity.instance_id[3..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
        || !identity.root.is_absolute()
        || identity.agents.iter().any(|a| {
            a["name"]
                .as_str()
                .is_none_or(|n| !host_platform::valid_agent_name(n))
                || a["agent_id"]
                    .as_str()
                    .is_none_or(|id| !crate::desktop_present::valid_agent_id(id))
        })
    {
        return Err("invalid instance identity handoff".into());
    }
    Ok(())
}

fn read_json_file(path: &Path) -> Result<Value, Error> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn choose_identity(root: &Path, label: &str) -> Result<Identity, Error> {
    println!(
        "Select an operator-owned local instance root or an identity file received through an authenticated administrative channel."
    );
    let path = PathBuf::from(ask(label, &root.to_string_lossy())?);
    let selected = if path.is_dir() {
        identity(&path)?
    } else {
        let selected: Identity = serde_json::from_value(read_json_file(&path)?)?;
        validate_identity(&selected)?;
        selected
    };
    println!(
        "Instance: {}\nOwning root: {}",
        safe(&selected.instance_id),
        safe(&selected.root.to_string_lossy())
    );
    if !yes(
        "Use these durable identities from the selected trusted source?",
        false,
    )? {
        return Err("identity selection cancelled".into());
    }
    Ok(selected)
}

fn lifetime(current: &Value) -> Result<Value, Error> {
    loop {
        let value = ask(
            "Authority lifetime: standing, a duration (e.g. 8h, 30d), or RFC 3339 expiry",
            current.as_str().unwrap_or("standing"),
        )?;
        if value == "standing" {
            return Ok(Value::Null);
        }
        let parsed = if let Some((number, suffix)) =
            value.split_at_checked(value.len().saturating_sub(1))
        {
            let unit = match suffix {
                "m" => Some(60i64),
                "h" => Some(3600),
                "d" => Some(86400),
                _ => None,
            };
            number
                .parse::<i64>()
                .ok()
                .filter(|n| *n > 0)
                .zip(unit)
                .and_then(|(n, u)| n.checked_mul(u))
                .and_then(|seconds| {
                    time::OffsetDateTime::now_utc().checked_add(time::Duration::seconds(seconds))
                })
                .or_else(|| {
                    time::OffsetDateTime::parse(
                        &value,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .ok()
                })
        } else {
            None
        };
        if let Some(expiry) = parsed.filter(|expiry| *expiry > time::OffsetDateTime::now_utc()) {
            return Ok(json!(
                expiry.format(&time::format_description::well_known::Rfc3339)?
            ));
        }
        println!("Use standing, a positive duration, or a future timestamp with its UTC offset.");
    }
}

fn choose_flags(label: &str, options: &[(&str, &str)], current: &Value) -> Result<Value, Error> {
    println!("{}; select comma-separated names, or none:", safe(label));
    for (name, meaning) in options {
        println!("  {name}: {meaning}");
    }
    let current_selection = strings(current);
    loop {
        let selected = ask(
            label,
            if current.as_array().is_some_and(|v| !v.is_empty()) {
                &current_selection
            } else {
                "none"
            },
        )?;
        if selected == "none" {
            return Ok(json!([]));
        }
        let selected = words(&selected);
        if selected
            .iter()
            .all(|s| options.iter().any(|(name, _)| s == name))
            && selected
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == selected.len()
        {
            return Ok(json!(selected));
        }
        println!("Select listed names or none.");
    }
}

async fn current(root: &Path, approvals: bool, name: &str) -> Result<(Value, Value), Error> {
    let listing = admin(
        root,
        if approvals {
            "/admin/approval-delegations"
        } else {
            "/admin/support-grants"
        },
        Method::GET,
        Value::Null,
    )
    .await?;
    let records = listing[if approvals { "delegations" } else { "grants" }]
        .as_array()
        .ok_or("authority inventory unavailable")?;
    Ok(records
        .iter()
        .find(|v| v["name"] == name)
        .map(|v| {
            (
                v[if approvals { "delegation" } else { "grant" }].clone(),
                v["revision"].clone(),
            )
        })
        .unwrap_or((Value::Null, Value::Null)))
}

fn show_agents(label: &str, agents: &Value) {
    let agents: Vec<_> = agents
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| {
            format!(
                "{} ({})",
                safe(text(&a["name"])),
                safe(text(&a["agent_id"]))
            )
        })
        .collect();
    println!(
        "{label}: {}",
        if agents.is_empty() {
            "none selected".into()
        } else {
            agents.join(", ")
        }
    );
}

fn show_authority(value: &Value) -> Result<(), Error> {
    let report = &value["authority"]["considered"];
    if report.is_null() {
        println!("Authority composition: unavailable; unknown reach is not empty reach.");
        return Ok(());
    }
    println!("Authority composition: {}", safe(text(&report["summary"])));
    for coverage in report["coverage"].as_array().into_iter().flatten() {
        println!(
            "  Owner {}: {}, observed {}, all agents: {}",
            safe(text(&coverage["owner"]["instance_id"])),
            safe(text(&coverage["status"])),
            context_json(&coverage["observed_at"])?,
            context_json(&coverage["all_agents"])?
        );
    }
    for label in ["added", "removed", "remaining", "unresolved_frontier"] {
        if let Some(items) = report[label].as_array() {
            for item in items {
                println!("  {label}: {}", context_json(item)?);
            }
        } else if report.get(label).is_some() {
            println!("  {label}: unknown");
        }
    }
    for label in ["before", "after"] {
        if let Some(control) = report[label].get("common_control") {
            println!("  {label} reviewer control: {}", context_json(control)?);
        }
    }
    println!("{}", safe(text(&report["limits"])));
    Ok(())
}

pub(super) fn show_record(value: &Value, approvals: bool) -> Result<(), Error> {
    if value.is_null() {
        println!("None configured.");
        return Ok(());
    }
    if approvals {
        show_agents("Reviewers (each can decide alone)", &value["reviewers"]);
        for reviewer in value["reviewers"].as_array().into_iter().flatten() {
            println!(
                "  Reviewer {} owner: {}",
                safe(text(&reviewer["name"])),
                safe(
                    reviewer["instance_id"]
                        .as_str()
                        .unwrap_or("this selected owner")
                )
            );
        }
        show_agents("Beneficiaries", &value["beneficiaries"]);
        println!(
            "Approval scopes: {}\nIssued-permission lifetime: {}\nGateway once: {}",
            context_json(&value["scopes"])?,
            value["grant_seconds"].as_u64().map_or_else(
                || "current worker run (other permission-specific limits still apply)".into(),
                |s| format!("{s} seconds")
            ),
            value["gateway_once"]
        );
    } else {
        println!(
            "Owner: {}\nSupport: {} ({}) on {}",
            safe(text(&value["instance_id"])),
            safe(text(&value["support"]["name"])),
            safe(text(&value["support"]["agent_id"])),
            safe(
                value["support_instance_id"]
                    .as_str()
                    .unwrap_or(text(&value["instance_id"]))
            )
        );
        show_agents("Targets", &value["targets"]);
        println!(
            "Inspection: included\nGuest administration: {}\nExact guest logs: {}\nLifecycle actions: {}\nNotices: {}\nSignal rooms: {}",
            value["guest_admin"],
            strings(&value["guest_logs"]),
            strings(&value["lifecycle"]),
            strings(&value["notifications"]),
            strings(&value["signal_rooms"])
        );
        if value.get("factory_directions").is_some() {
            println!(
                "Factory directions: {}",
                context_json(&value["factory_directions"])?
            );
        }
    }
    println!(
        "Authority lifetime: {}",
        safe(
            value["expires_at"]
                .as_str()
                .unwrap_or("standing until changed or revoked")
        )
    );
    Ok(())
}

pub(super) fn show_preview(value: &Value, approvals: bool) -> Result<(), Error> {
    println!(
        "{}: {}\nBefore:",
        if approvals {
            "Approval delegation"
        } else {
            "Support grant"
        },
        safe(text(&value["name"]))
    );
    show_record(&value["before"], approvals)?;
    println!("After:");
    show_record(&value["after"], approvals)?;
    for warning in value["warnings"].as_array().into_iter().flatten() {
        println!("Review: {}", safe(text(warning)));
    }
    if let Some(effect) = value["effect"].as_str() {
        println!("{}", safe(effect));
    }
    if let Some(remaining) = value.get("independent_access") {
        println!(
            "Independent access after revocation: {}",
            context_json(remaining)?
        );
    }
    if let Some(revocation) = value["revocation"].as_str() {
        println!("{}", safe(revocation));
    }
    show_authority(value)
}

async fn authority_owners(root: &Path) -> Result<Value, Error> {
    let mut owners = vec![json!({"instance_id":identity(root)?.instance_id,"home":null})];
    crate::coord_rooms::bootstrap(root)?;
    let conn = crate::coord_rooms::open(root)?;
    let routes = conn
        .prepare("SELECT name,instance_id FROM coord_federation_homes ORDER BY name")?
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    if !routes.is_empty() {
        println!(
            "Composition evidence can include these configured owners. A route does not grant disclosure:"
        );
        for (home, instance) in &routes {
            println!("  {}: {}", safe(home), safe(instance));
        }
        for home in words(&ask(
            "Additional owner route names, comma-separated, or none",
            "none",
        )?) {
            if home == "none" {
                continue;
            }
            let (_, instance) = routes
                .iter()
                .find(|(name, _)| name == &home)
                .ok_or("select a listed owner route")?;
            owners.push(json!({"instance_id":instance,"home":home}));
        }
    }
    Ok(json!({"owners":owners}))
}

async fn apply_preview(
    root: &Path,
    name: &str,
    approvals: bool,
    mut proposal: Value,
) -> Result<(), Error> {
    let base = format!(
        "/admin/{}/{}/",
        if approvals {
            "approval-delegations"
        } else {
            "support-grants"
        },
        encoded(name)
    );
    let field = if approvals { "delegation" } else { "grant" };
    loop {
        let view = admin(
            root,
            &format!("{base}preview"),
            Method::POST,
            proposal.clone(),
        )
        .await?;
        show_preview(&view, approvals)?;
        if !yes(
            "Apply this complete proposal and acknowledge its authority findings?",
            false,
        )? {
            println!("No authority change applied.");
            return Ok(());
        }
        proposal[field] = view["after"].clone();
        proposal[field]["acknowledgment"] = view["acknowledgment"].clone();
        proposal["authority"] = view["authority"].clone();
        match admin(
            root,
            &format!("{base}apply"),
            Method::POST,
            proposal.clone(),
        )
        .await
        {
            Ok(saved) => {
                println!(
                    "{} saved for {}. Routine authorized work needs no further prompt.",
                    if approvals {
                        "Approval delegation"
                    } else {
                        "Support grant"
                    },
                    safe(name)
                );
                if let Some(status) = saved.get("audit_status") {
                    println!("Audit delivery: {}", context_json(status)?);
                }
                return Ok(());
            }
            Err(error) => {
                let Some(refusal) = error
                    .downcast_ref::<native_client::ApiError>()
                    .filter(|e| e.status == 409)
                else {
                    println!(
                        "Apply result is uncertain. Inspect the named authority with approvals delegations or support grants before another edit; this command will not repeat the write."
                    );
                    return Err(error);
                };
                println!(
                    "Apply not confirmed: {}\nInspect the current state before another decision.",
                    safe(&error.to_string())
                );
                let (saved, revision) = current(root, approvals, name).await?;
                println!("Current saved authority:");
                show_record(&saved, approvals)?;
                if revision == view["revision"] {
                    println!(
                        "Current saved authority matches this preview. No write was repeated; inspect audit delivery separately."
                    );
                    return Ok(());
                }
                // A conflict response can also describe a transaction failure.
                // Read canonical state, then require a fresh preview and decision.
                // Keep requested durable identities and bindings, never a new name match.
                proposal["expected_revision"] = revision;
                proposal[field]["acknowledgment"] = Value::Null;
                proposal["authority"]["considered"] = Value::Null;
                if refusal.body.get("after").is_some() {
                    show_preview(&refusal.body, approvals)?;
                }
                if !yes(
                    "Prepare a new preview for the same requested identities and powers?",
                    false,
                )? {
                    return Ok(());
                }
            }
        }
    }
}

async fn support(root: &Path, name: &str) -> Result<(), Error> {
    let owner = identity(root)?;
    let (mut grant, revision) = current(root, false, name).await?;
    println!(
        "Selected owner {} at {}\nCurrent support grant:",
        safe(&owner.instance_id),
        safe(&owner.root.to_string_lossy())
    );
    show_record(&grant, false)?;
    let source = choose_identity(root, "Support agent's instance root or identity file")?;
    let selected = select(
        "Support agent",
        &source.agents,
        false,
        &names(&json!([grant["support"]])),
    )?
    .remove(0);
    if grant.is_null() {
        grant = json!({"instance_id":owner.instance_id,"guest_admin":false,"guest_logs":[],"lifecycle":[],"notifications":[],"signal_rooms":[],"expires_at":null,"acknowledgment":null});
    }
    grant["support"] = selected;
    grant
        .as_object_mut()
        .unwrap()
        .shift_remove("support_peer_epoch");
    grant
        .as_object_mut()
        .unwrap()
        .shift_remove("support_instance_id");
    if source.instance_id != owner.instance_id {
        grant["support_instance_id"] = json!(source.instance_id);
        grant["support"]["name"] = json!(ask(
            "Owner-side display handle for this remote support agent",
            text(&grant["support"]["name"])
        )?);
    }
    grant["targets"] = json!(select(
        "Targets on the selected owner",
        &owner.agents,
        true,
        &names(&grant["targets"])
    )?);
    println!(
        "Guest administration reaches arbitrary guest commands, guest sudo, target data, writable mounts, credentials, services and existing delegations. Indirect reach can include approval reviewers and other peers."
    );
    grant["guest_admin"] = json!(yes(
        "Allow arbitrary guest administration?",
        grant["guest_admin"] == true
    )?);
    let current_paths = strings(&grant["guest_logs"]);
    let paths = ask(
        "Exact absolute guest log paths, comma-separated, or none (guest links can expose other target-accessible data)",
        if grant["guest_logs"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
        {
            &current_paths
        } else {
            "none"
        },
    )?;
    grant["guest_logs"] = if paths == "none" {
        json!([])
    } else {
        json!(words(&paths))
    };
    grant["lifecycle"] = choose_flags(
        "Lifecycle actions",
        &[
            ("start_sandbox", "start the saved sandbox"),
            ("start_harness", "start the saved coding harness"),
            ("restart_harness", "restart the coding harness"),
            ("stop_sandbox", "stop the sandbox"),
            ("restart_sandbox", "restart the saved sandbox"),
        ],
        &grant["lifecycle"],
    )?;
    grant["notifications"] = choose_flags(
        "Operational notices",
        &[
            ("launch_failed", "launch attempt failed"),
            (
                "sandbox_availability",
                "host-observed sandbox availability changed",
            ),
            (
                "control_availability",
                "guest control became available/unavailable",
            ),
            (
                "sandbox_recovered",
                "sandbox returned; does not establish model progress",
            ),
            ("command_exit", "coding command exited"),
            ("command_restart", "coding command restarted"),
            ("command_failed", "coding command failed"),
            ("supervisor_exit", "supervisor exited"),
            ("supervisor_restart", "supervisor restarted"),
            (
                "needs_operator",
                "disclose target-authored material signal summaries and references in selected rooms",
            ),
            (
                "observation_health",
                "owner observation/notification health changed; gaps remain explicit",
            ),
        ],
        &grant["notifications"],
    )?;
    grant["signal_rooms"] = if grant["notifications"]
        .as_array()
        .unwrap()
        .contains(&json!("needs_operator"))
    {
        println!(
            "needs_operator discloses selected subjects' signal text, references, retained revisions and resolution state in the named rooms. It grants no unrelated signals or room history."
        );
        json!(words(&ask(
            "Signal room names, comma-separated",
            &strings(&grant["signal_rooms"])
        )?))
    } else {
        json!([])
    };
    grant["factory_directions"] = factory_directions(root, &owner, &mut grant)?;
    grant["expires_at"] = lifetime(&grant["expires_at"])?;
    grant["acknowledgment"] = Value::Null;
    let authority = authority_owners(root).await?;
    apply_preview(
        root,
        name,
        false,
        json!({"expected_revision":revision,"grant":grant,"authority":authority}),
    )
    .await
}

fn factory_directions(root: &Path, owner: &Identity, grant: &mut Value) -> Result<Value, Error> {
    let directory = root.join("factories");
    let mut approved = Vec::new();
    if directory.try_exists()? {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() && entry.path().join("approved").try_exists()? {
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| "invalid factory name")?;
                let (snapshot, _) = crate::factory::approved(root, &name)?;
                approved.push((name, snapshot));
            }
        }
    }
    approved.sort_by(|a, b| a.0.cmp(&b.0));
    if approved.is_empty() {
        println!("Factory directions: no approved factories on this owner.");
        return Ok(json!([]));
    }
    println!("Factory directions are separate from inspection, repair and approval decisions.");
    let mut selected = Vec::new();
    for (name, snapshot) in approved {
        let value = serde_json::to_value(&snapshot)?;
        let old = grant["factory_directions"]
            .as_array()
            .and_then(|v| v.iter().find(|v| v["factory"] == name))
            .cloned()
            .unwrap_or(Value::Null);
        println!(
            "Factory {} → operator-input agent {}",
            safe(&name),
            safe(snapshot.operator_agent())
        );
        let kinds: Vec<_> = value["operator_input"]["types"]
            .as_array()
            .ok_or("approved direction types unavailable")?
            .iter()
            .map(|v| v.as_str().ok_or("invalid direction type"))
            .collect::<Result<_, _>>()?;
        let choices: Vec<_> = kinds
            .iter()
            .map(|kind| {
                (
                    *kind,
                    "publish this approved direction under the support agent's own identity",
                )
            })
            .collect();
        let types = choose_flags("Approved direction types", &choices, &old["types"])?;
        if types.as_array().is_some_and(|v| !v.is_empty()) {
            let target = owner
                .agents
                .iter()
                .find(|v| v["name"] == snapshot.operator_agent())
                .ok_or("factory operator-input agent has no current durable identity")?;
            if !grant["targets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == target)
            {
                println!(
                    "This selection also requires inspection authority over {} ({}).",
                    safe(text(&target["name"])),
                    safe(text(&target["agent_id"]))
                );
                if !yes(
                    "Include this exact operator-input agent as a target?",
                    false,
                )? {
                    return Err("factory direction selection cancelled".into());
                }
                grant["targets"]
                    .as_array_mut()
                    .unwrap()
                    .push(target.clone());
            }
            selected.push(json!({"factory":name,"snapshot_id":snapshot.id()?,"types":types}));
        }
    }
    Ok(json!(selected))
}

async fn approvals(root: &Path, name: &str) -> Result<(), Error> {
    let owner = identity(root)?;
    let (mut delegation, revision) = current(root, true, name).await?;
    println!(
        "Approval owner {} at {}\nCurrent delegation:",
        safe(&owner.instance_id),
        safe(&owner.root.to_string_lossy())
    );
    show_record(&delegation, true)?;
    let source = choose_identity(root, "Reviewers' instance root or identity file")?;
    let mut reviewers = select(
        "Reviewers (each can decide alone)",
        &source.agents,
        true,
        &names(&delegation["reviewers"]),
    )?;
    if source.instance_id != owner.instance_id {
        for reviewer in &mut reviewers {
            reviewer["instance_id"] = json!(source.instance_id);
            reviewer["name"] = json!(ask(
                "Owner-side display handle for remote reviewer",
                text(&reviewer["name"])
            )?);
        }
    }
    let beneficiaries = select(
        "Beneficiaries on this owner",
        &owner.agents,
        true,
        &names(&delegation["beneficiaries"]),
    )?;
    if delegation.is_null() {
        delegation = json!({"scopes":[],"expires_at":null,"grant_seconds":null,"gateway_once":true,"acknowledgment":null});
    }
    delegation["reviewers"] = json!(reviewers);
    delegation["beneficiaries"] = json!(beneficiaries);
    if delegation["scopes"]
        .as_array()
        .is_some_and(|v| !v.is_empty())
        && yes("Keep the displayed approval scopes?", true)?
    {
        // Preserve complete prepared scopes, including definition bindings.
    } else {
        let mut scopes = Vec::new();
        loop {
            println!(
                "Choose an approval scope: network, credential, service, gateway, or request. Request selects a pending beneficiary request, including exact contract, desktop and room scopes, without copying internal identities or fingerprints."
            );
            scopes.push(approval_scope(root, &delegation["beneficiaries"]).await?);
            if !yes("Add another approval scope?", false)? {
                break;
            }
        }
        delegation["scopes"] = json!(scopes);
        delegation
            .as_object_mut()
            .unwrap()
            .shift_remove("definition_revisions");
    }
    delegation["expires_at"] = lifetime(&delegation["expires_at"])?;
    println!(
        "Delegation expiry bounds deciding authority. Issued-permission lifetime starts at each decision. Pending requests have their own expiry. Some permission types retain their own finite limits."
    );
    let seconds = ask(
        "Issued-permission seconds, or run",
        &delegation["grant_seconds"]
            .as_u64()
            .map_or_else(|| "run".into(), |v| v.to_string()),
    )?;
    delegation["grant_seconds"] = if seconds == "run" {
        Value::Null
    } else {
        json!(seconds.parse::<u64>()?)
    };
    delegation["gateway_once"] = json!(yes(
        "Limit gateway decisions to one use?",
        delegation["gateway_once"] == true
    )?);
    delegation["acknowledgment"] = Value::Null;
    let authority = authority_owners(root).await?;
    apply_preview(
        root,
        name,
        true,
        json!({"expected_revision":revision,"delegation":delegation,"authority":authority}),
    )
    .await
}

async fn approval_scope(root: &Path, beneficiaries: &Value) -> Result<Value, Error> {
    let kind = ask("Scope", "network")?;
    Ok(match kind.as_str() {
        "network" => {
            let host = ask("Destination host or existing supported pattern", "")?;
            let ports = ask("Destination ports, comma-separated, or all", "443")?;
            let all_ports = ports == "all";
            let ports = if all_ports {
                Vec::new()
            } else {
                words(&ports)
                    .iter()
                    .map(|p| p.parse::<u16>())
                    .collect::<Result<Vec<_>, _>>()?
            };
            let actions = choose_flags(
                "Network actions",
                &[("request", "HTTP requests"), ("connect", "TCP connections")],
                &json!(["request", "connect"]),
            )?;
            json!({"type":"network_egress","host":host,"ports":ports,"all_ports":all_ports,"actions":actions})
        }
        "credential" | "request" => {
            return pending_scope(root, beneficiaries, kind == "credential").await;
        }
        "service" => {
            json!({"type":"service_authorization","service":ask("Installed service", "")?,"capability":ask("Capability", "")?,"account":ask("Account", "")?,"credential":ask("Credential name", "")?,"resources":words(&ask("Resource paths, comma-separated", "")?)})
        }
        "gateway" => {
            json!({"type":"gateway_route","service":ask("Installed service", "")?,"capability":ask("Capability", "")?,"binding_id":match ask("Binding ID, or none", "none")? { v if v == "none" => Value::Null, v => json!(v) },"method":ask("HTTP method", "GET")?,"path":ask("Request path", "/")?})
        }
        _ => return Err("select network, credential, service, gateway or request".into()),
    })
}

async fn pending_scope(
    root: &Path,
    beneficiaries: &Value,
    credential: bool,
) -> Result<Value, Error> {
    let listed = pending(root, None).await?;
    let entries: Vec<_> = listed["approvals"]
        .as_array()
        .ok_or("pending approval inventory unavailable")?
        .iter()
        .filter(|entry| {
            (!credential || entry["action"]["kind"] == "credential_allow")
                && beneficiaries.as_array().into_iter().flatten().any(|agent| {
                    entry["action"]["agent"] == agent["name"]
                        && entry["action"]["agent_id"] == agent["agent_id"]
                })
        })
        .collect();
    if entries.is_empty() {
        return Err("no matching pending beneficiary requests; leave requests pending and return when the intended request is available".into());
    }
    for (index, entry) in entries.iter().enumerate() {
        println!(
            "{}: {} — {}",
            index + 1,
            safe(text(&entry["agent"])),
            context_json(&entry["summary"])?
        );
    }
    let index = ask(
        "Request number to use as the scope (this does not decide it)",
        "",
    )?
    .parse::<usize>()?;
    let entry = index
        .checked_sub(1)
        .and_then(|i| entries.get(i))
        .ok_or("select a listed request number")?;
    let id = entry["approval_id"]
        .as_str()
        .ok_or("canonical approval identity unavailable")?;
    let current = approval(root, id, None).await?;
    if current["status"] != "pending" || current["action"] != entry["action"] {
        return Err("request changed; rerun configuration and select the current request".into());
    }
    let action = &current["action"];
    println!(
        "Selected canonical request scope: {}",
        context_json(action)?
    );
    Ok(match action["kind"].as_str() {
        Some("credential_allow") => json!({"type":"credential","host":action["host"],"fingerprints":action["credentials"]}),
        Some("contract_binding") => {
            let choices: serde_json::Map<String, Value> = action["bindings"].as_object().ok_or("contract values unavailable")?.iter().map(|(name,value)| (name.clone(),json!([value]))).collect();
            json!({"type":"contract_binding","service":action["service"],"capability":action["capability"],"template":action["template"],"bound_values":choices,"grantable_operations":action["grantable_operations"]})
        }
        Some("coord_access") => json!({"type":"coord_room","room_id":action["room_id"],"participants":action["participants"],"permissions":action["permissions"]}),
        Some("operator_action") if action["action_id"] == crate::operator_actions::DESKTOP_PRESENT => json!({"type":"desktop_present","run":action["run"],"instance_id":action["instance_id"],"presentation":action["presentation"],"browser_urls":[action["parameters"]["browser_url"]],"any_browser_url":false,"max_ttl_seconds":action["parameters"]["ttl_seconds"],"configuration_revision":action["configuration_revision"]}),
        Some("gateway_route") => json!({"type":"gateway_route","service":action["service"],"capability":action["capability"],"binding_id":action["binding_id"],"method":action["method"],"path":action["path"]}),
        Some("service_authorize") if action["resources"].is_array() => json!({"type":"service_authorization","service":action["service"],"capability":action["capability"],"account":action["account"],"credential":action["credential"],"resources":action["resources"]}),
        Some("network_allow") if action["network_action"].is_string() => json!({"type":"network_egress","host":action["host"],"ports":[action["port"]],"all_ports":false,"actions":[action["network_action"]]}),
        _ => return Err("this request has no complete supported deciding scope; use its explicit scope menu or existing expert interface".into()),
    })
}

async fn revoke(root: &Path, name: &str, approvals: bool) -> Result<(), Error> {
    loop {
        let (saved, revision) = current(root, approvals, name).await?;
        if saved.is_null() {
            return Err("named authority is not configured".into());
        }
        println!(
            "Revoke {} on {}:",
            safe(name),
            safe(&root.canonicalize()?.to_string_lossy())
        );
        show_record(&saved, approvals)?;
        if !approvals {
            let report = admin(
                root,
                &format!("/admin/support-grants/{}/report", encoded(name)),
                Method::POST,
                json!({"owners":authority_owners(root).await?["owners"],"remove":true}),
            )
            .await?;
            show_authority(&report)?;
        } else {
            println!(
                "Independent operator permissions, other delegations and service grants can remain. Revocation cannot recall prior disclosure or undo admitted operations."
            );
        }
        if !yes("Revoke this exact saved authority?", false)? {
            return Ok(());
        }
        match admin(
            root,
            &format!(
                "/admin/{}/{}/revoke",
                if approvals {
                    "approval-delegations"
                } else {
                    "support-grants"
                },
                encoded(name)
            ),
            Method::POST,
            json!({"expected_revision":revision}),
        )
        .await
        {
            Ok(value) => {
                print_json(&value)?;
                return Ok(());
            }
            Err(error)
                if error
                    .downcast_ref::<native_client::ApiError>()
                    .is_some_and(|e| e.status == 409) =>
            {
                println!(
                    "Revocation refused: {}. Read the refreshed authority before deciding again.",
                    safe(&error.to_string())
                )
            }
            Err(error) => {
                println!(
                    "Result uncertain. Inspect the named authority before another write; no automatic retry was made."
                );
                return Err(error);
            }
        }
    }
}

async fn command_centre(root: &Path, destination: Option<&Path>) -> Result<(), Error> {
    let config_path = host_platform::config_path();
    let settings = native_config::read(&config_path)?;
    let (socket, host, token) = crate::native_client::operator_socket(&config_path).await?;
    let current = crate::native_client::send_json(
        socket,
        &host,
        "/admin/instance",
        token.trim(),
        Method::GET,
        Value::Null,
        Duration::from_secs(5),
    )
    .await?;
    let expected = fs::read_to_string(root.join("data/instance_id"))?;
    if current["safeyolo_instance_id"].as_str() != Some(expected.trim()) {
        return Err("running owner differs from this root's durable identity; restore the selected owner before exporting a connection".into());
    }
    let events_port = current["command_centre_events"]["port"].as_u64()
        .filter(|port| *port > 0 && *port <= u16::MAX as u64)
        .ok_or("live events are disabled; on this owner set command_centre.enabled=true and restart its proxy before exporting a connection")?;
    let (transport, admin_url, events_url) = if settings
        .native_settings
        .as_ref()
        .ok_or("operator settings unavailable")?
        .command_centre
        .share
        == "tailnet"
    {
        let publication: Value = serde_json::from_slice(&fs::read(
            root.join("data/command-centre-tailnet-status.json"),
        )?)?;
        if publication["state"] != "healthy" {
            return Err("this owner's Tailnet publication is unavailable; inspect its command-centre sharing configuration and restart before exporting".into());
        }
        (
            "tailnet",
            publication["admin_url"]
                .as_str()
                .ok_or("published Admin URL unavailable")?
                .to_owned(),
            publication["events_url"]
                .as_str()
                .ok_or("published Events URL unavailable")?
                .to_owned(),
        )
    } else {
        (
            "loopback",
            format!("http://{host}"),
            format!("ws://127.0.0.1:{events_port}/admin/events"),
        )
    };
    println!("Owning instance: {}", safe(expected.trim()));
    println!(
        "Owning root: {}",
        safe(&root.canonicalize()?.to_string_lossy())
    );
    println!("Admin URL: {}", safe(&admin_url));
    println!("Events URL: {}", safe(&events_url));
    println!(
        "Transport: {transport}. The Admin read authenticated this owner; live event delivery and support authority require their own checks."
    );
    if let Some(destination) = destination {
        let mut handoff = json!({"schema":"safeyolo.command-centre-connection/v1",
            "friendly_name":root.file_name().and_then(|name| name.to_str()).unwrap_or("SafeYolo"),
            "admin_url":admin_url,"events_url":events_url,"instance_id":expected.trim(),
            "owner_root":root.canonicalize()?,"token":token.trim(),"transport":transport});
        let serialized = serde_json::to_vec_pretty(&handoff);
        crate::credentials::wipe_json(&mut handoff);
        let bytes = zeroize::Zeroizing::new(serialized?);
        write_new(destination, &bytes)?;
        println!(
            "Private operator connection handoff saved to {}. It contains full Admin access to this owner. Import Connection File in Command Centre reviews the pinned owner before connecting. Transfer only through your authenticated administrative channel.",
            safe(&destination.to_string_lossy())
        );
    }
    Ok(())
}

pub(super) async fn run(root: &Path, arguments: &[String]) -> Result<(), Error> {
    match arguments
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] | ["--help"] => {
            println!("{HELP}");
            Ok(())
        }
        ["identity", file] => {
            let selected = identity(root)?;
            write_new(Path::new(file), &serde_json::to_vec_pretty(&selected)?)?;
            println!(
                "Public identity handoff saved to {} for {} at {}. Transfer through an authenticated administrative channel.",
                safe(file),
                safe(&selected.instance_id),
                safe(&selected.root.to_string_lossy())
            );
            Ok(())
        }
        ["command-centre"] => command_centre(root, None).await,
        ["command-centre", file] => command_centre(root, Some(Path::new(file))).await,
        ["connection"] => connection::run(root).await,
        ["support", name] => {
            validate_name(name)?;
            support(root, name).await
        }
        ["approvals", name] => {
            validate_name(name)?;
            approvals(root, name).await
        }
        ["revoke-support", name] => {
            validate_name(name)?;
            revoke(root, name, false).await
        }
        ["revoke-approvals", name] => {
            validate_name(name)?;
            revoke(root, name, true).await
        }
        _ => Err(HELP.into()),
    }
}
