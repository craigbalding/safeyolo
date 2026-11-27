//! Shared output mechanics. Each command owns the meaning of its human view.

use crate::Error;
use serde_json::Value;

/// Output format is explicit and independent of terminal detection. Arguments
/// after `--` belong to the launched program, not to the operator CLI.
pub fn json_requested() -> bool {
    std::env::args_os()
        .skip(1)
        .take_while(|arg| arg != "--")
        .any(|arg| arg == "--json")
}

pub fn without_json(args: &[String]) -> Vec<String> {
    let mut passthrough = false;
    args.iter()
        .filter(|arg| {
            if arg.as_str() == "--" {
                passthrough = true;
            }
            passthrough || arg.as_str() != "--json"
        })
        .cloned()
        .collect()
}

pub fn json(value: &Value) -> Result<(), Error> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

pub fn text(value: &Value) -> String {
    let text = match value {
        Value::Null => "unavailable".to_owned(),
        Value::String(text) => text.clone(),
        Value::Bool(value) => if *value { "yes" } else { "no" }.to_owned(),
        Value::Number(value) => value.to_string(),
        _ => return "details available with --json".to_owned(),
    };
    crate::network_guard::sanitize_with_limit(&text, 240)
}

pub fn field(label: &str, value: &Value) {
    if !value.is_null() {
        println!("{label}: {}", text(value));
    }
}

pub fn table(headers: &[&str], rows: &[Vec<String>]) {
    let widths: Vec<_> = headers
        .iter()
        .enumerate()
        .map(|(i, header)| {
            rows.iter()
                .filter_map(|row| row.get(i))
                .map(|cell| cell.chars().count())
                .max()
                .unwrap_or(0)
                .max(header.len())
        })
        .collect();
    let print_row = |row: &[String]| {
        for (i, cell) in row.iter().enumerate() {
            if i > 0 {
                print!("  ");
            }
            print!(
                "{cell}{}",
                " ".repeat(widths[i].saturating_sub(cell.chars().count()))
            );
        }
        println!();
    };
    print_row(&headers.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>());
    for row in rows {
        print_row(row);
    }
}

/// Named columns keep internal records out of ordinary output. Callers select
/// the fields appropriate to their operation; full records stay in JSON mode.
pub fn rows(items: &[Value], columns: &[(&str, &str)]) {
    let rows: Vec<_> = items
        .iter()
        .map(|item| {
            columns
                .iter()
                .map(|(_, key)| {
                    text(if key.starts_with('/') {
                        item.pointer(key).unwrap_or(&Value::Null)
                    } else {
                        &item[*key]
                    })
                })
                .collect()
        })
        .collect();
    table(
        &columns.iter().map(|(label, _)| *label).collect::<Vec<_>>(),
        &rows,
    );
}

pub fn policy(value: &Value) -> Result<(), Error> {
    if json_requested() {
        return json(value);
    }
    if value["policy_file"].is_null() {
        field("Policy", &value["sources"]["policy"]);
    }
    for (label, key) in [
        ("Policy", "policy_file"),
        ("Status", "status"),
        ("Saved matches active", "saved_matches_active"),
        ("Recovery", "repair"),
        ("Active policy observation", "active_error"),
        ("Decision", "decision"),
        ("Reason", "reason"),
    ] {
        field(label, &value[key]);
    }
    if !value["result"].is_null() {
        field("Decision", &value["result"]["decision"]);
        field("Reason", &value["result"]["reason"]);
    }
    let policy = value.get("effective").or_else(|| value.get("saved"));
    if let Some(policy) = policy {
        field("Request budget", &policy["budget"]);
        if let Some(hosts) = policy["hosts"].as_object() {
            let rows = hosts
                .iter()
                .map(|(host, rule)| {
                    vec![
                        text(&Value::String(host.clone())),
                        text(&rule["egress"]),
                        rule["allow"]
                            .as_array()
                            .map(|values| values.iter().map(text).collect::<Vec<_>>().join(", "))
                            .unwrap_or_else(|| "inherited".into()),
                        text(&rule["unknown_creds"]),
                        text(&rule["rate"]),
                    ]
                })
                .collect::<Vec<_>>();
            table(
                &[
                    "HOST",
                    "EGRESS",
                    "CREDENTIALS ALLOWED",
                    "UNKNOWN CREDENTIALS",
                    "RATE",
                ],
                &rows,
            );
        }
        if let Some(agents) = policy["agents"].as_object() {
            println!(
                "Agent overrides: {}",
                agents.keys().cloned().collect::<Vec<_>>().join(", ")
            );
        }
    }
    println!("Use --json for the complete policy record.");
    Ok(())
}

/// Inspect the selected saved policy through the same loader as activation.
/// The absence of the Admin API cannot establish which policy is active.
pub fn saved_policy(config: &std::path::Path, error: &str) -> Result<Value, Error> {
    let config = crate::native_config::read(config)?;
    let path = config
        .policy_file
        .ok_or("this instance has no saved policy selected")?;
    let policy = crate::policy::Policy::from_native_candidate(
        &path,
        path.parent().ok_or("policy has no parent directory")?,
    )?;
    let mut value = policy
        .native_view(&path)
        .ok_or("saved native policy unavailable")?;
    value["saved"] = value
        .as_object_mut()
        .unwrap()
        .remove("effective")
        .unwrap_or(Value::Null);
    value["status"] = Value::String("saved_only; active policy unavailable".into());
    value["policy_file"] = serde_json::json!(path);
    value["active_error"] = Value::String(error.into());
    Ok(value)
}

pub fn coord(value: &Value) -> Result<(), Error> {
    if json_requested() {
        return json(value);
    }
    if let Some(advertised) = value["advertised"].as_bool() {
        println!(
            "{} advertisement {}.",
            text(&value["kind"]),
            if advertised { "saved" } else { "removed" }
        );
        for (label, key) in [
            ("Room", "room_id"),
            ("Agent", "agent_id"),
            ("Provider", "provider"),
            ("Label", "label"),
            ("Operation", "operation_id"),
            ("Changed at", "changed_at"),
        ] {
            field(label, &value[key]);
        }
    } else if let Some(permissions) = value["permissions"].as_array() {
        field("Room", value.get("room_name").unwrap_or(&value["room_id"]));
        field("Agent", value.get("agent").unwrap_or(&value["agent_id"]));
        if permissions.is_empty() {
            println!("Room membership revoked.");
        } else {
            println!(
                "Granted room permissions: {}",
                permissions.iter().map(text).collect::<Vec<_>>().join(", ")
            );
        }
        field("Operation", &value["operation_id"]);
        println!("Use --json for the complete membership receipt.");
    } else if let Some(items) = value["items"].as_array() {
        if items.is_empty() {
            println!("No records in this selection.");
        } else if items[0].get("work_id").is_some() {
            rows(
                items,
                &[
                    ("WORK", "work_id"),
                    ("TITLE", "title"),
                    ("EXECUTION", "state"),
                    ("ACCEPTANCE", "/acceptance_status/state"),
                ],
            );
        } else {
            rows(
                items,
                &[
                    ("SIGNAL", "signal_id"),
                    ("KIND", "kind"),
                    ("STATE", "state"),
                    ("SUMMARY", "summary"),
                ],
            );
        }
        field("Next page (--after)", &value["next_after"]);
    } else if let Some(rooms) = value["rooms"].as_array() {
        if rooms.is_empty() {
            println!("No rooms configured. Create one: safeyolo coord room create NAME");
        } else {
            rows(rooms, &[("ROOM", "room_name"), ("ID", "room_id")]);
        }
    } else if let Some(messages) = value["messages"].as_array() {
        for message in messages {
            println!(
                "{}  {}: {}",
                text(&message["sequence"]),
                text(&message["sender_agent_name"]),
                text(&message["body"])
            );
        }
        if messages.is_empty() {
            println!("No retained messages in this range.");
        }
    } else {
        let selected = value
            .get("work")
            .or(value.get("signal"))
            .or(value.get("envelope"))
            .unwrap_or(value);
        for (label, key) in [
            ("Room", "room_name"),
            ("State", "state"),
            ("Status", "status"),
            ("Work", "work_id"),
            ("Title", "title"),
            ("Signal", "signal_id"),
            ("Kind", "kind"),
            ("Summary", "summary"),
            ("Version", "version"),
            ("Generation", "claim_generation"),
            ("Candidate", "target_ref"),
            ("Sequence", "sequence"),
            ("Operation", "operation_id"),
            ("Agent", "agent"),
            ("Next action", "next_action"),
            ("Error", "error"),
        ] {
            field(label, &selected[key]);
        }
        field("Output acceptance", &selected["acceptance_status"]["state"]);
        field("Report author", &selected["author"]["id"]);
        field("Observation basis", &selected["basis"]);
        field(
            "Acceptance evidence",
            &selected["acceptance_status"]["reason"],
        );
        if let Some(markdown) = selected["markdown"].as_str() {
            println!(
                "{}",
                crate::network_guard::sanitize_with_limit(markdown, 4000)
            );
        }
        for key in ["client_port", "monitor_port", "availability"] {
            field(key, &value[key]);
        }
        if value["state"] == "running" {
            println!("Managed NATS is running; role readiness is separate.");
        }
        println!("Use --json for full receipts, permissions and evidence.");
    }
    Ok(())
}
