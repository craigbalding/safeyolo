//! Bounded current room projections and the operator's deterministic text view.
use crate::{Error, coord_rooms::work::attestations, coord_timeline::visible};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::fmt::Write;

pub(crate) const MAX_ITEMS: usize = 50;
pub(crate) const SECTION_BYTES: usize = 64 * 1024;
const BRIEF_BYTES: usize = 2048;
const WORK_TEXT_BYTES: usize = 512;

// Limits apply to UTF-8 source bytes, without splitting a code point. The
// canonical text and revision remain available through their ordinary reads.
fn prefix(text: &str, limit: usize) -> &str {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

pub(crate) fn brief_excerpt(mut brief: Value) -> Value {
    let markdown = brief.as_object_mut().unwrap().remove("markdown").unwrap();
    let text = markdown.as_str().unwrap_or("");
    brief["excerpt"] = json!(prefix(text, BRIEF_BYTES));
    brief["utf8_bytes"] = json!(text.len());
    brief["truncated"] = json!(text.len() > BRIEF_BYTES);
    brief
}

pub(crate) fn bounded_items(items: Vec<Value>, total: usize, budget: usize) -> Value {
    let mut bytes = 2; // Array brackets; item separators count below.
    let items = items
        .into_iter()
        .take(MAX_ITEMS)
        .take_while(|item| {
            bytes += item.to_string().len() + 1;
            bytes <= budget
        })
        .collect::<Vec<_>>();
    json!({"total":total,"shown":items.len(),"truncated":items.len()<total,"items":items})
}

fn work_summary(mut work: Value) -> Value {
    // Descriptions and refs can fill a complete mutation. Status needs the
    // current ownership/version and a bounded title or completion result.
    let external_ref = work.as_object_mut().unwrap().remove("external_ref");
    if let Some(reference) = external_ref
        .as_ref()
        .and_then(Value::as_str)
        .and_then(|value| crate::coord_rooms::work::github::Reference::parse(value).ok())
    {
        work["github_reference"] = json!({"source":"github","url":reference.url});
    }
    for field in ["title", "short_result"] {
        if let Some(text) = work[field].as_str() {
            let excerpt = prefix(text, WORK_TEXT_BYTES).to_owned();
            let bytes = text.len();
            work[format!("{field}_bytes")] = json!(bytes);
            work[format!("{field}_truncated")] = json!(excerpt.len() < bytes);
            work[field] = json!(excerpt);
        }
    }
    work
}

pub(crate) fn work_page(conn: &Connection, room: &str, completed: bool) -> Result<Value, Error> {
    let total: i64 = conn.query_row(
        "SELECT count(*) FROM coord_work WHERE room_id=?1 AND (state='done')=?2",
        params![room, completed],
        |row| row.get(0),
    )?;
    // Recent completions first; active work uses stable durable IDs. A claim's
    // age never changes ownership. Released claims are already open in this table.
    let mut query = conn.prepare("SELECT document_json FROM coord_work WHERE room_id=?1 AND (state='done')=?2 ORDER BY CASE WHEN ?2 THEN json_extract(document_json,'$.updated_at') ELSE 0 END DESC,work_id LIMIT ?3")?;
    let items = query
        .query_map(params![room, completed, MAX_ITEMS as i64], |row| {
            row.get::<_, String>(0)
        })?
        .map(|row| {
            let mut work = work_summary(serde_json::from_str(&row?)?);
            let mut counts = attestations::counts(conn, &work)?;
            let total =
                counts["current_total"].as_u64().unwrap() + counts["stale_total"].as_u64().unwrap();
            let items =
                attestations::items(conn, room, work["work_id"].as_str().unwrap(), "", 8, true)?
                    .into_iter()
                    .map(|mut item| {
                        let record = item["attestation"].as_object_mut().unwrap();
                        let summary = record["summary"].as_str().unwrap();
                        let excerpt = prefix(summary, 128).to_owned();
                        let truncated = excerpt.len() < summary.len();
                        record.insert("summary_truncated".into(), json!(truncated));
                        record.insert("summary".into(), json!(excerpt));
                        let refs = record.remove("evidence_refs").unwrap();
                        record.insert(
                            "evidence_ref_count".into(),
                            json!(refs.as_array().unwrap().len()),
                        );
                        record.remove("target_ref");
                        record.remove("room_id");
                        record.remove("work_id");
                        item
                    })
                    .collect();
            let page = bounded_items(items, total as usize, 4096);
            counts
                .as_object_mut()
                .unwrap()
                .extend(page.as_object().unwrap().clone());
            work["attestations"] = counts;
            Ok(work)
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(bounded_items(items, total as usize, SECTION_BYTES))
}

pub(crate) const HELP: &str = "safeyolo [--root ROOT] coord status ROOM [--json]\n\nRead the canonical room state through Admin API. Show the brief revision and a UTF-8 prefix of at most 2048 bytes, current agent members, advertised authorized capabilities, expiring declarations, provider-owned leases, active work, recent completions, operator needs and latest current results/corrections. No chat replay or model is used. Each section shows at most 50 items and 64 KiB of item JSON, with counts and truncation. Per-member verified and declared capability arrays also have byte limits. Work titles and completion results show at most 512 UTF-8 bytes each. Recognized GitHub URLs are labelled external references without a network fetch; read_github_work reads external metadata through the caller's service access. Each work item shows its current target generation and acceptance counts, with up to eight attestation excerpts in 4096 item JSON bytes, current first. Attestation summaries show at most 128 UTF-8 bytes; evidence refs are counted and remain untrusted external content. Counts include omitted current and stale attestations. No majority or automatic completion is inferred. Use coord brief show, coord work show, coord work attestations and coord signal show for full canonical records. Availability without fresh provider evidence is unknown. Claims remain owned until an explicit transition. Bare coord status reports the owned NATS process.";

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or("none")
}
fn quoted(value: &Value) -> String {
    // Quoting prevents embedded newlines/tabs from impersonating another row.
    visible(&value.to_string())
}
fn heading(output: &mut String, title: &str, page: &Value) {
    let _ = writeln!(
        output,
        "\n{title} ({} of {}{})",
        page["shown"],
        page["total"],
        if page["truncated"] == true {
            "; truncated"
        } else {
            ""
        }
    );
    if page["shown"] == 0 {
        let _ = writeln!(
            output,
            "  {}",
            if page["total"] == 0 {
                "none"
            } else {
                "no items fit the display limit"
            }
        );
    }
}
fn work_rows(output: &mut String, title: &str, page: &Value) {
    heading(output, title, page);
    for work in page["items"].as_array().unwrap() {
        let _ = writeln!(
            output,
            "  {} v{} {} title={}{} {}={} generation={} claimed_at={} result={}{}",
            text(&work["work_id"]),
            work["version"],
            text(&work["state"]),
            quoted(&work["title"]),
            if work["title_truncated"] == true {
                " [excerpt]"
            } else {
                ""
            },
            if work["state"] == "done" {
                "last_holder"
            } else {
                "owner"
            },
            text(&work["claim_agent_id"]),
            work["claim_generation"],
            work["claimed_at"],
            quoted(&work["short_result"]),
            if work["short_result_truncated"] == true {
                " [excerpt]"
            } else {
                ""
            }
        );
        if work["github_reference"].is_object() {
            let _ = writeln!(
                output,
                "    GitHub reference (external): {}; metadata requires read_github_work and the caller's service access",
                quoted(&work["github_reference"]["url"])
            );
        }
        let evidence = &work["attestations"];
        let acceptance = &evidence["current_acceptance"];
        let _ = writeln!(
            output,
            "    target generation={} ref={}; current acceptance approve={} reject={} abstain={}; stale attestations={}",
            work["target_generation"],
            quoted(&work["target_ref"]),
            acceptance["approve"],
            acceptance["reject"],
            acceptance["abstain"],
            evidence["stale_total"]
        );
        if acceptance["approve"] == 0 && acceptance["reject"] == 0 && acceptance["abstain"] == 0 {
            let _ = writeln!(output, "    no current acceptance attestations");
        }
        for item in evidence["items"].as_array().unwrap() {
            let record = &item["attestation"];
            let _ = writeln!(
                output,
                "    {} {} generation={} author={}:{} kind={} verdict={} summary={}{} evidence_refs={} (untrusted external content; use coord work attestations)",
                text(&record["attestation_id"]),
                if item["current"] == true {
                    "current"
                } else {
                    "stale"
                },
                record["target_generation"],
                text(&record["author"]["kind"]),
                text(&record["author"]["id"]),
                quoted(&record["kind"]),
                quoted(&record["verdict"]),
                quoted(&record["summary"]),
                if record["summary_truncated"] == true {
                    " [excerpt]"
                } else {
                    ""
                },
                record["evidence_ref_count"]
            );
        }
        if evidence["truncated"] == true {
            let _ = writeln!(
                output,
                "    attestations: {} of {}; truncated; use coord work attestations",
                evidence["shown"], evidence["total"]
            );
        }
    }
}
fn signal_rows(output: &mut String, title: &str, page: &Value) {
    let mut page = page.clone();
    page["shown"] = json!(page["items"].as_array().unwrap().len());
    heading(output, title, &page);
    for item in page["items"].as_array().unwrap() {
        let signal = &item["signal"];
        let _ = writeln!(
            output,
            "  {} r{} {} author={}:{} basis={} (author report) summary={}",
            text(&signal["signal_id"]),
            signal["revision"],
            text(&signal["kind"]),
            text(&signal["author"]["kind"]),
            text(&signal["author"]["id"]),
            text(&signal["basis"]),
            quoted(&signal["summary"])
        );
    }
}

pub(crate) fn render(state: &Value) -> String {
    let mut output = String::new();
    let _ = writeln!(
        output,
        "Room {} ({})\nBrief v{} {}{}",
        quoted(&state["room_name"]),
        text(&state["room_id"]),
        state["brief"]["revision"],
        quoted(&state["brief"]["excerpt"]),
        if state["brief"]["truncated"] == true {
            " [excerpt; use coord brief show]"
        } else {
            ""
        }
    );
    heading(&mut output, "Members", &state["bounds"]["members"]);
    for member in state["members"].as_array().unwrap() {
        let _ = writeln!(
            output,
            "  {} {}",
            quoted(&member["display_name"]),
            text(&member["agent_id"])
        );
        for capability in member["verified"].as_array().unwrap() {
            let _ = writeln!(
                output,
                "    {} (authorized; availability {}; {}; observed_at={}; valid_until={})",
                text(&capability["capability"]),
                text(&capability["availability"]),
                text(&capability["freshness"]),
                capability["observed_at"],
                capability["valid_until"]
            );
        }
        for capability in member["declared"].as_array().unwrap() {
            let _ = writeln!(
                output,
                "    {} (agent declared; unverified; valid_until={})",
                text(&capability["capability"]),
                capability["valid_until"]
            );
        }
        for field in ["verified", "declared"] {
            let counts = &member["bounds"][field];
            if counts["truncated"] == true {
                let _ = writeln!(
                    output,
                    "    {field}: {} of {}; truncated",
                    counts["shown"], counts["total"]
                );
            }
        }
    }
    heading(
        &mut output,
        "Resource leases",
        &state["bounds"]["resource_leases"],
    );
    for lease in state["resource_leases"].as_array().unwrap() {
        let _ = writeln!(
            output,
            "  {}:{} state={} holder={} {} observed_at={} valid_until={}",
            text(&lease["provider"]),
            text(&lease["resource"]),
            text(&lease["state"]),
            text(&lease["holder_agent_id"]),
            text(&lease["freshness"]),
            lease["observed_at"],
            lease["valid_until"]
        );
    }
    work_rows(&mut output, "Active work", &state["active_work"]);
    work_rows(&mut output, "Completed work", &state["completed_work"]);
    signal_rows(&mut output, "Needs operator", &state["needs_operator"]);
    signal_rows(
        &mut output,
        "Latest material results",
        &state["latest_results"],
    );
    visible(&output)
}

#[cfg(test)]
mod tests;
