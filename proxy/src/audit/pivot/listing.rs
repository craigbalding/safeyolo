//! Entry navigation through retained NSM evidence, without live inventory.

use std::collections::BTreeMap;

use super::*;

fn references(line: RecordLine, row: &Value) -> Vec<Value> {
    let query = Query {
        instance: row["details"]["instance_id"].as_str().unwrap(),
        runtime: row["details"]["runtime_id"].as_str().unwrap(),
        kind: "connection",
        id: "",
        agent: row["agent"].as_str(),
        lines: 0,
    };
    let mut references = Vec::new();
    let mut add = |kind, field, id| {
        let reference = json!({"kind":kind,"field":field,"id":id});
        if !references.contains(&reference) {
            references.push(reference);
        }
    };
    if let Some(id) = row["details"]["connection_id"].as_str() {
        add("connection", "details.connection_id", id);
    }
    if let Some(id) = row["request_id"]
        .as_str()
        .filter(|id| !id.trim().is_empty())
    {
        add("request", "request_id", id);
    }
    for link in links(line, row, &query) {
        add("connection", link.field, link.connection_id);
        if let Some(id) = link.request_id {
            add("request", "details.source.request_id", id);
        }
    }
    references
}

pub(crate) fn read(
    paths: &[PathBuf],
    tails: Vec<super::super::reader::LocalTail>,
    explicit: bool,
    lines: usize,
    instance: Option<&str>,
    runtime: Option<&str>,
    agent: Option<&str>,
) -> Result<Value, crate::Error> {
    if [instance, runtime]
        .into_iter()
        .flatten()
        .any(|id| id.trim().is_empty())
    {
        return Err("logs list namespace filters require nonempty IDs".into());
    }
    let (inputs, mut search) = search_window(paths, &tails, explicit, lines);
    search["non_nsm_rows"] = json!(
        tails
            .iter()
            .flat_map(|tail| &tail.rows)
            .filter(|(_, row)| row["schema_version"] != super::super::nsm::SCHEMA_VERSION)
            .count()
    );
    let retained = retained_rows(tails, explicit, true, |row| {
        instance.is_none_or(|id| row["details"]["instance_id"] == id)
            && runtime.is_none_or(|id| row["details"]["runtime_id"] == id)
    });
    let rows: Vec<_> = retained.records.iter().collect();
    let conflicts = conflicting_lines(&rows);
    search["distinct_nsm_records"] = json!(rows.len());
    search["duplicate_nsm_rows"] = json!(
        retained
            .copies
            .values()
            .map(|locations| locations.len() - 1)
            .sum::<usize>()
    );
    search["conflicting_nsm_records"] = json!(conflicts.len());
    search["limits"] = json!(
        "Retained evidence only, not live agents or sessions. Each input is validated to EOF; --lines retains the last selected-agent rows per input before namespace selection. Counts describe retained records and copies, not lifetime traffic. Equal parsed records share evidence; every retained location is preserved. Conflicting records and unknown attribution remain separate from resolved agent context. References name recorded keys, not verified relationships; use the scoped pivot to inspect support. Legacy rows remain available through raw logs. Unselected rotations, filtered/outside-window rows, queues and loss can omit evidence. Input order and timestamps do not establish global chronology. Selection and schema validation do not authenticate a producer. No content is fetched or input changed."
    );
    // Separate attribution classes even when their envelope agent names match.
    let mut namespaces = BTreeMap::new();
    for (line, row) in &retained.records {
        let context = if conflicts.contains(line) {
            "conflicting"
        } else if trusted_agent(row).is_some() {
            "resolved_agent"
        } else {
            "unknown"
        };
        let groups = namespaces
            .entry((
                row["details"]["instance_id"].as_str().unwrap(),
                row["details"]["runtime_id"].as_str().unwrap(),
            ))
            .or_insert_with(BTreeMap::new);
        let records = groups
            .entry((row["agent"].as_str(), context))
            .or_insert_with(Vec::new);
        let mut entry = json!({
            "line":line,"locations":retained.copies[line],"event":row["event"],
            "event_id":row["event_id"],"ts":row["ts"],"summary":row["summary"],
            "decision":row["decision"],
            "attribution":row["details"]["attribution"],"conflicting":conflicts.contains(line),
            "references":references(*line, row)
        });
        if row["event"] == "security.indicator" {
            let details = &row["details"];
            entry["indicator"] = json!({
                "indicator_type":details["indicator_type"],"sensor":details["sensor"],
                "rule":details["rule"],"confidence":details["confidence"],
                "direction":details["direction"],"evidence_hash":details["evidence_hash"]
            });
        }
        records.push(entry);
    }
    let namespaces: Vec<_> = namespaces
        .into_iter()
        .map(|((instance, runtime), groups)| {
            let agents: Vec<_> = groups.into_iter().map(|((agent, context), records)|
            json!({"agent":agent,"context":context,"records":records})).collect();
            json!({"instance_id":instance,"runtime_id":runtime,"agents":agents})
        })
        .collect();
    Ok(json!({
        "selection":{"instance_id":instance,"runtime_id":runtime,"agent":agent},
        "inputs":inputs,"search":search,"namespaces":namespaces
    }))
}
