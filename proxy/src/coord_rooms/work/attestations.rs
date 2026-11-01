//! Bounded reads of attestations held in canonical immutable work revisions.
use super::*;

pub(crate) const MAX_RECORD_BYTES: usize = 32 * 1024;
const MAX_PAGE_BYTES: usize = 64 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Verdict {
    Approve,
    Reject,
    Abstain,
}

pub(crate) fn list(
    conn: &mut Connection,
    room: &str,
    actor: Actor<'_>,
    work_id: &str,
    after: &str,
    limit: usize,
) -> Result<Value, WorkError> {
    let tx = conn.transaction()?;
    let room_id = authorize(&tx, room, actor, false)?;
    let work = current(&tx, &room_id, work_id)?;
    if !(1..=MAX_PAGE).contains(&limit) {
        return Err(invalid("limit must be 1..200"));
    }
    let rows = items(&tx, &room_id, work_id, after, limit + 1, false)?;
    let mut selected = Vec::new();
    let mut bytes = 2;
    let mut more = false;
    for item in rows {
        bytes += item.to_string().len() + 1;
        if selected.len() == limit || bytes > MAX_PAGE_BYTES {
            more = true;
            break;
        }
        selected.push(item);
    }
    let next = more.then(|| selected.last().unwrap()["attestation"]["attestation_id"].clone());
    Ok(
        json!({"room_id":room_id,"work_id":work_id,"target_generation":work.target_generation,
        "items":selected,"next_after":next}),
    )
}

pub(crate) fn items(
    conn: &Connection,
    room_id: &str,
    work_id: &str,
    after: &str,
    limit: usize,
    current_first: bool,
) -> Result<Vec<Value>, WorkError> {
    let mut query = conn.prepare("SELECT json_extract(r.document_json,'$.attestation'), a.target_generation=json_extract(w.document_json,'$.target_generation')
        FROM coord_work_attestations AS a JOIN coord_work_revisions AS r ON r.work_id=a.work_id AND r.version=a.work_version
        JOIN coord_work AS w ON w.work_id=a.work_id
        WHERE a.room_id=?1 AND a.work_id=?2 AND a.attestation_id>?3
        ORDER BY CASE WHEN ?5 THEN a.target_generation=json_extract(w.document_json,'$.target_generation') ELSE 0 END DESC,a.attestation_id LIMIT ?4")?;
    query
        .query_map(
            params![room_id, work_id, after, limit as i64, current_first],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
        )?
        .map(|row| {
            let (document, current) = row?;
            let attestation: Value = serde_json::from_str(&document)?;
            Ok(json!({"attestation":attestation,"current":current}))
        })
        .collect()
}

pub(crate) fn counts(conn: &Connection, work: &Value) -> Result<Value, WorkError> {
    let mut query = conn.prepare("SELECT target_generation=?3 AS current,kind,verdict,count(*) FROM coord_work_attestations WHERE room_id=?1 AND work_id=?2 GROUP BY current,kind,verdict")?;
    let rows = query.query_map(
        params![
            work["room_id"].as_str(),
            work["work_id"].as_str(),
            work["target_generation"].as_i64()
        ],
        |row| {
            Ok((
                row.get::<_, bool>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        },
    )?;
    let mut result = json!({"current_total":0,"stale_total":0,"current_acceptance":{"approve":0,"reject":0,"abstain":0}});
    for row in rows {
        let (current, kind, verdict, count) = row?;
        let field = if current {
            "current_total"
        } else {
            "stale_total"
        };
        result[field] = json!(result[field].as_i64().unwrap() + count);
        if current && kind == "acceptance" {
            result["current_acceptance"][verdict] = json!(count);
        }
    }
    Ok(result)
}
