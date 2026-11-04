//! Bounded related-work projections; full records and history stay in native work.
use super::*;

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
    current(&tx, &room_id, work_id)?;
    if !(1..=MAX_PAGE).contains(&limit) {
        return Err(invalid("limit must be 1..200"));
    }
    let mut query = tx.prepare("SELECT document_json FROM coord_work WHERE room_id=?1 AND work_id>?2 AND
        (json_extract(document_json,'$.check.subject.root_work_id')=?3 OR json_extract(document_json,'$.check.subject.reference.work_id')=?3
        OR json_extract(document_json,'$.challenge.subject.root_work_id')=?3 OR json_extract(document_json,'$.challenge.subject.reference.work_id')=?3)
        ORDER BY work_id LIMIT ?4")?;
    let rows = query.query_map(params![room_id, after, work_id, limit as i64 + 1], |r| {
        r.get::<_, String>(0)
    })?;
    let mut items = Vec::new();
    let mut bytes = 2;
    let mut more = false;
    for row in rows {
        let work: Work = serde_json::from_str(&row?)?;
        let mut item = super::super::room_status::work_summary(describe(&tx, work)?);
        if item.to_string().len() > attestations::MAX_RECORD_BYTES {
            item = json!({"work_id":item["work_id"],"version":item["version"],"state":item["state"],
                "claim_generation":item["claim_generation"],"review_status":item["review_status"],"details_truncated":true});
        }
        bytes += item.to_string().len() + 1;
        if items.len() == limit || bytes > 64 * 1024 {
            more = true;
            break;
        }
        items.push(item);
    }
    let next = more.then(|| items.last().unwrap()["work_id"].clone());
    Ok(json!({"room_id":room_id,"work_id":work_id,"items":items,"next_after":next}))
}
