//! Retained-flow tags and response comparisons; caller owns authorization.

mod diff;

use std::borrow::Cow;

use indexmap::IndexMap;
use rusqlite::{params, types::Value as SqlValue};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{
    Error, ErrorKind, FlowStore, Result, Side, SqlParams, is_text_like_content_type, row_map,
    sql_value,
};
use crate::circuits::CircuitValue;

impl FlowStore {
    /// Return the original successful inputs, before SQLite TEXT affinity.
    pub fn tag_flow(
        &self,
        id: i64,
        tag: &CircuitValue,
        value: &CircuitValue,
        now_ms: i64,
    ) -> Result<CircuitValue> {
        let mut connection = self.lock()?;
        let values = SqlParams(vec![tag_binding(tag)?, tag_binding(value)?]);
        let pending = !connection.is_autocommit();
        let transaction = connection.savepoint()?;
        transaction.execute(
            "INSERT OR REPLACE INTO flow_tags (flow_id,tag,value,created_at) VALUES (?,?,?,?)",
            params![id, &values.0[0], &values.0[1], now_ms],
        )?;
        transaction.commit()?;
        if pending {
            connection.execute_batch("COMMIT")?;
        }
        Ok(CircuitValue::Object(IndexMap::from([
            ("flow_id".into(), id.into()),
            ("tag".into(), tag.clone()),
            ("value".into(), value.clone()),
            ("created_at".into(), now_ms.into()),
        ])))
    }

    pub fn untag_flow(&self, id: i64, tag: &CircuitValue) -> Result<bool> {
        let mut connection = self.lock()?;
        let values = SqlParams(vec![tag_binding(tag)?]);
        let pending = !connection.is_autocommit();
        let transaction = connection.savepoint()?;
        let deleted = transaction.execute(
            "DELETE FROM flow_tags WHERE flow_id=? AND tag=?",
            params![id, &values.0[0]],
        )?;
        transaction.commit()?;
        if pending {
            connection.execute_batch("COMMIT")?;
        }
        Ok(deleted > 0)
    }

    pub fn get_flow_tags(&self, id: i64) -> Result<Value> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT tag,value,created_at FROM flow_tags WHERE flow_id=? ORDER BY tag")?;
        let rows = statement
            .query_map([id], |row| Ok(row_map(row)))?
            .map(|row| Ok(Value::Object(row??)))
            .collect::<Result<Vec<_>>>()?;
        Ok(Value::Array(rows))
    }

    pub fn diff_flows(&self, id_a: i64, id_b: i64) -> Result<Option<Value>> {
        // Source reaches the second body read even when the first ID is absent.
        let body_a = self.body(id_a, Side::Response)?;
        let body_b = self.body(id_b, Side::Response)?;
        let (Some(body_a), Some(body_b)) = (body_a, body_b) else {
            return Ok(None);
        };
        let ct_a = body_a
            .metadata
            .get("response_content_type")
            .unwrap_or(&Value::Null);
        let ct_b = body_b
            .metadata
            .get("response_content_type")
            .unwrap_or(&Value::Null);
        // Evaluate both MIME values in source order, without boolean short circuit.
        let text_a = is_text_like_content_type(ct_a)?;
        let text_b = is_text_like_content_type(ct_b)?;
        let both_text = text_a && text_b;
        let mut result = json!({
            "identical": body_a.body == body_b.body,
            "size_a": body_a.body.len(), "size_b": body_b.body.len(),
            "size_delta": body_b.body.len() as i128 - body_a.body.len() as i128,
            "both_text": both_text, "body_text_a": null, "body_text_b": null,
            "diff_lines": [], "diff_truncated": false,
        });
        if both_text {
            let mut a = text_prefix(&body_a.body);
            let mut b = text_prefix(&body_b.body);
            let (lines, truncated) = diff::unified(&a, &b, id_a, id_b);
            result["body_text_a"] = Value::String(std::mem::take(&mut *a));
            result["body_text_b"] = Value::String(std::mem::take(&mut *b));
            result["diff_lines"] = Value::Array(lines);
            result["diff_truncated"] = Value::Bool(truncated);
        }
        Ok(Some(result))
    }
}

fn tag_binding(value: &CircuitValue) -> Result<SqlValue> {
    Ok(match value {
        CircuitValue::Integer(value) => {
            SqlValue::Integer(i64::try_from(value).map_err(|_| Error(ErrorKind::Overflow))?)
        }
        CircuitValue::Float(value) => SqlValue::Real(*value),
        CircuitValue::Bool(value) => SqlValue::Integer(i64::from(*value)),
        CircuitValue::Other(value) => sql_value(value)?,
        _ => return Err(Error(ErrorKind::Programming)),
    })
}

fn text_prefix(body: &[u8]) -> Zeroizing<String> {
    // Invalid UTF-8 creates an owned replacement buffer; wipe that temporary too.
    match String::from_utf8_lossy(body) {
        Cow::Borrowed(text) => Zeroizing::new(text.chars().take(100_000).collect()),
        Cow::Owned(text) => {
            let text = Zeroizing::new(text);
            Zeroizing::new(text.chars().take(100_000).collect())
        }
    }
}
