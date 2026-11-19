//! One authored source and host-held restoration data for an approved disclosure.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroize;

use super::{Policy, invalid};

pub(crate) const MARKER: &str = "__SAFEYOLO_PRESERVE_";

pub(crate) fn source_revision(source: &str) -> String {
    ring::digest::digest(&ring::digest::SHA256, source.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum Field {
    Name(String),
    Index(usize),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Redaction {
    path: Vec<Field>,
    json_path: Option<Vec<Field>>,
    marker: String,
}

/// This type is serialized only into the private canonical approval database.
/// Approval views, attention and audit must project `metadata`, never this type.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedPolicySnapshot {
    source: String,
    pub(crate) disclosed_source: String,
    pub(crate) metadata: Value,
    redactions: Vec<Redaction>,
}

impl Drop for RetainedPolicySnapshot {
    fn drop(&mut self) {
        self.source.zeroize();
        self.disclosed_source.zeroize();
    }
}

impl Policy {
    pub fn full_snapshot(
        &self,
        saved: &str,
        path: &std::path::Path,
        instance: &str,
        run: &crate::host_runs::AgentRun,
    ) -> super::Result<RetainedPolicySnapshot> {
        let active = self
            .native_source_text()
            .ok_or_else(|| invalid("native policy source unavailable"))?;
        let saved_revision = source_revision(saved);
        let active_revision = source_revision(active);
        let basis = json!({"instance_id":instance,"requester":run,
            "saved_source_revision":saved_revision,
            "active_source_revision":active_revision});
        let snapshot_id = format!("pol-{}", crate::approvals::pending::digest(&basis));
        let view = self
            .native_view(path)
            .ok_or_else(|| invalid("native policy view unavailable"))?;
        let metadata = json!({"snapshot_id":snapshot_id,"instance_id":instance,
            "requester":run,"source_kind":"saved_authored_toml",
            "source_revision":saved_revision,"saved_source_revision":saved_revision,
            "active_source_revision":active_revision,"saved_matches_active":saved == active,
            "source_bytes":saved.len(),"scope":"Complete authored local policy; no config.toml, credential store, Admin credentials or apply authority.",
            "effective":{"controls":view["effective"]["controls"],"logging":view["effective"]["logging"]},
            "expanded_inputs":{"lists":view["effective"].get("lists"),
                "status":self.native_list_file_status()},
            "effective_source":"active policy; defaults and expanded inputs are not authored source bytes"});
        RetainedPolicySnapshot::new(saved, metadata)
    }
}

// Service `token` and `credential` fields are selection references, not secret
// values. Do not hide them or credential classifier definitions. Literal auth
// fields can occur in retained authored extension/contract data.
fn literal_credential(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "password"
            | "passphrase"
            | "client_secret"
            | "api_key"
            | "access_token"
            | "refresh_token"
            | "authorization"
            | "admin_api_token"
    )
}

fn redact(
    item: &mut toml_edit::Item,
    path: &mut Vec<Field>,
    id: &str,
    fields: &mut Vec<Redaction>,
) {
    if let Some(table) = item.as_table_like_mut() {
        for (key, child) in table.iter_mut() {
            path.push(Field::Name(key.to_owned()));
            if literal_credential(&key) && child.as_str().is_some_and(|value| !value.is_empty()) {
                let marker = format!("{MARKER}{id}_{}__", fields.len());
                let decor = child.as_value().map(|value| value.decor().clone());
                *child = toml_edit::value(&marker);
                if let Some(decor) = decor {
                    *child.as_value_mut().expect("marker is a value").decor_mut() = decor;
                }
                fields.push(Redaction {
                    path: path.clone(),
                    json_path: None,
                    marker,
                });
            } else {
                if let Some(encoded) = child.as_str()
                    && let Ok(mut value) = serde_json::from_str::<Value>(encoded)
                {
                    let before = fields.len();
                    redact_json(&mut value, path, &mut Vec::new(), id, fields);
                    if fields.len() != before {
                        let decor = child.as_value().expect("encoded value").decor().clone();
                        *child = toml_edit::value(value.to_string());
                        *child.as_value_mut().expect("encoded value").decor_mut() = decor;
                    }
                }
                redact(child, path, id, fields);
            }
            path.pop();
        }
    } else {
        let length = item
            .as_array()
            .map(toml_edit::Array::len)
            .or_else(|| item.as_array_of_tables().map(toml_edit::ArrayOfTables::len))
            .unwrap_or(0);
        for index in 0..length {
            path.push(Field::Index(index));
            if let Some(child) = item.get_mut(index) {
                redact(child, path, id, fields);
            }
            path.pop();
        }
    }
}

fn redact_json(
    value: &mut Value,
    path: &[Field],
    json_path: &mut Vec<Field>,
    id: &str,
    fields: &mut Vec<Redaction>,
) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                json_path.push(Field::Name(key.clone()));
                if literal_credential(key) && value.as_str().is_some_and(|value| !value.is_empty())
                {
                    let marker = format!("{MARKER}{id}_{}__", fields.len());
                    *value = json!(marker);
                    fields.push(Redaction {
                        path: path.to_vec(),
                        json_path: Some(json_path.clone()),
                        marker,
                    });
                } else {
                    redact_json(value, path, json_path, id, fields);
                }
                json_path.pop();
            }
        }
        Value::Array(array) => {
            for (index, value) in array.iter_mut().enumerate() {
                json_path.push(Field::Index(index));
                redact_json(value, path, json_path, id, fields);
                json_path.pop();
            }
        }
        _ => {}
    }
}

fn json_at<'a>(mut value: &'a Value, path: &[Field]) -> Option<&'a Value> {
    for field in path {
        value = match field {
            Field::Name(name) => value.get(name)?,
            Field::Index(index) => value.get(*index)?,
        };
    }
    Some(value)
}

fn json_at_mut<'a>(mut value: &'a mut Value, path: &[Field]) -> Option<&'a mut Value> {
    for field in path {
        value = match field {
            Field::Name(name) => value.get_mut(name)?,
            Field::Index(index) => value.get_mut(*index)?,
        };
    }
    Some(value)
}

fn at<'a>(mut item: &'a toml_edit::Item, path: &[Field]) -> Option<&'a toml_edit::Item> {
    for field in path {
        item = match field {
            Field::Name(name) => item.get(name.as_str())?,
            Field::Index(index) => item.get(*index)?,
        };
    }
    Some(item)
}

fn at_mut<'a>(
    mut item: &'a mut toml_edit::Item,
    path: &[Field],
) -> Option<&'a mut toml_edit::Item> {
    for field in path {
        // `get_mut` can insert missing table fields; first require existence.
        match field {
            Field::Name(name) => {
                item.get(name.as_str())?;
                item = item.get_mut(name.as_str())?;
            }
            Field::Index(index) => {
                item = item.get_mut(*index)?;
            }
        }
    }
    Some(item)
}

impl RetainedPolicySnapshot {
    fn new(source: &str, mut metadata: Value) -> super::Result<Self> {
        let (mut document, context) = super::parse_toml_for_edit(source)
            .map_err(|_| invalid("saved authored policy is not valid TOML"))?;
        let mut redactions = Vec::new();
        redact(
            document.as_item_mut(),
            &mut Vec::new(),
            metadata["snapshot_id"]
                .as_str()
                .ok_or_else(|| invalid("snapshot identity unavailable"))?,
            &mut redactions,
        );
        let disclosed_source = if redactions.is_empty() {
            source.to_owned()
        } else {
            super::restore_large_toml_integers(&document.to_string(), &context)
        };
        metadata["redactions"] = json!(redactions);
        metadata["preservation_ref"] = metadata["snapshot_id"].clone();
        metadata["disclosed_source_revision"] = json!(source_revision(&disclosed_source));
        Ok(Self {
            source: source.to_owned(),
            disclosed_source,
            metadata,
            redactions,
        })
    }

    pub fn disclosed(&self) -> Value {
        let mut result = self.metadata.clone();
        result["source"] = json!(self.disclosed_source);
        result
    }

    pub(crate) fn reference(&self) -> Value {
        let mut reference = self.metadata.clone();
        if let Some(fields) = reference.as_object_mut() {
            fields.shift_remove("effective");
            fields.shift_remove("expanded_inputs");
        }
        reference
    }

    /// This only restores source. The adoption owner must separately authorize,
    /// validate and compare the materialized candidate before any application.
    pub fn materialize(&self, candidate: &str) -> super::Result<zeroize::Zeroizing<String>> {
        if candidate == self.disclosed_source {
            return Ok(zeroize::Zeroizing::new(self.source.clone()));
        }
        let (original, _) = super::parse_toml_for_edit(&self.source)
            .map_err(|_| invalid("snapshot restoration data unavailable"))?;
        let (mut document, context) = super::parse_toml_for_edit(candidate)
            .map_err(|_| invalid("candidate is not valid TOML"))?;
        for redaction in &self.redactions {
            if let Some(json_path) = &redaction.json_path {
                let item = at_mut(document.as_item_mut(), &redaction.path)
                    .ok_or_else(|| invalid("hidden encoded policy field removed"))?;
                let mut value: Value = item
                    .as_str()
                    .and_then(|value| serde_json::from_str(value).ok())
                    .ok_or_else(|| invalid("hidden encoded policy field changed"))?;
                let original: Value = at(original.as_item(), &redaction.path)
                    .and_then(toml_edit::Item::as_str)
                    .and_then(|value| serde_json::from_str(value).ok())
                    .ok_or_else(|| invalid("snapshot restoration data unavailable"))?;
                let hidden = json_at_mut(&mut value,json_path).filter(|value| value.as_str()==Some(redaction.marker.as_str()))
                    .ok_or_else(|| invalid("hidden encoded value changed or removed; explicit authorized replacement is required"))?;
                *hidden = json_at(&original, json_path)
                    .ok_or_else(|| invalid("snapshot restoration data unavailable"))?
                    .clone();
                let decor = item.as_value().expect("encoded value").decor().clone();
                *item = toml_edit::value(value.to_string());
                *item.as_value_mut().expect("encoded value").decor_mut() = decor;
                continue;
            }
            let field = at_mut(document.as_item_mut(), &redaction.path)
                .filter(|item| item.as_str() == Some(redaction.marker.as_str()))
                .ok_or_else(|| invalid("hidden field changed or removed; explicit authorized replacement is required"))?;
            *field = at(original.as_item(), &redaction.path)
                .ok_or_else(|| invalid("snapshot restoration data unavailable"))?
                .clone();
        }
        if substituted_marker(document.as_item(), Some(original.as_item())) {
            return Err(invalid(
                "invented, copied or moved preservation marker in a candidate value",
            ));
        }
        let source = zeroize::Zeroizing::new(super::restore_large_toml_integers(
            &document.to_string(),
            &context,
        ));
        Ok(source)
    }
}

fn substituted_marker(item: &toml_edit::Item, original: Option<&toml_edit::Item>) -> bool {
    if let Some(value) = item.as_str() {
        if let Ok(value) = serde_json::from_str::<Value>(value) {
            let original = original
                .and_then(toml_edit::Item::as_str)
                .and_then(|value| serde_json::from_str::<Value>(value).ok());
            return json_substituted_marker(&value, original.as_ref());
        }
        return value.contains(MARKER) && original.and_then(toml_edit::Item::as_str) != Some(value);
    }
    if let Some(table) = item.as_table_like() {
        return table.iter().any(|(key, child)| {
            substituted_marker(child, original.and_then(|item| item.get(key)))
        });
    }
    let length = item
        .as_array()
        .map(toml_edit::Array::len)
        .or_else(|| item.as_array_of_tables().map(toml_edit::ArrayOfTables::len))
        .unwrap_or(0);
    (0..length).any(|index| {
        item.get(index).is_some_and(|child| {
            substituted_marker(child, original.and_then(|item| item.get(index)))
        })
    })
}

fn json_substituted_marker(value: &Value, original: Option<&Value>) -> bool {
    match value {
        Value::String(value) => {
            value.contains(MARKER) && original.and_then(Value::as_str) != Some(value)
        }
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            json_substituted_marker(value, original.and_then(|value| value.get(key)))
        }),
        Value::Array(values) => values.iter().enumerate().any(|(index, value)| {
            json_substituted_marker(value, original.and_then(|value| value.get(index)))
        }),
        _ => false,
    }
}
