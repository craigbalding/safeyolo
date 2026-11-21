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

pub(crate) fn assessment_inputs_revision(inputs: &Value) -> String {
    let mut identity = inputs.clone();
    for input in identity.as_array_mut().into_iter().flatten() {
        let managed = &mut input["managed"];
        if let Some(fields) = managed.as_object_mut() {
            if let Some(mut source) = fields.shift_remove("source") {
                fields.insert("max_age_seconds".into(), source["max_age_seconds"].clone());
                fields.insert("on_stale".into(), source["on_stale"].clone());
                crate::credentials::wipe_json(&mut source);
            }
            if let Some(snapshot) = fields.get_mut("snapshot").and_then(Value::as_object_mut) {
                snapshot.shift_remove("config_identity");
            }
        }
    }
    crate::approvals::pending::digest(&identity)
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
    pub(crate) assessment_inputs: Value,
}

impl Drop for RetainedPolicySnapshot {
    fn drop(&mut self) {
        self.source.zeroize();
        self.disclosed_source.zeroize();
        crate::credentials::wipe_json(&mut self.assessment_inputs);
    }
}

impl Policy {
    pub(crate) fn assessment_task(&mut self, current: &Policy) {
        self.task = current.task.clone();
    }
    pub(crate) fn assessment_list_inputs(&self) -> Value {
        json!(self.list_files.iter().map(|(name, list)| {
            json!({"reference":self.native.as_ref().map(|native| &native.authored["lists"][name]),"managed":list.managed,
                "entries":list.hosts,"agents":list.agents,"include_apex":list.managed.as_ref().is_some_and(|managed|
                    managed.snapshot.as_ref().is_some_and(|snapshot| matches!(snapshot.scope, crate::policy_feeds::Scope::DomainSuffix)))})
        }).collect::<Vec<_>>())
    }
    pub(crate) fn assessment_network(&self, after: &Policy) -> super::Result<Value> {
        let agents: std::collections::BTreeSet<_> = std::iter::once(None)
            .chain(
                self.agent_identities()
                    .into_iter()
                    .chain(after.agent_identities())
                    .map(|(name, _)| Some(name)),
            )
            .collect();
        let mut cases = std::collections::BTreeSet::from([(
            "safeyolo-assessment.invalid".to_owned(),
            443,
            "GET".to_owned(),
            "/".to_owned(),
        )]);
        for rule in self
            .rules
            .iter()
            .chain(&after.rules)
            .filter(|rule| matches!(rule.action, super::Action::Network))
        {
            let host = rule.resource.strip_suffix("/*").unwrap_or(&rule.resource);
            let host = if host.contains(['*', '?', '[']) {
                host.replace('*', "safeyolo-assessment")
                    .replace('?', "x")
                    .replace(['[', ']'], "")
            } else {
                host.to_owned()
            };
            let ports = rule.condition.ports.clone().unwrap_or_else(|| vec![443]);
            let methods = rule
                .condition
                .methods
                .clone()
                .unwrap_or_else(|| vec!["GET".into()]);
            for port in ports {
                for method in &methods {
                    if cases.len() >= 512 {
                        break;
                    }
                    cases.insert((
                        host.clone(),
                        port,
                        method.clone(),
                        rule.condition
                            .path_prefix
                            .clone()
                            .unwrap_or_else(|| "/".into()),
                    ));
                }
            }
        }
        let mut rows = Vec::new();
        for agent in agents {
            for (host, port, method, path) in &cases {
                if rows.len() >= 512 {
                    break;
                }
                let request = super::NetworkRequest {
                    agent,
                    host,
                    port: Some(*port),
                    method,
                    path,
                };
                rows.push(
                    json!({"agent":agent,"host":host,"port":port,"method":method,"path":path,
                "before":self.evaluate(request,super::current_time_ms(),false)?,
                "after":after.evaluate(request,super::current_time_ms(),false)?}),
                );
            }
        }
        Ok(
            json!({"cases":rows,"coverage":"Representative decisions from the native matcher, including inherited/default rules. Full compiled selectors remain in effective.permissions; overlapping arbitrary glob regions are not exhaustively modelled.",
            "truncated":rows.len()>=512 || cases.len()>=512}),
        )
    }
    pub(crate) fn assessment_effective(&self) -> Value {
        let baseline = self.baseline.as_ref().map(|baseline| &baseline.value);
        json!({"controls":self.native_controls(),
            "permissions":baseline.map(|value| &value["permissions"]),
            "budgets":baseline.map(|value| &value["budgets"]),
            "default_network":"deny when no applicable rule; agent-scoped rules precede inherited rules",
            "default_gateway":"prompt when no applicable route; credentials, bindings, network and risk checks remain separate",
            "logging":{"quiet_hosts":self.request_logger_settings().value()},
            "checks":self.named_checks(),
            "support_grants":self.support_grants(),
            "approval_delegations":self.delegations(),
            "active_task":self.task.as_ref().map(|task| &task.baseline.value),
            "lifetime":"Saved permissions persist until changed, revoked or their explicit expiry; activation and current issuance checks remain with their owners."})
    }
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
        let mut retained = RetainedPolicySnapshot::new(saved, metadata)?;
        // Only inputs already loaded by the active policy owner are captured.
        // Candidate paths are never passed to a file or feed loader.
        retained.assessment_inputs = self.assessment_list_inputs();
        retained.metadata["assessment_inputs_revision"] =
            json!(assessment_inputs_revision(&retained.assessment_inputs));
        Ok(retained)
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
    if let Some(encoded) = item.as_str()
        && let Ok(mut value) = serde_json::from_str::<Value>(encoded)
    {
        let before = fields.len();
        redact_json(&mut value, path, &mut Vec::new(), id, fields);
        if fields.len() != before {
            let decor = item.as_value().expect("encoded value").decor().clone();
            *item = toml_edit::value(value.to_string());
            *item.as_value_mut().expect("encoded value").decor_mut() = decor;
        }
    }
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
    pub(crate) fn matches_reference(&self, reference: &Value) -> bool {
        self.reference() == *reference
            && assessment_inputs_revision(&self.assessment_inputs)
                == self.metadata["assessment_inputs_revision"]
            && source_revision(&self.disclosed_source) == self.metadata["disclosed_source_revision"]
            && self
                .materialize(&self.disclosed_source)
                .is_ok_and(|source| {
                    source_revision(&source) == self.metadata["saved_source_revision"]
                })
    }

    /// Include unused declarations before the loader receives source. A new
    /// reference still needs its existing trusted adoption path.
    pub(crate) fn adoption_references_allowed(&self, source: &str) -> bool {
        let Ok((document, _)) = super::parse_toml_with_timestamps(source) else {
            return false;
        };
        document["lists"]
            .as_object()
            .into_iter()
            .flatten()
            .all(|(_, reference)| {
                self.assessment_inputs
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|input| input["reference"] == *reference)
            })
    }
    pub(crate) fn adoption_inputs_match(&self, candidate: &Policy) -> bool {
        candidate
            .assessment_list_inputs()
            .as_array()
            .into_iter()
            .flatten()
            .all(|input| {
                self.assessment_inputs
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|accepted| {
                        accepted["reference"] == input["reference"]
                            && assessment_inputs_revision(&json!([accepted]))
                                == assessment_inputs_revision(&json!([input]))
                    })
            })
    }
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
            assessment_inputs: json!([]),
        })
    }

    pub fn disclosed(&self) -> Value {
        let mut result = self.metadata.clone();
        result["source"] = json!(self.disclosed_source);
        result
    }

    pub(crate) fn candidate_view(&self, source: &str) -> super::Result<String> {
        Ok(Self::new(source, self.metadata.clone())?
            .disclosed_source
            .clone())
    }

    /// Compile with captured list contents and definition data supplied by the
    /// authorized caller. Source must be the audience's field-redacted view;
    /// hidden literals must not influence derived fields or validation errors.
    /// This path has no input acquisition or execution.
    pub(crate) fn compile_assessment(
        &self,
        source: &str,
        registry: Option<std::sync::Arc<crate::services::Registry>>,
        now_ms: f64,
    ) -> super::Result<(Option<Policy>, Vec<Value>)> {
        let (mut document, context) = super::parse_toml_for_edit(source)?;
        let mut dependencies = Vec::new();
        let mut resolved_lists: std::collections::BTreeMap<String, (Value, Option<Vec<String>>)> =
            Default::default();
        let mut references: Vec<_> = document
            .get("hosts")
            .and_then(toml_edit::Item::as_table_like)
            .into_iter()
            .flat_map(|hosts| hosts.iter())
            .filter_map(|(host, config)| {
                host.strip_prefix('$')
                    .map(|name| (None, host.to_owned(), name.to_owned(), config.clone()))
            })
            .collect();
        for (agent, settings) in document
            .get("agents")
            .and_then(toml_edit::Item::as_table_like)
            .into_iter()
            .flat_map(|agents| agents.iter())
        {
            if let Some(hosts) = settings
                .get("hosts")
                .and_then(toml_edit::Item::as_table_like)
            {
                references.extend(hosts.iter().filter_map(|(host, config)| {
                    host.strip_prefix('$').map(|name| {
                        (
                            Some(agent.to_owned()),
                            host.to_owned(),
                            name.to_owned(),
                            config.clone(),
                        )
                    })
                }));
            }
        }
        let mut missing = false;
        for (agent, host, name, config) in references {
            let reference = document
                .get("lists")
                .and_then(|lists| lists.get(&name))
                .map(|item| item.to_string());
            // Parse the selected value through the ordinary TOML owner. Its
            // string is data, never a filename supplied to std::fs.
            let value = reference
                .as_ref()
                .and_then(|entry| super::parse_toml_with_timestamps(&format!("value={entry}")).ok())
                .and_then(|(value, _)| value.get("value").cloned());
            let accepted = self
                .assessment_inputs
                .as_array()
                .into_iter()
                .flatten()
                .find(|input| Some(&input["reference"]) == value.as_ref());
            dependencies.push(json!({"kind":"host_list","name":name,"agent":agent,"reference":value,
                "status":if accepted.is_some(){"captured_adopted_input"}else{"trusted_adoption_required"},
                "content_revision":accepted.map(|input| assessment_inputs_revision(&json!([input])))}));
            let Some(accepted) = accepted else {
                missing = true;
                continue;
            };
            resolved_lists
                .entry(name.clone())
                .and_modify(|(_, scopes)| {
                    if let (Some(scopes), Some(agent)) = (scopes.as_mut(), agent.as_ref()) {
                        if !scopes.contains(agent) {
                            scopes.push(agent.clone());
                        }
                    } else if agent.is_none() {
                        *scopes = None;
                    }
                })
                .or_insert_with(|| {
                    (
                        accepted.clone(),
                        agent.as_ref().map(|agent| vec![agent.clone()]),
                    )
                });
            let hosts = if let Some(agent) = &agent {
                &mut document["agents"][agent]["hosts"]
            } else {
                &mut document["hosts"]
            };
            let hosts = hosts.as_table_like_mut().expect("referenced hosts");
            hosts.remove(&host);
            for entry in accepted["entries"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                for member in [
                    Some(entry),
                    accepted["include_apex"]
                        .as_bool()
                        .unwrap_or(false)
                        .then(|| entry.strip_prefix("*."))
                        .flatten(),
                ]
                .into_iter()
                .flatten()
                {
                    if !hosts.contains_key(member) {
                        hosts.insert(member, config.clone());
                    }
                }
            }
        }
        document.remove("lists");
        let (authored, _) = super::parse_toml_with_timestamps(source)?;
        let (base, _) = super::parse_toml_with_timestamps(&self.disclosed_source)?;
        for (name, check) in authored
            .get("checks")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            let input = &check["source"];
            dependencies.push(json!({"kind":"check_source","name":name,"reference":input,
                "status":if base["checks"][name]["source"] == *input {"adopted_reference; evidence_not_read"}else{"trusted_adoption_required"}}));
        }
        if missing {
            return Ok((None, dependencies));
        }
        let compiled_source = zeroize::Zeroizing::new(super::restore_large_toml_integers(
            &document.to_string(),
            &context,
        ));
        let (mut policy, _) = Policy::native_source_inputs(
            &compiled_source,
            std::path::Path::new("/__safeyolo_assessment__/policy.toml"),
            registry,
            now_ms,
            None,
            false,
        )?;
        // Keep authored scope for authority and structural projections. Network
        // rules retain the captured expansion compiled above.
        let native = policy.native.as_mut().expect("native assessment");
        native.authored = authored;
        for (name, (input, agents)) in resolved_lists {
            let managed = serde_json::from_value(input["managed"].clone())
                .map_err(|_| invalid("captured managed list unavailable"))?;
            let hosts = serde_json::from_value(input["entries"].clone())
                .map_err(|_| invalid("captured list entries unavailable"))?;
            policy.list_files.insert(
                name,
                super::HostList {
                    path: std::path::PathBuf::from("/__safeyolo_assessment__/captured-list"),
                    source: zeroize::Zeroizing::new(String::new()),
                    hosts,
                    managed,
                    agents,
                },
            );
        }
        Ok((Some(policy), dependencies))
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
