use indexmap::IndexMap;
use serde_json::Value;
use std::io::Write as _;
use time::OffsetDateTime;
use zeroize::{Zeroize, Zeroizing};

use super::{Error, ErrorKind, Result};
use crate::circuits::CircuitValue;

macro_rules! names {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum $name { $($variant),+ }
        impl $name {
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $value),+ }
            }
        }
    }
}
names!(Kind { Security=>"security", Gateway=>"gateway", Traffic=>"traffic", Ops=>"ops", Admin=>"admin", Agent=>"agent", Plumb=>"plumb", Coord=>"coord" });
names!(Severity { Critical=>"critical", High=>"high", Medium=>"medium", Low=>"low" });
names!(Decision { Allow=>"allow", Deny=>"deny", Warn=>"warn", RequireApproval=>"require_approval", BudgetExceeded=>"budget_exceeded", Log=>"log" });
names!(ApprovalType { Credential=>"credential", NetworkEgress=>"network_egress", GatewayRoute=>"gateway_route", Service=>"service", ContractBinding=>"contract_binding", Plumb=>"plumb", DesktopPresent=>"desktop_present" });
names!(Initiator { Agent=>"agent", Operator=>"operator", External=>"external", Unknown=>"unknown" });
names!(AttributionStatus { Resolved=>"resolved", Delegated=>"delegated", Unavailable=>"unavailable", Conflict=>"conflict" });

/// These fields serialize inside details.attribution, not at the envelope root.
#[derive(Clone, Default)]
pub struct Attribution {
    pub evidence_owner: Option<String>,
    pub trusted_transport_identity: Option<String>,
    pub initiator: Option<Initiator>,
    pub status: Option<AttributionStatus>,
    pub provenance: Option<CircuitValue>,
}

pub struct Approval {
    pub required: bool,
    pub approval_type: ApprovalType,
    pub key: String,
    pub target: String,
    pub scope_hint: CircuitValue,
}

/// Owned audit input. No Debug/Serialize exposes fields to routine diagnostics.
/// Details retain the existing typed JSON number and temporal representation.
pub struct Event {
    validation_failed: bool,
    pub event: String,
    pub kind: Kind,
    pub severity: Severity,
    pub summary: String,
    pub event_id: Option<String>,
    pub request_id: Option<String>,
    pub agent: Option<String>,
    pub addon: Option<String>,
    pub decision: Option<Decision>,
    pub host: Option<String>,
    pub approval: Option<Approval>,
    pub attribution: Option<Attribution>,
    pub details: CircuitValue,
}

impl Event {
    pub fn new(
        event: impl Into<String>,
        kind: Kind,
        severity: Severity,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            validation_failed: false,
            event: event.into(),
            kind,
            severity,
            summary: summary.into(),
            event_id: None,
            request_id: None,
            agent: None,
            addon: None,
            decision: None,
            host: None,
            approval: None,
            attribution: None,
            details: CircuitValue::Object(IndexMap::new()),
        }
    }

    /// A concrete producer has reached a source envelope type error. Retain
    /// only the same five fallback fields through the normal writer path.
    pub fn validation_fallback(
        event: impl Into<String>,
        kind: Kind,
        severity: Severity,
        summary: impl Into<String>,
    ) -> Self {
        let mut event = Self::new(event, kind, severity, summary);
        event.validation_failed = true;
        event
    }

    /// Match utils.write_event: invalid envelope fields yield its minimal
    /// unvalidated fallback, not a rejected request or fabricated attribution.
    pub(super) fn record(self, now: OffsetDateTime) -> Record {
        match self.envelope(now) {
            Ok(value) => Record(value),
            Err(_) => {
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "[safeyolo] audit event validation failed"
                );
                Record(CircuitValue::Object(IndexMap::from([
                    ("ts".into(), text(timestamp(now, false))),
                    ("event".into(), text(self.event.clone())),
                    ("kind".into(), text(self.kind.as_str())),
                    ("severity".into(), text(self.severity.as_str())),
                    ("summary".into(), text(self.summary.clone())),
                ])))
            }
        }
    }

    fn envelope(&self, now: OffsetDateTime) -> Result<CircuitValue> {
        let invalid = || Error(ErrorKind::Encoding);
        if self.validation_failed
            || self.summary.is_empty()
            || !self.event.starts_with(&format!("{}.", self.kind.as_str()))
            || self
                .event_id
                .as_ref()
                .is_some_and(|id| !(1..=128).contains(&id.chars().count()))
        {
            return Err(invalid());
        }
        let mut fields = IndexMap::new();
        fields.insert("schema_version".into(), CircuitValue::Integer(1.into()));
        optional(&mut fields, "event_id", self.event_id.as_deref());
        fields.insert("ts".into(), text(timestamp(now, true)));
        fields.insert("event".into(), text(&self.event));
        fields.insert("kind".into(), text(self.kind.as_str()));
        fields.insert("severity".into(), text(self.severity.as_str()));
        fields.insert("summary".into(), text(&self.summary));
        optional(&mut fields, "request_id", self.request_id.as_deref());
        optional(&mut fields, "agent", self.agent.as_deref());
        optional(&mut fields, "addon", self.addon.as_deref());
        optional(&mut fields, "decision", self.decision.map(Decision::as_str));
        optional(&mut fields, "host", self.host.as_deref());
        if let Some(approval) = &self.approval {
            let scope = object(&approval.scope_hint)?;
            fields.insert(
                "approval".into(),
                CircuitValue::Object(IndexMap::from([
                    ("required".into(), CircuitValue::Bool(approval.required)),
                    (
                        "approval_type".into(),
                        text(approval.approval_type.as_str()),
                    ),
                    ("key".into(), text(&approval.key)),
                    ("target".into(), text(&approval.target)),
                    ("scope_hint".into(), CircuitValue::Object(scope)),
                ])),
            );
        }
        let mut details = if self.details.truthy() {
            object(&self.details)?
        } else {
            IndexMap::new()
        };
        // write_event supplies each top-level attribution argument, even None.
        // The schema removes corresponding compatibility nested inputs first.
        if let Some(CircuitValue::Object(nested)) = details.get_mut("attribution") {
            for name in [
                "evidence_owner",
                "trusted_transport_identity",
                "initiator",
                "attribution_status",
                "attribution_provenance",
            ] {
                nested.shift_remove(name);
            }
            if nested.is_empty() {
                details.shift_remove("attribution");
            }
        }
        if let Some(attribution) = &self.attribution {
            let mut nested = IndexMap::new();
            optional(
                &mut nested,
                "evidence_owner",
                attribution.evidence_owner.as_deref(),
            );
            optional(
                &mut nested,
                "trusted_transport_identity",
                attribution.trusted_transport_identity.as_deref(),
            );
            optional(
                &mut nested,
                "initiator",
                attribution.initiator.map(Initiator::as_str),
            );
            optional(
                &mut nested,
                "attribution_status",
                attribution.status.map(AttributionStatus::as_str),
            );
            if let Some(provenance) = &attribution.provenance {
                nested.insert(
                    "attribution_provenance".into(),
                    CircuitValue::Object(object(provenance)?),
                );
            }
            if !nested.is_empty() {
                let mut prior = match details.get_mut("attribution") {
                    Some(CircuitValue::Object(value)) => std::mem::take(value),
                    _ => IndexMap::new(),
                };
                prior.extend(nested);
                details.insert("attribution".into(), CircuitValue::Object(prior));
            }
        }
        fields.insert("details".into(), CircuitValue::Object(details));
        Ok(CircuitValue::Object(fields))
    }
}

fn object(value: &CircuitValue) -> Result<IndexMap<String, CircuitValue>> {
    object_at(value, 0)
}
fn object_at(value: &CircuitValue, depth: usize) -> Result<IndexMap<String, CircuitValue>> {
    match value {
        CircuitValue::Object(values) => values
            .iter()
            .map(|(key, value)| Ok((key.clone(), model_value(value, depth + 1)?)))
            .collect(),
        CircuitValue::Other(Value::Object(values)) => {
            object_at(&CircuitValue::from(Value::Object(values.clone())), depth)
        }
        CircuitValue::Temporal(_) => {
            let (raw, types) = value.annotated().ok_or(Error(ErrorKind::Encoding))?;
            let values = raw.as_object().ok_or(Error(ErrorKind::Encoding))?;
            if types.value_at(&[]).is_some()
                || values.keys().any(|key| types.key_at(&[key]).is_some())
            {
                return Err(Error(ErrorKind::Encoding));
            }
            let mut normalized = annotated(raw, types, &mut Vec::new(), depth)?;
            match &mut normalized {
                CircuitValue::Object(values) => Ok(std::mem::take(values)),
                _ => Err(Error(ErrorKind::Encoding)),
            }
        }
        _ => Err(Error(ErrorKind::Encoding)),
    }
}

fn model_value(value: &CircuitValue, depth: usize) -> Result<CircuitValue> {
    // No parser or model is recreated: normalize only JSON-mode Any values.
    // Pinned Pydantic serialization raises ValueError beyond this depth; this
    // is an envelope fallback, never policy rejection or a new traffic cap.
    if depth > 255 {
        return Err(Error(ErrorKind::Encoding));
    }
    match value {
        CircuitValue::Float(value) if !value.is_finite() => Ok(CircuitValue::Other(Value::Null)),
        CircuitValue::Array(values) => Ok(CircuitValue::Array(
            values
                .iter()
                .map(|value| model_value(value, depth + 1))
                .collect::<Result<_>>()?,
        )),
        CircuitValue::Object(_) => Ok(CircuitValue::Object(object_at(value, depth)?)),
        CircuitValue::Temporal(_) => {
            let (value, types) = value.annotated().ok_or(Error(ErrorKind::Encoding))?;
            annotated(value, types, &mut Vec::new(), depth)
        }
        CircuitValue::Other(Value::Array(_) | Value::Object(_) | Value::Number(_)) => {
            let normalized = value.json().map_err(|_| Error(ErrorKind::Encoding))?;
            model_value(&CircuitValue::from(normalized), depth)
        }
        _ => Ok(value.clone()),
    }
}

fn temporal(value: &crate::policy::TemporalValue) -> Result<CircuitValue> {
    let mut encoded = Zeroizing::new(Vec::new());
    value
        .write_model_json(&mut *encoded)
        .map_err(|_| Error(ErrorKind::Encoding))?;
    // Temporal model JSON is an ASCII quoted ISO value with no JSON escapes.
    Ok(text(
        std::str::from_utf8(&encoded[1..encoded.len() - 1])
            .map_err(|_| Error(ErrorKind::Encoding))?,
    ))
}
fn annotated(
    value: &Value,
    types: &crate::policy::TimestampPaths,
    path: &mut Vec<String>,
    depth: usize,
) -> Result<CircuitValue> {
    if depth > 255 {
        return Err(Error(ErrorKind::Encoding));
    }
    let parts: Vec<_> = path.iter().map(String::as_str).collect();
    if let Some(value) = types.value_at(&parts) {
        return temporal(value);
    }
    match value {
        Value::Object(values) => {
            let mut output = IndexMap::new();
            for (key, value) in values {
                path.push(key.clone());
                let parts: Vec<_> = path.iter().map(String::as_str).collect();
                let key = if let Some(value) = types.key_at(&parts) {
                    match temporal(value)? {
                        CircuitValue::Other(Value::String(ref text)) => text.clone(),
                        _ => unreachable!(),
                    }
                } else {
                    key.clone()
                };
                output.insert(key, annotated(value, types, path, depth + 1)?);
                path.pop();
            }
            Ok(CircuitValue::Object(output))
        }
        Value::Array(values) => {
            let mut output = Vec::new();
            for (index, value) in values.iter().enumerate() {
                path.push(index.to_string());
                output.push(annotated(value, types, path, depth + 1)?);
                path.pop();
            }
            Ok(CircuitValue::Array(output))
        }
        _ => model_value(&CircuitValue::from(value.clone()), depth),
    }
}

fn optional(fields: &mut IndexMap<String, CircuitValue>, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        fields.insert(name.into(), text(value));
    }
}
fn text(value: impl Into<String>) -> CircuitValue {
    CircuitValue::Other(Value::String(value.into()))
}

fn timestamp(now: OffsetDateTime, model: bool) -> String {
    let mut text = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    if now.microsecond() != 0 {
        text.push_str(&format!(".{:06}", now.microsecond()));
    }
    let offset = now.offset().whole_seconds();
    if offset == 0 && model {
        text.push('Z');
    } else {
        text.push_str(&format!(
            "{}{:02}:{:02}",
            if offset < 0 { '-' } else { '+' },
            offset.abs() / 3600,
            offset.abs() / 60 % 60
        ));
        if !model && offset.abs() % 60 != 0 {
            text.push_str(&format!(":{:02}", offset.abs() % 60));
        }
    }
    text
}

pub(super) struct Record(CircuitValue);
impl Record {
    pub(super) fn encode(&self) -> Result<Zeroizing<String>> {
        let mut pending = vec![&self.0];
        while let Some(value) = pending.pop() {
            match value {
                CircuitValue::Integer(value)
                    if value.to_string().trim_start_matches('-').len() > 4300 =>
                {
                    return Err(Error(ErrorKind::Encoding));
                }
                CircuitValue::Array(values) => pending.extend(values),
                CircuitValue::Object(values) => pending.extend(values.values()),
                _ => {}
            }
        }
        self.0
            .render_json(false)
            .map(Zeroizing::new)
            .map_err(|_| Error(ErrorKind::Encoding))
    }
}
impl Drop for Record {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}
fn wipe(value: &mut CircuitValue) {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            CircuitValue::Other(value) => crate::credentials::wipe_json(value),
            CircuitValue::Array(values) => pending.extend(values.iter_mut()),
            CircuitValue::Object(values) => {
                // IndexMap keeps keys immutable while indexed: take entries first.
                let owned = std::mem::take(values);
                for (mut key, mut value) in owned {
                    key.zeroize();
                    wipe(&mut value);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests;
