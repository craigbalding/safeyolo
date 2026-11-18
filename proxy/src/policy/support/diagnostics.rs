//! The evidence selection stored with an ordinary host-held support grant.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::policy::{Result, invalid};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct History {
    pub since: Option<String>,
    pub until: Option<String>,
    pub future: bool,
}

pub(crate) fn timestamp(value: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Room {
    pub room_id: String,
    pub history: bool,
    pub membership: bool,
    pub attention: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Scope {
    pub audit: bool,
    pub runtime: bool,
    pub rooms: Vec<Room>,
    pub system_categories: Vec<String>,
    pub history: History,
    #[serde(default)]
    pub runs: BTreeMap<String, Vec<String>>,
    pub snapshot: bool,
}

impl Scope {
    pub(crate) fn validate(&self) -> Result<()> {
        if (!self.audit
            && !self.runtime
            && self.rooms.is_empty()
            && self.system_categories.is_empty())
            || self
                .history
                .since
                .as_deref()
                .is_some_and(|v| timestamp(v).is_none())
            || self
                .history
                .until
                .as_deref()
                .is_some_and(|v| timestamp(v).is_none())
            || (self.history.future && self.history.until.is_some())
            || (!self.history.future && self.history.until.is_none())
            || (self.snapshot && self.history.future)
        {
            return Err(invalid(
                "select evidence and an explicit valid history range; future records require future=true and no fixed end",
            ));
        }
        if let (Some(since), Some(until)) = (&self.history.since, &self.history.until)
            && timestamp(since) > timestamp(until)
        {
            return Err(invalid("diagnostic history starts after its end"));
        }
        if self
            .rooms
            .iter()
            .any(|r| r.room_id.is_empty() || !(r.history || r.membership || r.attention))
            || self
                .system_categories
                .iter()
                .any(|s| !matches!(s.as_str(), "coord_health" | "audit_health"))
            || self
                .runs
                .values()
                .flatten()
                .any(|run| run.len() != 32 || !run.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(invalid(
                "select supported room, system category and sandbox-run scopes",
            ));
        }
        Ok(())
    }

    pub(crate) fn contains_time(&self, value: &str) -> bool {
        timestamp(value).is_some_and(|time| {
            self.history
                .since
                .as_deref()
                .and_then(timestamp)
                .is_none_or(|since| time >= since)
                && self
                    .history
                    .until
                    .as_deref()
                    .and_then(timestamp)
                    .is_none_or(|until| time <= until)
        })
    }
}
