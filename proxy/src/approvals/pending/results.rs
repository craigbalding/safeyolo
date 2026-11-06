//! Private result references. Decisions and revocation tombstones stay with
//! the canonical approval, independently of the broker and its projections.
use super::*;

pub(crate) const RETAIN_SECONDS: i64 = 7 * 24 * 60 * 60;
pub(crate) const PAGE: usize = 64;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Delivery {
    pub(crate) attention_id: String,
    pub(crate) expires_at: Option<i64>,
    pub(crate) withheld: bool,
    pub(crate) stream_sequence: Option<u64>,
}

impl Delivery {
    pub(crate) fn new() -> Self {
        Self {
            attention_id: format!("attn-{}", uuid::Uuid::new_v4().simple()),
            expires_at: None,
            withheld: false,
            stream_sequence: None,
        }
    }

    pub(crate) fn admit(&mut self, current: bool, terminal_at: Option<i64>) -> bool {
        if let Some(terminal_at) = terminal_at {
            self.expires_at
                .get_or_insert(terminal_at.saturating_add(RETAIN_SECONDS));
        }
        if !current || self.expires_at.is_some_and(|expiry| now() >= expiry) {
            self.withheld = true;
        }
        !self.withheld && self.expires_at.is_some()
    }

    pub(crate) fn view(&self) -> Value {
        json!({"status": if self.withheld || self.expires_at.is_some_and(|expiry| now() >= expiry) {
            "withheld"
        } else if self.stream_sequence.is_some() { "published" } else { "pending" },
        "expires_at":self.expires_at,
        "message":"Broker retention and attention do not establish requester receipt. Read canonical state before retrying an operation."})
    }
}

pub(crate) fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reference {
    pub(crate) approval_id: String,
    pub(crate) source: String,
    pub(crate) agent_id: String,
    pub(crate) attention_id: String,
}

#[derive(Clone)]
pub(crate) struct Ready {
    pub(crate) scan_position: i64,
    pub(crate) reference: Reference,
    pub(crate) delivery: Delivery,
    pub(crate) outcome: String,
}

impl Record {
    fn result_reference(&self) -> Reference {
        Reference {
            approval_id: self.approval_id.clone(),
            source: "approval".into(),
            agent_id: self.authority.action["agent_id"]
                .as_str()
                .unwrap_or("")
                .into(),
            attention_id: self.result_delivery.attention_id.clone(),
        }
    }

    fn refresh_result(&mut self, policy: &Policy) -> Result<Option<Ready>> {
        if self.status == "challenged" {
            return Ok(None);
        }
        if self.status == "pending" {
            let status = self.current_status(policy)?;
            if matches!(status.as_str(), "approved" | "expired") {
                if status == "approved" {
                    let receipt = self
                        .committed(policy)?
                        .ok_or_else(|| invalid("approval receipt unavailable"))?;
                    self.option = receipt["option"].as_str().map(str::to_owned);
                    self.result = receipt["result"].clone();
                }
                self.status = status;
                self.decided_at = Some(if self.status == "expired" {
                    self.authority
                        .expires_at
                        .as_deref()
                        .and_then(crate::policy::parse_expiry)
                        .map_or_else(now, |expiry| expiry.unix_timestamp())
                } else {
                    now()
                });
            }
        }
        let current = self.authority.action["agent_id"]
            .as_str()
            .is_some_and(|id| {
                policy.evidence_agent_id(self.authority.action["agent"].as_str().unwrap_or(""))
                    == Some(id)
            });
        let terminal_at = (self.status != "pending").then_some(self.decided_at.unwrap_or_else(now));
        if !self.result_delivery.admit(current, terminal_at) {
            return Ok(None);
        }
        Ok(Some(Ready {
            scan_position: 0,
            reference: self.result_reference(),
            delivery: self.result_delivery.clone(),
            outcome: self.status.clone(),
        }))
    }
}

impl Store {
    /// A bounded scan also materializes expiry and recovered committed decisions
    /// while the requester is offline. No per-request polling is required.
    pub(crate) fn result_page(&self, policy: &Policy, after: i64) -> Result<(i64, Vec<Ready>)> {
        let mut connection = self.connect()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let rows = tx
            .prepare("SELECT rowid,record FROM approvals WHERE rowid>?1 ORDER BY rowid LIMIT ?2")
            .map_err(unavailable)?
            .query_map(params![after, PAGE as i64], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(unavailable)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(unavailable)?;
        let next = rows.last().map_or(0, |row| row.0);
        let mut ready = vec![];
        for (position, encoded) in rows {
            let mut record = decode_record(&encoded)?;
            if let Some(mut result) = record.refresh_result(policy)? {
                result.scan_position = position;
                ready.push(result);
            }
            if serde_json::to_string(&record).map_err(unavailable)? != encoded {
                save(&tx, &record)?;
            }
        }
        tx.commit().map_err(unavailable)?;
        Ok((next, ready))
    }

    pub(crate) fn result(&self, reference: &Reference, policy: &Policy) -> Result<Option<Ready>> {
        let mut ready = None;
        self.decide(&reference.approval_id, |record| {
            if record.result_reference() == *reference {
                ready = record.refresh_result(policy)?;
            }
            Ok(())
        })?;
        Ok(ready)
    }

    pub(crate) fn result_published(&self, reference: &Reference, sequence: u64) -> Result<()> {
        self.decide(&reference.approval_id, |record| {
            if record.result_reference() == *reference && !record.result_delivery.withheld {
                record.result_delivery.stream_sequence = Some(sequence);
            }
            Ok(())
        })?;
        Ok(())
    }

    pub(crate) fn withhold_results(&self, agent_id: &str) -> Result<()> {
        self.connect()?.execute("UPDATE approvals SET record=json_set(record,'$.result_delivery.withheld',json('true')) WHERE json_extract(record,'$.authority.action.agent_id')=?1 AND json_extract(record,'$.result_delivery.withheld')=0", [agent_id]).map_err(unavailable)?;
        Ok(())
    }
}
