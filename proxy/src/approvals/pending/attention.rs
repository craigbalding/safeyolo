//! Durable delivery claims bound interruptions, never approval authority.

use super::*;

pub(crate) const WINDOW_SECONDS: i64 = 60;
pub(crate) const AGENT_NOTICES: i64 = 5;
pub(crate) const INSTANCE_NOTICES: i64 = 20;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Delivery {
    pub(crate) status: String,
    pub(crate) attempted_at: i64,
}

impl Store {
    /// A claim precedes publication. Lost replies and reconnects cannot repeat
    /// the interruption. Suppression leaves canonical reads and decisions open.
    pub(crate) fn claim_attention(
        &self,
        id: &str,
        recipient: &str,
        policy: &Policy,
    ) -> Result<bool> {
        self.claim_attention_at(
            id,
            recipient,
            policy,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
    }

    fn claim_attention_at(
        &self,
        id: &str,
        recipient: &str,
        policy: &Policy,
        now: i64,
    ) -> Result<bool> {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let Some(mut record) = read(&transaction, id)? else {
            return Ok(false);
        };
        if record.current_status(policy)? != "pending" || record.attention.contains_key(recipient) {
            return Ok(false);
        }
        let agent_id = record.authority.action["agent_id"]
            .as_str()
            .ok_or_else(|| invalid("requester identity unavailable"))?;
        let (admitted, status) = claim_delivery(
            &transaction,
            &record.approval_id,
            recipient,
            agent_id,
            &record.authority_digest,
            now,
        )?;
        record.attention.insert(
            recipient.into(),
            Delivery {
                status: status.into(),
                attempted_at: now,
            },
        );
        if let Some(reviewer) = recipient.strip_prefix("reviewer:") {
            record
                .reviewer_delivery
                .insert(reviewer.into(), status.into());
        }
        save(&transaction, &record)?;
        transaction.commit().map_err(unavailable)?;
        Ok(admitted)
    }

    /// Plumb's existing audit-backed owner supplies the pending identity and
    /// scope. Only interruption metadata shares this store; no grant is copied.
    pub(crate) fn claim_plumb_attention(
        &self,
        id: &str,
        agent_id: &str,
        authority_digest: &str,
    ) -> Result<bool> {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let (admitted, _) = claim_delivery(
            &transaction,
            id,
            "operator",
            agent_id,
            authority_digest,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )?;
        transaction.commit().map_err(unavailable)?;
        Ok(admitted)
    }

    pub(crate) fn request_history(&self, record: &Record) -> Result<Value> {
        let connection = self.connect()?;
        let mut statement = connection
            .prepare("SELECT record FROM approvals WHERE authority_digest=?1 ORDER BY rowid")
            .map_err(unavailable)?;
        let rows = statement
            .query_map([&record.authority_digest], |row| row.get::<_, String>(0))
            .map_err(unavailable)?;
        let mut count = 0u64;
        let mut approvals = 0u64;
        let mut first = record.created_at;
        let mut last = record.created_at;
        let mut refusal = Value::Null;
        for row in rows {
            let prior = decode_record(&row.map_err(unavailable)?)?;
            count = count.saturating_add(prior.request_count);
            approvals += 1;
            first = first.min(prior.created_at);
            last = last.max(prior.last_requested_at);
            if prior.status == "rejected"
                && (refusal.is_null() || prior.decided_at >= refusal["decided_at"].as_i64())
            {
                refusal = json!({"approval_id":prior.approval_id,"decided_at":prior.decided_at});
            }
        }
        Ok(
            json!({"equivalent_request_count":count,"approval_count":approvals,
            "first_requested_at":first,"last_requested_at":last,"last_refusal":refusal}),
        )
    }
}

fn claim_delivery(
    transaction: &Connection,
    id: &str,
    recipient: &str,
    agent_id: &str,
    authority_digest: &str,
    now: i64,
) -> Result<(bool, &'static str)> {
    let already_claimed: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM approval_attention WHERE approval_id=?1 AND recipient=?2)",
            params![id, recipient],
            |row| row.get(0),
        )
        .map_err(unavailable)?;
    if already_claimed {
        return Ok((false, "already claimed; publication may be unknown"));
    }
    // Reviewer equivalence keeps its existing run/authority lifetime.
    // Operator retries may notify after the cooling interval, but never
    // notify twice for one canonical approval.
    let since = if recipient.starts_with("reviewer:") {
        i64::MIN
    } else {
        now.saturating_sub(WINDOW_SECONDS)
    };
    let equivalent: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM approval_attention WHERE authority_digest=?1 AND recipient=?2 AND attempted_at>?3)",
        params![authority_digest, recipient, since], |row| row.get(0)).map_err(unavailable)?;
    let (agent_count, instance_count): (i64, i64) = transaction.query_row(
        "SELECT coalesce(sum(agent_id=?1),0),count(*) FROM approval_attention WHERE attempted_at>?2",
        params![agent_id, now.saturating_sub(WINDOW_SECONDS)], |row| Ok((row.get(0)?, row.get(1)?))).map_err(unavailable)?;
    let status = if equivalent {
        "coalesced with prior equivalent authority; inspect the canonical list"
    } else if agent_count >= AGENT_NOTICES {
        "requester attention limit reached; inspect the canonical list"
    } else if instance_count >= INSTANCE_NOTICES {
        "instance attention limit reached; inspect the canonical list"
    } else {
        "attempted; publication may be unknown"
    };
    let admitted = !equivalent && agent_count < AGENT_NOTICES && instance_count < INSTANCE_NOTICES;
    if admitted {
        transaction
            .execute(
                "INSERT INTO approval_attention VALUES (?1,?2,?3,?4,?5)",
                params![id, recipient, agent_id, authority_digest, now],
            )
            .map_err(unavailable)?;
    }
    Ok((admitted, status))
}

pub(crate) fn event(record: &Record, recipient: &str) -> Event {
    let mut event = Event::new(
        "security.approval_attention",
        crate::audit::Kind::Security,
        crate::audit::Severity::Medium,
        "Approval attention claimed or suppressed",
    );
    event.agent = record.authority.action["agent"].as_str().map(str::to_owned);
    event.request_id = Some(record.request_id.clone());
    event.details = json!({"approval_id":record.approval_id,"authority_digest":record.authority_digest,
        "recipient":recipient,"delivery":record.attention.get(recipient),
        "window_seconds":WINDOW_SECONDS,"requester_limit":AGENT_NOTICES,"instance_limit":INSTANCE_NOTICES}).into();
    event
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority(policy: &Policy, agent: usize, port: u16) -> Authority {
        let action = json!({"kind":"network_allow","agent":format!("worker{agent}"),
            "agent_id":format!("ag-{agent:032x}"),"host":"owned.example","port":port,"network_action":"request"});
        Authority {
            revision: revision(policy, &action).unwrap(),
            resource_digest: digest(&json!(port)),
            action,
            method: "GET".into(),
            scheme: "http".into(),
            port: Some(port),
            options: vec![OptionScope {
                id: "persistent".into(),
                effect: "Allow this destination".into(),
                session_id: None,
                parameters: Value::Null,
            }],
            expires_at: None,
            credential_bindings: Default::default(),
        }
    }

    #[test]
    fn concurrent_requesters_share_durable_attention_bounds_and_recover_after_window() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::new(root.path().join("approvals.sqlite3"));
        store.initialize().unwrap();
        let source: String = (0..6)
            .map(|n| format!("[agents.worker{n}]\nagent_id='ag-{n:032x}'\n"))
            .collect();
        let policy_path = root.path().join("policy.toml");
        std::fs::write(&policy_path, source).unwrap();
        let policy = Arc::new(Policy::from_native_path(&policy_path).unwrap());
        let mut threads = vec![];
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        for agent in 0..6 {
            let (store, policy) = (store.clone(), policy.clone());
            threads.push(std::thread::spawn(move || {
                (0..8)
                    .map(|i| {
                        let record = store
                            .submit(
                                authority(&policy, agent, 12000 + i),
                                &format!("request-{agent}-{i}"),
                                &policy,
                            )
                            .unwrap();
                        let admitted = store
                            .claim_attention_at(&record.approval_id, "operator", &policy, now)
                            .unwrap();
                        (record.approval_id, admitted)
                    })
                    .collect::<Vec<_>>()
            }));
        }
        let groups: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(
            groups.iter().flatten().filter(|(_, yes)| *yes).count(),
            INSTANCE_NOTICES as usize
        );
        assert!(groups.iter().all(|group|group.iter().filter(|(_,yes)|*yes).count()<=AGENT_NOTICES as usize));
        let reopened = Store::new(store.path.clone());
        reopened.initialize().unwrap();
        for (id, _) in groups.iter().flatten() {
            assert!(
                !reopened
                    .claim_attention_at(id, "operator", &policy, now + WINDOW_SECONDS + 1)
                    .unwrap()
            );
        }
        let fresh = reopened
            .submit(authority(&policy, 0, 13000), "fresh", &policy)
            .unwrap();
        assert!(
            reopened
                .claim_attention_at(
                    &fresh.approval_id,
                    "operator",
                    &policy,
                    now + WINDOW_SECONDS + 1
                )
                .unwrap()
        );
        // A refusal stays terminal; changed circumstances can request the same
        // authority again. The new ID may notify after the cooling interval.
        reopened
            .decide(&fresh.approval_id, |record| {
                record.status = "rejected".into();
                Ok(())
            })
            .unwrap();
        let retry = reopened
            .submit(authority(&policy, 0, 13000), "retry", &policy)
            .unwrap();
        assert_ne!(fresh.approval_id, retry.approval_id);
        assert!(
            reopened
                .claim_attention_at(
                    &retry.approval_id,
                    "operator",
                    &policy,
                    now + 2 * WINDOW_SECONDS + 2
                )
                .unwrap()
        );
        assert_eq!(
            reopened.get(&fresh.approval_id).unwrap().unwrap().status,
            "rejected"
        );
    }
}
