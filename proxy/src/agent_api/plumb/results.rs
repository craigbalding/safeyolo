//! Plumb decisions retain their private delivery receipt in plumb_pending.
use super::*;
use crate::approvals::pending::results::{Delivery, PAGE, Ready, Reference};
use crate::policy::Policy;

fn decode_delivery(encoded: &str) -> rusqlite::Result<Delivery> {
    serde_json::from_str(encoded).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn result(db: &Connection, id: &str, policy: &Policy) -> rusqlite::Result<Option<Ready>> {
    use rusqlite::OptionalExtension;
    let record = db.query_row("SELECT requester,requester_id,status,decided_at,result_delivery FROM plumb_pending WHERE request_id=?1", [id], |r| Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<i64>>(3)?,r.get::<_,String>(4)?))).optional()?;
    let Some((agent, agent_id, status, decided_at, encoded)) = record else {
        return Ok(None);
    };
    let mut delivery = decode_delivery(&encoded)?;
    let current = agent_id.is_some() && policy.evidence_agent_id(&agent) == agent_id.as_deref();
    let admitted = delivery.admit(
        current,
        (status != "pending")
            .then_some(decided_at.unwrap_or_else(crate::approvals::pending::results::now)),
    );
    let updated = serde_json::to_string(&delivery)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    if updated != encoded {
        db.execute(
            "UPDATE plumb_pending SET result_delivery=?1 WHERE request_id=?2",
            params![updated, id],
        )?;
    }
    Ok(admitted.then(|| Ready {
        scan_position: 0,
        reference: Reference {
            source: "plumb".into(),
            approval_id: id.into(),
            agent_id: agent_id.unwrap_or_default(),
            attention_id: delivery.attention_id.clone(),
        },
        delivery,
        outcome: status,
    }))
}

impl PlumbOwner {
    async fn approval_result_call<T: Send + 'static>(
        &self,
        call: impl FnOnce(Arc<Store>) -> rusqlite::Result<T> + Send + 'static,
    ) -> Result<T, ()> {
        let store = self.store.as_ref().ok_or(())?.clone();
        let owner = self.clone();
        self.spawn_owned(async move { owner.db_call(store, call).await })
            .await?
            .await
            .map_err(|_| ())?
    }
    pub(crate) async fn approval_result_page(
        &self,
        policy: Arc<Policy>,
        after: i64,
    ) -> Result<(i64, Vec<Ready>), ()> {
        self.approval_result_call(move |store| {
            let mut db = store.connection.lock().unwrap_or_else(|e| e.into_inner());
            let tx = db.transaction()?;
            let rows = tx.prepare("SELECT rowid,request_id FROM plumb_pending WHERE rowid>?1 ORDER BY rowid LIMIT ?2")?
                .query_map(params![after,PAGE as i64], |r| Ok((r.get::<_,i64>(0)?, r.get::<_,String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let next = rows.last().map_or(0, |r| r.0);
            let mut ready = vec![];
            for (position,id) in rows { if let Some(mut value) = result(&tx, &id, &policy)? { value.scan_position = position; ready.push(value); } }
            tx.commit()?;
            Ok((next,ready))
        }).await
    }

    pub(crate) async fn approval_result(
        &self,
        reference: Reference,
        policy: Arc<Policy>,
    ) -> Result<Option<Ready>, ()> {
        self.approval_result_call(move |store| {
            let mut db = store.connection.lock().unwrap_or_else(|e| e.into_inner());
            let tx = db.transaction()?;
            // Resolve against current owner authority, then match the exact reference.
            let candidate = result(&tx, &reference.approval_id, &policy)?;
            let candidate = candidate.filter(|ready| ready.reference == reference);
            tx.commit()?;
            Ok(candidate)
        })
        .await
    }

    pub(crate) async fn approval_result_published(
        &self,
        reference: Reference,
        sequence: u64,
    ) -> Result<(), ()> {
        self.approval_result_call(move |store| {
            let db = store.connection.lock().unwrap_or_else(|e| e.into_inner());
            db.execute("UPDATE plumb_pending SET result_delivery=json_set(result_delivery,'$.stream_sequence',?1) WHERE request_id=?2 AND requester_id=?3 AND json_extract(result_delivery,'$.attention_id')=?4 AND json_extract(result_delivery,'$.withheld')=0", params![i64::try_from(sequence).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,reference.approval_id,reference.agent_id,reference.attention_id])?;
            Ok(())
        }).await
    }

    pub(crate) fn withhold_approval_results(&self, agent_id: &str) -> Result<(), crate::Error> {
        let store = self
            .store
            .as_ref()
            .ok_or("Plumb approval state unavailable")?;
        let db = store.connection.lock().unwrap_or_else(|e| e.into_inner());
        db.execute("UPDATE plumb_pending SET result_delivery=json_set(result_delivery,'$.withheld',json('true')) WHERE requester_id=?1", [agent_id])?;
        Ok(())
    }
}
