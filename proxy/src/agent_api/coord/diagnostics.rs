//! Read-only diagnostic projections at the canonical Coord source owner.
use super::*;
use crate::policy::support::Grant;

impl CoordClient {
    pub(crate) async fn diagnostic_evidence(&self, grant: &Grant) -> Vec<Value> {
        let mut sources = Vec::new();
        let scope = grant.diagnostics.as_ref().expect("diagnostic grant");
        let mut retained_bytes = 0;
        let mut retained_rows = 0;
        for selected in &scope.rooms {
            let result = self.diagnostic_room(grant, selected).await;
            let mut source = result.unwrap_or_else(|_| {
                json!({"source":"coord","room_id":selected.room_id,"status":"unavailable","rows":[],
                "limitations":["selected Coord source unavailable; this is not empty history"]})
            });
            if let Some(rows) = source["rows"].as_array_mut() {
                let before = rows.len();
                rows.retain(|row| {
                    let size = row.to_string().len();
                    if retained_rows >= 2000 || retained_bytes + size > 3 * 1024 * 1024 {
                        return false;
                    }
                    retained_rows += 1;
                    retained_bytes += size;
                    true
                });
                if rows.len() < before {
                    source["status"] = json!("limited");
                    source["collection_limit_reached"] = json!(true);
                }
            }
            sources.push(source);
        }
        if scope.system_categories.iter().any(|s| s == "coord_health") {
            sources.push(match self.diagnostics().await {
                Ok(health)=> {
                    let mut projection=json!({});
                    for field in ["local_connection","owner_federation_connection"] {
                        projection[field]=match health[field].as_str() {
                            Some("Connected")=>json!("connected"),
                            Some("Disconnected")=>json!("disconnected"),
                            Some("Pending")=>json!("pending"),
                            _=>json!("not_observed"),
                        };
                    }
                    let outbox:Vec<_>=health["outbox"].as_array().into_iter().flatten().filter_map(|destination| {
                        let name=destination["destination"].as_str()?;
                        if !matches!(name,"audit-jsonl"|"attention-nats"|"federation-nats") {return None;}
                        let mut result=json!({"destination":name});
                        for key in ["retained_rows","pending","oldest_pending_age_ms","failed_pending","attempts"] {
                            if destination[key].is_number() || destination[key].is_null() {result[key]=destination[key].clone();}
                        }
                        Some(result)
                    }).collect();
                    projection["outbox"]=json!(outbox);
                    json!({"source":"coord_health","status":"observed","rows":[{"source":"coord_health","record":{"ts":now_iso(),"observation":projection}}],
                        "limitations":["current component observation; endpoints, broker credentials and nested operational references are excluded"]})
                },
                Err(_)=>json!({"source":"coord_health","status":"unavailable","rows":[]}),
            });
        }
        sources
    }

    async fn diagnostic_room(
        &self,
        grant: &Grant,
        selected: &crate::policy::support::diagnostics::Room,
    ) -> Result<Value, crate::Error> {
        let scope = grant.diagnostics.as_ref().unwrap();
        let db = self.owner.data_dir.join("v0.db");
        let conn = open_db(&db, false).map_err(|_| "Coord source unavailable")?;
        let room: String = conn.query_row(
            "SELECT name FROM rooms WHERE room_id=?1",
            [&selected.room_id],
            |r| r.get(0),
        )?;
        let mut rows = Vec::new();
        let mut row_bytes = 0;
        let mut limitations = Vec::new();
        if selected.membership {
            let members:Vec<_> = crate::coord_rooms::membership::effective(&conn, &selected.room_id)?.into_iter().map(|m|json!({"participant":m.participant,"granted_at":m.granted_at,"receive_generations":m.receive_generations})).collect();
            rows.push(json!({"source":"coord_membership","room_id":selected.room_id,"record":{"ts":now_iso(),"members":members}}));
            limitations.push(
                "membership is current effective authority, not historical membership".to_owned(),
            );
        }
        if selected.attention {
            // No attention object resolver and no impersonated recipient. The
            // projection contains only delivery references in selected rooms.
            for subject in &grant.targets {
                let mut statement=conn.prepare("SELECT feed_sequence,attention_id,kind,object_id,revision_or_sequence,created_at FROM coord_attention_edges WHERE recipient_agent_id=?1 AND room_id=?2 ORDER BY feed_sequence DESC LIMIT 201")?;
                let edges=statement.query_map(params![subject.agent_id,selected.room_id],|r|Ok(json!({"feed_sequence":r.get::<_,i64>(0)?,"attention_id":r.get::<_,String>(1)?,"kind":r.get::<_,String>(2)?,"object_id":r.get::<_,String>(3)?,"revision_or_sequence":r.get::<_,i64>(4)?,"created_at":r.get::<_,i64>(5)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
                if edges.len() > 200 {
                    limitations.push(
                        "selected attention projection exceeded 200 references per recipient"
                            .into(),
                    );
                }
                for edge in edges.into_iter().take(200) {
                    let Some(ts) = edge["created_at"]
                        .as_i64()
                        .and_then(|t| {
                            OffsetDateTime::from_unix_timestamp_nanos(i128::from(t) * 1_000_000)
                                .ok()
                        })
                        .and_then(|t| t.format(&Rfc3339).ok())
                    else {
                        continue;
                    };
                    if scope.contains_time(&ts) {
                        rows.push(json!({"source":"coord_attention","subject_id":subject.agent_id,"room_id":selected.room_id,"record":{"ts":ts,"delivery":edge}}));
                    }
                }
                limitations.push("attention references record projected delivery, not application consumption; the recipient's harness cursor is not stored by this source".into());
            }
        }
        drop(conn);
        if selected.history {
            let connection = self
                .client()
                .await
                .map_err(|_| "Coord history transport unavailable")?;
            let mut stream = jetstream::new(connection)
                .get_stream(room_stream(&selected.room_id))
                .await?;
            let (first, last) = {
                let state = &stream.info().await?.state;
                (state.first_sequence, state.last_sequence)
            };
            if first > 1 {
                limitations.push("room retention has pruned earlier history".into());
            }
            let start = first.max(last.saturating_sub(199));
            if start > first {
                limitations.push(
                    "room history search was limited to its last 200 retained messages".into(),
                );
            }
            for sequence in start..=last {
                let raw = match stream.get_raw_message(sequence).await {
                    Ok(raw) => raw,
                    Err(_) => {
                        limitations
                            .push("a selected room message was lost during collection".into());
                        continue;
                    }
                };
                let envelope: Value = serde_json::from_slice(&raw.payload)?;
                let Some(ts) = envelope["sent_at"]
                    .as_i64()
                    .and_then(|t| {
                        OffsetDateTime::from_unix_timestamp_nanos(i128::from(t) * 1_000_000).ok()
                    })
                    .and_then(|t| t.format(&Rfc3339).ok())
                else {
                    limitations.push("a retained message has no usable timestamp".into());
                    continue;
                };
                if scope.contains_time(&ts) {
                    let row = json!({"source":"coord_history","room_id":selected.room_id,"record":{"ts":ts,"sequence":sequence,"envelope":envelope}});
                    let size = row.to_string().len();
                    if row_bytes + size <= 3 * 1024 * 1024 {
                        row_bytes += size;
                        rows.push(row);
                    } else {
                        limitations
                            .push("room history result exceeded the collection byte limit".into());
                    }
                }
            }
        }
        limitations.sort();
        limitations.dedup();
        Ok(
            json!({"source":"coord","room_id":selected.room_id,"room_name":room,"status":if limitations.is_empty(){"complete_retained_search"}else{"limited"},"rows":rows,"limitations":limitations}),
        )
    }
}

fn now_iso() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("UTC timestamp")
}
