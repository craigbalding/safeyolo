//! Native work uses the existing checkpoint and canonical operation receipts.
use super::*;
use crate::coord_rooms::work::actions::Action;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Delivery {
    pub room_name: String,
    pub source_attention_id: String,
    pub action: Action,
}

impl Supervisor {
    async fn native_actions(
        &self,
        room: &str,
        work: &str,
        received: bool,
    ) -> Result<Vec<Action>, Error> {
        let result = self
            .client
            .call(
                "read_work_actions",
                &json!({"room_name":room,"work_id":work,"include_received":received}),
            )
            .await?;
        if result["source_work_id"] != work {
            return Err("mismatched native action source".into());
        }
        Ok(serde_json::from_value(result["actions"].clone())?)
    }

    pub(super) async fn stage_native_page(
        &mut self,
        page: &Value,
        rooms: &BTreeMap<String, String>,
    ) -> Result<(usize, bool), Error> {
        if !self.config.native_work {
            return Ok((0, true));
        }
        let mut candidate = self.state.clone();
        let mut added = 0;
        let mut complete = true;
        let objects = page["objects"]
            .as_array()
            .filter(|o| o.len() <= self.config.page_limit)
            .ok_or("invalid resolved attention page")?;
        let reserved_messages = objects
            .iter()
            .filter(|r| r["edge"]["kind"] == "message")
            .count();
        for resolved in objects {
            let edge = &resolved["edge"];
            if edge["kind"] != "work_changed" {
                continue;
            }
            let Some(room) = rooms.get(text(edge, "room_id")?) else {
                continue;
            };
            let source = &resolved["object"];
            if source["room_id"] != edge["room_id"]
                || source["work_id"] != edge["object_id"]
                || source["version"] != edge["revision_or_sequence"]
            {
                return Err("mismatched native work attention".into());
            }
            let attention = text(edge, "attention_id")?;
            if !attention_id(attention) {
                return Err("invalid native attention ID".into());
            }
            for action in self
                .native_actions(room, text(source, "work_id")?, false)
                .await?
            {
                if candidate
                    .native_in_flight
                    .iter()
                    .any(|d| d.action.key == action.key)
                {
                    continue;
                }
                if candidate.in_flight.len() + candidate.native_in_flight.len() + reserved_messages
                    >= MAX_PENDING
                {
                    // Keep the source cursor until the rest can be checkpointed.
                    // Already staged receipts exclude just this batch on retry.
                    complete = false;
                    break;
                }
                candidate.native_in_flight.push(Delivery {
                    room_name: room.clone(),
                    source_attention_id: attention.into(),
                    action,
                });
                added += 1;
            }
        }
        if added > 0 && candidate.phase != "uncertain" {
            candidate.phase = "accepted".into();
        }
        // This precedes the canonical receipt and the attention cursor commit.
        candidate.save(&self.state_path)?;
        self.state = candidate;
        Ok((added, complete))
    }

    pub(super) async fn reconcile_native(&mut self) -> Result<(), Error> {
        if !self.config.native_work && !self.state.native_in_flight.is_empty() {
            return Err("native work is pending; preserve native_work configuration while recovering its checkpoint".into());
        }
        for delivery in self.state.native_in_flight.clone() {
            if !self.config.rooms.contains(&delivery.room_name) {
                return Err("native work room was removed; recover the existing assignment before changing rooms".into());
            }
            let actions = self
                .native_actions(&delivery.room_name, &delivery.action.work_id, true)
                .await?;
            let Some(current) = actions.into_iter().find(|a| a.key == delivery.action.key) else {
                // Completed, cancelled, reassigned or superseded at its authority.
                self.state
                    .native_in_flight
                    .retain(|d| d.action.key != delivery.action.key);
                self.state.save(&self.state_path)?;
                continue;
            };
            let index = self
                .state
                .native_in_flight
                .iter()
                .position(|d| d.action.key == current.key)
                .unwrap();
            self.state.native_in_flight[index].action = current.clone();
            self.state.save(&self.state_path)?;
            if let Err(error) = self.client.call("receive_work_action", &json!({"room_name":delivery.room_name,"work_id":current.work_id,"action_key":current.key})).await {
                // A concurrent authority transition can retire an action between
                // query and receipt. An ambiguous receipt retries the same key.
                if self.native_actions(&delivery.room_name, &current.work_id, true).await?.iter().any(|a|a.key == current.key) {
                    return Err(error);
                }
                self.state.native_in_flight.retain(|d|d.action.key != current.key);
                self.state.save(&self.state_path)?;
            }
        }
        Ok(())
    }
}
