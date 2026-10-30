//! Authenticated work requests use the same transactional core as the operator.
use super::*;
use crate::coord_rooms::work::{self, Actor, Mutation};

pub(super) async fn respond(
    request: Request<'_>,
    client: &CoordClient,
    room: &str,
    principal: &str,
    payload: Option<&[u8]>,
) -> Outcome<'static> {
    if !["GET", "POST"].contains(&request.method) {
        return response(
            405,
            json!({"error":"Method Not Allowed","allowed":["GET","POST"]}),
        );
    }
    let mutation = if request.method == "POST" {
        let Some(payload) = payload else {
            return response(400, json!({"error":"body required"}));
        };
        let Ok(Value::Object(mut document)) = serde_json::from_slice::<Value>(payload) else {
            return response(400, json!({"error":"JSON body must be an object"}));
        };
        let operation = match document.remove("operation_id") {
            None => None,
            Some(Value::String(id)) => Some(id),
            _ => return response(400, json!({"error":"operation_id must be a string"})),
        };
        let mutation = match serde_json::from_value::<Mutation>(Value::Object(document)) {
            Ok(value) => value,
            Err(error) => {
                return response(
                    400,
                    json!({"error":format!("invalid work mutation: {error}")}),
                );
            }
        };
        Some((mutation, operation))
    } else {
        None
    };
    let fields = ["work_id", "after", "state", "limit"]
        .map(|key| query_parameter(request.path_and_query, key));
    let [Ok(work_id), Ok(after), Ok(state), Ok(limit)] = fields else {
        return response(400, json!({"error":"invalid work query"}));
    };
    let after = after.unwrap_or_default();
    let limit = match limit.as_deref().unwrap_or("50").parse::<usize>() {
        Ok(value) => value,
        Err(_) => return response(400, json!({"error":"invalid work page limit"})),
    };
    let db = client.owner.data_dir.join("v0.db");
    let room = room.to_owned();
    let principal = principal.to_owned();
    let result = tokio::task::spawn_blocking(move || {
        let mut conn = open_db(&db, mutation.is_some())
            .map_err(|_| work::WorkError(503, "work store unavailable".into()))?;
        match mutation {
            Some((mutation, operation)) => work::mutate(
                &mut conn,
                &room,
                Actor::Agent(&principal),
                mutation,
                operation.as_deref(),
            ),
            None => match work_id {
                Some(id) => work::read(&mut conn, &room, Actor::Agent(&principal), &id),
                None => work::list(
                    &mut conn,
                    &room,
                    Actor::Agent(&principal),
                    &after,
                    limit,
                    state.as_deref(),
                ),
            },
        }
    })
    .await;
    match result {
        Ok(Ok(value)) => response(200, value),
        Ok(Err(error)) => response(error.0, json!({"error":error.1})),
        Err(_) => response(503, json!({"error":"work store unavailable"})),
    }
}
