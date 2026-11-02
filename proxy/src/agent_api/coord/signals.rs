//! Authenticated material signals use the owning room's transactional core.
use super::*;
use crate::coord_rooms::{
    signals::{self, Mutation, SignalError},
    work::Actor,
};

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
                    json!({"error":format!("invalid signal mutation: {error}")}),
                );
            }
        };
        Some((mutation, operation))
    } else {
        None
    };
    let fields = [
        "signal_id",
        "revision",
        "after",
        "limit",
        "state",
        "needs_operator",
    ]
    .map(|key| query_parameter(request.path_and_query, key));
    let [
        Ok(id),
        Ok(revision),
        Ok(after),
        Ok(limit),
        Ok(state),
        Ok(needs),
    ] = fields
    else {
        return response(400, json!({"error":"invalid signal query"}));
    };
    let revision = match revision.map(|r| r.parse::<i64>()).transpose() {
        Ok(value) if value.is_none_or(|r| r > 0) => value,
        _ => return response(400, json!({"error":"revision must be positive"})),
    };
    let limit = match limit.as_deref().unwrap_or("50").parse::<usize>() {
        Ok(value) => value,
        Err(_) => return response(400, json!({"error":"invalid signal page limit"})),
    };
    let needs = match needs.as_deref() {
        None | Some("false") => false,
        Some("true") => true,
        _ => return response(400, json!({"error":"needs_operator must be true or false"})),
    };
    let db = client.owner.data_dir.join("v0.db");
    let room = room.to_owned();
    let principal = principal.to_owned();
    let remote = client.remote.clone();
    let caller = client.clone();
    let result = tokio::task::spawn_blocking(move || {
        caller
            .bound_current()
            .map_err(|_| SignalError(403, "requester run changed".into()))?;
        let mut conn = open_db(&db, mutation.is_some())
            .map_err(|_| SignalError(503, "signal store unavailable".into()))?;
        let actor = remote
            .as_ref()
            .map_or(Actor::Agent(&principal), Actor::Remote);
        match mutation {
            Some((mutation, operation)) => {
                signals::mutate(&mut conn, &room, actor, mutation, operation.as_deref())
            }
            None => match id {
                Some(id) => signals::read(&mut conn, &room, actor, &id, revision),
                None => signals::list(
                    &mut conn,
                    &room,
                    actor,
                    after.as_deref().unwrap_or(""),
                    limit,
                    state.as_deref(),
                    needs,
                ),
            },
        }
    })
    .await;
    match result {
        Ok(Ok(value)) => response(200, value),
        Ok(Err(error)) => response(error.0, json!({"error":error.1})),
        Err(_) => response(503, json!({"error":"signal store unavailable"})),
    }
}

// The authenticated Admin listener is the operator boundary. It returns only
// metadata in lists; watch must fetch the requested immutable revision.
pub(crate) async fn operator_read(
    state: &crate::RuntimeState,
    id: Option<String>,
    revision: Option<i64>,
    after: String,
    limit: usize,
    room_id: Option<String>,
) -> Result<Value, SignalError> {
    let db = state
        .read()
        .map_err(|_| SignalError(503, "runtime unavailable".into()))?
        .coord
        .owner
        .data_dir
        .join("v0.db");
    tokio::task::spawn_blocking(move || {
        let mut conn =
            open_db(&db, false).map_err(|_| SignalError(503, "signal store unavailable".into()))?;
        let tx = conn.transaction()?;
        if let Some(id) = id {
            let rev = revision
                .ok_or_else(|| SignalError(400, "an exact signal revision is required".into()))?;
            signals::revision(&tx, room_id.as_deref(), &id, rev)
        } else {
            signals::page(
                &tx,
                room_id.as_deref(),
                &after,
                limit,
                Some("current"),
                true,
                true,
            )
        }
    })
    .await
    .map_err(|_| SignalError(503, "signal store unavailable".into()))?
}
