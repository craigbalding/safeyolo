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
    let fields = [
        "work_id",
        "after",
        "state",
        "limit",
        "attestations",
        "outputs",
        "reviews",
        "version",
    ]
    .map(|key| query_parameter(request.path_and_query, key));
    let [
        Ok(work_id),
        Ok(after),
        Ok(state),
        Ok(limit),
        Ok(attestations),
        Ok(outputs),
        Ok(reviews),
        Ok(version),
    ] = fields
    else {
        return response(400, json!({"error":"invalid work query"}));
    };
    let after = after.unwrap_or_default();
    let attestations = match attestations.as_deref() {
        None | Some("false") => false,
        Some("true") if work_id.is_some() => true,
        _ => {
            return response(
                400,
                json!({"error":"attestations must be true or false; true requires work_id"}),
            );
        }
    };
    let outputs = match outputs.as_deref() {
        None | Some("false") => false,
        Some("true") if work_id.is_some() && !attestations => true,
        _ => {
            return response(
                400,
                json!({"error":"outputs must be true or false; true requires work_id and excludes attestations"}),
            );
        }
    };
    let after_version = if outputs {
        match after.parse::<i64>() {
            Ok(v) => v,
            Err(_) if after.is_empty() => 0,
            Err(_) => return response(400, json!({"error":"invalid output after version"})),
        }
    } else {
        0
    };
    let reviews = match reviews.as_deref() {
        None | Some("false") => false,
        Some("true") if work_id.is_some() && !outputs && !attestations => true,
        _ => {
            return response(
                400,
                json!({"error":"reviews=true requires work_id and excludes outputs/attestations"}),
            );
        }
    };
    let version = match version {
        None => None,
        Some(v) if work_id.is_some() && !outputs && !attestations && !reviews => {
            match v.parse::<i64>() {
                Ok(v) if v > 0 => Some(v),
                _ => return response(400, json!({"error":"version must be positive"})),
            }
        }
        _ => {
            return response(
                400,
                json!({"error":"version requires a single work revision read"}),
            );
        }
    };
    let limit = match limit.as_deref().unwrap_or("50").parse::<usize>() {
        Ok(value) => value,
        Err(_) => return response(400, json!({"error":"invalid work page limit"})),
    };
    let db = client.owner.data_dir.join("v0.db");
    let room = room.to_owned();
    let principal = principal.to_owned();
    let remote = client.remote.clone();
    let caller = client.clone();
    let result = tokio::task::spawn_blocking(move || {
        caller
            .bound_current()
            .map_err(|_| work::WorkError(403, "requester run changed".into()))?;
        let mut conn = open_db(&db, mutation.is_some())
            .map_err(|_| work::WorkError(503, "work store unavailable".into()))?;
        let actor = remote
            .as_ref()
            .map_or(Actor::Agent(&principal), Actor::Remote);
        match mutation {
            Some((mutation, operation)) => {
                work::mutate(&mut conn, &room, actor, mutation, operation.as_deref())
            }
            None => match work_id {
                Some(id) if reviews => {
                    work::reviews::list(&mut conn, &room, actor, &id, &after, limit)
                }
                Some(id) if version.is_some() => {
                    work::read_at_version(&mut conn, &room, actor, &id, version.unwrap())
                }
                Some(id) if outputs => {
                    work::outputs::list(&mut conn, &room, actor, &id, after_version, limit)
                }
                Some(id) if attestations => {
                    work::attestations::list(&mut conn, &room, actor, &id, &after, limit)
                }
                Some(id) => work::read(&mut conn, &room, actor, &id),
                None => work::list(&mut conn, &room, actor, &after, limit, state.as_deref()),
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
