use super::*;

fn healthy() -> Value {
    let mut steps: Vec<_> = REQUEST_CONTROLS
        .iter()
        .map(|control| {
            json!({
                "control":control_label(control), "hook":"request", "state":"evaluated",
                "outcome":"allowed", "duration_us":1
            })
        })
        .collect();
    steps.push(json!({"control":"probe-sink", "hook":"request", "state":"evaluated", "outcome":"probe_terminated"}));
    json!({"agent_id":"alice", "request_id":"owned", "truncated":false,
        "incomplete":false, "steps":steps, "not_loaded":[]})
}

fn verdict(trace: &Value) -> Value {
    classify(trace, "alice", "owned")["verdict"].clone()
}

#[test]
fn doctor_uses_first_request_observations_and_all_error_observations() {
    let mut trace = healthy();
    assert_eq!(verdict(&trace), "pass");
    let duplicate = trace["steps"][0].clone();
    trace["steps"].as_array_mut().unwrap().push(duplicate);
    trace["steps"].as_array_mut().unwrap().push(
        json!({"control":"extra", "hook":"request", "state":"evaluated", "outcome":"observed"}),
    );
    assert_eq!(verdict(&trace), "pass");
    trace["steps"].as_array_mut().unwrap().push(
        json!({"control":"extra", "hook":"response", "state":"error", "reason":"OwnedFailure"}),
    );
    assert_eq!(verdict(&trace), "fail");
    trace = healthy();
    trace["steps"].as_array_mut().unwrap().swap(0, 1);
    assert_eq!(verdict(&trace), "fail");
}

#[test]
fn doctor_distinguishes_disabled_preempted_absent_failed_and_incomplete() {
    for reason in ["control_disabled", "policy_disabled"] {
        let mut trace = healthy();
        trace["steps"][2] =
            json!({"control":"credentials", "hook":"request", "state":"bypassed", "reason":reason});
        assert_eq!(verdict(&trace), "pass", "{reason}");
    }
    let mut trace = healthy();
    trace["steps"][2] = json!({"control":"credentials", "hook":"request", "state":"bypassed", "reason":"prior_response", "details":{"preempted_by":"network"}});
    let result = classify(&trace, "alice", "owned");
    assert_eq!(result["verdict"], "warn");
    assert!(result.to_string().contains("earlier response"));
    for state in ["not_loaded", "error", "unknown"] {
        let mut trace = healthy();
        trace["steps"][2]["state"] = json!(state);
        assert_eq!(verdict(&trace), "fail", "{state}");
    }
    for flag in ["truncated", "incomplete"] {
        let mut trace = healthy();
        trace[flag] = json!(true);
        assert_eq!(verdict(&trace), "fail", "{flag}");
    }
    for field in ["steps", "agent_id", "request_id", "truncated", "incomplete"] {
        let mut trace = healthy();
        trace.as_object_mut().unwrap().remove(field);
        assert_eq!(verdict(&trace), "fail", "{field}");
    }
    let mut trace = healthy();
    trace["steps"].as_array_mut().unwrap().remove(2);
    let result = classify(&trace, "alice", "owned");
    assert_eq!(result["verdict"], "fail");
    assert!(result.to_string().contains("no request execution evidence"));
    trace["not_loaded"] = json!([{"control":"credentials", "state":"not_loaded"}]);
    assert!(
        classify(&trace, "alice", "owned")
            .to_string()
            .contains("credentials: not loaded")
    );
}
