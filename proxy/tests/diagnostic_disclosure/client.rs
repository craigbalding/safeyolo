//! Exercise the advertised arguments through the native tool and HTTP owner.
use super::*;
use safeyolo_proxy::coord_tools::Client;

fn client(f: &Fixture) -> Client {
    Client {
        socket: Some(f.root.path().join("helper.sock")),
        token_file: f.root.path().join("data/agent_token"),
        home: None,
    }
}

#[tokio::test]
async fn nullable_history_lifetimes_and_run_maps_reach_the_approval_owner() {
    let f = Fixture::with_installed_settings().await;
    let _runs = runs(&f);
    let client = client(&f);
    for (index, snapshot, expiry, since, selected_runs) in [
        (0, false, Value::Null, Value::Null, None),
        (
            1,
            false,
            json!(timestamp(3600)),
            json!(timestamp(-60)),
            Some(json!({})),
        ),
        (
            2,
            true,
            Value::Null,
            Value::Null,
            Some(json!({(HELPER_ID):[RUN]})),
        ),
    ] {
        let mut input = request(&format!("native-request-{index}"), snapshot, vec!["helper"]);
        input["expires_at"] = expiry;
        input["scope"]["history"]["since"] = since;
        if let Some(selected_runs) = selected_runs {
            input["scope"]["runs"] = selected_runs;
        }
        let pending = client
            .call("request_diagnostic_access", &input)
            .await
            .unwrap();
        assert_eq!(pending["status"], "pending");
        let grant = &pending["action"]["grant"];
        assert_eq!(grant["expires_at"], input["expires_at"]);
        assert_eq!(grant["diagnostics"]["history"], input["scope"]["history"]);
        assert_eq!(
            grant["diagnostics"]["runs"],
            input["scope"].get("runs").cloned().unwrap_or(json!({}))
        );
        let id = pending["approval_id"].as_str().unwrap();
        assert!(
            client
                .call(
                    "query_diagnostic_evidence",
                    &json!({"operation_id":"pending","grant":id,"page_token":null})
                )
                .await
                .is_err()
        );
        approve(&f, id).await;
        let decision = client
            .call("read_approval", &json!({"approval_id":id}))
            .await
            .unwrap();
        assert_eq!(decision["status"], "approved");
        let result = client
            .call(
                "query_diagnostic_evidence",
                &json!({"operation_id":"approved","grant":id,"page_token":null}),
            )
            .await
            .unwrap();
        assert_eq!(result["applied_scope"]["diagnostics"], grant["diagnostics"]);
    }

    // Invalid declared types/unknown fields stay local refusals. Semantic
    // timestamp/run/instance validation still belongs to the HTTP owner.
    for (path, value, local) in [
        ("/expires_at", json!(42), true),
        ("/scope/history/since", json!([]), true),
        ("/scope/history/until", json!(true), true),
        ("/scope/runs", json!({(HELPER_ID):[42]}), true),
        ("/scope", json!({"unexpected":true}), true),
        ("/expires_at", json!("invalid-time"), false),
        (
            "/instance_id",
            json!("sy-00000000000000000000000000000000"),
            false,
        ),
        ("/scope/runs", json!({(HELPER_ID):["invalid-run"]}), false),
    ] {
        let mut input = request("invalid-native-request", false, vec!["helper"]);
        input["scope"]["runs"] = json!({});
        *input.pointer_mut(path).unwrap() = value;
        let error = client
            .call("request_diagnostic_access", &input)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            error.contains("invalid type or value"),
            local,
            "{path}: {error}"
        );
        if !local {
            assert!(error.starts_with("API 400"), "{error}");
        }
    }
    let mut missing = request("missing-native-request", false, vec!["helper"]);
    missing.as_object_mut().unwrap().remove("scope");
    assert!(
        client
            .call("request_diagnostic_access", &missing)
            .await
            .unwrap_err()
            .to_string()
            .contains("missing argument")
    );
    f.stop().await;
}

#[tokio::test]
async fn optional_query_filters_and_page_tokens_preserve_values_and_records() {
    let f = Fixture::with_installed_settings().await;
    let _runs = runs(&f);
    let client = client(&f);
    assert_eq!(f.network("worker", f.address).await.status, 428);
    assert_eq!(f.network("helper", f.address).await.status, 428);
    let pending = client
        .call(
            "request_diagnostic_access",
            &request("native-filters", true, vec!["helper", "worker"]),
        )
        .await
        .unwrap();
    let id = pending["approval_id"].as_str().unwrap();
    approve(&f, id).await;
    let base = json!({"operation_id":"native-query","grant":id,"limit":200});
    let all = client
        .call("query_diagnostic_evidence", &base)
        .await
        .unwrap();
    let row = all["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["record"]["event"] == "traffic.response" && row["subject_id"] == WORKER_ID)
        .unwrap();
    let runtime = &row["record"]["details"]["runtime_id"];
    assert!(runtime.is_string(), "{row}");
    for filter in [
        json!({}),
        json!({"sources":["audit"]}),
        json!({"failures_only":true}),
        json!({"run_id":RUN,"subject_ids":[WORKER_ID]}),
        json!({"runtime_id":runtime,"request_id":row["record"]["request_id"]}),
    ] {
        let mut input = base.clone();
        input["filter"] = filter.clone();
        let result = client
            .call("query_diagnostic_evidence", &input)
            .await
            .unwrap();
        for (key, value) in filter.as_object().unwrap() {
            assert_eq!(&result["filter"][key], value);
        }
        assert!(!result["rows"].as_array().unwrap().is_empty(), "{result}");
        for returned in result["rows"].as_array().unwrap() {
            assert!(all["rows"].as_array().unwrap().contains(returned));
            if filter.get("sources").is_some() {
                assert_eq!(returned["source"], "audit");
            }
            if filter["failures_only"] == true {
                assert!(
                    matches!(
                        returned["record"]["decision"].as_str(),
                        Some("deny" | "require_approval" | "budget_exceeded")
                    ) || matches!(
                        returned["record"]["severity"].as_str(),
                        Some("high" | "critical")
                    ),
                    "{returned}"
                );
            }
            if filter.get("request_id").is_some() {
                assert_eq!(returned["record"]["request_id"], filter["request_id"]);
                assert_eq!(returned["record"]["details"]["runtime_id"], *runtime);
            }
            if filter.get("run_id").is_some() {
                assert_eq!(returned["record"]["details"]["sandbox_run"]["run_id"], RUN);
                assert_eq!(returned["subject_id"], WORKER_ID);
            }
        }
    }
    let mut page = base.clone();
    page["limit"] = json!(1);
    page["page_token"] = Value::Null;
    let first = client
        .call("query_diagnostic_evidence", &page)
        .await
        .unwrap();
    assert!(first["next_page_token"].is_string());
    page["page_token"] = first["next_page_token"].clone();
    let next = client
        .call("query_diagnostic_evidence", &page)
        .await
        .unwrap();
    assert_eq!(next["offset"], 1);
    assert_eq!(next["rows"][0], all["rows"][1]);
    for (field, value, local) in [
        ("page_token", json!(4), true),
        ("filter", json!({"sources":"audit"}), true),
        ("filter", json!({"failures_only":"true"}), true),
        ("filter", json!({"unexpected":true}), true),
        (
            "filter",
            json!({"request_id":"no-runtime-namespace"}),
            false,
        ),
        ("filter", json!({"sources":["runtime"]}), false),
    ] {
        let mut input = base.clone();
        input[field] = value;
        let error = client
            .call("query_diagnostic_evidence", &input)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            error.contains("invalid type or value"),
            local,
            "{field}: {error}"
        );
        if !local {
            assert!(
                error.starts_with("API 400") || error.starts_with("API 403"),
                "{error}"
            );
        }
    }
    f.stop().await;
}
