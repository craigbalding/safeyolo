use std::{net::SocketAddr, path::Path, process::Command};

use safeyolo_proxy::admin_shield::{AdminShield, ConfigError, REJECTION, targets_listener};
use serde_json::{Value, json};

fn fixture() -> Value {
    serde_json::from_str(include_str!("admin_shield_source.json")).unwrap()
}

fn port(value: &Value) -> u16 {
    u16::try_from(value.as_u64().unwrap()).unwrap()
}

fn compare_row(row: &Value) {
    let shield = AdminShield::new(port(&row["admin_port"]), row["extras"].as_str().unwrap());
    if row.get("error").is_some() {
        assert_eq!(row["error"], "ValueError");
        assert!(
            shield.is_err(),
            "source-invalid extra-port candidate accepted"
        );
        return;
    }
    let Ok(shield) = shield else {
        // Source hooks now retain the configured admin-port check if an extra
        // entry cannot be parsed. Native rejects that configuration earlier.
        assert_eq!(row["host"], "localhost");
        assert_eq!(row["blocked"], row["port"] == row["admin_port"]);
        return;
    };
    let blocked =
        shield.blocks_request_destination(row["host"].as_str().unwrap(), port(&row["port"]));
    assert_eq!(blocked, row["blocked"].as_bool().unwrap());
    if blocked {
        assert_eq!(row["response"]["status"], REJECTION.status);
        let body: String = REJECTION.body.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(row["response"]["body_hex"], body);
        let mut headers: Vec<_> = REJECTION
            .headers
            .iter()
            .map(|(name, value)| json!([name, value]))
            .collect();
        // Framing is the caller's responsibility, not a second response body.
        headers.push(json!(["content-length", REJECTION.body.len().to_string()]));
        assert_eq!(row["response"]["headers"], json!(headers));
        assert_eq!(row["metadata"]["blocked_by"], REJECTION.blocked_by);
        assert_eq!(row["metadata"]["block_reason"], REJECTION.block_reason);
    } else {
        assert_eq!(row["metadata"], json!({}));
        if row["prior"] == true {
            // This decision leaves a prior response to the caller; a shield
            // rejection above overrides the source's prior response instead.
            assert_eq!(row["response"]["status"], 418);
        } else {
            assert!(row["response"].is_null());
        }
    }
}

fn compare_rows(source: &Value) {
    for row in source["hooks"].as_array().unwrap() {
        compare_row(row);
    }
    for row in source["forms"].as_array().unwrap() {
        assert_eq!(row["extracted_host"], row["observation"]["host"]);
        assert_eq!(row["extracted_port"], row["observation"]["port"]);
        compare_row(&row["observation"]);
    }
    let shield = AdminShield::new(9090, "").unwrap();
    for row in source["server_hooks"].as_array().unwrap() {
        let blocked = row["address"].as_array().is_some_and(|address| {
            shield.blocks_request_destination(address[0].as_str().unwrap(), port(&address[1]))
        });
        assert_eq!(
            row["error"],
            blocked
                .then_some(REJECTION.transport_error)
                .map_or(Value::Null, |message| json!(message))
        );
    }
}

#[test]
fn source_request_connect_url_forms_and_transport_rejection_match() {
    let source = fixture();
    assert_eq!(source["hooks"].as_array().unwrap().len(), 120);
    assert_eq!(source["forms"].as_array().unwrap().len(), 10);
    assert_eq!(source["server_hooks"].as_array().unwrap().len(), 5);
    compare_rows(&source);
}

#[test]
fn extra_port_grammar_preserves_ignored_and_out_of_range_settings() {
    let shield = AdminShield::new(9090, "65536,99999999999999999999999999,0,0009091").unwrap();
    assert!(shield.blocks_host("localhost", 9091));
    assert!(shield.blocks_host("localhost", 0));
    assert!(shield.blocks_host("localhost", 9090));
    assert!(!shield.blocks_host("localhost", 65535));
    let ignored = AdminShield::new(9090, "-1,+9091,909_1,²x,½,Ⅻ,junk,,").unwrap();
    assert!(!ignored.blocks_host("localhost", 9091));
    assert_eq!(
        AdminShield::new(9090, "²").unwrap_err(),
        ConfigError::NonDecimalDigit
    );
    assert_eq!(
        AdminShield::new(9090, &"0".repeat(4301)).unwrap_err(),
        ConfigError::IntegerDigitLimit
    );
    assert!(AdminShield::new(9090, &"0".repeat(4300)).is_ok());
}

#[test]
fn bound_endpoint_check_covers_only_the_actual_listener() {
    let bound: SocketAddr = "127.0.0.1:43210".parse().unwrap();
    for selected in [
        "127.0.0.1:43210",
        "[::ffff:127.0.0.1]:43210",
        "0.0.0.0:43210",
    ] {
        assert!(targets_listener(selected.parse().unwrap(), bound));
    }
    for selected in [
        "127.0.0.1:43211",
        "127.0.0.2:43210",
        "[::1]:43210",
        "[::]:43210",
        "203.0.113.8:43210",
        "[2001:db8::1]:43210",
    ] {
        assert!(!targets_listener(selected.parse().unwrap(), bound));
    }
    let mapped_bound = "[::ffff:127.0.0.1]:43210".parse().unwrap();
    assert!(targets_listener(bound, mapped_bound));
    let other_bound = "127.0.0.2:43210".parse().unwrap();
    assert!(targets_listener(other_bound, other_bound));
    assert!(!targets_listener(
        "0.0.0.0:43210".parse().unwrap(),
        other_bound
    ));
}

#[test]
fn resolved_check_retains_dns_alias_protection_and_bound_port_witnesses() {
    let source = fixture();
    let transport = &source["transport"];
    let bound = SocketAddr::new(
        transport["listener"][0].as_str().unwrap().parse().unwrap(),
        port(&transport["listener"][1]),
    );
    let shield = AdminShield::new(bound.port(), "").unwrap();
    let mut source_alias_reaches = 0;
    for row in transport["cases"].as_array().unwrap() {
        let host = row["host"].as_str().unwrap();
        assert_eq!(
            shield.blocks_request_destination(host, port(&row["port"])),
            row["ingress_blocked"].as_bool().unwrap()
        );
        if row["owned_accepts"] == 1 {
            source_alias_reaches += 1;
            assert_eq!(row["ingress_blocked"], false);
            assert!(row["server_error"].is_null());
            assert!(targets_listener(
                SocketAddr::new(
                    row["peer"][0].as_str().unwrap().parse().unwrap(),
                    port(&row["peer"][1])
                ),
                bound
            ));
            let selected_ip = match host {
                "alias-unspecified.invalid" => "0.0.0.0",
                "::ffff:127.0.0.1" => "::ffff:127.0.0.1",
                _ => "127.0.0.1",
            };
            assert!(targets_listener(
                SocketAddr::new(selected_ip.parse().unwrap(), bound.port()),
                bound
            ));
            let events = row["events"].as_array().unwrap();
            assert_eq!(events[0], "ServerConnectHook");
            assert!(events.iter().any(|event| event == "ServerConnectedHook"));
        }
    }
    assert_eq!(source_alias_reaches, 2);
    for label in [
        "changed_option_old_bound_port",
        "configured_zero_actual_ephemeral_port",
    ] {
        let row = &transport[label];
        assert_eq!(row["blocked"], true);
        assert!(
            AdminShield::new(bound.port(), "")
                .unwrap()
                .blocks_request_destination(row["host"].as_str().unwrap(), bound.port())
        );
        assert!(targets_listener(bound, bound));
    }
}

#[test]
fn malformed_extra_candidate_has_distinct_source_and_native_failure_boundaries() {
    let source: Value =
        serde_json::from_str(include_str!("admin_shield_failure_source.json")).unwrap();
    let cases = source["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    for row in cases {
        assert_eq!(row["ingress_blocked"], true);
        assert_eq!(row["owned_accepts"], 0);
        assert_eq!(row["server_error"], REJECTION.transport_error);
        assert!(AdminShield::new(port(&row["port"]), row["extras"].as_str().unwrap()).is_err());
    }
}

#[test]
fn configured_extra_ports_reject_source_alias_reach_with_exact_local_ip_scope() {
    let source: Value =
        serde_json::from_str(include_str!("admin_shield_extra_source.json")).unwrap();
    let row = &source["cases"][0];
    let protected = port(&row["port"]);
    let admin = port(&source["configured_admin_port"]);
    assert_ne!(protected, admin);
    assert_eq!(row["extras"], protected.to_string());
    assert_eq!(row["ingress_blocked"], false);
    assert!(row["server_error"].is_null());
    assert_eq!(row["owned_accepts"], 1);
    let shield = AdminShield::new(admin, row["extras"].as_str().unwrap()).unwrap();
    assert!(shield.protects_port(admin));
    assert!(shield.protects_port(protected));
    assert!(!shield.blocks_host(row["host"].as_str().unwrap(), protected));
    assert!(shield.blocks_address(SocketAddr::new(
        row["peer"][0].as_str().unwrap().parse().unwrap(),
        protected,
    )));
    let unrelated = (1..=u16::MAX)
        .find(|candidate| *candidate != admin && *candidate != protected)
        .unwrap();
    assert!(!shield.protects_port(unrelated));
    for ip in [
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "::ffff:127.0.0.1",
        "::ffff:0.0.0.0",
    ] {
        assert!(shield.blocks_address(SocketAddr::new(ip.parse().unwrap(), protected)));
        assert!(!shield.blocks_address(SocketAddr::new(ip.parse().unwrap(), unrelated)));
    }
    for ip in [
        "127.0.0.2",
        "::ffff:127.0.0.2",
        "203.0.113.8",
        "::",
        "2001:db8::1",
    ] {
        assert!(!shield.blocks_address(SocketAddr::new(ip.parse().unwrap(), protected)));
    }
}

#[test]
#[ignore = "requires the pinned source Python environment"]
fn live_python_source_hook_and_scalar_oracle() {
    let python = std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON");
    let output = Command::new(python)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/admin_shield_oracle.py"))
        .arg("--rows")
        .output()
        .unwrap();
    assert!(output.status.success(), "source shield oracle failed");
    let live: Value = serde_json::from_slice(&output.stdout).unwrap();
    let frozen = fixture();
    for key in [
        "hooks",
        "forms",
        "server_hooks",
        "nondecimal_digit_ranges",
        "nondecimal_digit_all_scalars_sha256",
    ] {
        assert_eq!(
            live[key], frozen[key],
            "source shield contract changed: {key}"
        );
    }
    compare_rows(&live);
}
