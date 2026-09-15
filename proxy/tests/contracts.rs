use safeyolo_proxy::{contracts::*, services::ServiceDefinition};
use serde_json::{Value, json};

fn contract_document(transport: Value) -> Value {
    let mut request = json!({"method":"POST","path":"/items","query":{"allow":{"limit":{"integer_range":[1,100]},"name":{"equals_var":"approved"},"page":{"type":"string"}},"deny_unknown":true},"body":{"allow":{"name":{"equals_var":"approved"},"metadata":{"type":"string"}},"deny_unknown":true}});
    if !transport.is_null() {
        request["transport"] = transport;
    }
    json!({"schema_version":1,"name":"test-service","auth":{"type":"bearer","header":"X-Auth-Token"},"capabilities":{"test":{"routes":[{"methods":"*","path":"/**"}],"contract":{"template":"test.v1","bindings":{"approved":{"type":"string"}},"operations":[{"name":"write","request":request},{"name":"discover","request":{"method":"GET","path":"/discovery"}},{"name":"stateful","requires_enforcement":"state_enforcement","request":{"method":"GET","path":"/items/{id}","path_params":{"id":{"in_state_set":"ids"}}}}],"enforcement":{"request_shape":"enforced","transport_hygiene":"enforced","state_capture":"declared","state_enforcement":"declared","response_validators":"declared"}}}}})
}
fn binding() -> ContractBinding {
    serde_json::from_value(json!({"agent":"alice","service":"test-service","capability":"test","template":"test.v1","bound_values":{"approved":"chosen","approved_category_id":137,"approved_category":"CATEGORY_PROMOTIONS"},"grantable_operations":["write","discover","list_feeds","list_entries","create_feed","list_messages"]})).unwrap()
}
fn enforce(
    document: &Value,
    request: &Value,
    bound: bool,
) -> Result<CanonicalRequest, ContractDenial> {
    let service = ServiceDefinition::from_value(document.clone()).unwrap();
    let contract = service.capabilities[request["capability"].as_str().unwrap_or("test")]
        .contract
        .as_ref()
        .unwrap();
    let headers: Vec<(String, String)> =
        serde_json::from_value(request["headers"].clone()).unwrap();
    let body = request["body"].as_str().unwrap_or("").as_bytes();
    let mut state = binding();
    if let Some(value) = request.get("bound_value") {
        state.bound_values.insert("approved".into(), value.clone());
    }
    enforce_request(
        contract,
        bound.then_some(&state),
        service.auth.as_ref().unwrap().header.as_str(),
        ContractRequest {
            method: request["method"].as_str().unwrap(),
            target: request["target"].as_str().unwrap(),
            headers: &headers,
            body,
        },
    )
}
fn case(method: &str, target: &str, headers: Value, body: &str) -> Value {
    json!({"method":method,"target":target,"headers":headers,"body":body})
}
fn result_code(result: Result<CanonicalRequest, ContractDenial>) -> Value {
    match result {
        Ok(value) => json!({"allowed":true,"operation":value.operation}),
        Err(error) => json!({"allowed":false,"code":error.code}),
    }
}

#[test]
fn bound_request_checks_keep_failure_order_and_duplicate_json_detection() {
    use ContractCode::*;
    let document = contract_document(Value::Null);
    let cases = [
        (
            case("POST", "/items/../items", json!([]), ""),
            TransportPathTrick,
        ),
        (
            case(
                "POST",
                "/items",
                json!([["Accept", "a"], ["accept", "b"]]),
                "",
            ),
            TransportDuplicateHeader,
        ),
        (
            case("POST", "/items?limit=1&limit=2", json!([]), ""),
            TransportAmbiguousEncoding,
        ),
        (
            case("POST", "/items?_method=GET", json!([]), ""),
            TransportAmbiguousEncoding,
        ),
        (
            case(
                "POST",
                "/items",
                json!([["Content-Type", "text/plain"]]),
                "{}",
            ),
            TransportContentType,
        ),
        (
            case(
                "POST",
                "/items",
                json!([["Content-Type", "application/json"]]),
                "[]",
            ),
            ContractViolation,
        ),
        (
            case(
                "POST",
                "/items",
                json!([["Content-Type", "application/json"]]),
                r#"{"metadata":{"nested":1,"nested":2}}"#,
            ),
            TransportDuplicateJsonKey,
        ),
        (
            case(
                "POST",
                "/items?name=chosen",
                json!([["Content-Type", "application/json"]]),
                r#"{"name":"chosen"}"#,
            ),
            TransportCrossLocation,
        ),
        (
            case("POST", "/items", json!([["X-Extra", "1"]]), ""),
            TransportHeaderDenied,
        ),
        (
            case("POST", "/items?limit=101", json!([]), ""),
            ContractViolation,
        ),
        (
            case("POST", "/items?name=other", json!([]), ""),
            ContractViolation,
        ),
    ];
    for (request, expected) in cases {
        assert_eq!(
            enforce(&document, &request, true).unwrap_err().code,
            expected,
            "{request}"
        );
    }
    assert!(
        enforce(
            &document,
            &case("POST", "/items?limit=1_0", json!([]), ""),
            true
        )
        .is_ok()
    );
    assert!(
        enforce(
            &document,
            &case(
                "POST",
                "/items",
                json!([["Content-Type", "application/json; charset=utf-8"]]),
                r#"{"name":"chosen","metadata":{"nested":true}}"#
            ),
            true
        )
        .is_ok()
    );
}

#[test]
fn omitted_empty_and_explicit_header_policies_differ() {
    let request = case(
        "POST",
        "/items",
        json!([["Accept", "application/json"], ["User-Agent", "synthetic"]]),
        "",
    );
    assert!(enforce(&contract_document(Value::Null), &request, true).is_ok());
    assert!(
        enforce(
            &contract_document(json!({"allow_headers":[]})),
            &request,
            true
        )
        .is_err()
    );
    assert!(
        enforce(
            &contract_document(json!({"allow_headers":["Accept","User-Agent"]})),
            &request,
            true
        )
        .is_ok()
    );
    assert!(
        enforce(
            &contract_document(json!({"allow_headers":[]})),
            &case(
                "POST",
                "/items",
                json!([["X-Auth-Token", "sgw_synthetic"], ["Host", "example"]]),
                ""
            ),
            true
        )
        .is_ok()
    );
    for value in [Value::Null, json!("Accept"), json!([3])] {
        assert!(
            ServiceDefinition::from_value(contract_document(json!({"allow_headers":value})))
                .is_err()
        );
    }
}

#[test]
fn only_value_free_operations_work_before_binding_and_declared_state_stays_ungrantable() {
    let document = contract_document(Value::Null);
    assert!(enforce(&document, &case("GET", "/discovery", json!([]), ""), false).is_ok());
    assert_eq!(
        enforce(&document, &case("POST", "/items", json!([]), ""), false)
            .unwrap_err()
            .code,
        ContractCode::ContractNotBound
    );
    assert_eq!(
        enforce(&document, &case("GET", "/items/42", json!([]), ""), true)
            .unwrap_err()
            .code,
        ContractCode::OperationNotGrantable
    );
}

#[test]
fn types_are_declared_and_missing_fields_are_not_made_required() {
    let document = contract_document(Value::Null);
    // Python only validates supplied values and equals_var/range constraints.
    assert!(
        enforce(
            &document,
            &case(
                "POST",
                "/items",
                json!([["Content-Type", "application/json"]]),
                "{}"
            ),
            true
        )
        .is_ok()
    );
    assert!(
        enforce(
            &document,
            &case(
                "POST",
                "/items",
                json!([["Content-Type", "application/json"]]),
                r#"{"metadata": [1,true,{"arbitrary":"value"}]}"#
            ),
            true
        )
        .is_ok()
    );
    assert!(
        enforce(
            &document,
            &case("POST", "/items?page=arbitrary", json!([]), ""),
            true
        )
        .is_ok()
    );
}

#[test]
fn integer_bound_values_are_compared_without_float_rounding() {
    let mut document = contract_document(Value::Null);
    document["capabilities"]["test"]["contract"]["bindings"]["approved"]["type"] = json!("integer");
    let service = ServiceDefinition::from_value(document).unwrap();
    let contract = service.capabilities["test"].contract.as_ref().unwrap();
    let mut state = binding();
    state
        .bound_values
        .insert("approved".into(), json!(9007199254740993_u64));
    let headers = vec![("Content-Type".into(), "application/json".into())];
    for (body, allowed) in [
        (r#"{"name":9007199254740993}"#, true),
        (r#"{"name":9007199254740992}"#, false),
        (r#"{"name":9007199254740993.0}"#, false),
    ] {
        let result = enforce_request(
            contract,
            Some(&state),
            "X-Auth-Token",
            ContractRequest {
                method: "POST",
                target: "/items",
                headers: &headers,
                body: body.as_bytes(),
            },
        );
        assert_eq!(result.is_ok(), allowed, "{body}");
    }
    for (bound, actual, allowed) in [
        ("18446744073709551616", "18446744073709551616", true),
        ("18446744073709551616", "18446744073709551617", false),
        ("18446744073709551617", "18446744073709551616", false),
        ("18446744073709551616", "18446744073709551616.0", true),
        ("18446744073709551617", "18446744073709551617.0", false),
        ("-18446744073709551617", "-18446744073709551616", false),
        (
            "10000000000000000000000000",
            "10000000000000000000000001",
            false,
        ),
        ("10000000000000000000000000", "1e25", false),
        ("10000000000000000905969664", "1e25", true),
        ("0", "-0.0", true),
        (
            "18446744073709551616",
            r#"{"$serde_json::private::Number":"18446744073709551616"}"#,
            false,
        ),
    ] {
        // Exercise typed persisted-state JSON deserialization as well as body
        // parsing; neither side may round the incoming integer token.
        let mut state_json = serde_json::to_string(&binding()).unwrap();
        state_json = state_json.replace("\"chosen\"", bound);
        let state: ContractBinding = serde_json::from_str(&state_json).unwrap();
        let body = format!("{{\"name\":{actual}}}");
        let result = enforce_request(
            contract,
            Some(&state),
            "X-Auth-Token",
            ContractRequest {
                method: "POST",
                target: "/items",
                headers: &headers,
                body: body.as_bytes(),
            },
        );
        assert_eq!(result.is_ok(), allowed, "binding {bound}, body {body}");
    }
}

#[test]
fn operation_specificity_is_exact_then_parameter_then_glob_in_source_order() {
    let contract:ContractTemplate=serde_json::from_value(json!({"operations":[{"name":"glob","request":{"path":"/items/*/ignored"}},{"name":"parameter","request":{"path":"/items/{id}"}},{"name":"exact","request":{"path":"/items/list"}},{"name":"same","request":{"path":"/items/list"}}],"enforcement":{"request_shape":"enforced"}})).unwrap();
    assert_eq!(
        contract.match_operation("get", "/items/list").unwrap().name,
        "exact"
    );
    assert_eq!(
        contract.match_operation("GET", "/items/42").unwrap().name,
        "parameter"
    );
    assert_eq!(
        contract
            .match_operation("GET", "/items/42/more")
            .unwrap()
            .name,
        "glob"
    );
    assert_eq!(path_specificity("/items", "/items/*"), 0);
}

#[test]
fn binding_json_keeps_authored_marker_objects_and_last_duplicate_value() {
    let source = r#"{"agent":"alice","service":"test-service","capability":"test","bound_values":{"approved":{"$serde_json::private::Number":"18446744073709551616"},"id":1,"id":2}}"#;
    let direct: ContractBinding = serde_json::from_str(source).unwrap();
    let object = &direct.bound_values["approved"];
    assert!(object.is_object());
    assert_eq!(
        object["$serde_json::private::Number"].as_str(),
        Some("18446744073709551616")
    );
    assert_eq!(direct.bound_values["id"], 2);
    let from_value: ContractBinding =
        serde_json::from_value(serde_json::to_value(&direct).unwrap()).unwrap();
    assert!(from_value.bound_values["approved"].is_object());
    assert_eq!(from_value.bound_values, direct.bound_values);
}

#[test]
fn contract_query_rejects_encoded_aliases_before_values_can_diverge_upstream() {
    let document = contract_document(json!({"deny_ambiguous_encoding":false}));
    assert_eq!(
        enforce(
            &document,
            &case("POST", "/items?limit=1&limit=1", json!([]), ""),
            true
        )
        .unwrap_err()
        .code,
        ContractCode::TransportAmbiguousEncoding
    );
    for target in [
        "/items?limit=1&%6Cimit=101",
        "/items?name=chosen&%6Eame=forbidden",
    ] {
        assert_eq!(
            enforce(&document, &case("POST", target, json!([]), ""), true)
                .unwrap_err()
                .code,
            ContractCode::TransportAmbiguousEncoding
        );
    }
    assert_eq!(
        enforce(
            &document,
            &case("GET", "/discovery?x=1&%78=2", json!([]), ""),
            false
        )
        .unwrap_err()
        .code,
        ContractCode::TransportAmbiguousEncoding
    );
}

fn differential_cases() -> Vec<Value> {
    let generic = contract_document(Value::Null);
    let mut requests = Vec::new();
    for target in [
        "/items",
        "/items?name=chosen",
        "/items?name=wrong",
        "/items?limit=0",
        "/items?limit=1",
        "/items?limit=100",
        "/items?limit=101",
        "/items?limit=+10",
        "/items?limit=1_0",
        "/items?limit=not-integer",
        "/items?unknown=x",
        "/items?limit=1&limit=2",
        "/items?limit=1&%6Cimit=2",
        "/items?name=chosen&%6Eame=forbidden",
        "/items?name=%2561",
        "/items?name=%2f",
        "/items?name=%2F",
        "/items?_method=GET",
        "/items?%5Fmethod=GET",
        "/items?x=%FF",
        "/items//",
        "/items/../items",
        "/%69tems",
        "/%2E/items",
        "/items%2F",
        "/items%252F",
        "/ITEMS",
        "/discovery",
        "/items/42",
    ] {
        let mut request = case("POST", target, json!([]), "");
        if [
            "/items?limit=1&%6Cimit=2",
            "/items?name=chosen&%6Eame=forbidden",
        ]
        .contains(&target)
        {
            request["intentional_difference"] = json!("decoded_query_alias_rejection");
        }
        requests.push(request);
    }
    for headers in [
        json!([["Accept", "application/json"]]),
        json!([["User-Agent", "ordinary"]]),
        json!([["X-Extra", "x"]]),
        json!([["X-Auth-Token", "sgw_synthetic"]]),
        json!([["Accept", "a"], ["accept", "b"]]),
        json!([["X-HTTP-Method-Override", "GET"]]),
        json!([["Via", "test"], ["Connection", "close"]]),
    ] {
        requests.push(case("POST", "/items", headers, ""));
    }
    for (content_type, body) in [
        ("application/json", "{}"),
        ("APPLICATION/JSON; charset=utf-8", r#"{"name":"chosen"}"#),
        ("text/plain", "{}"),
        ("", "{}"),
        ("application/json", "[]"),
        ("application/json", "null"),
        ("application/json", "not json"),
        ("application/json", r#"{"name":"chosen","name":"other"}"#),
        ("application/json", r#"{"metadata":{"x":1,"x":2}}"#),
        ("application/json", r#"{"metadata":[true,3,"arbitrary"]}"#),
        ("application/json", r#"{"unknown":1}"#),
        ("application/json", r#"{"name":"wrong"}"#),
    ] {
        requests.push(case(
            "POST",
            "/items",
            json!([["Content-Type", content_type]]),
            body,
        ));
    }
    requests.push(case(
        "POST",
        "/items?name=chosen",
        json!([["Content-Type", "application/json"]]),
        r#"{"name":"chosen"}"#,
    ));
    requests.push(case("GET", "/discovery", json!([]), ""));
    requests.push(case("GET", "/discovery", json!([]), "unparsed GET body"));
    let mut scenarios = Vec::new();
    for transport in [
        Value::Null,
        json!({"allow_headers":[]}),
        json!({"allow_headers":["Accept","X-Extra"]}),
        json!({"require_no_body":true,"deny_ambiguous_encoding":false}),
    ] {
        for bound in [true, false] {
            scenarios.push(json!({"document":contract_document(transport.clone()),"capability":"test","bound":bound,"requests":requests}));
        }
    }
    for (service, capability, paths) in [
        (
            "gmail",
            "read_messages",
            vec![
                "/gmail/v1/users/me/messages",
                "/gmail/v1/users/me/messages?labelIds=CATEGORY_PROMOTIONS",
                "/gmail/v1/users/me/messages?labelIds=CATEGORY_SOCIAL",
                "/gmail/v1/users/me/messages?maxResults=101",
                "/gmail/v1/users/me/messages/42",
            ],
        ),
        (
            "minifuse",
            "category_manager",
            vec![
                "/v1/categories/137/feeds",
                "/v1/categories/138/feeds",
                "/v1/categories/137/entries?limit=100",
                "/v1/categories/137/entries?unknown=1",
                "/v1/feeds",
                "/v1/feeds/42",
            ],
        ),
    ] {
        let document = ServiceDefinition::from_yaml(
            &std::fs::read_to_string(format!(
                "{}/../cli/src/safeyolo/services/{service}.yaml",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        )
        .unwrap()
        .raw;
        let mut requests = Vec::new();
        for path in paths {
            for method in ["GET", "POST", "PUT", "DELETE"] {
                for body in [
                    "",
                    r#"{"category_id":137}"#,
                    r#"{"category_id":138}"#,
                    r#"{"category_id":137,"feed_url":3}"#,
                ] {
                    requests.push(case(
                        method,
                        path,
                        json!([
                            ["Content-Type", "application/json"],
                            ["Accept", "application/json"]
                        ]),
                        body,
                    ));
                }
            }
        }
        for bound in [true, false] {
            scenarios.push(json!({"document":document,"capability":capability,"bound":bound,"requests":requests}));
        }
    }
    let mut integer_document = generic.clone();
    integer_document["capabilities"]["test"]["contract"]["bindings"]["approved"]["type"] =
        json!("integer");
    let mut integers: Vec<String> = [
        "0",
        "1",
        "9007199254740992",
        "9007199254740993",
        "18446744073709551615",
        "18446744073709551616",
        "18446744073709551617",
        "10000000000000000905969664",
    ]
    .map(str::to_owned)
    .into();
    for zeros in [25, 50, 200] {
        integers.push(format!("1{}0", "0".repeat(zeros - 1)));
        integers.push(format!("1{}1", "0".repeat(zeros - 1)));
    }
    integers.extend(
        integers
            .clone()
            .into_iter()
            .filter(|value| value != "0")
            .map(|value| format!("-{value}")),
    );
    let mut integer_requests = Vec::new();
    for bound in &integers {
        for actual in &integers {
            for actual in [actual.clone(), format!("{actual}.0")] {
                let mut request = case(
                    "POST",
                    "/items",
                    json!([["Content-Type", "application/json"]]),
                    &format!("{{\"name\":{actual}}}"),
                );
                request["bound_value"] = serde_json::from_str(bound).unwrap();
                integer_requests.push(request);
            }
        }
    }
    scenarios.push(json!({"document":integer_document,"capability":"test","bound":true,"requests":integer_requests}));
    assert!(generic.is_object());
    scenarios
}

#[test]
#[ignore = "historical Python oracle; set SAFEYOLO_POLICY_PYTHON to the baseline environment"]
fn differential_request_enforcement_matches_existing_gateway() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let scenarios = differential_cases();
    let script = r#"
import json,sys,http.client,threading,urllib.parse
from http.server import BaseHTTPRequestHandler,HTTPServer
from mitmproxy.http import Headers
from mitmproxy.test import tflow
from safeyolo.core.service_loader import ServiceDefinition
from safeyolo.mitm_addons.service_gateway import ServiceGateway,ContractBindingState
from safeyolo.detection.matching import normalize_path
x=json.load(sys.stdin); output=[]
for scenario in x['scenarios']:
 service=ServiceDefinition.from_dict(scenario['document']); cap=service.capabilities[scenario['capability']]
 state=ContractBindingState(binding_id='',agent='alice',service=service.name,capability=cap.name,template=cap.contract.template,bound_values=x['binding']['bound_values'],grantable_operations=x['binding']['grantable_operations']) if scenario['bound'] else None
 gateway=ServiceGateway(); results=[]
 for request in scenario['requests']:
  if state and 'bound_value' in request: state.bound_values['approved']=request['bound_value']
  flow=tflow.tflow(); flow.request.method=request['method']; flow.request.path=request['target']; flow.request.host='synthetic.example'; flow.request.scheme='https'; flow.request.headers=Headers([(k.encode('latin-1'),v.encode('latin-1')) for k,v in request['headers']]); flow.request.content=request['body'].encode(); flow.response=None
  result={}
  def deny(flow,status,reason,code,**kw): result.update(allowed=False,code=code)
  gateway._deny=deny
  allowed=gateway._enforce_contract(flow,state,service,cap,request['method'],request['target'].split('?',1)[0])
  if allowed: result={'allowed':True,'operation':cap.contract.match_operation(request['method'],normalize_path(request['target'].split('?',1)[0])).name}
  results.append(result)
 output.append(results)
probe=x['scenarios'][0]
service=ServiceDefinition.from_dict(probe['document']); cap=service.capabilities['test']
state=ContractBindingState(binding_id='',agent='alice',service=service.name,capability=cap.name,template=cap.contract.template,bound_values={'approved':'chosen'},grantable_operations=['write'])
flow=tflow.tflow(); flow.request.method='POST'; flow.request.path='/items?name=chosen&%6Eame=forbidden'; flow.request.host='synthetic.example'; flow.request.scheme='https'; flow.request.headers=Headers(); flow.request.content=b''; flow.response=None
gateway=ServiceGateway(); failures=[]
gateway._deny=lambda *args,**kwargs: failures.append(args[3])
assert gateway._enforce_contract(flow,state,service,cap,'POST','/items') and not failures
assert flow.request.path=='/items?name=chosen&%6Eame=forbidden'
observed={}
class Origin(BaseHTTPRequestHandler):
 def do_POST(self):
  query=urllib.parse.urlsplit(self.path).query
  observed.update(raw_target=self.path,decoded_values=urllib.parse.parse_qs(query)['name'],last_value=dict(urllib.parse.parse_qsl(query))['name'])
  self.send_response(200); self.end_headers()
 def log_message(self,*args): pass
with HTTPServer(('127.0.0.1',0),Origin) as origin:
 worker=threading.Thread(target=origin.handle_request); worker.start()
 client=http.client.HTTPConnection('127.0.0.1',origin.server_port,timeout=5)
 client.request('POST',flow.request.path,body=b''); response=client.getresponse(); assert response.status==200; response.read(); client.close(); worker.join(timeout=5); assert not worker.is_alive()
assert observed['decoded_values']==['chosen','forbidden'] and observed['last_value']=='forbidden'
json.dump({'outcomes':output,'decoded_query_alias_proof':observed},sys.stdout)
"#;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let mut child = Command::new(
        std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON"),
    )
    .args(["-c", script])
    .env(
        "PYTHONPATH",
        format!("{}:{}", root.join("cli/src").display(), root.display()),
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            serde_json::to_string(&json!({"scenarios":scenarios,"binding":binding()}))
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        expected["decoded_query_alias_proof"]["decoded_values"],
        json!(["chosen", "forbidden"])
    );
    assert_eq!(
        expected["decoded_query_alias_proof"]["last_value"],
        "forbidden"
    );
    let mut count = 0;
    let mut intentional_differences = 0;
    for (index, scenario) in scenarios.iter().enumerate() {
        for (request_index, request) in scenario["requests"].as_array().unwrap().iter().enumerate()
        {
            let mut request = request.clone();
            request["capability"] = scenario["capability"].clone();
            let result = result_code(enforce(
                &scenario["document"],
                &request,
                scenario["bound"].as_bool().unwrap(),
            ));
            if request["intentional_difference"] == "decoded_query_alias_rejection" {
                let old = if scenario["bound"] == true {
                    json!({"allowed":true,"operation":"write"})
                } else {
                    json!({"allowed":false,"code":"CONTRACT_NOT_BOUND"})
                };
                assert_eq!(
                    expected["outcomes"][index][request_index], old,
                    "historical alias behavior changed: {request}"
                );
                assert_eq!(
                    result,
                    json!({"allowed":false,"code":"TRANSPORT_AMBIGUOUS_ENCODING"})
                );
                intentional_differences += 1;
            } else {
                assert_eq!(
                    result, expected["outcomes"][index][request_index],
                    "scenario {index}, request {request}"
                );
            }
            count += 1;
        }
    }
    eprintln!(
        "Compared {count} request-contract outcomes across {} shipped/synthetic definitions with production Python gateway; {intentional_differences} explicit decoded-query-alias repairs. Owned HTTP origin received historical forbidden second value.",
        scenarios.len()
    );
}
