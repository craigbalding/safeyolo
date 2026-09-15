use safeyolo_proxy::circuits::*;
use serde_json::{Value, json};

fn tag(value: &Value) -> Value {
    match value {
        Value::Number(number) => {
            let text = number.to_string();
            if text.contains(['.', 'e', 'E']) {
                json!({"float_bits":format!("{:016x}",text.parse::<f64>().unwrap().to_bits())})
            } else {
                json!({"integer":text})
            }
        }
        Value::Array(values) => Value::Array(values.iter().map(tag).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), tag(value)))
                .collect(),
        ),
        value => value.clone(),
    }
}
fn typed_tag(value: &CircuitValue) -> Value {
    match value {
        CircuitValue::Float(value) => json!({"float_bits":format!("{:016x}",value.to_bits())}),
        CircuitValue::Integer(value) => json!({"integer":value.to_string()}),
        CircuitValue::Bool(value) => json!(value),
        CircuitValue::Other(value) => tag(value),
        CircuitValue::Temporal(_) => panic!("numeric-only fixture has no temporal operands"),
        CircuitValue::Array(values) => Value::Array(values.iter().map(typed_tag).collect()),
        CircuitValue::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), typed_tag(value)))
                .collect(),
        ),
    }
}
fn scalar_tag(value: CircuitValue) -> Value {
    typed_tag(&value)
}
trait Observation {
    fn tagged(self) -> Value;
}
impl Observation for () {
    fn tagged(self) -> Value {
        Value::Null
    }
}
impl Observation for bool {
    fn tagged(self) -> Value {
        json!(self)
    }
}
impl Observation for Status {
    fn tagged(self) -> Value {
        typed_tag(&self.document())
    }
}
impl Observation for (bool, Status) {
    fn tagged(self) -> Value {
        json!([self.0, typed_tag(&self.1.document())])
    }
}
impl Observation for CircuitValue {
    fn tagged(self) -> Value {
        typed_tag(&self)
    }
}
fn observed<T: Observation>(
    result: Result<Outcome<T>, Error>,
) -> Result<(Value, Vec<Transition>), Error> {
    result.map(|outcome| (outcome.value.tagged(), outcome.events))
}
fn exception(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::Type => "TypeError",
        ErrorKind::Value => "ValueError",
        ErrorKind::Overflow => "OverflowError",
        ErrorKind::ZeroDivision => "ZeroDivisionError",
        ErrorKind::Compatibility => "Compatibility",
        ErrorKind::Invalid => "Invalid",
        ErrorKind::Audit(_) => "Audit",
    }
}
fn actual(cases: &Value) -> Value {
    let mut output = Vec::new();
    for case in cases.as_array().unwrap() {
        let cb = CircuitBreaker::new();
        let mut operations = Vec::new();
        for (index, op) in case["operations"].as_array().unwrap().iter().enumerate() {
            let now = op["now"].as_f64().unwrap_or(100.);
            let mut draws = 0usize;
            let samples = op.get("random").cloned().unwrap_or(json!([0.5]));
            let samples = samples.as_array().unwrap();
            let mut random = || {
                let result = samples[draws % samples.len()].as_f64().unwrap();
                draws += 1;
                result
            };
            let result = match op["op"].as_str().unwrap() {
                "config" => {
                    let section = op
                        .get("json")
                        .map(|text| serde_json::from_str(text.as_str().unwrap()).unwrap())
                        .unwrap_or_else(|| op["value"].clone());
                    cb.apply_sensor_config(&json!({"policy_hash":(index+1).to_string(),"addons":{"circuit_breaker":section}}))
                        .map(|value|(json!(value),vec![]))
                }
                "restore" => observed(cb.restore(&op["value"], now, &mut random)),
                "timeout" => cb
                    .settings()
                    .unwrap()
                    .calculate_timeout(
                        CircuitValue::from(
                            op.get("streak_json")
                                .map(|value| serde_json::from_str(value.as_str().unwrap()).unwrap())
                                .unwrap_or_else(|| op["streak"].clone()),
                        ),
                        &mut random,
                    )
                    .map(|value| (scalar_tag(value), vec![])),
                "status" => observed(cb.status("api", now, &mut random)),
                "failure" => observed(cb.record_failure("api", None, now, &mut random)),
                "success" => observed(cb.record_success("api", now, &mut random)),
                "force" => observed(cb.force_open("api", now)),
                "admit" => observed(cb.admit("api", now, &mut random)),
                "stats" => observed(cb.stats_document(true, now, &mut random)),
                value => panic!("unexpected operation {value}"),
            };
            let (value, error, events) = match result {
                Ok((value, events)) => (value, Value::Null, events),
                Err(error) => (
                    Value::Null,
                    json!(exception(error.kind())),
                    error.events().to_vec(),
                ),
            };
            let snapshot = cb.snapshot_document(now).unwrap();
            operations.push(json!({"value":value,"error":error,"events":events.iter().map(|event|typed_tag(&event.document())).collect::<Vec<_>>(),
                "snapshot":typed_tag(&snapshot),"state_order":snapshot.as_object().unwrap()["states"].as_object().unwrap().keys().collect::<Vec<_>>(),"draws":draws}));
        }
        output.push(json!({"name":case["name"],"operations":operations}));
    }
    Value::Array(output)
}
fn cases() -> Value {
    serde_json::from_str(include_str!("circuit_numeric_cases.json")).unwrap()
}

#[test]
fn exact_numeric_kinds_operations_errors_and_committed_state_match_frozen_source() {
    let cases = cases();
    let expected: Value =
        serde_json::from_str(include_str!("circuit_numeric_source.json")).unwrap();
    let actual = actual(&cases);
    for (index, case) in cases.as_array().unwrap().iter().enumerate() {
        for (operation, op) in case["operations"].as_array().unwrap().iter().enumerate() {
            assert_eq!(
                actual[index]["operations"][operation], expected[index]["operations"][operation],
                "case {} operation {operation}: {op}",
                case["name"]
            );
        }
    }
}

#[test]
#[ignore = "actual source circuit numeric oracle; set SAFEYOLO_POLICY_PYTHON"]
fn frozen_numeric_rows_match_actual_python() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let mut child = Command::new(
        std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON"),
    )
    .arg(root.join("proxy/tests/circuit_numeric_oracle.py"))
    .env(
        "PYTHONPATH",
        format!("{}:{}", root.join("cli/src").display(), root.display()),
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        stdin
            .write_all(include_bytes!("circuit_numeric_cases.json"))
            .unwrap()
    });
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(output.status.success(), "source numeric oracle failed");
    let actual: Value = serde_json::from_slice(&output.stdout).unwrap();
    let expected: Value =
        serde_json::from_str(include_str!("circuit_numeric_source.json")).unwrap();
    assert_eq!(actual, expected);
    eprintln!(
        "Compared 102 cases / 322 circuit operations to actual Python, with exact numeric kinds and float bits"
    );
}

#[test]
fn nan_remains_a_scalar_until_the_current_json_boundary() {
    let settings = Settings {
        timeout_seconds: CircuitValue::Float(f64::NAN),
        ..Default::default()
    };
    let value = settings
        .calculate_timeout(0, &mut || panic!("zero streak draws no jitter"))
        .unwrap();
    assert!(matches!(value,CircuitValue::Float(value) if value.is_nan()));
    assert!(
        serde_json::to_value(&value).is_err(),
        "never encode NaN as null"
    );
    let settings = Settings {
        timeout_seconds: CircuitValue::Float(f64::INFINITY),
        ..Default::default()
    };
    let value = settings
        .calculate_timeout(0, &mut || panic!("zero streak draws no jitter"))
        .unwrap();
    assert!(matches!(value,CircuitValue::Float(value) if value.is_infinite()));
    assert!(serde_json::to_value(&value).is_err());
    assert_eq!(value.render_json(false).unwrap(), "Infinity");
}

#[test]
#[ignore = "actual source division/nonfinite oracle; set SAFEYOLO_POLICY_PYTHON"]
fn division_and_nonfinite_witnesses_match_actual_python() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let mut child = Command::new(
        std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON"),
    )
    .arg(root.join("proxy/tests/circuit_numeric_extra_oracle.py"))
    .env(
        "PYTHONPATH",
        format!("{}:{}", root.join("cli/src").display(), root.display()),
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        stdin
            .write_all(include_bytes!("circuit_ratio_source.json"))
            .unwrap()
    });
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(
        output.status.success(),
        "source numeric boundary oracle failed"
    );
    let actual: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        actual["ratios"],
        serde_json::from_str::<Value>(include_str!("circuit_ratio_source.json")).unwrap()
    );
    assert_eq!(
        actual["nonfinite"],
        serde_json::from_str::<Value>(include_str!("circuit_nonfinite_source.json")).unwrap()
    );
}
