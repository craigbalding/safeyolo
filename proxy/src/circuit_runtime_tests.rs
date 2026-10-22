//! Finite actual-source audit and Python counter presentation specimens.
//! The source writer adds attribution to its envelope; these comparisons keep
//! its original detail fields through the canonical writer.

use serde_json::Value;

use super::count_text;
use crate::circuits::CircuitValue;

fn source() -> Value {
    serde_json::from_str(include_str!("../tests/circuit_audit_source.json")).unwrap()
}

#[test]
fn actual_source_counter_str_matches_existing_formatter() {
    let fixture = source();
    let mut checked = 0;
    for row in fixture["source_rows"].as_array().unwrap() {
        let Some(input) = row["count_json"].as_str() else {
            continue;
        };
        let value = CircuitValue::parse_json(input).unwrap();
        assert_eq!(
            count_text(&value).unwrap(),
            row["python_count_text"].as_str().unwrap(),
            "{}",
            row["name"].as_str().unwrap()
        );
        checked += 1;
    }
    assert_eq!(checked, 18);
}
