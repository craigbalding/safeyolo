//! Pinned Python 3.12 / Unicode 15 scalar operations shared by policy and API.
//! Provenance and regeneration live in data/agent_api/README.md.

use serde::Deserialize;
use std::sync::OnceLock;

#[derive(Deserialize)]
struct UnicodeData {
    uppercase: Vec<(u32, String)>,
    decimal_zero: Vec<u32>,
    nonprintable: Vec<(u32, u32)>,
}
fn unicode() -> &'static UnicodeData {
    static DATA: OnceLock<UnicodeData> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("../data/agent_api/unicode.json"))
            .expect("validated Python scalar tables")
    })
}
pub(crate) fn uppercase(value: &str) -> String {
    // Ordinary HTTP methods remain allocation-only without initializing Unicode
    // data. Non-ASCII input uses the same pinned operation as Python policy.
    if value.is_ascii() {
        return value.to_ascii_uppercase();
    }
    let mut output = String::new();
    for character in value.chars() {
        if let Ok(index) = unicode()
            .uppercase
            .binary_search_by_key(&(character as u32), |row| row.0)
        {
            output.push_str(&unicode().uppercase[index].1);
        } else {
            output.push(character);
        }
    }
    output
}
pub(crate) fn decimal(character: char) -> Option<u32> {
    let point = character as u32;
    let index = unicode()
        .decimal_zero
        .partition_point(|zero| *zero <= point);
    (index > 0)
        .then(|| point - unicode().decimal_zero[index - 1])
        .filter(|value| *value < 10)
}
pub(crate) fn printable(character: char) -> bool {
    let point = character as u32;
    let index = unicode().nonprintable.partition_point(|row| row.0 <= point);
    index == 0 || point > unicode().nonprintable[index - 1].1
}
