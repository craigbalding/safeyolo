//! Bounded GitHub issue-author predicate. Identity and time belong to the host.
#![no_std]
extern crate alloc;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

const MAX_CAPTURE: usize = 1024 * 1024;
const CHUNK: usize = 16 * 1024;

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value[key]
        .as_str()
        .ok_or_else(|| alloc::format!("missing {key}"))
}

/// Both the input and the bridge replies are complete JSON, never prefixes.
pub fn service_check(
    input: &[u8],
    mut call: impl FnMut(Value) -> Result<Value, String>,
) -> Result<Value, String> {
    let request: Value = serde_json::from_slice(input).map_err(|e| e.to_string())?;
    let inputs = &request["inputs"];
    let issue = text(&request["subject"], "value")?;
    let number = decimal(issue)?;
    if number == 0 || request["subject"]["kind"] != "value" {
        return Err("subject must be a positive issue number".into());
    }
    let repository = text(inputs, "repository")?;
    let author = decimal(text(inputs, "expected_author_id")?)?;
    let url = alloc::format!("https://api.github.com/repos/{repository}/issues/{number}");
    let response = call(json!({"kind":"service","service":"github","method":"GET","url":url}))?;
    let size = response["bytes"]
        .as_u64()
        .filter(|n| *n <= MAX_CAPTURE as u64)
        .ok_or("capture is missing or exceeds checker limit")? as usize;
    if response["status"] != 200 {
        return Err("GitHub evidence needs HTTP 200".into());
    }
    let id = text(&response, "id")?;
    let mut bytes = Vec::with_capacity(size);
    while bytes.len() < size {
        let chunk = call(json!({"kind":"read","id":id,"offset":bytes.len(),"length":CHUNK}))?;
        if chunk["total_bytes"].as_u64() != Some(size as u64) {
            return Err("capture size changed".into());
        }
        let data = STANDARD
            .decode(text(&chunk, "data_base64")?)
            .map_err(|e| e.to_string())?;
        if data.is_empty() || data.len() > CHUNK || data.len() > size - bytes.len() {
            return Err("capture chunk is empty or exceeds remaining bytes".into());
        }
        bytes.extend_from_slice(&data);
    }
    let evidence: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if evidence["url"] != url
        || evidence["number"].as_u64() != Some(number)
        || !evidence["title"].is_string()
        || !evidence["updated_at"].is_string()
        || evidence["id"].as_u64().is_none()
    {
        return Err("GitHub evidence subject or required metadata mismatch".into());
    }
    let actual_author = evidence["user"]["id"]
        .as_u64()
        .ok_or("GitHub author ID unavailable")?;
    Ok(
        json!({"finding":{"kind":"finding","positive":actual_author == author && evidence.get("pull_request").is_none()}}),
    )
}

/// Verify the small JSON artifact retained by native Work, not a caller-selected path.
pub fn artifact_check(input: &[u8]) -> Result<Value, String> {
    let request: Value = serde_json::from_slice(input).map_err(|e| e.to_string())?;
    if request["subject"]["kind"] != "value" {
        return Err("artifact subject must be a value".into());
    }
    let subject: Value =
        serde_json::from_str(text(&request["subject"], "value")?).map_err(|e| e.to_string())?;
    let bytes = STANDARD
        .decode(text(&subject, "artifact_base64")?)
        .map_err(|e| e.to_string())?;
    let artifact: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let status = text(&artifact, "status")?;
    let expected = text(&request["inputs"], "expected_status")?;
    Ok(json!({"finding":{"kind":"finding","positive":status == expected}}))
}

fn decimal(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("issue and author IDs must be unsigned decimal integers".into());
    }
    value.parse::<u64>().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPTURE: &[u8] =
        include_bytes!("../../../proxy/tests/fixtures/policy-check-github-issue.json");

    fn input() -> Value {
        let capture: Value = serde_json::from_slice(CAPTURE).unwrap();
        json!({"subject":{"kind":"value","value":"1544"},"inputs":{
            "repository":"craigbalding/safeyolo", "expected_author_id":capture["user"]["id"].to_string()}})
    }

    fn evaluate(input: Value, bytes: &[u8]) -> Result<Value, String> {
        let mut offset = 0;
        service_check(input.to_string().as_bytes(), |request| {
            if request["kind"] == "service" {
                assert_eq!(
                    request["url"],
                    "https://api.github.com/repos/craigbalding/safeyolo/issues/1544"
                );
                return Ok(json!({"id":"host-capture","status":200,"bytes":bytes.len()}));
            }
            assert_eq!(request["id"], "host-capture");
            assert_eq!(request["offset"], offset);
            let end = (offset + CHUNK).min(bytes.len());
            let value = json!({"data_base64":STANDARD.encode(&bytes[offset..end]),"total_bytes":bytes.len()});
            offset = end;
            Ok(value)
        })
    }

    #[test]
    fn captured_github_identity_and_chunked_complete_json() {
        let mut capture: Value = serde_json::from_slice(CAPTURE).unwrap();
        capture["body"] = json!("large authenticated issue body ".repeat(2000));
        let bytes = serde_json::to_vec(&capture).unwrap();
        assert!(bytes.len() > 3 * CHUNK);
        assert_eq!(
            evaluate(input(), &bytes).unwrap()["finding"]["positive"],
            true
        );
        let mut other = input();
        other["inputs"]["expected_author_id"] = json!("0");
        assert_eq!(
            evaluate(other, &bytes).unwrap()["finding"]["positive"],
            false
        );
        for key in ["url", "number", "id", "title", "updated_at", "user"] {
            let mut missing = capture.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(
                evaluate(input(), &serde_json::to_vec(&missing).unwrap()).is_err(),
                "{key}"
            );
        }
        capture["url"] = json!("https://api.github.com/repos/other/repository/issues/1544");
        assert!(evaluate(input(), &serde_json::to_vec(&capture).unwrap()).is_err());
        assert!(evaluate(input(), &bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn unavailable_oversized_and_partial_captures_never_become_findings() {
        let bytes = input().to_string();
        assert!(service_check(bytes.as_bytes(), |_| Err("policy_denied".into())).is_err());
        for response in [
            json!({"status":200,"bytes":MAX_CAPTURE+1}),
            json!({"status":403,"bytes":0}),
        ] {
            assert!(service_check(bytes.as_bytes(), |_| Ok(response.clone())).is_err());
        }
        for chunk in [
            json!({"total_bytes":2,"data_base64":""}),
            json!({"total_bytes":3,"data_base64":"e30="}),
            json!({"total_bytes":2,"data_base64":"invalid base64"}),
        ] {
            assert!(
                service_check(bytes.as_bytes(), |request| {
                    Ok(if request["kind"] == "service" {
                        json!({"id":"capture","status":200,"bytes":2})
                    } else {
                        chunk.clone()
                    })
                })
                .is_err()
            );
        }
    }

    #[test]
    fn shared_author_and_autonomy_cases() {
        let cases: Vec<Value> = serde_json::from_slice(include_bytes!(
            "../../../proxy/tests/fixtures/hyperlight-author-cases.json"
        ))
        .unwrap();
        for case in cases {
            let mut capture: Value = serde_json::from_slice(CAPTURE).unwrap();
            capture
                .as_object_mut()
                .unwrap()
                .extend(case["patch"].as_object().unwrap().clone());
            let mut request = input();
            if let Some(author) = case.get("expected_author_id") {
                request["inputs"]["expected_author_id"] = author.clone();
            }
            let result = evaluate(request, &serde_json::to_vec(&capture).unwrap());
            match case["outcome"].as_str().unwrap() {
                "pass" => assert_eq!(result.unwrap()["finding"]["positive"], true, "{case}"),
                "reject" => assert_eq!(result.unwrap()["finding"]["positive"], false, "{case}"),
                "unavailable" => assert!(result.is_err(), "{case}"),
                other => panic!("unknown outcome {other}"),
            }
        }
    }

    #[test]
    fn shared_exact_artifact_cases() {
        let cases: Vec<Value> = serde_json::from_slice(include_bytes!(
            "../../../proxy/tests/fixtures/hyperlight-artifact-cases.json"
        ))
        .unwrap();
        for case in cases {
            let subject =
                json!({"artifact_base64":STANDARD.encode(case["artifact"].as_str().unwrap())});
            let request = json!({"subject":{"kind":"value","value":subject.to_string()},
                "inputs":{"expected_status":"ready"}});
            let result = artifact_check(request.to_string().as_bytes());
            if case["positive"].is_null() {
                assert!(result.is_err(), "{case}");
            } else {
                assert_eq!(
                    result.unwrap()["finding"]["positive"],
                    case["positive"],
                    "{case}"
                );
            }
        }
    }
}
