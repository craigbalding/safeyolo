use safeyolo_proxy::http_content::{ContentError, decode, decode_prefix, decode_prefix_with_size};
use serde_json::Value;

fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn rows() -> Vec<Value> {
    serde_json::from_str::<Value>(include_str!("http_content_source.json")).unwrap()["rows"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn actual_source_encoding_controls() {
    let mut matched = 0;
    for row in rows() {
        let name = row["name"].as_str().unwrap();
        let encoding = unhex(row["encoding_hex"].as_str().unwrap());
        let encoded = unhex(row["encoded_hex"].as_str().unwrap());
        let original = encoded.clone();
        let result = decode(&encoded, &encoding);
        if let Some(expected) = row["decoded_hex"].as_str() {
            let expected = unhex(expected);
            assert_eq!(result.unwrap().as_slice(), expected, "{name}");
            for limit in [0, 1, 17, 4096, usize::MAX] {
                let captured = decode_prefix_with_size(&encoded, &encoding, limit).unwrap();
                assert_eq!(
                    captured.total_bytes,
                    expected.len(),
                    "{name}, size at {limit}"
                );
                assert_eq!(
                    captured.content.as_slice(),
                    &expected[..expected.len().min(limit)]
                );
                assert_eq!(
                    decode_prefix(&encoded, &encoding, limit)
                        .unwrap()
                        .as_slice(),
                    &expected[..expected.len().min(limit)],
                    "{name}, prefix {limit}"
                );
            }
            matched += 1;
        } else {
            let expected = match row["error"].as_str().unwrap() {
                "ValueError" => ContentError::Value,
                "TypeError" => ContentError::Type,
                other => panic!("unaccounted source error: {other}"),
            };
            assert_eq!(result.unwrap_err(), expected, "{name}");
            assert_eq!(
                decode_prefix_with_size(&encoded, &encoding, 0)
                    .err()
                    .unwrap(),
                expected,
                "{name}, failed capture has no successful size"
            );
            assert_eq!(
                decode_prefix(&encoded, &encoding, 0).unwrap_err(),
                expected,
                "{name}"
            );
            assert_eq!(
                decode_prefix(&encoded, &encoding, 4096).unwrap_err(),
                expected,
                "{name}"
            );
            matched += 1;
        }
        assert_eq!(encoded, original, "decoder altered forwarded bytes: {name}");
    }
    assert_eq!(matched, 138);
}

#[test]
fn prefix_does_not_hide_late_checksum_or_trailing_data_failures() {
    for row in rows().into_iter().filter(|row| {
        matches!(
            row["name"].as_str(),
            Some("gzip_late_bad_crc" | "br_trailing" | "zstd_trailing")
        )
    }) {
        let encoded = unhex(row["encoded_hex"].as_str().unwrap());
        let encoding = unhex(row["encoding_hex"].as_str().unwrap());
        assert_eq!(
            decode_prefix(&encoded, &encoding, 0).unwrap_err(),
            ContentError::Value
        );
        assert_eq!(
            decode_prefix(&encoded, &encoding, 4096).unwrap_err(),
            ContentError::Value
        );
    }
}

#[test]
fn full_decode_has_no_streaming_threshold_and_prefix_is_only_retention() {
    use std::io::Write;
    let source = vec![b'x'; 10 * 1024 * 1024 + 1];
    let mut compressor = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    compressor.write_all(&source).unwrap();
    let encoded = compressor.finish().unwrap();
    assert_eq!(decode(&encoded, b"gzip").unwrap().as_slice(), source);
    assert_eq!(
        decode_prefix(&encoded, b"gzip", 4096).unwrap().as_slice(),
        &source[..4096]
    );
    let captured = decode_prefix_with_size(&encoded, b"gzip", 4096).unwrap();
    assert_eq!(captured.content.as_slice(), &source[..4096]);
    assert_eq!(captured.total_bytes, source.len());
    // This API does not guess whether the source transport streamed the body.
    assert_eq!(decode(&source, b"identity").unwrap().len(), source.len());
}

#[test]
#[ignore = "requires the retained Python 3.12 mitmproxy environment"]
fn actual_python_decoder_oracle() {
    let python =
        std::env::var("SAFEYOLO_PYTHON").expect("set SAFEYOLO_PYTHON to the source environment");
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let output = std::process::Command::new(python)
        .arg(directory.join("http_content_source.py"))
        .arg(directory.join("http_content_source.json"))
        .arg("--check")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "source oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
