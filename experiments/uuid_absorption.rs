//! Bounded #856 ownership experiment; deliberately not used by the product.
//! Independent implementation. SafeYolo retains uuid after this experiment.

use ring::rand::{SecureRandom, SystemRandom};

fn generate(fill: impl FnOnce(&mut [u8; 16]) -> Result<(), ()>) -> Result<[u8; 16], ()> {
    let mut bytes = [0; 16];
    fill(&mut bytes)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(bytes)
}

fn new_v4() -> Result<[u8; 16], ()> {
    generate(|bytes| SystemRandom::new().fill(bytes).map_err(|_| ()))
}

fn simple(bytes: [u8; 16]) -> String {
    format!("{:032x}", u128::from_be_bytes(bytes))
}

fn hyphenated(bytes: [u8; 16]) -> String {
    let text = simple(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &text[..8],
        &text[8..12],
        &text[12..16],
        &text[16..20],
        &text[20..]
    )
}

// The host_runs caller needs canonical lowercase boot IDs, not a general UUID
// parser. Accept all bit patterns, as its current parse+round-trip check does.
fn canonical_boot_id(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

#[test]
fn vectors_preserve_bits_and_both_encodings() {
    for (input, expected) in [
        (0, "00000000-0000-4000-8000-000000000000"),
        (255, "ffffffff-ffff-4fff-bfff-ffffffffffff"),
    ] {
        let bytes = generate(|output| {
            output.fill(input);
            Ok(())
        })
        .unwrap();
        assert_eq!(hyphenated(bytes), expected);
        assert_eq!(simple(bytes), expected.replace('-', ""));
        assert!(canonical_boot_id(expected));
    }
    for _ in 0..32 {
        let bytes = new_v4().unwrap();
        assert_eq!(bytes[6] >> 4, 4);
        assert_eq!(bytes[8] >> 6, 2);
        assert!(canonical_boot_id(&hyphenated(bytes)));
        assert_eq!(simple(bytes).len(), 32);
    }
}

#[test]
fn entropy_failure_is_not_an_identifier() {
    assert_eq!(generate(|_| Err(())), Err(()));
}

#[test]
fn boot_id_validation_keeps_the_current_canonical_input_boundary() {
    assert!(canonical_boot_id("00000000-0000-0000-0000-000000000000"));
    let valid = "4dd62838-c039-4325-9a43-e2f91ce6f153";
    assert!(canonical_boot_id(valid));
    for invalid in [
        valid.to_uppercase(),
        valid.replace('-', ""),
        format!("{{{valid}}}"),
        format!("urn:uuid:{valid}"),
        format!(" {valid}"),
        valid.replace('e', "g"),
        valid.replace('-', "/"),
        valid[..35].to_owned(),
        "éééééééé-éé-éé-éé-éééééé".into(),
    ] {
        assert!(!canonical_boot_id(&invalid), "{invalid}");
    }
}
