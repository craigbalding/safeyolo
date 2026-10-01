use fancy_regex::{Error, Regex, RegexBuilder, RegexInput, RuntimeError};
use std::sync::atomic::AtomicBool;

#[test]
fn ascii_backreference_extension_is_off_by_default() {
    assert!(Regex::new(r"(?A:(a)\1)").is_err());
    assert!(RegexBuilder::new(r"(?A:(a)\1)").build().is_err());
    let regex = RegexBuilder::new(r"(?i)(.)(?A:\1)")
        .allow_ascii_backref_flag(true)
        .build()
        .unwrap();
    for text in ["aA", "Aa", "kk", "KK", "ää", "KK", "İİ"] {
        assert!(regex.is_match(text).unwrap());
    }
    for text in ["kK", "Kk", "iİ", "İi", "äÄ", "Ää"] {
        assert!(!regex.is_match(text).unwrap());
    }
}

#[test]
fn scope_restores_unicode_folding_without_changing_literal_or_scalar_behavior() {
    let regex = RegexBuilder::new(r"(?i)(ä)(?A:\1)\1")
        .allow_ascii_backref_flag(true)
        .build()
        .unwrap();
    assert!(regex.is_match("ääÄ").unwrap());
    assert!(!regex.is_match("äÄÄ").unwrap());
    let named = RegexBuilder::new(r"(?i)(?P<unit>ä)(?A:(?P=unit))(?P=unit)")
        .allow_ascii_backref_flag(true)
        .build()
        .unwrap();
    assert!(named.is_match("ääÄ").unwrap());
    // The private flag is deliberately a backreference marker, not Python (?a).
    assert!(RegexBuilder::new(r"(?iA:ä)")
        .allow_ascii_backref_flag(true)
        .build()
        .unwrap()
        .is_match("Ä")
        .unwrap());
    assert!(RegexBuilder::new(r"(?A:^.$)")
        .allow_ascii_backref_flag(true)
        .build()
        .unwrap()
        .is_match("é")
        .unwrap());
}

#[test]
fn private_scope_preserves_cancellation_and_capture_offsets() {
    let regex = RegexBuilder::new(r"(?i)(a)(?A:\1)")
        .allow_ascii_backref_flag(true)
        .stack_limit(None)
        .build()
        .unwrap();
    let flag = AtomicBool::new(true);
    assert!(matches!(
        regex.is_match_input(RegexInput::new("aA").with_cancel_flag(&flag)),
        Err(Error::RuntimeError(RuntimeError::Cancelled))
    ));
    let captures = regex.captures("xaAy").unwrap().unwrap();
    assert_eq!(captures.get(0).unwrap().range(), 1..3);
    assert_eq!(captures.get(1).unwrap().range(), 1..2);
}
