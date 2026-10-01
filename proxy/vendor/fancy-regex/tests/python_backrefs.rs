//! The opt-in Python comparison uses scalar lowercase, separate from literal folding.
#[path = "../src/python_lowercase.rs"]
mod python_lowercase;
use fancy_regex::{Error, Input, Regex, RegexBuilder, RegexInput, RuntimeError};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Barrier};
use std::time::Duration;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}
struct AllocationCounter;
unsafe impl GlobalAlloc for AllocationCounter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if COUNTING.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        }
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if COUNTING.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        }
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: AllocationCounter = AllocationCounter;

fn python(pattern: &str, seek: bool) -> Regex {
    RegexBuilder::new(pattern)
        .python_backreferences(true)
        .allow_ascii_backref_flag(true)
        .seek(seek)
        .stack_limit(None)
        .backtrack_limit(usize::MAX)
        .delegate_size_limit(usize::MAX)
        .build()
        .unwrap()
}

#[test]
fn option_preserves_default_relation_and_does_not_change_literal_folding() {
    let legacy = Regex::new(r"(?i)\A(.)\1\z").unwrap();
    let adapted = python(r"(?i)\A(.)\1\z", false);
    assert!(legacy.is_match("σς").unwrap());
    assert!(!adapted.is_match("σς").unwrap());
    assert!(!legacy.is_match("iİ").unwrap());
    assert!(adapted.is_match("iİ").unwrap());
    // The frontend separately repairs the four-I literal equivalence.
    assert!(!python("(?i)i", false).is_match("ı").unwrap());
}

#[test]
fn scalar_lowercase_consumes_subject_width_and_preserves_captures() {
    let regex = python(r"(?i)\A(.)\1(?-i:X)\z", false);
    for text in [
        "iİX",
        "İiX",
        "KkX",
        "kKX",
        "ÅåX",
        "ßẞX",
        "ẞßX",
        "\u{10400}\u{10428}X",
        "\u{10428}\u{10400}X",
    ] {
        let captures = regex.captures(text).unwrap().unwrap();
        assert_eq!(captures.get(0).unwrap().as_str(), text);
        assert_eq!(captures.get(0).unwrap().end(), text.len());
        assert_eq!(
            captures.get(1).unwrap().end(),
            text.chars().next().unwrap().len_utf8()
        );
    }
    let regex = python(r"(?i)\A(.)\1\z", false);
    for left in ['I', 'i', 'İ', 'ı'] {
        for right in ['I', 'i', 'İ', 'ı'] {
            assert_eq!(
                regex.is_match(&format!("{left}{right}")).unwrap(),
                (left == 'ı') == (right == 'ı')
            );
        }
    }
    for text in [
        "σς",
        "ςΣ",
        "sſ",
        "µμ",
        "ﬅﬆ",
        "ßss",
        "\u{a7cb}ɤ",
        "\u{1c89}\u{1c8a}",
    ] {
        assert!(!regex.is_match(text).unwrap(), "unexpected fold {:?}", text);
    }
    for text in ["Σσ", "ſſ", "µµ", "ıı", "\u{a7cb}\u{a7cb}"] {
        assert!(
            regex.is_match(text).unwrap(),
            "missing exact/lower match {:?}",
            text
        );
    }
    let regex = python(r"(?i)\A(.+)\1\z", false);
    for text in ["aiaİ", "aİai", "KbKb", "KbKb", "σςσς"] {
        assert!(regex.is_match(text).unwrap(), "mixed width {:?}", text);
    }
    for text in ["σςσσ", "ſssſ", "ıiii", "aİai!"] {
        assert!(!regex.is_match(text).unwrap());
    }
}

#[test]
fn ascii_reference_folds_ascii_with_identical_non_ascii_scalars() {
    let regex = python(r"(?i)\A(.+)(?A:\1)\z", false);
    for text in ["äaäA", "aİAİ", "aıAı", "µaµA", "aéAé", "aaAA", "ääää"] {
        assert!(
            regex.is_match(text).unwrap(),
            "ASCII mixed reference {:?}",
            text
        );
    }
    for text in ["äaÄA", "aİAI", "iİ", "µaμA", "éaÉA"] {
        assert!(
            !regex.is_match(text).unwrap(),
            "non-ASCII folded {:?}",
            text
        );
    }
    assert!(python(r"(?i)\A(.)(?A:\1)\1\z", false)
        .is_match("iiİ")
        .unwrap());
    assert!(!python(r"(?i)\A(.)(?A:\1)\1\z", false)
        .is_match("iİi")
        .unwrap());
}

#[test]
fn enabled_seek_keeps_python_reference_candidates_and_offsets() {
    for (pattern, yes, no) in [
        (r"(i)(?i:\1)", "!iİ!", "!iı!"),
        (r"(İ)(?i:\1)", "!İi!", "!İı!"),
        (r"(K)(?i:\1)", "!Kk!", "!Kj!"),
        (r"(σ)(?i:\1)", "!σΣ!", "!σς!"),
        (r"(äa)(?i:(?A:\1))", "!äaäA!", "!äaÄA!"),
    ] {
        let enabled = python(pattern, true);
        let disabled = python(pattern, false);
        for (text, expected) in [(yes, true), (no, false)] {
            let actual = enabled.find(text).unwrap().map(|m| (m.start(), m.end()));
            assert_eq!(actual.is_some(), expected, "{pattern:?} {text:?}");
            assert_eq!(
                actual,
                disabled.find(text).unwrap().map(|m| (m.start(), m.end()))
            );
        }
    }
    let mut builder = RegexBuilder::new(r"(i)(?i:\1)");
    builder.python_backreferences(true).seek_filter(|pattern| {
        assert_eq!(pattern, "i(?s:.)+");
        true
    });
    assert!(builder.build().unwrap().is_match("iİ").unwrap());
}

struct ScalarInput<'a> {
    text: String,
    steps: AtomicUsize,
    at: usize,
    stop_counting_at: Option<usize>,
    hook: Box<dyn Fn() + Send + Sync + 'a>,
}
impl Input for ScalarInput<'_> {
    type Match<'t>
        = (usize, usize)
    where
        Self: 't;
    fn len(&self) -> usize {
        self.text.len()
    }
    fn as_bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }
    fn is_char_boundary(&self, position: usize) -> bool {
        self.text.is_char_boundary(position)
    }
    fn is_ascii(&self) -> bool {
        self.text.is_ascii()
    }
    fn prev_codepoint_ix(&self, position: usize) -> usize {
        <str as Input>::prev_codepoint_ix(&self.text, position)
    }
    fn make_match<'t>(&'t self, start: usize, end: usize) -> Self::Match<'t> {
        (start, end)
    }
    fn advance_position(&self, position: usize) -> usize {
        let step = self.steps.fetch_add(1, Ordering::Relaxed) + 1;
        if step == self.at {
            (self.hook)();
        }
        if Some(step) == self.stop_counting_at {
            COUNTING.with(|value| value.set(false));
        }
        <str as Input>::advance_position(&self.text, position)
    }
}

#[test]
fn running_scalar_comparison_cancels_without_affecting_another_request() {
    let regex = python(r"\A(äa+)(?i:(?A:\1))\z", false);
    let cancel = AtomicBool::new(false);
    let entered = Barrier::new(2);
    let resume = Barrier::new(2);
    let input = ScalarInput {
        text: format!("ä{}ä{}", "a".repeat(65536), "A".repeat(65536)),
        steps: AtomicUsize::new(0),
        at: 8192,
        stop_counting_at: None,
        hook: Box::new(|| {
            entered.wait();
            resume.wait();
        }),
    };
    let (send, receive) = mpsc::channel();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            send.send(regex.is_match_input(RegexInput::new(&input).with_cancel_flag(&cancel)))
                .unwrap()
        });
        entered.wait();
        assert_eq!(input.steps.load(Ordering::Relaxed), 8192);
        assert!(regex.clone().is_match("äaäA").unwrap());
        cancel.store(true, Ordering::Relaxed);
        resume.wait();
        assert!(matches!(
            receive.recv_timeout(Duration::from_secs(2)).unwrap(),
            Err(Error::RuntimeError(RuntimeError::Cancelled))
        ));
        worker.join().unwrap();
    });
    assert!(regex.is_match(&input.text).unwrap());
    assert!(cancel.load(Ordering::Relaxed));
}

#[test]
fn scalar_comparison_does_not_allocate() {
    let regex = python(r"\A(äa+)(?i:(?A:\1))\z", false);
    let input = ScalarInput {
        text: format!("ä{}ä{}", "a".repeat(65536), "A".repeat(65536)),
        steps: AtomicUsize::new(0),
        at: 1,
        // Stop at the final subject scalar, before the VM returns its scratch
        // state to the pool. Pool bookkeeping is outside the comparison helper.
        stop_counting_at: Some(131074),
        hook: Box::new(|| {
            ALLOCATIONS.with(|n| n.set(0));
            COUNTING.with(|v| v.set(true));
        }),
    };
    let result = regex.is_match_input(RegexInput::new(&input));
    COUNTING.with(|v| v.set(false));
    let allocations = ALLOCATIONS.with(Cell::get);
    assert!(result.unwrap());
    assert!(input.steps.load(Ordering::Relaxed) >= 131074);
    assert_eq!(allocations, 0);
}

#[test]
#[ignore = "requires SAFEYOLO_POLICY_PYTHON with CPython 3.12"]
fn every_valid_scalar_lowercase_matches_actual_python_312() {
    let python = std::env::var_os("SAFEYOLO_POLICY_PYTHON").unwrap();
    let output = std::process::Command::new(python)
        .args([
            "-c",
            r#"
import _sre,sys,unicodedata
assert sys.version_info[:2]==(3,12) and unicodedata.unidata_version=='15.0.0'
for code in range(0x110000):
    if 0xd800<=code<=0xdfff:continue
    lower=_sre.unicode_tolower(code)
    if lower!=code:print(code,lower)
"#,
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let pairs: std::collections::BTreeMap<_, _> = std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            let (code, lower) = line.split_once(' ').unwrap();
            (code.parse::<u32>().unwrap(), lower.parse::<u32>().unwrap())
        })
        .collect();
    assert_eq!(pairs.len(), 1433);
    for scalar in (0..=0x10ffff).filter_map(char::from_u32) {
        assert_eq!(
            python_lowercase::lowercase(scalar) as u32,
            *pairs.get(&(scalar as u32)).unwrap_or(&(scalar as u32)),
            "U+{:X}",
            scalar as u32
        );
    }
}
