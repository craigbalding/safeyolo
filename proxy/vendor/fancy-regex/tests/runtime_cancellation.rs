//! Per-input cancellation. Synthetic Input hooks establish that a call reached
//! actual matching work, rather than merely being queued on a worker thread.
use fancy_regex::{Error, Input, Regex, RegexBuilder, RegexInput, RuntimeError};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::time::{Duration, Instant};

fn unlimited(pattern: &str) -> Regex {
    RegexBuilder::new(pattern)
        .stack_limit(None)
        .backtrack_limit(usize::MAX)
        .delegate_size_limit(usize::MAX)
        .build()
        .unwrap()
}
fn cancelled<T>(result: fancy_regex::Result<T>) {
    assert!(matches!(
        result,
        Err(Error::RuntimeError(RuntimeError::Cancelled))
    ));
}
struct ProbeInput<'a> {
    text: String,
    reads: AtomicUsize,
    at: usize,
    hook: Box<dyn Fn() + Send + Sync + 'a>,
}
impl Input for ProbeInput<'_> {
    type Match<'t>
        = (usize, usize)
    where
        Self: 't;
    fn len(&self) -> usize {
        self.text.len()
    }
    fn as_bytes(&self) -> &[u8] {
        if self.reads.fetch_add(1, Ordering::Relaxed) + 1 == self.at {
            (self.hook)();
        }
        self.text.as_bytes()
    }
    fn is_char_boundary(&self, ix: usize) -> bool {
        self.text.is_char_boundary(ix)
    }
    fn is_ascii(&self) -> bool {
        self.text.is_ascii()
    }
    fn prev_codepoint_ix(&self, ix: usize) -> usize {
        <str as Input>::prev_codepoint_ix(&self.text, ix)
    }
    fn make_match<'t>(&'t self, start: usize, end: usize) -> Self::Match<'t> {
        (start, end)
    }
    fn advance_position(&self, ix: usize) -> usize {
        <str as Input>::advance_position(&self.text, ix)
    }
}

#[test]
fn precancelled_inputs_keep_cancellation_through_all_regex_entry_points() {
    let cancel = AtomicBool::new(true);
    for pattern in [r"a+", r"(a|aa)*\1$"] {
        let regex = unlimited(pattern);
        let input = RegexInput::new("aaaa")
            .with_cancel_flag(&cancel)
            .range(0..4)
            .from_pos(1);
        cancelled(regex.is_match_input(input.clone()));
        cancelled(regex.find_input(input.clone()));
        cancelled(regex.captures_input(input.clone()));
        cancelled(regex.find_iter_input(input.clone()).next().unwrap());
        cancelled(regex.captures_iter_input(input).next().unwrap());
        // An exhausted input is still a cancelled call, not a clean non-match.
        cancelled(regex.is_match_input(RegexInput::new("").with_cancel_flag(&cancel).from_pos(1)));
        assert!(regex.is_match("aaaa").unwrap());
    }
    let input = RegexInput::new(b"aaaa".as_slice()).with_cancel_flag(&cancel);
    cancelled(unlimited("a+").is_match_input(input));
}

#[test]
fn external_cancellation_interrupts_running_vm_and_does_not_cancel_clones() {
    let regex = unlimited(r"^(a|aa)*\1$");
    let cancel = AtomicBool::new(false);
    let entered = Barrier::new(2);
    let resume = Barrier::new(2);
    let subject = ProbeInput {
        text: format!("{}b", "a".repeat(4096)),
        reads: AtomicUsize::new(0),
        at: 512,
        hook: Box::new(|| {
            entered.wait();
            resume.wait();
        }),
    };
    let (send, recv) = mpsc::channel();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let result = regex.is_match_input(RegexInput::new(&subject).with_cancel_flag(&cancel));
            send.send(result).unwrap();
        });
        entered.wait();
        assert!(subject.reads.load(Ordering::Relaxed) >= 512);
        let sibling = scope.spawn(|| {
            let independent = AtomicBool::new(false);
            assert!(regex
                .clone()
                .is_match_input(RegexInput::new("aaaa").with_cancel_flag(&independent))
                .unwrap());
        });
        cancel.store(true, Ordering::Relaxed);
        let start = Instant::now();
        resume.wait();
        cancelled(
            recv.recv_timeout(Duration::from_secs(2))
                .expect("VM did not cooperate"),
        );
        eprintln!("running VM cancellation observed in {:?}", start.elapsed());
        sibling.join().unwrap();
        worker.join().unwrap();
    });
    // A later request gets a fresh flag; the old flag remains permanently true.
    assert!(cancel.load(Ordering::Relaxed));
    assert!(regex.is_match("aaaa").unwrap());
}

#[test]
fn cancellation_survives_capture_atomic_and_seek_paths() {
    let cancel = AtomicBool::new(false);
    for (pattern, text, at) in [
        (
            r"(?>(a|aa)*\1)(b)\2$",
            format!("{}bb", "a".repeat(4096)),
            512,
        ),
        (
            r"((?:ab)+)(?=c)c\1$",
            format!("{}c{}", "ab".repeat(4096), "ab".repeat(4096)),
            3,
        ),
        (r"(?<!b)(a|aa)*\1$", "a".repeat(4096), 512),
    ] {
        cancel.store(false, Ordering::Relaxed);
        let regex = unlimited(pattern);
        let subject = ProbeInput {
            text,
            reads: AtomicUsize::new(0),
            at,
            hook: Box::new(|| cancel.store(true, Ordering::Relaxed)),
        };
        let result = regex.captures_input(RegexInput::new(&subject).with_cancel_flag(&cancel));
        cancelled(result);
        assert!(subject.reads.load(Ordering::Relaxed) >= at);
        assert!(regex.captures(&subject.text).unwrap().is_some());
    }
}

#[test]
fn unchanged_flag_preserves_native_matches_offsets_and_captures() {
    let cancel = AtomicBool::new(false);
    for (pattern, text) in [
        (r"(?<=x)(a+)\1", "xaaaa"),
        (r"(?>a|ab)c", "abc ac"),
        (r"(?i)([a-z]+)\1", "xAbAb"),
        (r"(a)?(?(1)b|c)", "ab c"),
        (r"(?<=a{1,3})b", "aaab"),
        (r"a+", "baaaa"),
    ] {
        let regex = unlimited(pattern);
        let input = RegexInput::new(text).with_cancel_flag(&cancel);
        assert_eq!(
            regex.is_match(text).unwrap(),
            regex.is_match_input(input.clone()).unwrap()
        );
        assert_eq!(
            regex.find(text).unwrap().map(|m| m.range()),
            regex.find_input(input.clone()).unwrap().map(|m| m.range())
        );
        let ordinary = regex
            .captures(text)
            .unwrap()
            .map(|c| c.iter().map(|m| m.map(|m| m.range())).collect::<Vec<_>>());
        let cooperative = regex
            .captures_input(input)
            .unwrap()
            .map(|c| c.iter().map(|m| m.map(|m| m.range())).collect::<Vec<_>>());
        assert_eq!(ordinary, cooperative);
    }
}

#[test]
fn delegated_search_returns_cancellation_instead_of_late_match_or_nonmatch() {
    for (pattern, text) in [("a+", "aaaa"), ("b+", "aaaa")] {
        let cancel = AtomicBool::new(false);
        let regex = unlimited(pattern);
        let subject = ProbeInput {
            text: text.into(),
            reads: AtomicUsize::new(0),
            at: 1,
            hook: Box::new(|| cancel.store(true, Ordering::Relaxed)),
        };
        // Whole-regex delegation enters as_bytes only after its pre-check.
        cancelled(regex.is_match_input(RegexInput::new(&subject).with_cancel_flag(&cancel)));
        assert!(cancel.load(Ordering::Relaxed));
    }
}

#[test]
#[ignore = "resource experiment: delegated engine has no mid-search cancellation callback"]
fn opaque_delegate_delays_observation_until_search_returns() {
    let regex = unlimited(r"a{8192}");
    let cancel = Arc::new(AtomicBool::new(false));
    let (entered_send, entered_recv) = mpsc::channel();
    let (result_send, result_recv) = mpsc::channel();
    let worker_cancel = Arc::clone(&cancel);
    let worker = std::thread::spawn(move || {
        let subject = ProbeInput {
            text: "a".repeat(8192),
            reads: AtomicUsize::new(0),
            at: 1,
            hook: Box::new(|| {
                entered_send.send(()).unwrap();
            }),
        };
        let start = Instant::now();
        let result =
            regex.is_match_input(RegexInput::new(&subject).with_cancel_flag(&worker_cancel));
        result_send.send((result, start.elapsed())).unwrap();
    });
    entered_recv.recv_timeout(Duration::from_secs(2)).unwrap();
    cancel.store(true, Ordering::Relaxed);
    // This is a test observation window, not a production deadline or policy.
    assert!(matches!(
        result_recv.recv_timeout(Duration::from_millis(20)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    let (result, elapsed) = result_recv.recv_timeout(Duration::from_secs(30)).unwrap();
    cancelled(result);
    eprintln!(
        "opaque delegated search returned cancellation after {:?}",
        elapsed
    );
    worker.join().unwrap();
}
