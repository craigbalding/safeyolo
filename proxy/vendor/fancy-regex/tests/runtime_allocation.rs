//! Allocation failures are injected only on the current test thread, after
//! compilation and delegated-engine caches have been warmed. No real OOM.
use fancy_regex::{Error, Regex, RegexBuilder, RegexInput, RegexOptionsBuilder, RuntimeError};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

thread_local! {
    static FAIL_AT: Cell<usize> = const { Cell::new(0) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static CANCEL_AT: Cell<usize> = const { Cell::new(0) };
}
static CANCEL: AtomicBool = AtomicBool::new(false);
static LIVE_BYTES: AtomicIsize = AtomicIsize::new(0);
struct Allocator;
fn fail_now() -> bool {
    let _ = CANCEL_AT.try_with(|remaining| {
        let value = remaining.get();
        if value > 0 {
            remaining.set(value - 1);
            if value == 1 {
                CANCEL.store(true, Ordering::Relaxed);
            }
        }
    });
    let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
    FAIL_AT
        .try_with(|remaining| {
            let value = remaining.get();
            if value == 0 {
                false
            } else {
                remaining.set(value - 1);
                value == 1
            }
        })
        .unwrap_or(false)
}
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if fail_now() {
            return std::ptr::null_mut();
        }
        let result = unsafe { System.alloc(layout) };
        if !result.is_null() {
            LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        result
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if fail_now() {
            return std::ptr::null_mut();
        }
        let result = unsafe { System.alloc_zeroed(layout) };
        if !result.is_null() {
            LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        result
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if fail_now() {
            return std::ptr::null_mut();
        }
        let result = unsafe { System.realloc(pointer, layout, size) };
        if !result.is_null() {
            LIVE_BYTES.fetch_add(size as isize - layout.size() as isize, Ordering::Relaxed);
        }
        result
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn unlimited(pattern: &str) -> Regex {
    RegexBuilder::new(pattern)
        .stack_limit(None)
        .backtrack_limit(usize::MAX)
        .build()
        .unwrap()
}

#[test]
fn default_limit_is_preserved_and_explicit_none_matches_large_subject() {
    let text = "a".repeat(1_000_100);
    let bounded = RegexBuilder::new(r"(a|aa)*\1$")
        .backtrack_limit(usize::MAX)
        .build()
        .unwrap();
    assert!(matches!(
        bounded.find(&text),
        Err(Error::RuntimeError(RuntimeError::StackOverflow))
    ));
    let mut options = RegexOptionsBuilder::new();
    options.stack_limit(None).backtrack_limit(usize::MAX);
    let grown = options.build(r"(a|aa)*\1$".into()).unwrap();
    assert_eq!(grown.find(&text).unwrap().unwrap().range(), 0..text.len());
    let small = RegexBuilder::new(r"(a|aa)*\1$")
        .stack_limit(Some(1))
        .build()
        .unwrap();
    assert!(matches!(
        small.find("aaaa"),
        Err(Error::RuntimeError(RuntimeError::StackOverflow))
    ));
}

#[test]
fn injected_allocation_failures_return_errors_and_next_search_recovers() {
    // Cover repeated capture saves, explicit atomic-group stack and cut scratch,
    // delegated captures, and final returned capture-vector allocation.
    let mut injected = 0;
    for (pattern, subject) in [
        (r"(a|aa)*\1$", "a".repeat(2048)),
        (r"(?>(a|aa)*)(b)\2$", format!("{}bb", "a".repeat(2048))),
        (
            r"((?:ab)+)(?=c)c\1$",
            format!("{}c{}", "ab".repeat(64), "ab".repeat(64)),
        ),
    ] {
        let regex = unlimited(pattern);
        assert!(regex.captures(&subject).unwrap().is_some());
        ALLOCATIONS.with(|count| count.set(0));
        let warm = regex.captures(&subject).unwrap();
        let allocations = ALLOCATIONS.with(Cell::get);
        drop(warm);
        assert!(allocations > 0);
        injected += allocations;
        for nth in 1..=allocations {
            FAIL_AT.with(|value| value.set(nth));
            let result = regex.captures(&subject);
            FAIL_AT.with(|value| value.set(0));
            assert!(
                matches!(
                    result,
                    Err(Error::RuntimeError(RuntimeError::AllocationFailed))
                ),
                "allocation {} of {}",
                nth,
                allocations
            );
            assert!(regex.captures(&subject).unwrap().is_some());
        }
    }
    eprintln!(
        "Injected {} individual VM allocation failures and verified recovery",
        injected
    );
}

#[test]
fn unbounded_search_releases_vm_buffers_on_success_and_error() {
    let regex = unlimited(r"(a|aa)*\1$");
    let text = "a".repeat(1_000_100);
    assert!(regex.is_match("aaaa").unwrap());
    let before = LIVE_BYTES.load(Ordering::Relaxed);
    ALLOCATIONS.with(|count| count.set(0));
    assert!(regex.is_match(&text).unwrap());
    let allocations = ALLOCATIONS.with(Cell::get);
    let after = LIVE_BYTES.load(Ordering::Relaxed);
    // Only cache/accounting tolerance; this does not limit inspected subjects.
    assert!(
        after - before < 1024 * 1024,
        "VM buffers remained live: {} bytes",
        after - before
    );
    FAIL_AT.with(|value| value.set(allocations));
    let result = regex.is_match(&text);
    FAIL_AT.with(|value| value.set(0));
    assert!(matches!(
        result,
        Err(Error::RuntimeError(RuntimeError::AllocationFailed))
    ));
    assert!(LIVE_BYTES.load(Ordering::Relaxed) - before < 1024 * 1024);
    assert!(regex.is_match("aaaa").unwrap());
}

#[test]
fn concurrent_searches_do_not_share_mutable_vm_buffers() {
    let regex = unlimited(r"(a|aa)*\1$");
    let text = "a".repeat(1_000_100);
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..4)
            .map(|_| {
                let regex = regex.clone();
                let text = &text;
                scope.spawn(move || {
                    for _ in 0..2 {
                        assert_eq!(regex.find(text).unwrap().unwrap().range(), 0..text.len());
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    });
}

#[test]
fn cancellation_after_large_growth_releases_scratch_and_next_request_recovers() {
    let regex = unlimited(r"(a|aa)*\1$");
    let text = "a".repeat(1_000_100);
    assert!(regex.is_match(&text).unwrap());
    ALLOCATIONS.with(|count| count.set(0));
    assert!(regex.is_match(&text).unwrap());
    let allocations = ALLOCATIONS.with(Cell::get);
    let before = LIVE_BYTES.load(Ordering::Relaxed);
    CANCEL.store(false, Ordering::Relaxed);
    // Cancel inside the final growth allocation, after the VM accumulated large
    // buffers. The allocator still succeeds: this is cancellation, not OOM.
    CANCEL_AT.with(|value| value.set(allocations));
    let result = regex.is_match_input(RegexInput::new(&text).with_cancel_flag(&CANCEL));
    CANCEL_AT.with(|value| value.set(0));
    assert!(matches!(
        result,
        Err(Error::RuntimeError(RuntimeError::Cancelled))
    ));
    assert!(LIVE_BYTES.load(Ordering::Relaxed) - before < 1024 * 1024);
    assert!(regex.is_match("aaaa").unwrap());
}
