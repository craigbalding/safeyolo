//! Allocation control for the reached approval creation and detail paths.

use super::*;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicU64, Ordering},
};

struct ApprovalAllocations;
static ALLOCATED: AtomicU64 = AtomicU64::new(0);

#[global_allocator]
static ALLOCATOR: ApprovalAllocations = ApprovalAllocations;

unsafe impl GlobalAlloc for ApprovalAllocations {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            ALLOCATED.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            ALLOCATED.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let pointer = unsafe { System.realloc(pointer, layout, size) };
        if !pointer.is_null() {
            ALLOCATED.fetch_add(size as u64, Ordering::Relaxed);
        }
        pointer
    }
}

/// Run alone: counts requested Rust allocation bytes across all proxy threads,
/// including request, audit and transport work. Excludes fixture construction.
/// These are cumulative allocations, not live bytes, RSS or installed attribution.
#[tokio::test]
#[ignore = "resource control: run alone with --ignored --exact --nocapture"]
async fn creation_and_detail_allocations_do_not_scale_with_policy_host_lists() {
    let mut measurements = Vec::new();
    for credentials in [false, true] {
        for count in [0, 20_000] {
            let fixture = Fixture::new().await;
            let hosts: String = (0..count)
                .map(|index| format!("blocked-{index:05}.example.invalid\n"))
                .collect();
            fs::write(fixture.root.path().join("blocked.txt"), hosts).unwrap();
            let source = if credentials {
                fixture
                    .source()
                    .replace("egress='prompt'", "egress='allow'")
                    .replace("enabled=false", "enabled=true")
            } else {
                fixture.source()
            };
            fs::write(
                fixture.root.path().join("policy.toml"),
                format!(
                    "{source}\n[lists]\nblocked='blocked.txt'\n[hosts.'$blocked']\negress='deny'\n"
                ),
            )
            .unwrap();
            let fixture = fixture.restart().await;
            // Start the blocking pool before measuring the first submission.
            assert_eq!(
                fixture.admin("GET", "/admin/approvals", None).await.status,
                200
            );
            let headers = if credentials {
                format!("Authorization: Bearer {SECRET}\r\n")
            } else {
                String::new()
            };
            let mut phases = [0; 6];
            for _ in 0..3 {
                let before = ALLOCATED.load(Ordering::Relaxed);
                let blocked = fixture
                    .request("worker", fixture.address, "GET", "/marker", &headers)
                    .await;
                phases[0] += ALLOCATED.load(Ordering::Relaxed) - before;
                assert_eq!(blocked.status, 428, "{}", blocked.json());
                let id = blocked.id();
                let path = format!("/approvals/{id}");
                let before = ALLOCATED.load(Ordering::Relaxed);
                let detail = fixture.agent("worker", "GET", &path, None).await;
                phases[1] += ALLOCATED.load(Ordering::Relaxed) - before;
                assert_eq!(detail.status, 200, "{}", detail.json());
                assert_eq!(detail.json()["action"]["agent_id"], WORKER_ID);
                assert_eq!(
                    detail.json()["action"]["kind"],
                    if credentials {
                        "credential_allow"
                    } else {
                        "network_allow"
                    }
                );
                assert_eq!(
                    fixture.agent("helper", "GET", &path, None).await.status,
                    404
                );
                let before = ALLOCATED.load(Ordering::Relaxed);
                let detail = fixture.admin("GET", &format!("/admin{path}"), None).await;
                phases[2] += ALLOCATED.load(Ordering::Relaxed) - before;
                assert_eq!(detail.status, 200);
                let before = ALLOCATED.load(Ordering::Relaxed);
                let explanation = fixture
                    .admin("POST", &format!("/admin{path}/explain"), None)
                    .await;
                phases[3] += ALLOCATED.load(Ordering::Relaxed) - before;
                assert_eq!(explanation.status, 200, "{}", explanation.json());
                assert_eq!(fixture.resolve(&id, "reject").await.status, 200);
                let before = ALLOCATED.load(Ordering::Relaxed);
                let detail = fixture.agent("worker", "GET", &path, None).await;
                phases[4] += ALLOCATED.load(Ordering::Relaxed) - before;
                assert_eq!(detail.status, 200);
                assert_eq!(detail.json()["status"], "rejected");
                let before = ALLOCATED.load(Ordering::Relaxed);
                let detail = fixture.admin("GET", &format!("/admin{path}"), None).await;
                phases[5] += ALLOCATED.load(Ordering::Relaxed) - before;
                assert_eq!(detail.status, 200);
                assert_eq!(detail.json()["status"], "rejected");
            }
            println!(
                "credentials={credentials}, hosts={count}, three requests per phase [creation, pending agent detail, pending operator detail, explanation, rejected agent detail, rejected operator detail] allocated bytes={phases:?}"
            );
            measurements.push(phases);
            fixture.stop().await;
        }
    }
    for pair in measurements.chunks_exact(2) {
        // Pending reads must still compile the saved policy to check changes
        // outside the active snapshot. Rejected records use the same detail
        // worker without that required reload, isolating its ownership cost.
        for index in [0, 4, 5] {
            let (small, large) = (pair[0][index], pair[1][index]);
            assert!(
                large.saturating_sub(small) < 2 * 1024 * 1024,
                "approval path allocated at least 2 MiB more with an unrelated 20,000-host list: {measurements:?}"
            );
        }
    }
}
