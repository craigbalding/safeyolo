//! Native PTY selections are checked against canonical state and real effects.
use super::*;
use operator_pty::Terminal;

fn number(output: &str, agent: &str) -> usize {
    output
        .lines()
        .rev()
        .find_map(|line| {
            if !line.contains(&format!("agent={agent} ")) {
                return None;
            }
            line.split_once('#')?
                .1
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .unwrap_or_else(|| panic!("no numbered request for {agent}: {output}"))
}

async fn shown(fixture: &Fixture, request: &str) -> Value {
    success(
        fixture.root.path(),
        &["approvals", "show", request, "--json"],
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_watch_keeps_selected_input_arrivals_deferral_and_concurrent_outcomes() {
    let fixture = Fixture::new().await;
    configure(&fixture);
    let worker = fixture.network("worker", fixture.address).await;
    let helper = fixture.network("helper", fixture.address).await;
    assert_eq!((worker.status, helper.status), (428, 428));
    let worker_view = shown(&fixture, &worker.id()).await;
    let helper_view = shown(&fixture, &helper.id()).await;
    let mut terminal = Terminal::start(fixture.root.path(), &["watch", "--no-color"]);
    terminal
        .until(0, "PENDING APPROVALS: 2 (current state refreshed)")
        .await;
    terminal.until(0, "agent=worker ").await;
    let attached = terminal.until(0, "agent=helper ").await;
    assert!(
        attached.contains(&format!(
            "network_allow → {}",
            worker_view["approval"]["target"].as_str().unwrap()
        )),
        "{attached}"
    );
    assert!(
        !attached.contains("network_allow → unavailable"),
        "{attached}"
    );
    let worker_number = number(&attached, "worker");
    let helper_number = number(&attached, "helper");
    assert_ne!(worker_number, helper_number);
    terminal
        .until(
            0,
            &format!(
                "Type a displayed request number (for example, {})",
                worker_number.min(helper_number)
            ),
        )
        .await;
    terminal.send(&format!("{worker_number}\n"));
    let reviewed = terminal
        .until(
            0,
            &format!("Request #{worker_number} [choice / d / r / l / q]"),
        )
        .await;
    assert_eq!(
        reviewed
            .matches(worker_view["effect"].as_str().unwrap())
            .count(),
        1,
        "permission should appear once in its displayed choice: {reviewed}"
    );
    assert!(!terminal.output().contains("approve once"));
    assert!(!terminal.output().contains("approve run"));
    let empty = terminal.mark();
    terminal.send("\n");
    terminal.until(empty, "No decision selected").await;
    assert_eq!(shown(&fixture, &worker.id()).await["status"], "pending");
    let invalid = terminal.mark();
    terminal.send("a\n");
    terminal.until(invalid, "Choose a displayed number").await;
    assert_eq!(shown(&fixture, &worker.id()).await["status"], "pending");
    let unavailable = terminal.mark();
    terminal.send("c\n");
    terminal
        .until(unavailable, "Agent context is unavailable")
        .await;
    // This fixture has no signal store. Reattachment must keep approvals
    // current without scrolling the selected decision away every second.
    terminal.until(0, "Pending signals unavailable").await;
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert_eq!(
        terminal
            .output()
            .matches("Pending signals unavailable")
            .count(),
        1,
        "unchanged signal failure flooded the approval review: {}",
        terminal.output()
    );
    terminal.send("1");
    let arrival = terminal.mark();
    let peer = fixture.network("peer", fixture.address).await;
    assert_eq!(peer.status, 428);
    terminal
        .until(arrival, "PENDING APPROVALS: 3 (current state refreshed)")
        .await;
    let output = terminal.until(arrival, "agent=peer ").await;
    let peer_number = number(&output, "peer");
    assert_eq!(number(&output, "worker"), worker_number);
    assert_eq!(number(&output, "helper"), helper_number);
    terminal.send("\n");
    terminal
        .until(
            arrival,
            &format!("CANONICAL OUTCOME Request #{worker_number}: approved"),
        )
        .await;
    assert_eq!(shown(&fixture, &worker.id()).await["status"], "approved");
    assert_eq!(shown(&fixture, &helper.id()).await["status"], "pending");
    // Approval permits a later explicit attempt; the watcher does not replay it.
    assert!(
        timeout(Duration::from_millis(30), fixture.origin.accept())
            .await
            .is_err()
    );
    let origin = fixture.origin.clone();
    let served = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let _ = http_head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    assert_eq!(fixture.network("worker", fixture.address).await.status, 200);
    served.await.unwrap();

    let deferred = terminal.mark();
    terminal.send(&format!("{helper_number}\n"));
    terminal
        .until(deferred, &format!("Request #{helper_number} [choice"))
        .await;
    terminal.send("l\n");
    let unchanged = terminal
        .until(
            deferred,
            &format!("No decision sent for request #{helper_number}."),
        )
        .await;
    terminal
        .until(unchanged.rfind("No decision sent").unwrap(), "watch> ")
        .await;
    let listed = terminal.mark();
    terminal.send("list\n");
    terminal
        .until(
            listed,
            &format!("#{helper_number} [left pending] agent=helper"),
        )
        .await;
    terminal
        .until(
            listed,
            &format!(
                "Type a displayed request number (for example, {})",
                helper_number.min(peer_number)
            ),
        )
        .await;
    assert_eq!(shown(&fixture, &helper.id()).await["status"], "pending");

    let concurrent = terminal.mark();
    terminal.send(&format!("{peer_number}\n"));
    terminal
        .until(concurrent, &format!("Request #{peer_number} [choice"))
        .await;
    let peer_view = shown(&fixture, &peer.id()).await;
    let rejected = success(
        fixture.root.path(),
        &[
            "approvals",
            "reject",
            peer_view["approval_id"].as_str().unwrap(),
            "--json",
        ],
    )
    .await;
    assert_eq!(rejected["status"], "rejected");
    terminal
        .until(concurrent, "PENDING APPROVALS: 1 (current state refreshed)")
        .await;
    terminal.send("1\n");
    terminal
        .until(
            concurrent,
            &format!("CANONICAL OUTCOME Request #{peer_number}: rejected"),
        )
        .await;
    assert_eq!(fixture.network("peer", fixture.address).await.status, 428);
    assert_eq!(shown(&fixture, &peer.id()).await["status"], "rejected");
    // The old number cannot select the genuinely new request after rejection.
    let old_number = terminal.mark();
    terminal.send(&format!("{peer_number}\n"));
    terminal
        .until(old_number, "Resolved numbers are never reassigned")
        .await;

    let listed = success(fixture.root.path(), &["approvals", "list", "--json"]).await;
    assert!(
        listed["approvals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["approval_id"] == helper_view["approval_id"])
    );
    assert!(
        !listed["approvals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["approval_id"] == worker_view["approval_id"]
                || item["approval_id"] == peer_view["approval_id"])
    );
    terminal.finish().await;
    let audit = fs::read_to_string(fixture.root.path().join("audit.jsonl")).unwrap();
    for id in [&worker_view["approval_id"], &peer_view["approval_id"]] {
        assert_eq!(
            audit
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .filter(|event| event["event"] == "admin.approval_decided"
                    && event["details"]["approval_id"] == *id)
                .count(),
            1,
            "duplicate decision for {id}"
        );
    }
    fixture.stop().await;
}
