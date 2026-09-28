//! Native watcher publication while durable writers overlap.

use super::*;
use crate::approvals::{self, NetworkScope};
use std::sync::{
    Arc as Shared,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use tokio::{net::TcpListener, task::JoinHandle};

const SOURCE: &str = "# retain operator context\nversion='2.0'\nbudget=12000\n\
    [hosts]\n'*'={egress='deny'}\n'permitted.invalid'={egress='allow'}\n\
    'blocked.invalid'={egress='deny'}\n[agents.alice]\nfolder='/fixture/alice'\n\
    [agents.bob]\nfolder='/fixture/bob'\n";

async fn origin() -> (String, Shared<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Shared::new(AtomicUsize::new(0));
    let count = accepted.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let count = count.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 8192];
                let size = stream.read(&mut head).await.unwrap();
                assert!(size > 0);
                count.fetch_add(1, Ordering::SeqCst);
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
            });
        }
    });
    (format!("http://{address}"), accepted, task)
}

async fn host_request(fixture: &Fixture, host: &str, expected: u16, accepted: &AtomicUsize) {
    let before = accepted.load(Ordering::SeqCst);
    let mut stream = UnixStream::connect(fixture.directory.path().join("alice.sock"))
        .await
        .unwrap();
    let request = format!(
        "GET http://{host}:8123/c4 HTTP/1.1\r\nHost: {host}:8123\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut reply = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    let head = String::from_utf8_lossy(&reply);
    let status: u16 = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    assert_eq!(status, expected, "{host}: {head}");
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        before + usize::from(expected == 200),
        "{host} reached the origin in an unexpected policy state"
    );
}

async fn start() -> (Fixture, PathBuf, Shared<AtomicUsize>, JoinHandle<()>) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.toml");
    std::fs::write(&path, SOURCE).unwrap();
    let (parent, accepted, origin_task) = origin().await;
    let mut settings = config(directory.path());
    settings.policy_file = Some(path.clone());
    settings.parent_proxy = Some(parent);
    let fixture = Fixture::start(directory, settings).await;
    (fixture, path, accepted, origin_task)
}

#[test]
fn older_load_and_later_scoped_revoke_converge_without_resurrecting_access() {
    owned_child(
        "service_catalog_tests::contention::older_load_and_later_scoped_revoke_converge_without_resurrecting_access",
        older_load_and_revoke(),
    );
}

async fn older_load_and_revoke() {
    let (mut fixture, path, accepted, origin_task) = start().await;
    host_request(&fixture, "permitted.invalid", 200, &accepted).await;
    host_request(&fixture, "blocked.invalid", 403, &accepted).await;
    let scope = NetworkScope::new("first.invalid", None, None).unwrap();
    approvals::allow_host(&path, &scope, Some(100), |_| Ok(())).unwrap();

    let previous = fixture.runtime();
    let prior = previous.clone();
    let load_path = path.clone();
    let (loaded_tx, loaded_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let loader = std::thread::spawn(move || {
        crate::policy::after_next_baseline_read(move || {
            loaded_tx.send(()).unwrap();
            release_rx.recv_timeout(LIMIT).unwrap();
        });
        crate::policy_runtime::load(&load_path, None, prior.policy.as_ref(), &prior.audit).unwrap()
    });
    loaded_rx.recv_timeout(LIMIT).unwrap();
    // The old candidate has read the complete first edit. A later agent-scoped
    // revocation must remain visible to the next watcher observation.
    let revoke = NetworkScope::new("permitted.invalid", Some("alice"), None).unwrap();
    approvals::deny_host(&path, &revoke, None, |_| Ok(())).unwrap();
    release_tx.send(()).unwrap();
    let candidate = loader.join().unwrap();
    fixture.proxy.publish_policy(&previous, candidate).unwrap();
    host_request(&fixture, "permitted.invalid", 200, &accepted).await;
    host_request(&fixture, "first.invalid", 200, &accepted).await;
    assert!(fixture.proxy.reload_policy_if_changed().await.unwrap());
    host_request(&fixture, "permitted.invalid", 403, &accepted).await;
    host_request(&fixture, "first.invalid", 200, &accepted).await;
    host_request(&fixture, "blocked.invalid", 403, &accepted).await;
    assert!(!fixture.proxy.reload_policy_if_changed().await.unwrap());
    host_request(&fixture, "permitted.invalid", 403, &accepted).await;
    let saved = std::fs::read_to_string(&path).unwrap();
    assert!(saved.contains("# retain operator context"));
    assert!(saved.contains("first.invalid"));
    assert!(saved.contains("permitted.invalid"));
    origin_task.abort();
    timeout(LIMIT, fixture.proxy.shutdown()).await.unwrap();
}

#[test]
fn rejected_mutation_never_publishes_while_unrelated_writer_waits() {
    owned_child(
        "service_catalog_tests::contention::rejected_mutation_never_publishes_while_unrelated_writer_waits",
        rejected_mutation_and_waiter(),
    );
}

async fn rejected_mutation_and_waiter() {
    let (mut fixture, path, accepted, origin_task) = start().await;
    host_request(&fixture, "rejected.invalid", 403, &accepted).await;
    let rejected = NetworkScope::new("rejected.invalid", None, None).unwrap();
    let failed_path = path.clone();
    let (saved_tx, saved_rx) = mpsc::sync_channel(1);
    let (reject_tx, reject_rx) = mpsc::sync_channel(1);
    let failed_writer = std::thread::spawn(move || {
        let mut activations = 0;
        approvals::allow_host(&failed_path, &rejected, Some(100), |_| {
            activations += 1;
            if activations == 1 {
                saved_tx.send(()).unwrap();
                reject_rx.recv_timeout(LIMIT).unwrap();
                Err("injected candidate rejection".into())
            } else {
                Ok(())
            }
        })
    });
    saved_rx.recv_timeout(LIMIT).unwrap();
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("rejected.invalid")
    );
    host_request(&fixture, "rejected.invalid", 403, &accepted).await;

    let (waiting_tx, waiting_rx) = mpsc::sync_channel(1);
    let unrelated_path = path.clone();
    approvals::before_next_policy_lock(path.clone(), move || {
        waiting_tx.send(()).unwrap();
    });
    let unrelated = std::thread::spawn(move || {
        let scope = NetworkScope::new("unrelated.invalid", None, None).unwrap();
        approvals::allow_host(&unrelated_path, &scope, Some(100), |_| Ok(()))
    });
    waiting_rx.recv_timeout(LIMIT).unwrap();

    let prior = fixture.runtime();
    let loader_path = path.clone();
    let loader_previous = prior.clone();
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (read_tx, read_rx) = mpsc::sync_channel(1);
    let loader = std::thread::spawn(move || {
        crate::policy::after_next_baseline_read(move || {
            read_tx.send(()).unwrap();
        });
        started_tx.send(()).unwrap();
        crate::policy_runtime::load(
            &loader_path,
            None,
            loader_previous.policy.as_ref(),
            &loader_previous.audit,
        )
        .unwrap()
    });
    started_rx.recv_timeout(LIMIT).unwrap();
    assert!(matches!(
        read_rx.recv_timeout(Duration::from_millis(200)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    host_request(&fixture, "rejected.invalid", 403, &accepted).await;
    reject_tx.send(()).unwrap();
    let failure = failed_writer.join().unwrap().unwrap_err();
    assert_eq!(failure.kind, approvals::ErrorKind::Activation);
    unrelated.join().unwrap().unwrap();
    read_rx.recv_timeout(LIMIT).unwrap();
    let candidate = loader.join().unwrap();
    fixture.proxy.publish_policy(&prior, candidate).unwrap();
    host_request(&fixture, "rejected.invalid", 403, &accepted).await;
    assert!(fixture.proxy.reload_policy_if_changed().await.unwrap());
    host_request(&fixture, "rejected.invalid", 403, &accepted).await;
    host_request(&fixture, "unrelated.invalid", 200, &accepted).await;
    host_request(&fixture, "blocked.invalid", 403, &accepted).await;
    let saved = std::fs::read_to_string(&path).unwrap();
    assert!(!saved.contains("rejected.invalid"));
    assert!(saved.contains("unrelated.invalid"));
    assert!(saved.contains("# retain operator context"));
    origin_task.abort();
    timeout(LIMIT, fixture.proxy.shutdown()).await.unwrap();
}
