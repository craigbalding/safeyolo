//! Owned in-memory task lifetimes. No sockets, process sampling or API handlers.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

struct Dropped(Arc<Mutex<Vec<&'static str>>>, &'static str);
impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.lock().unwrap().push(self.1);
    }
}
fn marker(events: &Arc<Mutex<Vec<&'static str>>>, name: &'static str) -> Dropped {
    Dropped(events.clone(), name)
}

#[tokio::test(start_paused = true)]
async fn transferred_child_survives_main_completion_and_joins_before_client_drop() {
    let (stop, receiver) = watch::channel(false);
    let owner = ConnectionTasks::new(receiver);
    let events = Arc::new(Mutex::new(Vec::new()));
    let child = marker(&events, "websocket");
    let client = marker(&events, "client");
    let (started, ready) = oneshot::channel();
    let child_owner = owner.clone();
    let supervisor = tokio::spawn(async move {
        let _client = client;
        owner
            .run(async move {
                child_owner.spawn(async move {
                    let _child = child;
                    let _ = started.send(());
                    std::future::pending::<()>().await;
                });
                Ok(())
            })
            .await;
    });
    ready.await.unwrap();
    tokio::task::yield_now().await;
    assert!(
        !supervisor.is_finished(),
        "ordinary transfer must not abort the child"
    );
    assert!(events.lock().unwrap().is_empty());
    stop.send_replace(true);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(9)).await;
    assert!(!supervisor.is_finished());
    tokio::time::advance(Duration::from_secs(1)).await;
    supervisor.await.unwrap();
    assert_eq!(*events.lock().unwrap(), ["websocket", "client"]);
}

#[tokio::test]
async fn main_error_and_panic_cancel_adopted_children() {
    for panic in [false, true] {
        let (_stop, receiver) = watch::channel(false);
        let owner = ConnectionTasks::new(receiver);
        let events = Arc::new(Mutex::new(Vec::new()));
        let child = marker(&events, "child");
        let descendants = owner.clone();
        owner
            .run(async move {
                descendants.spawn(async move {
                    let _child = child;
                    std::future::pending::<()>().await;
                });
                if panic {
                    panic!("owned main failure");
                }
                Err("owned main failure".into())
            })
            .await;
        assert_eq!(*events.lock().unwrap(), ["child"]);
        let weak = Arc::downgrade(&owner);
        drop(owner);
        assert!(
            weak.upgrade().is_none(),
            "joined task captures must release the owner"
        );
    }
}

#[tokio::test]
async fn tunnel_error_and_panic_cancel_children_after_outer_transfer() {
    for panic in [false, true] {
        let (_stop, receiver) = watch::channel(false);
        let owner = ConnectionTasks::new(receiver);
        let events = Arc::new(Mutex::new(Vec::new()));
        let child = marker(&events, "nested");
        let nested = owner.clone();
        owner.spawn_upgrade(async move {
            nested.spawn(async move {
                let _child = child;
                std::future::pending::<()>().await;
            });
            if panic {
                panic!("owned tunnel failure");
            }
            Err("owned tunnel failure".into())
        });
        owner.run(async { Ok(()) }).await;
        assert_eq!(*events.lock().unwrap(), ["nested"]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_registration_is_aborted_and_running_blocking_work_is_joined() {
    let (_stop, receiver) = watch::channel(false);
    let owner = ConnectionTasks::new(receiver);
    let events = Arc::new(Mutex::new(Vec::new()));
    let producer = marker(&events, "producer");
    let child = marker(&events, "late-child");
    let client = marker(&events, "client");
    let polled = Arc::new(AtomicBool::new(false));
    let child_polled = polled.clone();
    let (started, ready) = oneshot::channel();
    let (register, registration) = std::sync::mpsc::channel();
    let (registered, registration_done) = oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let descendants = owner.clone();
    let worker = owner.spawn_blocking(move || {
        let _producer = producer;
        let _ = started.send(());
        registration.recv().unwrap();
        descendants.spawn(async move {
            let _child = child;
            child_polled.store(true, Ordering::Release);
            std::future::pending::<()>().await;
        });
        let _ = registered.send(());
        released.recv().unwrap();
    });
    ready.await.unwrap();
    owner.abort_all();
    let cleanup = owner.clone();
    let supervisor = tokio::spawn(async move {
        let _client = client;
        cleanup.run(async { Ok(()) }).await;
    });
    register.send(()).unwrap();
    registration_done.await.unwrap();
    assert!(
        !supervisor.is_finished(),
        "abort cannot detach an already-running scanner"
    );
    assert!(
        !polled.load(Ordering::Acquire),
        "late registration must abort before polling"
    );
    release.send(()).unwrap();
    worker.await.unwrap();
    supervisor.await.unwrap();
    let events = events.lock().unwrap();
    assert!(events.contains(&"producer"));
    assert!(events.contains(&"late-child"));
    assert_eq!(events.last(), Some(&"client"));
}

#[tokio::test]
async fn receiver_drop_aborts_actual_driver_and_leaf_panic_remains_local() {
    let (_stop, receiver) = watch::channel(false);
    let owner = ConnectionTasks::new(receiver);
    let events = Arc::new(Mutex::new(Vec::new()));
    let driver = marker(&events, "driver");
    let handle = owner.spawn_result(async move {
        let _driver = driver;
        std::future::pending::<()>().await;
    });
    drop(handle); // same abort ownership as the upstream response body
    let failed = owner.spawn_result(async {
        panic!("owned reader failure");
    });
    assert!(
        failed.await.is_err(),
        "relay receives task_error rather than a fabricated result"
    );
    let healthy = owner.spawn_result(async { 7 });
    assert_eq!(
        healthy.await.unwrap(),
        7,
        "leaf failure does not cancel the relay supervisor"
    );
    owner.run(async { Ok(()) }).await;
    assert_eq!(*events.lock().unwrap(), ["driver"]);
}

#[tokio::test]
async fn hyper_executor_job_is_joined_by_the_same_owner() {
    use hyper::rt::Executor as _;
    let (_stop, receiver) = watch::channel(false);
    let owner = ConnectionTasks::new(receiver);
    let events = Arc::new(Mutex::new(Vec::new()));
    let job = marker(&events, "hyper-job");
    Executor(owner.clone()).execute(async move {
        let _job = job;
        std::future::pending::<()>().await;
    });
    owner.abort_all();
    owner.run(async { Ok(()) }).await;
    assert_eq!(*events.lock().unwrap(), ["hyper-job"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_owner_never_invokes_new_blocking_work() {
    let (_stop, receiver) = watch::channel(false);
    let owner = ConnectionTasks::new(receiver);
    owner.abort_all();
    let called = Arc::new(AtomicBool::new(false));
    let work_called = called.clone();
    let work = owner.spawn_blocking(move || work_called.store(true, Ordering::Release));
    assert!(work.await.is_err());
    owner.run(async { Ok(()) }).await;
    assert!(!called.load(Ordering::Acquire));
}

#[tokio::test(start_paused = true)]
async fn dropped_listener_sender_starts_grace_without_a_self_keeping_sender() {
    let (stop, receiver) = watch::channel(false);
    // The accept loop retains only this weak signal for its own error path.
    let stop = Arc::new(stop);
    let error_signal = Arc::downgrade(&stop);
    let owner = ConnectionTasks::new(receiver);
    let events = Arc::new(Mutex::new(Vec::new()));
    let child = marker(&events, "child");
    owner.spawn(async move {
        let _child = child;
        std::future::pending::<()>().await;
    });
    drop(stop);
    assert!(error_signal.upgrade().is_none());
    let started = tokio::time::Instant::now();
    owner.run(async { Ok(()) }).await;
    assert_eq!(started.elapsed(), Duration::from_secs(10));
    assert_eq!(*events.lock().unwrap(), ["child"]);
}
