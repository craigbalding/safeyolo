//! Owned decoded-message/spool and in-memory relay observations. No sockets,
//! HTTP service, operational files, or process sampling are involved.

use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio::io::AsyncWriteExt;

fn exchange(runtime: &Runtime, id: &str) -> Arc<Exchange> {
    runtime
        .traffic_view
        .begin(crate::traffic_view::RequestInfo {
            id: id.into(),
            connection_id: ID.into(),
            agent: Some("alice".into()),
            method: "GET".into(),
            url: "http://owned.invalid/socket".into(),
            headers: Vec::new(),
            started: crate::circuit_runtime::now(),
        })
}

pub(super) fn live_session(runtime: &Arc<Runtime>) -> (Session, LiveSession) {
    let live = exchange(runtime, "req-owned");
    live.request_body(Some(&[]));
    live.response_head(101, Vec::new());
    live.response_body(Some(&[]));
    live.finish(None);
    let mut session = session(runtime);
    session.live = Some(live);
    let guard = session.start_live();
    (session, guard)
}

fn transcript(runtime: &Runtime) -> Value {
    runtime
        .traffic_view
        .websocket_messages("req-owned")
        .unwrap()
}

fn page(runtime: &Runtime, message: u64, offset: u64, length: usize) -> Vec<u8> {
    let value = runtime
        .traffic_view
        .websocket_message_body("req-owned", message, offset, length)
        .unwrap();
    assert_eq!(value["available"], true);
    STANDARD
        .decode(value["data_base64"].as_str().unwrap())
        .unwrap()
}

#[tokio::test]
async fn shared_complete_content_ranges_survive_forwarding_without_moving_its_reader() {
    for payload in [
        b"small\0\xff".to_vec(),
        (0..70_000).map(|i| (i % 251) as u8).collect(),
    ] {
        let wire = frame(OpCode::Data(Data::Binary), true, true, &payload);
        let Event::Message(message) = Reader::new(Cursor::new(wire), true, None)
            .read()
            .await
            .unwrap()
        else {
            panic!("complete message missing");
        };
        assert_eq!(message.spilled(), payload.len() > 64 * 1024);
        let content = message.content();
        let same = message.content();
        assert!(Arc::ptr_eq(&content, &same));
        assert_eq!(content.len(), payload.len() as u64);
        assert_eq!(&*content.read_range(2, 3).unwrap(), &payload[2..5]);
        assert!(content.read_range(u64::MAX, usize::MAX).unwrap().is_empty());
        assert_eq!(
            &*content
                .read_range(payload.len() as u64 - 2, usize::MAX)
                .unwrap(),
            &payload[payload.len() - 2..]
        );

        let mut forwarded = Vec::new();
        Writer::new(&mut forwarded, false, None)
            .message(message)
            .await
            .unwrap();
        let Event::Message(delivered) = Reader::new(Cursor::new(forwarded), false, None)
            .read()
            .await
            .unwrap()
        else {
            panic!("forwarded complete message missing");
        };
        assert_eq!(
            &*delivered.content().read_range(0, payload.len()).unwrap(),
            &payload
        );
        // The forwarding message was consumed; its retained content remains
        // valid and shares the original allocation/file rather than a copy.
        assert_eq!(&*content.read_range(0, 5).unwrap(), &payload[..5]);
    }
}

#[tokio::test]
async fn duplex_relay_retains_dropped_and_spooled_messages_and_open_session() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Arc::new(runtime(directory.path()));
    let (session, guard) = live_session(&runtime);
    let memory = memory_runtime::WebSocket::new(&runtime, ID, HOST);
    let (client, client_peer) = tokio::io::duplex(131_072);
    let (server, server_peer) = tokio::io::duplex(131_072);
    let (_stop, stop) = watch::channel(false);
    let owner = ConnectionTasks::new(stop.clone());
    let task_owner = owner.clone();
    let task = tokio::spawn(async move {
        let _guard = guard;
        relay(
            Box::new(client),
            Box::new(server),
            Negotiated {
                client: None,
                server: None,
                subprotocol: None,
            },
            session,
            stop,
            memory,
            task_owner,
        )
        .await
    });
    let (client_read, mut client_write) = tokio::io::split(client_peer);
    let (server_read, mut server_write) = tokio::io::split(server_peer);
    let mut client_read = Reader::new(client_read, false, None);
    let mut server_read = Reader::new(server_read, true, None);

    client_write
        .write_all(&frame(OpCode::Control(Control::Ping), true, true, b"ping"))
        .await
        .unwrap();
    client_write
        .write_all(&frame(OpCode::Data(Data::Text), false, true, b"PROJ-"))
        .await
        .unwrap();
    client_write
        .write_all(&frame(OpCode::Data(Data::Continue), true, true, b"12345"))
        .await
        .unwrap();
    let payload: Vec<_> = (0..70_000).map(|i| (i % 251) as u8).collect();
    client_write
        .write_all(&frame(OpCode::Data(Data::Binary), true, true, &payload))
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), server_read.read())
            .await
            .unwrap()
            .unwrap(),
        Event::Ping(_)
    ));
    let Event::Message(forwarded) =
        tokio::time::timeout(Duration::from_secs(2), server_read.read())
            .await
            .unwrap()
            .unwrap()
    else {
        panic!("allowed binary missing (dropped text must not forward)");
    };
    assert_eq!(forwarded.kind, MessageType::Binary);
    assert!(forwarded.spilled());
    assert_eq!(
        &*forwarded.content().read_range(0, payload.len()).unwrap(),
        &payload
    );

    server_write
        .write_all(&frame(
            OpCode::Data(Data::Text),
            true,
            false,
            b"server reply",
        ))
        .await
        .unwrap();
    let Event::Message(reply) = tokio::time::timeout(Duration::from_secs(2), client_read.read())
        .await
        .unwrap()
        .unwrap()
    else {
        panic!("server reply missing");
    };
    assert_eq!(reply.with_text(str::to_owned).unwrap(), "server reply");
    let observed = transcript(&runtime);
    let messages = observed["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 3, "control frames are not data messages");
    assert_eq!(observed["websocket"]["state"], "open");
    assert!(observed["websocket"]["timestamp_end"].is_null());
    assert_eq!(
        runtime.traffic_view.detail("req-owned").unwrap()["state"],
        "websocket_open"
    );
    for (index, (kind, from_client, dropped)) in [
        ("text", true, true),
        ("binary", true, false),
        ("text", false, false),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(messages[index]["type"], kind);
        assert_eq!(messages[index]["from_client"], from_client);
        assert_eq!(messages[index]["dropped"], dropped);
        assert_eq!(messages[index]["injected"], false);
        if index != 0 {
            assert!(
                messages[index]["timestamp"].as_f64().unwrap()
                    >= messages[index - 1]["timestamp"].as_f64().unwrap()
            );
        }
    }
    assert_eq!(page(&runtime, 0, 0, 20), b"PROJ-12345");
    assert_eq!(page(&runtime, 1, 65_530, 30), payload[65_530..65_560]);
    assert_eq!(page(&runtime, 2, 0, 20), b"server reply");

    runtime.traffic_view.configure(1, 1 << 20);
    let other = exchange(&runtime, "terminal-http");
    other.response_head(200, Vec::new());
    other.finish(None);
    drop(other);
    assert!(runtime.traffic_view.detail("terminal-http").is_none());
    assert!(
        runtime.traffic_view.detail("req-owned").is_some(),
        "open WS must survive terminal-row eviction"
    );

    let mut close = 1000_u16.to_be_bytes().to_vec();
    close.extend_from_slice(b"owned close reason");
    client_write
        .write_all(&frame(OpCode::Control(Control::Close), true, true, &close))
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), server_read.read())
            .await
            .unwrap()
            .unwrap(),
        Event::Close(_)
    ));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), client_read.read())
            .await
            .unwrap()
            .unwrap(),
        Event::Close(_)
    ));
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    owner.run(async { Ok(()) }).await;
    let closed = transcript(&runtime);
    assert_eq!(closed["websocket"]["state"], "closed");
    assert_eq!(closed["websocket"]["closed_by_client"], true);
    assert_eq!(closed["websocket"]["close_code"], 1000);
    assert_eq!(closed["websocket"]["close_reason"], "owned close reason");
    assert!(
        closed["websocket"]["timestamp_end"].as_f64().unwrap()
            >= messages[2]["timestamp"].as_f64().unwrap()
    );
    assert_eq!(closed["messages"], observed["messages"]);
    assert!(
        !std::fs::read_to_string(directory.path().join("diagnostics.jsonl"))
            .unwrap()
            .contains("owned close reason")
    );
    let other = exchange(&runtime, "after-close");
    other.finish(None);
    drop(other);
    assert!(
        runtime.traffic_view.detail("req-owned").is_none(),
        "closed released session becomes eligible for eviction"
    );
    assert!(runtime.audit.shutdown(Duration::from_secs(1)).unwrap());
}

#[tokio::test]
async fn reached_drop_and_message_survive_diagnostic_failure() {
    let directory = tempfile::tempdir().unwrap();
    let mut runtime = runtime(directory.path());
    runtime.events = Arc::new(Mutex::new(
        std::fs::File::open(directory.path().join("diagnostics.jsonl")).unwrap(),
    ));
    let runtime = Arc::new(runtime);
    let (session, guard) = live_session(&runtime);
    let memory = memory_runtime::WebSocket::new(&runtime, ID, HOST);
    let wire = frame(OpCode::Data(Data::Text), true, true, b"PROJ-12345");
    let (sender, mut received) = mpsc::channel(1);
    let (_closing, close) = watch::channel(None);
    let owner = ConnectionTasks::new(watch::channel(false).1);
    let result = read_messages(
        Reader::new(Cursor::new(wire), true, None),
        true,
        sender,
        close,
        Arc::new(session),
        Arc::new(InspectionLifetime {
            cancelled: AtomicBool::new(false),
            publication: Mutex::new(()),
        }),
        memory.monitor(),
        owner.clone(),
    )
    .await;
    owner.run(async { Ok(()) }).await;
    assert!(matches!(
        result,
        Finished::Reader(Closing {
            outcome: "inspection_error",
            ..
        })
    ));
    assert!(received.recv().await.is_none());
    let observed = transcript(&runtime);
    assert_eq!(observed["messages"].as_array().unwrap().len(), 1);
    assert_eq!(observed["messages"][0]["dropped"], true);
    assert_eq!(page(&runtime, 0, 0, 20), b"PROJ-12345");
    drop(guard);
    assert!(transcript(&runtime)["websocket"]["timestamp_end"].is_number());
    drop(memory);
    assert!(runtime.audit.shutdown(Duration::from_secs(1)).unwrap());
}

#[tokio::test]
async fn unpolled_upgrade_guard_ends_session_despite_a_retained_exchange() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Arc::new(runtime(directory.path()));
    let (session, guard) = live_session(&runtime);
    let late_observer = session.live.as_ref().unwrap().clone();
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let _guard = guard;
        let _session = session;
        std::future::pending::<()>().await;
    });
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    let ended = transcript(&runtime);
    assert_eq!(ended["websocket"]["state"], "incomplete");
    assert!(ended["websocket"]["timestamp_end"].is_number());
    assert!(ended["websocket"]["close_code"].is_null());
    assert!(ended["websocket"]["closed_by_client"].is_null());
    drop(late_observer);
    assert_eq!(
        transcript(&runtime),
        ended,
        "last release must not rewrite terminal facts"
    );
    assert!(runtime.audit.shutdown(Duration::from_secs(1)).unwrap());
}
