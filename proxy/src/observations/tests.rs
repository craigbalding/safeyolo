use super::*;
use crate::Proxy;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::{Duration, timeout},
};

const WAIT: Duration = Duration::from_secs(5);
fn identity() -> crate::ConnectionIdentity {
    crate::ConnectionIdentity {
        agent_id: "alice".into(),
        run: None,
        connection_id: "conn-local".into(),
        source_id: None,
    }
}
fn bus(limits: Limits) -> Arc<ObservationBus> {
    ObservationBus::new(
        "installation".into(),
        "runtime".into(),
        limits,
        Arc::new(Counters::default()),
    )
}
fn sample(bus: &Arc<ObservationBus>) -> Observation {
    let identity = identity();
    Observation {
        id: bus.id(0),
        timestamp: Timestamp {
            wall_unix_ns: 0,
            monotonic_ns: 0,
        },
        timestamp_resolution: bus.session.timestamp_resolution,
        point: Point::AgentUds,
        layer: Layer::TransportStream,
        direction: Direction::ToProxy,
        transport: Transport::Unix,
        connection_id: identity.connection_id.clone(),
        request_id: None,
        protocol_stream_id: None,
        agent: Some(identity.agent_id.clone()),
        attribution: identity.audit_attribution(),
        input_span: None,
        parent_observation: None,
        transformed: false,
        stream_offset: Some(0),
        observed_length: Some(1),
        captured_length: 0,
        state: State::Chunk,
    }
}
async fn receive(consumer: &mut Consumer) -> Arc<Record> {
    let future = consumer.recv();
    fn require_send<T: Send>(_: &T) {}
    require_send(&future);
    timeout(WAIT, future)
        .await
        .expect("observation delivery")
        .expect("open bus")
}
async fn drain(consumer: &mut Consumer, bus: &ObservationBus) -> Vec<Arc<Record>> {
    let last = bus.sequence.load(Ordering::Acquire) - 1;
    let mut records = Vec::new();
    while consumer.next <= last {
        records.push(receive(consumer).await);
    }
    records
}
fn observations(records: &[Arc<Record>]) -> Vec<&Observation> {
    records
        .iter()
        .filter_map(|record| match record.as_ref() {
            Record::Observation(o) => Some(o.as_ref()),
            Record::Gap(_) => None,
        })
        .collect()
}

#[tokio::test]
async fn item_and_byte_limits_report_exact_canonical_loss_including_tail() {
    for limits in [
        Limits {
            items: 1,
            bytes: 100_000,
        },
        Limits {
            items: 100,
            bytes: 1,
        },
    ] {
        let bus = bus(limits);
        let mut consumer = bus.subscribe(ConsumerKind::Metrics, Limits::default());
        let n = 1000;
        for _ in 0..n {
            bus.emit(sample(&bus));
        }
        {
            let queue = bus.queue.lock().unwrap();
            assert!(queue.records.len() <= limits.items);
            assert!(queue.bytes <= limits.bytes);
        }
        let records = drain(&mut consumer, &bus).await;
        let accepted = usize::from(limits.bytes != 1);
        assert_eq!(observations(&records).len(), accepted);
        let Record::Gap(gap) = records.last().unwrap().as_ref() else {
            panic!("missing loss tail")
        };
        assert_eq!(
            (gap.first_sequence, gap.last_sequence, gap.count),
            (accepted as u64 + 1, n, n - accepted as u64)
        );
        assert!(matches!(
            gap.reason,
            LossReason::CanonicalAdmissionUnavailable
        ));
        bus.emit(sample(&bus));
        let recovered = receive(&mut consumer).await;
        if accepted != 0 {
            assert_eq!(recovered.range(), (n + 1, n + 1));
        }
        assert_eq!(
            bus.counters.dropped[0].load(Ordering::Relaxed),
            n - accepted as u64 + u64::from(accepted == 0)
        );
    }
}

#[tokio::test]
async fn a_slow_consumer_loses_only_its_own_sequences() {
    let bus = bus(Limits::default());
    let mut slow = bus.subscribe(
        ConsumerKind::Capture,
        Limits {
            items: 1,
            bytes: 100_000,
        },
    );
    let mut healthy = bus.subscribe(ConsumerKind::Metrics, Limits::default());
    for sequence in 1..=100 {
        bus.emit(sample(&bus));
        assert_eq!(receive(&mut healthy).await.range(), (sequence, sequence));
    }
    assert_eq!(receive(&mut slow).await.range(), (1, 1));
    let gap = receive(&mut slow).await;
    let Record::Gap(gap) = gap.as_ref() else {
        panic!("missing slow-consumer gap")
    };
    assert_eq!(
        (gap.first_sequence, gap.last_sequence, gap.count),
        (2, 100, 99)
    );
    assert!(matches!(
        gap.reason,
        LossReason::ConsumerAdmissionUnavailable
    ));
    assert_eq!(bus.counters.dropped[0].load(Ordering::Relaxed), 0);
    assert_eq!(bus.counters.consumer_dropped[0].load(Ordering::Relaxed), 0);
    assert_eq!(bus.counters.consumer_dropped[1].load(Ordering::Relaxed), 99);
    bus.emit(sample(&bus));
    assert_eq!(receive(&mut healthy).await.range(), (101, 101));
    assert_eq!(receive(&mut slow).await.range(), (101, 101));
}

#[tokio::test]
async fn concurrent_admission_preserves_order_and_explicit_gaps() {
    let bus = bus(Limits {
        items: 100,
        bytes: 100_000,
    });
    let mut consumer = bus.subscribe(ConsumerKind::Metrics, Limits::default());
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let bus = &bus;
            scope.spawn(move || {
                for _ in 0..1000 {
                    bus.emit(sample(bus));
                }
            });
        }
    });
    let records = drain(&mut consumer, &bus).await;
    let mut next = 1;
    for record in records {
        let (first, last) = record.range();
        assert_eq!(first, next);
        assert!(last >= first);
        next = last + 1;
    }
    assert_eq!(next, 4001);
}

#[tokio::test]
async fn namespaces_and_reconnect_sessions_do_not_reuse_observation_identity() {
    let first = bus(Limits::default());
    let restarted = ObservationBus::new(
        "installation".into(),
        "runtime-two".into(),
        Limits::default(),
        Arc::default(),
    );
    let other = ObservationBus::new(
        "other-installation".into(),
        "runtime".into(),
        Limits::default(),
        Arc::default(),
    );
    let ids = [
        first.emit(sample(&first)),
        restarted.emit(sample(&restarted)),
        other.emit(sample(&other)),
    ];
    assert_ne!(ids[0], ids[1]);
    assert_ne!(ids[0], ids[2]);
    let one = first.subscribe(ConsumerKind::Capture, Limits::default());
    let two = first.subscribe(ConsumerKind::Capture, Limits::default());
    assert_eq!(one.session.first_sequence, 2);
    assert_ne!(one.session.sink_session_id, two.session.sink_session_id);
    assert!(one.session.timestamp_resolution.wall_ns.is_some());
    assert!(one.session.timestamp_resolution.monotonic_ns.is_some());
    drop(first);
    let mut one = one;
    assert!(timeout(WAIT, one.recv()).await.unwrap().is_none());
}

async fn native_exchange(
    patterns: &[bool],
    unavailable: bool,
) -> (Vec<Arc<Record>>, Vec<String>, Arc<ObservationBus>) {
    let directory = tempfile::tempdir().unwrap();
    let (origin, address) = crate::test_owned_endpoint::bind().await;
    let count = patterns.len();
    let server = tokio::spawn(async move {
        for _ in 0..count {
            let (mut socket, _) = origin.accept().await.unwrap();
            let request = crate::connection_events::tests::head(&mut socket).await;
            assert!(
                request
                    .windows(b"content_canary".len())
                    .any(|part| part == b"content_canary")
            );
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        }
    });
    let mut config = crate::connection_events::tests::config(directory.path());
    if unavailable {
        config.native_settings = Some(crate::native_config::Settings {
            observations: Limits { items: 1, bytes: 1 },
            ..Default::default()
        });
        config.native_config_dir = Some(directory.path().to_owned());
        let data = config.data_dir();
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(
            data.join("instance_id"),
            "sy-0123456789abcdef0123456789abcdef",
        )
        .unwrap();
    }
    let proxy = Proxy::start(config).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let bus = runtime
        .connection_events
        .as_ref()
        .unwrap()
        .observations
        .clone();
    let mut consumer = bus.subscribe(ConsumerKind::Metrics, Limits::default());
    let request = format!(
        "GET http://{address}/ HTTP/1.1\r\nHost: {address}\r\nX-Test: content_canary\r\nConnection: close\r\n\r\n"
    );
    let mut records = Vec::new();
    let mut replies = Vec::new();
    for many in patterns {
        let mut client = UnixStream::connect(directory.path().join("alice.sock"))
            .await
            .unwrap();
        if *many {
            for chunk in request.as_bytes().chunks(7) {
                client.write_all(chunk).await.unwrap();
                loop {
                    let record = receive(&mut consumer).await;
                    let seen = matches!(record.as_ref(),Record::Observation(o) if o.point==Point::AgentUds && o.direction==Direction::ToProxy && o.state==State::Chunk);
                    records.push(record);
                    if seen {
                        break;
                    }
                }
            }
        } else {
            client.write_all(request.as_bytes()).await.unwrap();
        }
        let mut reply = String::new();
        timeout(WAIT, client.read_to_string(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert!(reply.ends_with("\r\n\r\nok"));
        replies.push(reply);
        drop(client);
        if !unavailable {
            records.extend(drain(&mut consumer, &bus).await);
        }
    }
    server.await.unwrap();
    proxy.shutdown().await;
    records.extend(drain(&mut consumer, &bus).await);
    let text = serde_json::to_string(&records.iter().map(Arc::as_ref).collect::<Vec<_>>()).unwrap();
    assert!(!text.contains("content_canary"));
    assert!(
        !std::fs::read_to_string(directory.path().join("audit.jsonl"))
            .unwrap()
            .contains("content_canary")
    );
    assert!(!directory.path().join("unused.sqlite3").exists());
    assert!(
        observations(&records)
            .iter()
            .all(|o| o.captured_length == 0)
    );
    (records, replies, bus)
}

#[tokio::test]
async fn native_receiver_chunks_preserve_offsets_and_application_result_without_payload() {
    let (all, replies, _) = native_exchange(&[false, true], false).await;
    let rows = observations(&all);
    let heads: Vec<_> = rows
        .iter()
        .filter(|o| o.state == State::ParsedHead)
        .collect();
    assert_eq!(heads.len(), 2);
    let one:Vec<_>=all.iter().filter(|r| matches!(r.as_ref(),Record::Observation(o) if o.connection_id==heads[0].connection_id)).cloned().collect();
    let many:Vec<_>=all.iter().filter(|r| matches!(r.as_ref(),Record::Observation(o) if o.connection_id==heads[1].connection_id)).cloned().collect();
    for reply in replies {
        assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(reply.ends_with("\r\n\r\nok"));
    }
    let ingress = |records: &[Arc<Record>]| {
        observations(records)
            .into_iter()
            .filter(|o| {
                o.point == Point::AgentUds
                    && o.direction == Direction::ToProxy
                    && o.state == State::Chunk
            })
            .map(|o| (o.stream_offset.unwrap(), o.observed_length.unwrap()))
            .collect::<Vec<_>>()
    };
    let single = ingress(&one);
    let split = ingress(&many);
    assert_eq!(single.len(), 1);
    assert!(split.len() > 10);
    for chunks in [&single, &split] {
        let mut offset = 0;
        for (start, length) in chunks {
            assert_eq!(*start, offset);
            offset += length;
        }
        assert_eq!(offset, single[0].1);
    }
    for records in [&one, &many] {
        let rows = observations(records);
        let head = rows
            .iter()
            .find(|o| o.layer == Layer::ProtocolMessage && o.state == State::ParsedHead)
            .unwrap();
        let complete = rows
            .iter()
            .find(|o| o.layer == Layer::ApplicationContent && o.state == State::Complete)
            .unwrap();
        assert_eq!(complete.parent_observation.as_ref(), Some(&head.id));
        assert_eq!(head.request_id, complete.request_id);
        assert_eq!(complete.connection_id, head.connection_id);
        assert_eq!(head.agent.as_deref(), Some("alice"));
        let prefix = head.input_span.as_ref().unwrap();
        assert_eq!(prefix.layer, Layer::TransportStream);
        assert_eq!(prefix.end_offset, single[0].1);
        assert!(rows.iter().all(|o| o.id.runtime_id == head.id.runtime_id));
        assert_eq!(
            rows.iter()
                .filter(|o| o.layer == Layer::ApplicationContent && o.state == State::Complete)
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn native_traffic_completes_during_canonical_admission_loss() {
    let (records, _, bus) = native_exchange(&[false], true).await;
    assert!(observations(&records).is_empty());
    let mut next = 1;
    for record in records {
        let Record::Gap(gap) = record.as_ref() else {
            panic!("missing canonical loss")
        };
        assert_eq!(gap.first_sequence, next);
        assert_eq!(gap.count, gap.last_sequence - gap.first_sequence + 1);
        assert!(matches!(
            gap.reason,
            LossReason::CanonicalAdmissionUnavailable
        ));
        next = gap.last_sequence + 1;
    }
    assert_eq!(next, bus.next_sequence());
    assert!(bus.counters.dropped[0].load(Ordering::Relaxed) > 0);
}

#[tokio::test]
async fn native_partial_head_retains_input_and_eof_without_a_parsed_message() {
    let directory = tempfile::tempdir().unwrap();
    let proxy = Proxy::start(crate::connection_events::tests::config(directory.path()))
        .await
        .unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let bus = runtime
        .connection_events
        .as_ref()
        .unwrap()
        .observations
        .clone();
    let mut consumer = bus.subscribe(ConsumerKind::Metrics, Limits::default());
    let mut client = UnixStream::connect(directory.path().join("alice.sock"))
        .await
        .unwrap();
    client
        .write_all(b"GET http://incomplete.invalid/ HTTP/1.1\r\nHost: ")
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    let mut reply = Vec::new();
    let _ = timeout(WAIT, client.read_to_end(&mut reply)).await.unwrap();
    proxy.shutdown().await;
    let records = drain(&mut consumer, &bus).await;
    let rows = observations(&records);
    assert!(rows.iter().any(|o| o.point == Point::AgentUds
        && o.state == State::Chunk
        && o.observed_length.unwrap() > 0));
    assert!(
        rows.iter()
            .any(|o| o.point == Point::AgentUds && o.state == State::Eof)
    );
    assert!(
        !rows
            .iter()
            .any(|o| o.state == State::ParsedHead || o.state == State::Complete)
    );
}

#[tokio::test]
async fn wall_clock_correction_does_not_reorder_monotonic_observations() {
    let bus = bus(Limits::default());
    let mut consumer = bus.subscribe(ConsumerKind::Metrics, Limits::default());
    for timestamp in [
        Timestamp {
            wall_unix_ns: 200,
            monotonic_ns: 10,
        },
        Timestamp {
            wall_unix_ns: 100,
            monotonic_ns: 20,
        },
    ] {
        bus.emit_with_clock(sample(&bus), || timestamp);
    }
    let records = drain(&mut consumer, &bus).await;
    let rows = observations(&records);
    assert_eq!(rows[0].id.sequence + 1, rows[1].id.sequence);
    assert!(rows[0].timestamp.wall_unix_ns > rows[1].timestamp.wall_unix_ns);
    assert_eq!(
        rows[1].timestamp.monotonic_ns - rows[0].timestamp.monotonic_ns,
        10
    );
}

#[tokio::test]
async fn final_source_drop_flushes_queued_observations_before_consumer_eof() {
    let bus = bus(Limits::default());
    let mut consumer = bus.subscribe(ConsumerKind::Metrics, Limits::default());
    bus.emit(sample(&bus));
    drop(bus);
    assert_eq!(receive(&mut consumer).await.range(), (1, 1));
    assert!(timeout(WAIT, consumer.recv()).await.unwrap().is_none());
}

#[tokio::test]
async fn late_session_clips_a_canonical_loss_range_to_its_starting_sequence() {
    let bus = bus(Limits { items: 0, bytes: 0 });
    for _ in 0..10 {
        bus.emit(sample(&bus));
    }
    let mut consumer = bus.subscribe(ConsumerKind::Metrics, Limits::default());
    for _ in 0..10 {
        bus.emit(sample(&bus));
    }
    let record = receive(&mut consumer).await;
    assert_eq!(consumer.session.first_sequence, 11);
    assert_eq!(record.range(), (11, 20));
}

#[tokio::test]
async fn consumer_byte_limit_and_sequence_exhaustion_remain_bounded() {
    let bus = bus(Limits::default());
    let mut consumer = bus.subscribe(
        ConsumerKind::Capture,
        Limits {
            items: 100,
            bytes: 1,
        },
    );
    bus.emit(sample(&bus));
    assert_eq!(receive(&mut consumer).await.range(), (1, 1));
    assert_eq!(consumer.inner.queue.lock().unwrap().bytes, 0);
    assert!(consumer.inner.queue.lock().unwrap().records.is_empty());
    bus.sequence.store(u64::MAX, Ordering::Release);
    assert!(bus.emit(sample(&bus)).is_none());
    assert_eq!(bus.next_sequence(), u64::MAX);
    assert_eq!(bus.counters.exhausted.load(Ordering::Relaxed), 1);
    // Restore the test-only counter jump so final drain does not claim it as loss.
    bus.sequence.store(2, Ordering::Release);
}

#[tokio::test]
async fn busy_source_prefix_cannot_claim_unobserved_parser_coverage() {
    use http_body_util::{BodyExt, Full};
    use hyper::{Request, Response, body::Incoming};
    use hyper_util::rt::TokioIo;
    use tokio::sync::oneshot;

    let (mut client, server) = UnixStream::pair().unwrap();
    let bus = bus(Limits::default());
    let mut consumer = bus.subscribe(ConsumerKind::Metrics, Limits::default());
    let source = Source::new(
        bus.clone(),
        &identity(),
        "conn-local",
        Point::AgentUds,
        Layer::TransportStream,
        Transport::Unix,
        None,
    );
    let observed = observe(Box::new(server), source.clone());
    let (head_tx, head_rx) = oneshot::channel();
    let (body_tx, body_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel();
    let gates = Mutex::new(Some((head_tx, body_tx, finish_rx)));
    let service = hyper::service::service_fn(move |request: Request<Incoming>| {
        let (head_tx, body_tx, finish_rx) = gates.lock().unwrap().take().unwrap();
        let source = source.clone();
        async move {
            let range = request
                .extensions()
                .get::<hyper::ext::RequestByteRange>()
                .unwrap()
                .clone();
            let application = source.application("request-local", None, Some(range), true);
            head_tx
                .send(source.clone())
                .unwrap_or_else(|_| panic!("head gate"));
            let body = request.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body.as_ref(), b"abc");
            body_tx.send(()).unwrap();
            finish_rx.await.unwrap();
            application.complete(Some(body.len() as u64), false);
            Ok::<_, std::convert::Infallible>(Response::new(Full::new(bytes::Bytes::from_static(
                b"ok",
            ))))
        }
    });
    let driver = tokio::spawn(async move {
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(observed), service)
            .await
            .unwrap();
    });
    let head = b"POST / HTTP/1.1\r\nHost: example.invalid\r\nContent-Length: 3\r\nConnection: close\r\n\r\n";
    client.write_all(head).await.unwrap();
    let source = timeout(WAIT, head_rx).await.unwrap().unwrap();
    let (locked_tx, locked_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        // A concurrent metadata reader holds the lock while Hyper reads the body.
        let _prefixes = source.prefix_lock_for_test();
        locked_tx.send(()).unwrap();
        release_rx.recv_timeout(WAIT).unwrap();
    });
    timeout(WAIT, locked_rx).await.unwrap().unwrap();
    client.write_all(b"abc").await.unwrap();
    timeout(WAIT, body_rx).await.unwrap().unwrap();
    release_tx.send(()).unwrap();
    reader.join().unwrap();
    finish_tx.send(()).unwrap();
    let mut response = Vec::new();
    timeout(WAIT, client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    timeout(WAIT, driver).await.unwrap().unwrap();
    assert!(response.ends_with(b"\r\n\r\nok"));
    let records = drain(&mut consumer, &bus).await;
    assert!(
        records
            .iter()
            .all(|r| matches!(r.as_ref(), Record::Observation(_)))
    );
    let rows = observations(&records);
    let chunks: Vec<_> = rows
        .iter()
        .filter(|o| {
            o.point == Point::AgentUds
                && o.direction == Direction::ToProxy
                && o.state == State::Chunk
        })
        .collect();
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].stream_offset, Some(0));
    assert_eq!(chunks[0].observed_length, Some(head.len() as u64));
    assert_eq!(chunks[1].stream_offset, Some(head.len() as u64));
    assert_eq!(chunks[1].observed_length, Some(3));
    let parsed = rows.iter().find(|o| o.state == State::ParsedHead).unwrap();
    let completed = rows.iter().find(|o| o.state == State::Complete).unwrap();
    assert!(parsed.input_span.as_ref().unwrap().parser_consumed);
    assert_eq!(completed.parent_observation.as_ref(), Some(&parsed.id));
    assert_eq!(completed.observed_length, Some(3));
    assert!(
        completed.input_span.is_none(),
        "busy source update must invalidate stale lineage"
    );
    assert!(rows.iter().all(|o| o.captured_length == 0));
}

#[tokio::test]
async fn http1_parser_ranges_exclude_read_ahead_and_include_body_framing() {
    use http_body_util::{BodyExt, Full};
    use hyper::{Request, Response, body::Incoming};
    use hyper_util::rt::TokioIo;
    for chunked in [false, true] {
        let (mut client, server) = tokio::io::duplex(4096);
        let bus = bus(Limits::default());
        let mut consumer = bus.subscribe(ConsumerKind::Metrics, Limits::default());
        let source = Source::new(
            bus.clone(),
            &identity(),
            "conn-local",
            Point::AgentUds,
            Layer::TransportStream,
            Transport::Unix,
            None,
        );
        let source = observe(Box::new(server), source);
        let ranges = Arc::new(Mutex::new(Vec::new()));
        let received = ranges.clone();
        let service = hyper::service::service_fn(move |request: Request<Incoming>| {
            let received = received.clone();
            async move {
                let range = request
                    .extensions()
                    .get::<hyper::ext::RequestByteRange>()
                    .unwrap()
                    .clone();
                let content = request.into_body().collect().await.unwrap().to_bytes();
                received.lock().unwrap().push((
                    range.start(),
                    range.head_end(),
                    range.end(),
                    content.to_vec(),
                ));
                Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                    bytes::Bytes::from_static(b"ok"),
                )))
            }
        });
        let driver = tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(source), service)
                .await
                .unwrap();
        });
        let body = if chunked {
            "3\r\nabc\r\n0\r\nX-T: trailer\r\n\r\n"
        } else {
            "abc"
        };
        let framing = if chunked {
            "Transfer-Encoding: chunked\r\nTrailer: X-T"
        } else {
            "Content-Length: 3"
        };
        let head = format!("POST /first HTTP/1.1\r\nHost: example.invalid\r\n{framing}\r\n\r\n");
        let first = format!("{head}{body}");
        let second = "GET /second HTTP/1.1\r\nHost: example.invalid\r\nConnection: close\r\n\r\n";
        let bytes = format!("{first}{second}");
        client.write_all(bytes.as_bytes()).await.unwrap();
        let mut reply = Vec::new();
        timeout(WAIT, client.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        driver.await.unwrap();
        {
            let ranges = ranges.lock().unwrap();
            assert_eq!(ranges.len(), 2);
            assert_eq!(
                ranges[0],
                (0, head.len() as u64, first.len() as u64, b"abc".to_vec())
            );
            assert_eq!(
                ranges[1],
                (
                    first.len() as u64,
                    bytes.len() as u64,
                    bytes.len() as u64,
                    Vec::new()
                )
            );
        }
        let records = drain(&mut consumer, &bus).await;
        let rows = observations(&records);
        let input: Vec<_> = rows
            .into_iter()
            .filter(|o| o.state == State::Chunk && o.direction == Direction::ToProxy)
            .collect();
        assert_eq!(
            input
                .iter()
                .map(|o| o.observed_length.unwrap())
                .sum::<u64>(),
            bytes.len() as u64
        );
        assert_eq!(
            input.len(),
            1,
            "fixture preserves parser read-ahead from one observed read"
        );
    }
}

#[tokio::test]
async fn operational_metrics_have_fixed_labels_and_no_encoded_or_payload_bytes() {
    let bus = bus(Limits::default());
    let mut consumer = bus.subscribe(ConsumerKind::Capture, Limits::default());
    let mut record = sample(&bus);
    record.connection_id = "arbitrary-connection-canary".into();
    record.request_id = Some("arbitrary-request-canary".into());
    bus.emit(record);
    receive(&mut consumer).await;
    let metrics = bus.counters.prometheus();
    assert!(metrics.contains("safeyolo_observations_total{layer=\"transport_stream\"} 1"));
    assert!(!metrics.contains("canary"));
    assert!(!metrics.contains("connection_id"));
    assert!(!metrics.contains("request_id"));
    let values = bus.counters.json();
    assert_eq!(values["sinks"]["capture"]["sink_bytes_total"], 0);
    assert!(
        values["sinks"]["capture"]["observation_consumer_metadata_bytes_total"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(
        values["layers"]["transport_stream"]["observation_payload_bytes_total"],
        0
    );
}
