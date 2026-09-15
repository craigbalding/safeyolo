use bytes::Bytes;
use h2::ext::{Aborted, ResponseCompletion, on_response_complete};
use hyper::http::{self, Request, StatusCode};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

const LIMIT: Duration = Duration::from_secs(3);

fn frame(kind: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![
        (payload.len() >> 16) as u8,
        (payload.len() >> 8) as u8,
        payload.len() as u8,
        kind,
        flags,
    ];
    out.extend_from_slice(&(if kind == 4 || kind == 6 { 0_u32 } else { 1 }).to_be_bytes());
    out.extend_from_slice(payload);
    out
}
fn head(code: u16, eos: bool, length: Option<u64>) -> Vec<u8> {
    let status = code.to_string();
    let mut payload = vec![8, status.len() as u8]; // literal :status, static name 8
    payload.extend_from_slice(status.as_bytes());
    if let Some(length) = length {
        let value = length.to_string();
        payload.extend_from_slice(&[15, 13, value.len() as u8]); // content-length, static name 28
        payload.extend_from_slice(value.as_bytes());
    }
    frame(1, 4 | u8::from(eos), &payload)
}
fn data(bytes: &[u8], eos: bool) -> Vec<u8> {
    frame(0, u8::from(eos), bytes)
}
fn trailers() -> Vec<u8> {
    frame(1, 5, b"\0\x07x-proof\x03yes")
}
fn reset(reason: u32) -> Vec<u8> {
    frame(3, 0, &reason.to_be_bytes())
}
async fn read_frame(socket: &mut TcpStream) -> io::Result<(u8, u8, u32, Vec<u8>)> {
    let mut header = [0_u8; 9];
    socket.read_exact(&mut header).await?;
    let length = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
    let mut payload = vec![0; length];
    socket.read_exact(&mut payload).await?;
    Ok((
        header[3],
        header[4],
        u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff,
        payload,
    ))
}
struct Command {
    frames: Vec<Vec<u8>>,
    barrier: bool,
    goaway: bool,
    done: oneshot::Sender<Option<u32>>,
}
struct Peer {
    tx: Option<mpsc::Sender<Command>>,
    task: JoinHandle<()>,
    ready: Option<oneshot::Receiver<()>>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Peer {
    async fn start() -> (Self, TcpStream) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel::<Command>(2);
        let (ready_tx, ready) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut preface = [0_u8; 24];
            socket.read_exact(&mut preface).await.unwrap();
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            socket.write_all(&frame(4, 0, &[])).await.unwrap();
            loop {
                let (kind, flags, stream, _) = read_frame(&mut socket).await.unwrap();
                if kind == 4 && flags == 0 {
                    socket.write_all(&frame(4, 1, &[])).await.unwrap();
                }
                if kind == 1 && stream == 1 {
                    break;
                }
            }
            let _ = ready_tx.send(());
            while let Some(command) = rx.recv().await {
                for bytes in command.frames {
                    if socket.write_all(&bytes).await.is_err() {
                        return;
                    }
                }
                if command.goaway {
                    loop {
                        let (kind, _, stream, payload) = read_frame(&mut socket).await.unwrap();
                        if kind == 7 {
                            assert_eq!(stream, 0);
                            assert!(payload.len() >= 8);
                            let code = u32::from_be_bytes(payload[4..8].try_into().unwrap());
                            let _ = command.done.send(Some(code));
                            break;
                        }
                    }
                    continue;
                }
                if command.barrier {
                    socket.write_all(&frame(6, 0, b"barrier!")).await.unwrap();
                    loop {
                        let Ok((kind, flags, _, payload)) = read_frame(&mut socket).await else {
                            return;
                        };
                        if kind == 6 && flags == 1 && payload == b"barrier!" {
                            break;
                        }
                    }
                }
                let _ = command.done.send(None);
            }
        });
        let socket = TcpStream::connect(address).await.unwrap();
        (
            Self {
                tx: Some(tx),
                task,
                ready: Some(ready),
            },
            socket,
        )
    }
    async fn ready(&mut self) {
        tokio::time::timeout(LIMIT, self.ready.take().unwrap())
            .await
            .unwrap()
            .unwrap();
    }
    async fn send(&self, frames: Vec<Vec<u8>>, barrier: bool) {
        assert!(self.exchange(frames, barrier, false).await.is_none());
    }
    async fn expect_goaway(&self, frames: Vec<Vec<u8>>) -> u32 {
        self.exchange(frames, false, true)
            .await
            .expect("GOAWAY response")
    }
    async fn exchange(&self, frames: Vec<Vec<u8>>, barrier: bool, goaway: bool) -> Option<u32> {
        let (done, wait) = oneshot::channel();
        self.tx
            .as_ref()
            .unwrap()
            .send(Command {
                frames,
                barrier,
                goaway,
                done,
            })
            .await
            .unwrap();
        tokio::time::timeout(LIMIT, wait).await.unwrap().unwrap()
    }
    async fn close(&mut self) {
        self.tx = None;
        tokio::time::timeout(LIMIT, &mut self.task)
            .await
            .unwrap()
            .unwrap();
    }
}
struct Driver(JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct Session {
    peer: Peer,
    _driver: Driver,
    sender: h2::client::SendRequest<Bytes>,
}
impl Session {
    async fn new() -> Self {
        Self::with_header_limit(None).await
    }
    async fn with_header_limit(limit: Option<u32>) -> Self {
        let (peer, socket) = Peer::start().await;
        let mut builder = h2::client::Builder::new();
        if let Some(limit) = limit {
            builder.max_header_list_size(limit);
        }
        let (sender, connection) = builder.handshake(socket).await.unwrap();
        let driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        Self {
            peer,
            _driver: driver,
            sender,
        }
    }
    async fn request(
        &mut self,
        method: &str,
        eos: bool,
    ) -> (
        ResponseCompletion,
        h2::client::ResponseFuture,
        h2::SendStream<Bytes>,
    ) {
        let mut request = Request::builder()
            .method(method)
            .uri("http://owned.invalid/")
            .body(())
            .unwrap();
        let complete = on_response_complete(&mut request);
        let (response, send) = self.sender.send_request(request, eos).unwrap();
        self.peer.ready().await;
        (complete, response, send)
    }
}
#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn poll_once(
    completion: &mut ResponseCompletion,
    count: &Arc<WakeCount>,
) -> Poll<Result<StatusCode, Aborted>> {
    let waker = Waker::from(count.clone());
    Pin::new(completion).poll(&mut Context::from_waker(&waker))
}
async fn terminal(completion: &mut ResponseCompletion) -> Result<StatusCode, Aborted> {
    tokio::time::timeout(LIMIT, completion)
        .await
        .expect("observer did not terminate")
}
fn pending(completion: &mut ResponseCompletion) {
    assert!(poll_once(completion, &Arc::default()).is_pending());
}

#[tokio::test]
async fn empty_head_and_nonempty_final_unread_latch_before_response_poll() {
    for (name, frames, method, expected) in [
        ("empty200", vec![head(200, true, Some(0))], "GET", 200),
        ("empty503", vec![head(503, true, None)], "GET", 503),
        ("head_length", vec![head(200, true, Some(99))], "HEAD", 200),
        ("204_length", vec![head(204, true, Some(99))], "GET", 204),
        ("304_length", vec![head(304, true, Some(99))], "GET", 304),
        (
            "unread_data",
            vec![head(201, false, Some(4)), data(b"body", true)],
            "GET",
            201,
        ),
        (
            "unread_trailers",
            vec![head(202, false, Some(4)), data(b"body", false), trailers()],
            "GET",
            202,
        ),
        (
            "empty_final_data",
            vec![head(200, false, Some(0)), data(b"", true)],
            "GET",
            200,
        ),
        (
            "existing_missing_status_default",
            vec![frame(1, 5, &[])],
            "GET",
            200,
        ),
    ] {
        let mut session = Session::new().await;
        let (mut completion, response, send) = session.request(method, true).await;
        pending(&mut completion);
        session.peer.send(frames, true).await;
        assert_eq!(
            terminal(&mut completion).await.unwrap().as_u16(),
            expected,
            "{name}"
        );
        drop(response);
        drop(send);
        session.peer.close().await;
        assert_eq!(
            terminal(&mut completion).await.unwrap().as_u16(),
            expected,
            "{name}: immutable after drops"
        );
        println!("PASS h2 {name}");
    }
}

#[tokio::test]
async fn informational_and_partial_frames_remain_pending_without_extra_buffering() {
    let mut session = Session::new().await;
    let (mut completion, response, send) = session.request("GET", true).await;
    session.peer.send(vec![head(103, false, None)], true).await;
    pending(&mut completion);
    session
        .peer
        .send(vec![head(429, false, Some(4)), data(b"bo", false)], true)
        .await;
    pending(&mut completion);
    let mut body = response.await.unwrap().into_body();
    assert_eq!(body.data().await.unwrap().unwrap(), "bo");
    body.flow_control().release_capacity(2).unwrap();
    drop(send); // request send half is finished; receiving remains live
    session.peer.send(vec![data(b"dy", true)], true).await;
    assert_eq!(
        terminal(&mut completion).await.unwrap(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert!(
        !body.is_end_stream(),
        "final DATA is still unread in the original queue"
    );
    drop(body);
    assert_eq!(
        terminal(&mut completion).await.unwrap(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn reset_and_validation_failures_never_complete() {
    let cases = [
        ("reset_no_error", vec![head(200, false, None), reset(0)]),
        ("reset_cancel", vec![head(200, false, None), reset(8)]),
        ("reset_before_head", vec![reset(8)]),
        ("head_short_length", vec![head(200, true, Some(1))]),
        (
            "data_short_length",
            vec![head(200, false, Some(2)), data(b"x", true)],
        ),
        (
            "data_long_length",
            vec![head(200, false, Some(0)), data(b"x", true)],
        ),
        (
            "trailers_short_length",
            vec![head(200, false, Some(1)), trailers()],
        ),
        ("data_before_head", vec![data(b"x", true)]),
        (
            "head_bad_content_length",
            vec![frame(1, 5, b"\x88\x0f\x0d\x01x")],
        ),
        (
            "frame_size_error",
            vec![head(200, false, None), data(&vec![0; 16385], true)],
        ),
    ];
    for (name, frames) in cases {
        let mut session = Session::new().await;
        let (mut completion, response, send) = session.request("GET", true).await;
        session.peer.send(frames, false).await;
        assert_eq!(terminal(&mut completion).await, Err(Aborted), "{name}");
        drop(response);
        drop(send);
        println!("PASS h2 {name}");
    }
}

#[tokio::test]
async fn cancellation_and_connection_end_abort_even_with_other_handles_retained() {
    for stage in [
        "response_future",
        "recv_body",
        "driver",
        "eof",
        "partial_frame_eof",
        "local_reset",
    ] {
        let mut session = Session::new().await;
        let (mut completion, response, mut send) = session.request("GET", false).await;
        match stage {
            "response_future" => drop(response),
            "recv_body" => {
                session.peer.send(vec![head(200, false, None)], true).await;
                drop(response.await.unwrap().into_body());
            }
            "driver" => {
                session._driver.0.abort();
                let _ = (&mut session._driver.0).await;
                assert_eq!(
                    terminal(&mut completion).await,
                    Err(Aborted),
                    "response future retained"
                );
                drop(response);
            }
            "eof" | "partial_frame_eof" => {
                session.peer.send(vec![head(200, false, None)], true).await;
                let _body = response.await.unwrap().into_body();
                if stage == "partial_frame_eof" {
                    session
                        .peer
                        .send(vec![vec![0, 0, 4, 0, 1, 0, 0, 0, 1, b'x']], false)
                        .await;
                }
                session.peer.close().await;
                assert_eq!(
                    terminal(&mut completion).await,
                    Err(Aborted),
                    "while receive body retained"
                );
            }
            "local_reset" => {
                send.send_reset(h2::Reason::NO_ERROR);
                assert_eq!(
                    terminal(&mut completion).await,
                    Err(Aborted),
                    "response future retained"
                );
                drop(response);
            }
            _ => unreachable!(),
        }
        assert_eq!(terminal(&mut completion).await, Err(Aborted), "{stage}");
        drop(send);
        println!("PASS h2 {stage}");
    }
}

#[tokio::test]
async fn canceled_receiver_wins_over_later_valid_eom_and_terminal_wakes_once() {
    let mut session = Session::new().await;
    let (mut completion, response, _send) = session.request("GET", true).await;
    session.peer.send(vec![head(200, false, None)], true).await;
    let body = response.await.unwrap().into_body();
    let wakes = Arc::<WakeCount>::default();
    assert!(poll_once(&mut completion, &wakes).is_pending());
    drop(body);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    assert_eq!(
        poll_once(&mut completion, &wakes),
        Poll::Ready(Err(Aborted))
    );
    session.peer.send(vec![data(b"late", true)], false).await;
    session.peer.close().await;
    assert_eq!(
        poll_once(&mut completion, &wakes),
        Poll::Ready(Err(Aborted))
    );
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn completed_status_wins_over_later_reset_and_wakes_once() {
    let mut session = Session::new().await;
    let (mut completion, response, _send) = session.request("POST", false).await;
    let wakes = Arc::<WakeCount>::default();
    assert!(poll_once(&mut completion, &wakes).is_pending());
    session
        .peer
        .send(
            vec![head(503, false, None), data(b"x", true), reset(8)],
            true,
        )
        .await;
    assert_eq!(
        poll_once(&mut completion, &wakes),
        Poll::Ready(Ok(StatusCode::SERVICE_UNAVAILABLE))
    );
    drop(response);
    session.peer.close().await;
    assert_eq!(
        poll_once(&mut completion, &wakes),
        Poll::Ready(Ok(StatusCode::SERVICE_UNAVAILABLE))
    );
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unsent_replaced_and_rejected_requests_abort_without_receiver() {
    let mut request = Request::new(());
    let mut first = on_response_complete(&mut request);
    let mut second = on_response_complete(&mut request);
    assert_eq!(terminal(&mut first).await, Err(Aborted));
    pending(&mut second);
    drop(request);
    assert_eq!(terminal(&mut second).await, Err(Aborted));
    let mut session = Session::new().await;
    let mut request = Request::builder()
        .uri("/")
        .version(http::Version::HTTP_2)
        .body(())
        .unwrap();
    let mut completion = on_response_complete(&mut request);
    assert!(session.sender.send_request(request, true).is_err());
    assert_eq!(terminal(&mut completion).await, Err(Aborted));
}

#[tokio::test]
async fn actual_hyper_h2_preserves_registration_before_dispatch_and_body_delivery() {
    use http_body_util::Empty;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    for case in [
        "empty",
        "unread_data",
        "unread_trailers",
        "no_error",
        "dropped_body",
        "queued_cancel",
        "channel_drop",
        "inflight_cancel",
    ] {
        let (mut peer, socket) = Peer::start().await;
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(socket))
                .await
                .unwrap();
        if case == "queued_cancel" || case == "channel_drop" {
            // A request dispatched while the connection has not been polled yet.
            let mut request = Request::builder()
                .uri("http://owned.invalid/")
                .body(Empty::<Bytes>::new())
                .unwrap();
            let mut complete = on_response_complete(&mut request);
            let response = sender.send_request(request);
            if case == "queued_cancel" {
                drop(response);
                let _driver = Driver(tokio::spawn(async move {
                    let _ = connection.await;
                }));
                assert_eq!(terminal(&mut complete).await, Err(Aborted));
                assert!(!sender.is_closed());
            } else {
                drop(connection);
                assert_eq!(terminal(&mut complete).await, Err(Aborted));
                drop(response);
            }
            println!("PASS hyper {case}");
            continue;
        }
        let _driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let mut request = Request::builder()
            .uri("http://owned.invalid/")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let mut complete = on_response_complete(&mut request);
        let response = sender.send_request(request);
        peer.ready().await;
        if case == "inflight_cancel" {
            drop(response);
            assert_eq!(terminal(&mut complete).await, Err(Aborted));
            assert!(!sender.is_closed());
            println!("PASS hyper {case}");
            continue;
        }
        let frames = match case {
            "empty" => vec![head(503, true, None)],
            "unread_data" => vec![head(503, false, Some(4)), data(b"body", true)],
            "unread_trailers" => vec![head(503, false, Some(4)), data(b"body", false), trailers()],
            "no_error" => vec![head(503, false, None), reset(0)],
            "dropped_body" => vec![head(503, false, None)],
            _ => unreachable!(),
        };
        peer.send(frames, case != "no_error").await;
        if case == "dropped_body" {
            drop(response.await.unwrap());
            assert_eq!(terminal(&mut complete).await, Err(Aborted));
        } else {
            let expected = if case == "no_error" {
                Err(Aborted)
            } else {
                Ok(StatusCode::SERVICE_UNAVAILABLE)
            };
            assert_eq!(terminal(&mut complete).await, expected, "{case}");
            drop(response);
        }
        println!("PASS hyper {case}");
    }
}

#[tokio::test]
async fn queued_h2_request_cancel_with_connection_and_send_handle_retained() {
    let (socket, _peer) = tokio::io::duplex(4096);
    let (mut sender, connection) = h2::client::Builder::new()
        .initial_max_send_streams(0)
        .handshake::<_, Bytes>(socket)
        .await
        .unwrap();
    let mut request = Request::builder()
        .uri("http://owned.invalid/")
        .body(())
        .unwrap();
    let mut complete = on_response_complete(&mut request);
    let (response, send) = sender.send_request(request, true).unwrap();
    pending(&mut complete);
    assert_eq!(sender.current_max_send_streams(), 0);
    drop(response);
    assert_eq!(terminal(&mut complete).await, Err(Aborted));
    drop((send, connection));
}

#[tokio::test]
async fn completed_request_half_close_does_not_abort_the_response() {
    let mut session = Session::new().await;
    let (mut completion, response, mut send) = session.request("POST", false).await;
    send.send_data(Bytes::new(), true).unwrap();
    drop(send);
    pending(&mut completion);
    session.peer.send(vec![head(200, true, None)], true).await;
    assert_eq!(terminal(&mut completion).await.unwrap(), StatusCode::OK);
    drop(response);
}

#[tokio::test]
async fn try_result_preserves_registered_waker_and_returns_latched_success_or_abort() {
    for complete_successfully in [true, false] {
        let mut session = Session::new().await;
        let (mut completion, response, _send) = session.request("GET", true).await;
        assert_eq!(completion.try_result(), None);
        let wakes = Arc::<WakeCount>::default();
        assert!(poll_once(&mut completion, &wakes).is_pending());
        assert_eq!(completion.try_result(), None);
        let frames = if complete_successfully {
            vec![head(201, true, None)]
        } else {
            vec![reset(0)]
        };
        session.peer.send(frames, true).await;
        assert_eq!(
            wakes.0.load(Ordering::SeqCst),
            1,
            "try_result did not replace the registered waker"
        );
        assert_eq!(
            completion.try_result(),
            Some(if complete_successfully {
                Ok(StatusCode::CREATED)
            } else {
                Err(Aborted)
            })
        );
        drop(response);
    }
}

#[derive(Default)]
struct Capture(std::sync::Mutex<Captured>);

#[derive(Default, Clone, Debug, PartialEq)]
struct Captured {
    heads: Vec<(StatusCode, Vec<Vec<u8>>, bool)>,
    data: Vec<u8>,
}

impl h2::ext::ResponseBodyCapture for Capture {
    fn head(&self, status: StatusCode, headers: &http::HeaderMap, end_stream: bool) {
        self.0.lock().unwrap().heads.push((
            status,
            headers
                .get_all("content-encoding")
                .iter()
                .map(|v| v.as_bytes().to_vec())
                .collect(),
            end_stream,
        ));
    }
    fn data(&self, data: &[u8]) {
        let mut captured = self.0.lock().unwrap();
        assert!(
            captured.data.len() + data.len() <= 4096,
            "finite fixture payload"
        );
        captured.data.extend_from_slice(data);
    }
}

async fn captured_request(
    session: &mut Session,
) -> (
    ResponseCompletion,
    h2::client::ResponseFuture,
    h2::SendStream<Bytes>,
    Arc<Capture>,
) {
    let mut request = Request::builder()
        .uri("http://owned.invalid/")
        .body(())
        .unwrap();
    let capture = Arc::new(Capture::default());
    let completion = h2::ext::on_response_complete_with_capture(&mut request, capture.clone());
    let (response, send) = session.sender.send_request(request, true).unwrap();
    session.peer.ready().await;
    (completion, response, send, capture)
}

#[tokio::test]
async fn capture_retains_unread_data_excludes_padding_and_ignores_informational() {
    for trailing_headers in [false, true] {
        let mut session = Session::new().await;
        let (mut completion, response, _send, capture) = captured_request(&mut session).await;
        // Literal indexed names: :status (8), content-encoding (26), repeated.
        let headers = frame(1, 4, b"\x88\x0f\x0b\x05first\x0f\x0b\x06second");
        session
            .peer
            .send(
                vec![head(103, false, None), headers, data(b"a\xff", false)],
                true,
            )
            .await;
        assert!(completion.try_result().is_none());
        assert_eq!(capture.0.lock().unwrap().data, b"a\xff");
        let mut frames = vec![frame(0, 8 | u8::from(!trailing_headers), b"\x02z\0\0")];
        if trailing_headers {
            frames.push(trailers());
        }
        session.peer.send(frames, true).await;
        assert_eq!(terminal(&mut completion).await.unwrap(), StatusCode::OK);
        assert_eq!(
            capture.0.lock().unwrap().heads,
            vec![(
                StatusCode::OK,
                vec![b"first".to_vec(), b"second".to_vec()],
                false
            )]
        );
        assert_eq!(capture.0.lock().unwrap().data, b"a\xffz");
        let body = response.await.unwrap().into_body();
        assert!(
            !body.is_end_stream(),
            "normal queue still contains every DATA frame"
        );
        let before = capture.0.lock().unwrap().clone();
        drop(body);
        session.peer.close().await;
        assert_eq!(completion.try_result(), Some(Ok(StatusCode::OK)));
        assert_eq!(*capture.0.lock().unwrap(), before);
    }
}

#[tokio::test]
async fn capture_stops_at_cancellation_and_never_accepts_invalid_final_data() {
    for mode in [
        "cancel",
        "no_error",
        "short_length",
        "long_length",
        "bad_head",
    ] {
        let mut session = Session::new().await;
        let (mut completion, response, _send, capture) = captured_request(&mut session).await;
        if mode == "bad_head" {
            session
                .peer
                .send(vec![head(200, true, Some(1))], false)
                .await;
            assert_eq!(terminal(&mut completion).await, Err(Aborted));
            assert!(capture.0.lock().unwrap().heads.is_empty());
            drop(response);
            continue;
        }
        let length = match mode {
            "short_length" => Some(3),
            "long_length" => Some(1),
            _ => None,
        };
        session
            .peer
            .send(vec![head(200, false, length), data(b"a", false)], true)
            .await;
        assert_eq!(capture.0.lock().unwrap().data, b"a");
        let body = response.await.unwrap().into_body();
        let before = capture.0.lock().unwrap().clone();
        if mode == "cancel" {
            drop(body);
            assert_eq!(terminal(&mut completion).await, Err(Aborted));
            session.peer.send(vec![data(b"late", true)], false).await;
            session.peer.close().await;
        } else {
            session
                .peer
                .send(
                    vec![if mode == "no_error" {
                        reset(0)
                    } else {
                        data(b"b", true)
                    }],
                    false,
                )
                .await;
            assert_eq!(terminal(&mut completion).await, Err(Aborted));
            drop(body);
        }
        assert_eq!(*capture.0.lock().unwrap(), before, "{mode}");
    }
}

#[tokio::test]
async fn actual_hyper_h2_captures_before_response_future_or_body_is_polled() {
    use http_body_util::Empty;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    for empty in [false, true] {
        let (mut peer, socket) = Peer::start().await;
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(socket))
                .await
                .unwrap();
        let _driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let mut request = Request::builder()
            .uri("http://owned.invalid/")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let capture = Arc::new(Capture::default());
        let mut completion =
            h2::ext::on_response_complete_with_capture(&mut request, capture.clone());
        let response = sender.send_request(request);
        peer.ready().await;
        let frames = if empty {
            vec![head(204, true, Some(99))]
        } else {
            vec![
                head(200, false, Some(3)),
                data(b"a", false),
                data(b"bc", true),
            ]
        };
        let status = if empty {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::OK
        };
        peer.send(frames, true).await;
        assert_eq!(terminal(&mut completion).await.unwrap(), status);
        assert_eq!(
            capture.0.lock().unwrap().heads,
            vec![(status, vec![], empty)]
        );
        assert_eq!(
            capture.0.lock().unwrap().data,
            if empty {
                b"".as_slice()
            } else {
                b"abc".as_slice()
            }
        );
        let before = capture.0.lock().unwrap().clone();
        drop(response);
        peer.close().await;
        assert_eq!(*capture.0.lock().unwrap(), before);
    }
}

#[tokio::test]
async fn capture_is_released_on_unsent_drop_and_replacement_without_callbacks() {
    let capture = Arc::new(Capture::default());
    let mut request = Request::new(());
    let mut first = h2::ext::on_response_complete_with_capture(&mut request, capture.clone());
    assert_eq!(Arc::strong_count(&capture), 2);
    let mut second = on_response_complete(&mut request);
    assert_eq!(terminal(&mut first).await, Err(Aborted));
    assert_eq!(Arc::strong_count(&capture), 1);
    drop(request);
    assert_eq!(terminal(&mut second).await, Err(Aborted));
    assert_eq!(*capture.0.lock().unwrap(), Captured::default());
}

#[tokio::test]
async fn response_pseudo_trailers_send_goaway_without_completing_or_changing_capture() {
    let mut oversized_path = vec![4, 127, 217, 3]; // :path, literal 600-byte value
    oversized_path.extend_from_slice(&[b'a'; 600]);
    let mut oversized_ordinary = b"\0\x07x-proof\x7f\xd9\x03".to_vec();
    oversized_ordinary.extend_from_slice(&[b'a'; 600]);
    for (name, trailer, reason) in [
        ("path", b"\x84".as_slice(), 1),
        ("status", b"\x88".as_slice(), 1),
        ("oversized-path", oversized_path.as_slice(), 11),
        ("oversized-ordinary", oversized_ordinary.as_slice(), 11),
    ] {
        let mut session = Session::with_header_limit(Some(512)).await;
        let (mut completion, response, send, capture) = captured_request(&mut session).await;
        session
            .peer
            .send(vec![head(200, false, Some(2)), data(b"ab", false)], true)
            .await;
        let mut body = response.await.unwrap().into_body();
        assert!(completion.try_result().is_none());
        assert_eq!(capture.0.lock().unwrap().data, b"ab");
        let captured = capture.0.lock().unwrap().clone();
        // Read accepted prefix so the failure assertion cannot confuse discarded
        // queued DATA with an invented or altered body payload.
        assert_eq!(body.data().await.unwrap().unwrap(), b"ab".as_slice());
        body.flow_control().release_capacity(2).unwrap();
        assert_eq!(
            session.peer.expect_goaway(vec![frame(1, 5, trailer)]).await,
            reason,
            "{name}"
        );
        assert!(terminal(&mut completion).await.is_err());
        assert!(body.trailers().await.is_err());
        assert_eq!(*capture.0.lock().unwrap(), captured);
        drop(body);
        drop(send);
        session.peer.close().await;
        tokio::time::timeout(LIMIT, &mut session._driver.0)
            .await
            .unwrap()
            .unwrap();
        assert!(completion.try_result().unwrap().is_err());
        println!("PASS response trailer={name} goaway={reason} prefix=ab joined=true");
    }
}
