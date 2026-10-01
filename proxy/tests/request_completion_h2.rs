use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, Response, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{convert::Infallible, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::mpsc,
    task::JoinHandle,
    time::timeout,
};
const LIMIT: Duration = Duration::from_secs(2);
fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![
        (payload.len() >> 16) as u8,
        (payload.len() >> 8) as u8,
        payload.len() as u8,
        kind,
        flags,
    ];
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}
fn head(end: bool, length: Option<usize>) -> Vec<u8> {
    let mut fields = vec![0x83, 0x86, 0x84, 0x01, 1, b'f']; // POST/http/path/authority
    if let Some(length) = length {
        let text = length.to_string();
        fields.extend_from_slice(&[15, 13, text.len() as u8]);
        fields.extend_from_slice(text.as_bytes());
    }
    frame(1, 4 | u8::from(end), 1, &fields)
}
struct Peer {
    socket: DuplexStream,
    requests: mpsc::UnboundedReceiver<Request<Incoming>>,
    task: JoinHandle<()>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Peer {
    async fn new() -> Self {
        Self::with_header_limit(None).await
    }
    async fn with_header_limit(limit: Option<u32>) -> Self {
        let (socket, server) = tokio::io::duplex(65536);
        let (tx, requests) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
            if let Some(limit) = limit {
                builder.max_header_list_size(limit);
            }
            let _ = builder
                .serve_connection(
                    TokioIo::new(server),
                    service_fn(move |request| {
                        tx.send(request).unwrap();
                        std::future::pending::<Result<Response<Empty<Bytes>>, Infallible>>()
                    }),
                )
                .await;
        });
        let mut peer = Self {
            socket,
            requests,
            task,
        };
        peer.socket
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .unwrap();
        peer.socket.write_all(&frame(4, 0, 0, &[])).await.unwrap();
        peer
    }
    async fn send(&mut self, bytes: &[u8]) {
        self.socket.write_all(bytes).await.unwrap();
    }
    async fn request(&mut self, end: bool, length: Option<usize>) -> Request<Incoming> {
        self.send(&head(end, length)).await;
        timeout(LIMIT, self.requests.recv()).await.unwrap().unwrap()
    }
    async fn goaway(&mut self) -> u32 {
        timeout(LIMIT, async {
            loop {
                let mut head = [0; 9];
                self.socket.read_exact(&mut head).await.unwrap();
                let length =
                    ((head[0] as usize) << 16) | ((head[1] as usize) << 8) | head[2] as usize;
                let mut payload = vec![0; length];
                self.socket.read_exact(&mut payload).await.unwrap();
                if head[3] == 7 {
                    assert_eq!(&head[5..9], &[0; 4]);
                    assert!(payload.len() >= 8);
                    return u32::from_be_bytes(payload[4..8].try_into().unwrap());
                }
            }
        })
        .await
        .expect("peer did not receive connection-level GOAWAY")
    }

    async fn barrier(&mut self) {
        self.send(&frame(6, 0, 0, b"owned123")).await;
        timeout(LIMIT, async {
            loop {
                let mut head = [0; 9];
                self.socket.read_exact(&mut head).await.unwrap();
                let length =
                    ((head[0] as usize) << 16) | ((head[1] as usize) << 8) | head[2] as usize;
                let mut body = vec![0; length];
                self.socket.read_exact(&mut body).await.unwrap();
                if head[3] == 6 && head[4] & 1 != 0 {
                    assert_eq!(body, b"owned123");
                    break;
                }
            }
        })
        .await
        .unwrap();
    }
}
#[tokio::test]
async fn hyper_server_retains_single_take_bodyless_request_observation() {
    let mut peer = Peer::new().await;
    let mut request = peer.request(true, Some(0)).await;
    let mut clone = Request::new(());
    *clone.extensions_mut() = request.extensions().clone();
    let mut done = h2::ext::take_request_completion(&mut request).unwrap();
    assert!(h2::ext::take_request_completion(&mut request).is_none());
    assert!(h2::ext::take_request_completion(&mut clone).is_none());
    peer.task.abort();
    assert_eq!(done.try_result(), Some(Ok(())));
}
#[tokio::test]
async fn validated_data_or_trailers_finish_while_payload_is_unread() {
    for trailers in [false, true] {
        let mut peer = Peer::new().await;
        let mut request = peer.request(false, Some(4)).await;
        let mut done = h2::ext::take_request_completion(&mut request).unwrap();
        peer.send(&frame(0, 0, 1, b"bo")).await;
        peer.barrier().await;
        assert!(done.try_result().is_none());
        peer.send(&frame(0, u8::from(!trailers), 1, b"dy")).await;
        if trailers {
            peer.send(&frame(1, 5, 1, b"\0\x07x-proof\x03yes")).await;
        }
        peer.barrier().await;
        assert_eq!(done.try_result(), Some(Ok(())));
        // Neither Incoming nor the outbound body has been polled.
        let data = request.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(data, b"body".as_slice());
    }
}
#[tokio::test]
async fn no_error_and_cancel_reset_abort_even_when_incoming_maps_reset_to_none() {
    for reason in [0_u32, 8] {
        let mut peer = Peer::new().await;
        let mut request = peer.request(false, None).await;
        let done = h2::ext::take_request_completion(&mut request).unwrap();
        peer.send(&frame(3, 0, 1, &reason.to_be_bytes())).await;
        peer.barrier().await;
        assert!(timeout(LIMIT, done).await.unwrap().is_err());
        let frame = request.body_mut().frame().await;
        if reason == 0 {
            assert!(frame.is_none());
        } else {
            assert!(frame.unwrap().is_err());
        }
    }
}
#[tokio::test]
async fn invalid_data_or_trailers_do_not_complete_before_validation() {
    for (case, (length, frames)) in [
        (4, vec![frame(0, 1, 1, b"ab")]),
        (1, vec![frame(0, 1, 1, b"ab")]),
        (
            4,
            vec![
                frame(0, 0, 1, b"ab"),
                frame(1, 5, 1, b"\0\x07x-proof\x03yes"),
            ],
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut peer = Peer::new().await;
        let mut request = peer.request(false, Some(length)).await;
        let done = h2::ext::take_request_completion(&mut request).unwrap();
        for f in frames {
            peer.send(&f).await;
        }
        peer.barrier().await;
        assert!(
            timeout(LIMIT, done).await.unwrap().is_err(),
            "invalid case {case}"
        );
    }
}
#[tokio::test]
async fn cancellation_or_connection_drop_aborts_and_latched_end_survives_later_reset() {
    for mode in [0, 1, 2] {
        let mut peer = Peer::new().await;
        let mut request = peer.request(false, None).await;
        let mut done = h2::ext::take_request_completion(&mut request).unwrap();
        if mode == 2 {
            peer.send(&frame(0, 1, 1, b"complete")).await;
            peer.barrier().await;
            peer.send(&frame(3, 0, 1, &8_u32.to_be_bytes())).await;
            peer.barrier().await;
            drop(request);
            assert_eq!(done.try_result(), Some(Ok(())));
        } else {
            if mode == 0 {
                drop(request);
            } else {
                peer.task.abort();
            }
            assert!(timeout(LIMIT, done).await.unwrap().is_err());
        }
    }
}

#[tokio::test]
async fn request_trailers_preserve_bytes_or_reject_pseudo_at_connection_scope() {
    // Actual configured source accepts x-proof but rejects HPACK 0x84 with
    // GOAWAY(PROTOCOL_ERROR), before request EOM/provenance/origin contact.
    // This protocol fixture proves the prerequisite EOM/error boundary only.
    let mut oversized_path = vec![4, 127, 217, 3]; // :path, literal 600-byte value
    oversized_path.extend_from_slice(&[b'a'; 600]);
    let mut oversized_ordinary = b"\0\x07x-proof\x7f\xd9\x03".to_vec();
    oversized_ordinary.extend_from_slice(&[b'a'; 600]);
    for (name, trailer, reason) in [
        ("ordinary", b"\0\x07x-proof\x03yes".as_slice(), None),
        ("path", b"\x84".as_slice(), Some(1)),
        ("status", b"\x88".as_slice(), Some(1)),
        ("oversized-path", oversized_path.as_slice(), Some(11)),
        (
            "oversized-ordinary",
            oversized_ordinary.as_slice(),
            Some(11),
        ),
    ] {
        // Use the existing configured limit; initial headers and valid trailers
        // fit. Oversized pseudo fields are discarded by HPACK before recv_trailers.
        let mut peer = Peer::with_header_limit(Some(512)).await;
        let mut request = peer.request(false, Some(2)).await;
        let mut done = h2::ext::take_request_completion(&mut request).unwrap();
        peer.send(&frame(0, 0, 1, b"ab")).await;
        peer.barrier().await;
        assert!(done.try_result().is_none());
        assert_eq!(
            request
                .body_mut()
                .frame()
                .await
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap(),
            b"ab".as_slice()
        );
        peer.send(&frame(1, 5, 1, trailer)).await;
        if let Some(reason) = reason {
            assert_eq!(
                peer.goaway().await,
                reason,
                "{name}: source connection error scope"
            );
            assert!(timeout(LIMIT, &mut done).await.unwrap().is_err());
            assert!(request.body_mut().frame().await.unwrap().is_err());
            drop(request);
            timeout(LIMIT, &mut peer.task).await.unwrap().unwrap();
            let mut byte = [0];
            assert_eq!(
                timeout(LIMIT, peer.socket.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
            assert!(done.try_result().unwrap().is_err());
        } else {
            peer.barrier().await;
            assert_eq!(done.try_result(), Some(Ok(())));
            let tail = request.into_body().collect().await.unwrap();
            assert_eq!(tail.trailers().unwrap()["x-proof"], "yes");
            assert!(tail.to_bytes().is_empty());
            peer.task.abort();
            let _ = (&mut peer.task).await;
        }
        println!("PASS request trailer={name} reason={reason:?} prefix=ab joined=true");
    }
}

#[tokio::test]
async fn zero_length_still_requires_end_stream_and_try_result_preserves_waker() {
    use std::{
        future::Future,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };
    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let mut peer = Peer::new().await;
    let mut request = peer.request(false, Some(0)).await;
    let mut done = h2::ext::take_request_completion(&mut request).unwrap();
    peer.barrier().await;
    let counter = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(counter.clone());
    let mut context = Context::from_waker(&waker);
    assert!(matches!(
        Pin::new(&mut done).poll(&mut context),
        Poll::Pending
    ));
    assert!(done.try_result().is_none());
    assert_eq!(counter.0.load(Ordering::SeqCst), 0);
    peer.send(&frame(0, 1, 1, b"")).await;
    peer.barrier().await;
    assert!(counter.0.load(Ordering::SeqCst) > 0);
    assert_eq!(done.try_result(), Some(Ok(())));
}
