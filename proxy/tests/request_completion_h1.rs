use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, Response, body::Incoming, ext::take_request_completion, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{convert::Infallible, time::Duration};
use tokio::{
    io::{AsyncWriteExt, DuplexStream},
    sync::mpsc,
    task::JoinHandle,
    time::timeout,
};
const LIMIT: Duration = Duration::from_secs(2);
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
async fn peer() -> Peer {
    let (socket, server) = tokio::io::duplex(65536);
    let (tx, requests) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(
                TokioIo::new(server),
                service_fn(move |request| {
                    tx.send(request).unwrap();
                    std::future::pending::<Result<Response<Empty<Bytes>>, Infallible>>()
                }),
            )
            .await;
    });
    Peer {
        socket,
        requests,
        task,
    }
}
async fn request(peer: &mut Peer, head: &[u8]) -> Request<Incoming> {
    peer.socket.write_all(head).await.unwrap();
    timeout(LIMIT, peer.requests.recv()).await.unwrap().unwrap()
}
#[tokio::test]
async fn bodyless_head_is_complete_before_body_poll_and_receiver_is_taken_once() {
    for head in [
        b"GET / HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n".as_slice(),
        b"POST / HTTP/1.1\r\nHost: fixture.invalid\r\nContent-Length: 0\r\n\r\n",
    ] {
        let mut peer = peer().await;
        let mut request = request(&mut peer, head).await;
        let mut clone = Request::new(());
        *clone.extensions_mut() = request.extensions().clone();
        let mut done = take_request_completion(&mut request).unwrap();
        assert!(take_request_completion(&mut request).is_none());
        assert!(take_request_completion(&mut clone).is_none());
        peer.task.abort();
        assert_eq!(done.try_result(), Some(Ok(())));
    }
}
#[tokio::test]
async fn final_fixed_data_is_validated_before_unread_frame_delivery() {
    let mut peer = peer().await;
    let mut request = request(
        &mut peer,
        b"POST / HTTP/1.1\r\nHost: fixture.invalid\r\nContent-Length: 4\r\n\r\n",
    )
    .await;
    let mut done = take_request_completion(&mut request).unwrap();
    assert!(done.try_result().is_none());
    // Express body demand but leave the final payload unread in Incoming.
    assert!(
        timeout(Duration::from_millis(10), request.body_mut().frame())
            .await
            .is_err()
    );
    peer.socket.write_all(b"body").await.unwrap();
    assert_eq!(timeout(LIMIT, &mut done).await.unwrap(), Ok(()));
    let data = request
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(data, b"body".as_slice());
    // No poll(None) was needed, as with an outbound fixed-length encoder.
}
#[tokio::test]
async fn chunked_zero_and_trailers_complete_only_after_validated_terminal_framing() {
    for tail in [b"0\r\n\r\n".as_slice(), b"0\r\nx-proof: yes\r\n\r\n"] {
        let mut peer = peer().await;
        let mut request = request(
            &mut peer,
            b"POST / HTTP/1.1\r\nHost: fixture.invalid\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .await;
        let mut done = take_request_completion(&mut request).unwrap();
        peer.socket.write_all(b"4\r\nbody\r\n").await.unwrap();
        assert_eq!(
            request
                .body_mut()
                .frame()
                .await
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap(),
            b"body".as_slice()
        );
        assert!(done.try_result().is_none());
        assert!(
            timeout(Duration::from_millis(10), request.body_mut().frame())
                .await
                .is_err()
        );
        peer.socket.write_all(tail).await.unwrap();
        assert_eq!(timeout(LIMIT, &mut done).await.unwrap(), Ok(()));
        if tail.len() > 5 {
            assert!(
                request
                    .body_mut()
                    .frame()
                    .await
                    .unwrap()
                    .unwrap()
                    .is_trailers()
            );
        }
    }
}
#[tokio::test]
async fn truncated_or_invalid_framing_aborts_instead_of_observing_body_none() {
    for (head, bytes) in [
        (
            b"POST / HTTP/1.1\r\nHost: f\r\nContent-Length: 4\r\n\r\n".as_slice(),
            b"ab".as_slice(),
        ),
        (
            b"POST / HTTP/1.1\r\nHost: f\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"1\r\na\r\n0\r\nx-bad\r\n\r\n",
        ),
    ] {
        let mut peer = peer().await;
        let mut request = request(&mut peer, head).await;
        let done = take_request_completion(&mut request).unwrap();
        peer.socket.write_all(bytes).await.unwrap();
        peer.socket.shutdown().await.unwrap();
        let body = tokio::spawn(async move {
            while let Some(frame) = request.body_mut().frame().await {
                if frame.is_err() {
                    break;
                }
            }
        });
        assert!(timeout(LIMIT, done).await.unwrap().is_err());
        timeout(LIMIT, body).await.unwrap().unwrap();
    }
}
#[tokio::test]
async fn receive_body_or_connection_cancellation_aborts_pending_observer() {
    for drop_connection in [false, true] {
        let mut peer = peer().await;
        let mut request = request(
            &mut peer,
            b"POST / HTTP/1.1\r\nHost: f\r\nContent-Length: 4\r\n\r\n",
        )
        .await;
        let done = take_request_completion(&mut request).unwrap();
        if drop_connection {
            peer.task.abort();
        } else {
            drop(request);
        }
        assert!(timeout(LIMIT, done).await.unwrap().is_err());
    }
}
