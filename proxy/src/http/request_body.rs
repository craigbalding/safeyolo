//! Buffer source-small request bytes and replay them with their trailer order.
//!
//! A body terminal is not a validated parser EOM: Hyper's HTTP/2 Incoming can
//! return None for a NO_ERROR reset. Callers must check independent parser
//! completion before applying context or using the unvalidated captured content.
//! No request-completion effects run on a body terminal, size hint, or drop.

use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use zeroize::Zeroizing;

use crate::http_content::BufferedContent;

pub(super) struct Prepared<B> {
    pub(super) body: ReplayBody<B>,
    /// Some only after buffering observed body None. Parser validation is still
    /// required; None instead means preparation stopped for streamed content.
    pub(super) unvalidated_content: Option<Zeroizing<Vec<u8>>>,
}

pub(super) struct ReplayBody<B> {
    source: B,
    frames: VecDeque<Frame<Bytes>>,
    source_terminal: bool,
    terminal_visible: bool,
    remaining_hint: SizeHint,
}

/// Buffer until a body terminal or the source encoded-body streaming threshold.
/// Known large or explicitly streamed bodies are returned without polling them.
pub(super) async fn prepare<B>(
    mut body: B,
    content_length: Option<u64>,
    streamed: bool,
) -> Result<Prepared<B>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    let remaining_hint = body.size_hint();
    let terminal_visible = body.is_end_stream();
    let mut content = BufferedContent::new(content_length, streamed);
    let mut frames = VecDeque::new();
    let mut buffered_data = BytesMut::new();
    let mut source_terminal = false;
    while !content.is_streamed() {
        let Some(frame) = body.frame().await else {
            source_terminal = true;
            break;
        };
        let frame = frame?;
        if let Some(data) = frame.data_ref() {
            content.push(data);
            if !content.is_streamed() {
                // Copy adjacent payloads into one allocation. Keeping each
                // source Bytes could pin a large slab for a one-byte slice;
                // empty DATA must not create retained queue entries either.
                buffered_data.extend_from_slice(data);
                continue;
            }
        }
        flush_data(&mut buffered_data, &mut frames);
        frames.push_back(frame);
    }
    flush_data(&mut buffered_data, &mut frames);
    Ok(Prepared {
        body: ReplayBody {
            source: body,
            frames,
            source_terminal,
            terminal_visible,
            remaining_hint,
        },
        unvalidated_content: if source_terminal {
            content.into_content()
        } else {
            None
        },
    })
}

fn flush_data(data: &mut BytesMut, frames: &mut VecDeque<Frame<Bytes>>) {
    if !data.is_empty() {
        frames.push_back(Frame::data(std::mem::take(data).freeze()));
    }
}

impl<B> ReplayBody<B> {
    fn forwarded(&mut self, frame: &Frame<Bytes>) {
        self.terminal_visible = true;
        if let Some(data) = frame.data_ref() {
            let length = data.len() as u64;
            let lower = self.remaining_hint.lower().saturating_sub(length);
            let upper = self
                .remaining_hint
                .upper()
                .map(|upper| upper.saturating_sub(length));
            self.remaining_hint.set_lower(lower);
            if let Some(upper) = upper {
                self.remaining_hint.set_upper(upper);
            }
        }
    }
}

impl<B> Body for ReplayBody<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(frame) = this.frames.pop_front() {
            this.forwarded(&frame);
            return Poll::Ready(Some(Ok(frame)));
        }
        if this.source_terminal {
            this.terminal_visible = true;
            return Poll::Ready(None);
        }
        match Pin::new(&mut this.source).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                this.forwarded(&frame);
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(terminal) => {
                this.source_terminal = true;
                this.terminal_visible = true;
                this.remaining_hint = SizeHint::with_exact(0);
                Poll::Ready(terminal)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        // Preserve the source's initial framing choice for an empty unknown
        // body: it must still be polled to finish an outbound chunked message.
        self.source_terminal && self.frames.is_empty() && self.terminal_visible
    }

    fn size_hint(&self) -> SizeHint {
        // In particular, buffered chunked input remains unknown length. Giving
        // it a new exact hint would alter outbound HTTP/1 framing selection.
        self.remaining_hint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        convert::Infallible,
        future::Future,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::Waker,
        time::Duration,
    };

    use http_body_util::Empty;
    use hyper::{HeaderMap, Request, Response, service::service_fn};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::{Mutex, oneshot},
    };

    use crate::http_content::BUFFERED_BODY_THRESHOLD;

    struct Source {
        frames: VecDeque<Result<Frame<Bytes>, &'static str>>,
        hint: SizeHint,
        pending_after_frames: bool,
        polls: Arc<AtomicUsize>,
        dropped: Arc<AtomicBool>,
    }

    impl Source {
        fn new(frames: impl IntoIterator<Item = Result<Frame<Bytes>, &'static str>>) -> Self {
            Self {
                frames: frames.into_iter().collect(),
                hint: SizeHint::default(),
                pending_after_frames: false,
                polls: Arc::new(AtomicUsize::new(0)),
                dropped: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl Drop for Source {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl Body for Source {
        type Data = Bytes;
        type Error = &'static str;

        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            let this = self.get_mut();
            this.polls.fetch_add(1, Ordering::SeqCst);
            if this.frames.is_empty() && this.pending_after_frames {
                Poll::Pending
            } else {
                Poll::Ready(this.frames.pop_front())
            }
        }

        fn size_hint(&self) -> SizeHint {
            self.hint
        }
    }

    fn data(bytes: &'static [u8]) -> Result<Frame<Bytes>, &'static str> {
        Ok(Frame::data(Bytes::from_static(bytes)))
    }

    #[tokio::test]
    async fn buffered_bytes_and_trailers_replay_without_repolling_source() {
        let mut trailers = HeaderMap::new();
        trailers.append("x-owned-trailer", "one".parse().unwrap());
        trailers.append("x-owned-trailer", "two".parse().unwrap());
        for exact in [false, true] {
            let mut source = Source::new([
                data(b"pre"),
                data(b""),
                data(b"fix"),
                Ok(Frame::trailers(trailers.clone())),
            ]);
            if exact {
                source.hint = SizeHint::with_exact(6);
            }
            let polls = source.polls.clone();
            let Prepared {
                mut body,
                unvalidated_content,
            } = prepare(source, exact.then_some(6), false).await.unwrap();
            assert_eq!(polls.load(Ordering::SeqCst), 5);
            assert_eq!(unvalidated_content.unwrap().as_slice(), b"prefix");
            assert_eq!(body.size_hint().exact(), exact.then_some(6));
            assert!(!body.is_end_stream());
            assert_eq!(
                body.frame().await.unwrap().unwrap().into_data().unwrap(),
                b"prefix".as_slice()
            );
            assert_eq!(body.size_hint().exact(), exact.then_some(0));
            assert!(!body.is_end_stream(), "trailers remain queued");
            assert_eq!(
                body.frame()
                    .await
                    .unwrap()
                    .unwrap()
                    .into_trailers()
                    .unwrap(),
                trailers
            );
            assert!(body.is_end_stream());
            assert!(body.frame().await.is_none());
            assert_eq!(polls.load(Ordering::SeqCst), 5);
        }
    }

    #[tokio::test]
    async fn empty_runs_and_tiny_payload_slices_do_not_retain_frames_or_backing_slabs() {
        struct Slab {
            bytes: [u8; 8192],
            live: Arc<AtomicUsize>,
        }
        impl AsRef<[u8]> for Slab {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
        impl Drop for Slab {
            fn drop(&mut self) {
                self.live.fetch_sub(1, Ordering::SeqCst);
            }
        }
        struct Burst {
            empty: usize,
            payload: usize,
            trailer: bool,
            live: Arc<AtomicUsize>,
            peak: Arc<AtomicUsize>,
        }
        impl Body for Burst {
            type Data = Bytes;
            type Error = Infallible;

            fn poll_frame(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
                let this = self.get_mut();
                if this.empty > 0 {
                    this.empty -= 1;
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::new()))));
                }
                if this.payload > 0 {
                    this.payload -= 1;
                    let live = this.live.fetch_add(1, Ordering::SeqCst) + 1;
                    this.peak.fetch_max(live, Ordering::SeqCst);
                    let bytes = Bytes::from_owner(Slab {
                        bytes: [b'x'; 8192],
                        live: this.live.clone(),
                    });
                    return Poll::Ready(Some(Ok(Frame::data(bytes.slice(4095..4096)))));
                }
                if this.trailer {
                    this.trailer = false;
                    let mut trailer = HeaderMap::new();
                    trailer.insert("x-owned-control", "finished".parse().unwrap());
                    return Poll::Ready(Some(Ok(Frame::trailers(trailer))));
                }
                Poll::Ready(None)
            }
        }
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let Prepared {
            mut body,
            unvalidated_content,
        } = prepare(
            Burst {
                empty: 100_000,
                payload: 4096,
                trailer: true,
                live: live.clone(),
                peak: peak.clone(),
            },
            None,
            false,
        )
        .await
        .unwrap();
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert_eq!(peak.load(Ordering::SeqCst), 1);
        assert_eq!(body.frames.len(), 2, "one owned DATA segment and trailers");
        let content = unvalidated_content.unwrap();
        assert_eq!(content.len(), 4096);
        assert!(content.iter().all(|byte| *byte == b'x'));
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            content.as_slice()
        );
        let trailer = body
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_trailers()
            .unwrap();
        assert_eq!(trailer["x-owned-control"], "finished");
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn empty_content_requires_a_body_terminal_even_with_zero_hint() {
        let mut source = Source::new([]);
        source.hint = SizeHint::with_exact(0);
        let polls = source.polls.clone();
        let mut prepared = prepare(source, Some(0), false).await.unwrap();
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert!(prepared.unvalidated_content.unwrap().is_empty());
        assert!(!prepared.body.is_end_stream());
        assert!(prepared.body.frame().await.is_none());
        assert!(prepared.body.is_end_stream());
    }

    #[tokio::test]
    async fn known_large_and_explicit_streaming_skip_initial_polls() {
        for (length, streamed) in [
            (Some(BUFFERED_BODY_THRESHOLD as u64 + 1), false),
            (None, true),
            (Some(0), true),
        ] {
            let source = Source::new([data(b"first"), data(b"second")]);
            let polls = source.polls.clone();
            let Prepared {
                mut body,
                unvalidated_content,
            } = prepare(source, length, streamed).await.unwrap();
            assert!(unvalidated_content.is_none());
            assert_eq!(polls.load(Ordering::SeqCst), 0);
            assert!(!body.is_end_stream());
            for expected in [b"first".as_slice(), b"second"] {
                assert_eq!(
                    body.frame().await.unwrap().unwrap().into_data().unwrap(),
                    expected
                );
            }
            assert!(!body.is_end_stream());
            assert!(body.frame().await.is_none());
            assert!(body.is_end_stream());
            assert_eq!(polls.load(Ordering::SeqCst), 3);
        }
    }

    #[tokio::test]
    async fn exact_threshold_waits_for_terminal_but_crossing_returns_before_next_poll() {
        let threshold = Bytes::from(vec![b'x'; BUFFERED_BODY_THRESHOLD]);
        let source = Source::new([Ok(Frame::data(threshold.clone()))]);
        let polls = source.polls.clone();
        let prepared = prepare(source, None, false).await.unwrap();
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(prepared.unvalidated_content.unwrap().len(), threshold.len());

        let source = Source::new([
            Ok(Frame::data(threshold.clone())),
            data(b"y"),
            data(b"remaining"),
        ]);
        let polls = source.polls.clone();
        let Prepared {
            mut body,
            unvalidated_content,
        } = prepare(source, None, false).await.unwrap();
        assert!(unvalidated_content.is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(body.size_hint().upper(), None);
        for expected in [threshold.as_ref(), b"y".as_slice()] {
            assert_eq!(
                body.frame().await.unwrap().unwrap().into_data().unwrap(),
                expected
            );
            assert_eq!(polls.load(Ordering::SeqCst), 2);
        }
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            b"remaining".as_slice()
        );
        assert!(body.frame().await.is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn errors_survive_preparation_and_streamed_replay_without_later_frames() {
        let source = Source::new([data(b"partial"), Err("before terminal")]);
        let dropped = source.dropped.clone();
        assert!(matches!(
            prepare(source, None, false).await,
            Err("before terminal")
        ));
        assert!(dropped.load(Ordering::SeqCst));

        let source = Source::new([
            Ok(Frame::data(Bytes::from(vec![
                b'x';
                BUFFERED_BODY_THRESHOLD + 1
            ]))),
            Err("after crossing"),
            data(b"must not be forwarded after error"),
        ]);
        let polls = source.polls.clone();
        let mut body = prepare(source, None, false).await.unwrap().body;
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert!(body.frame().await.unwrap().is_ok());
        assert!(matches!(body.frame().await, Some(Err("after crossing"))));
        assert!(body.frame().await.is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn dropping_pending_preparation_or_replay_does_not_poll_for_completion() {
        let mut source = Source::new([data(b"partial")]);
        source.pending_after_frames = true;
        source.hint = SizeHint::with_exact(0);
        let polls = source.polls.clone();
        let dropped = source.dropped.clone();
        let mut preparation = Box::pin(prepare(source, Some(0), false));
        let mut context = Context::from_waker(Waker::noop());
        assert!(preparation.as_mut().poll(&mut context).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert!(!dropped.load(Ordering::SeqCst));
        drop(preparation);
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(polls.load(Ordering::SeqCst), 2);

        let mut source = Source::new([data(b"partial")]);
        source.pending_after_frames = true;
        let polls = source.polls.clone();
        let dropped = source.dropped.clone();
        let mut preparation = Box::pin(prepare(source, None, true));
        let Poll::Ready(Ok(mut prepared)) = preparation.as_mut().poll(&mut context) else {
            panic!("explicitly streamed preparation must not poll the source");
        };
        assert!(
            Pin::new(&mut prepared.body)
                .poll_frame(&mut context)
                .is_ready()
        );
        assert!(
            Pin::new(&mut prepared.body)
                .poll_frame(&mut context)
                .is_pending()
        );
        assert!(!prepared.body.is_end_stream());
        drop(prepared);
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(polls.load(Ordering::SeqCst), 2);
    }

    struct Task<T>(tokio::task::JoinHandle<T>);
    impl<T> Drop for Task<T> {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    #[tokio::test]
    async fn actual_h1_empty_unknown_body_preserves_chunked_framing() {
        let mut observed = Vec::new();
        for replay in [false, true] {
            let source = Source::new([]);
            let body = if replay {
                prepare(source, None, false)
                    .await
                    .unwrap()
                    .body
                    .map_err(std::io::Error::other)
                    .boxed()
            } else {
                source.map_err(std::io::Error::other).boxed()
            };
            let (client, mut peer) = tokio::io::duplex(4096);
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(client))
                    .await
                    .unwrap();
            let _driver = Task(tokio::spawn(connection));
            let mut peer_task = Task(tokio::spawn(async move {
                let mut wire = Vec::new();
                while !wire.ends_with(b"\r\n\r\n") {
                    wire.push(peer.read_u8().await.unwrap());
                }
                let head_length = wire.len();
                while !wire[head_length..].ends_with(b"0\r\n\r\n") {
                    wire.push(peer.read_u8().await.unwrap());
                }
                peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
                wire
            }));
            let response = tokio::time::timeout(
                Duration::from_secs(3),
                sender.send_request(
                    Request::builder()
                        .method("POST")
                        .uri("/")
                        .header("Host", "owned.invalid")
                        .body(body)
                        .unwrap(),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(response.status(), 200);
            observed.push(
                tokio::time::timeout(Duration::from_secs(3), &mut peer_task.0)
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        assert_eq!(observed[0], observed[1]);
        assert!(
            String::from_utf8(observed.pop().unwrap())
                .unwrap()
                .contains("transfer-encoding: chunked\r\n")
        );
    }

    #[tokio::test]
    async fn actual_h2_no_error_reset_is_only_an_unvalidated_body_terminal() {
        for reset in [false, true] {
            let (client, server) = tokio::io::duplex(16_384);
            let (body_sender, body_receiver) = oneshot::channel();
            let body_sender = Arc::new(Mutex::new(Some(body_sender)));
            let _server = Task(tokio::spawn(async move {
                hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(server),
                        service_fn(move |request: Request<hyper::body::Incoming>| {
                            let body_sender = body_sender.clone();
                            async move {
                                assert!(
                                    body_sender
                                        .lock()
                                        .await
                                        .take()
                                        .unwrap()
                                        .send(request.into_body())
                                        .is_ok()
                                );
                                std::future::pending::<Result<Response<Empty<Bytes>>, Infallible>>()
                                    .await
                            }
                        }),
                    )
                    .await
            }));
            let (mut sender, connection) = h2::client::handshake(client).await.unwrap();
            let _client = Task(tokio::spawn(connection));
            let (_response, mut stream) = sender
                .send_request(
                    Request::builder()
                        .method("POST")
                        .uri("https://owned.invalid/")
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            let incoming = tokio::time::timeout(Duration::from_secs(3), body_receiver)
                .await
                .unwrap()
                .unwrap();
            if reset {
                stream.send_reset(h2::Reason::NO_ERROR);
            } else {
                stream
                    .send_data(Bytes::from_static(b"complete"), true)
                    .unwrap();
            }
            let prepared =
                tokio::time::timeout(Duration::from_secs(3), prepare(incoming, None, false))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(
                prepared.unvalidated_content.unwrap().as_slice(),
                if reset { b"".as_slice() } else { b"complete" },
                "both paths yield captured bytes, but only END_STREAM is valid completion"
            );
        }
    }
}
