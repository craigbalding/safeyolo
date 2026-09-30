//! Valid response heads retain observed fields before unread completion.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{HeaderMap, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    task::JoinHandle,
};

const LIMIT: Duration = Duration::from_secs(3);
type Pairs = Vec<(Vec<u8>, Vec<u8>)>;

#[derive(Default)]
struct Observed {
    heads: usize,
    legacy_heads: usize,
    fields: Option<Pairs>,
    reason: Option<Vec<u8>>,
    data: Vec<u8>,
    terminal_head: bool,
}

#[derive(Default)]
struct Capture(Mutex<Observed>);

impl Capture {
    fn head(&self, terminal: bool, fields: Option<Pairs>, reason: Option<&[u8]>) {
        let mut seen = self.0.lock().unwrap();
        seen.heads += 1;
        assert_eq!(seen.heads, 1);
        assert!(seen.data.is_empty());
        seen.fields = fields;
        seen.reason = reason.map(<[u8]>::to_vec);
        seen.terminal_head = terminal;
    }

    fn data(&self, data: &[u8]) {
        let mut seen = self.0.lock().unwrap();
        assert_eq!(seen.heads, 1, "head facts precede accepted DATA");
        seen.data.extend_from_slice(data);
    }
}

impl hyper::ext::ResponseBodyCapture for Capture {
    fn head(&self, _: StatusCode, _: &HeaderMap, _: bool) {
        panic!("extended implementation receives the extended callback");
    }
    fn head_with_fields(
        &self,
        _: StatusCode,
        _: &HeaderMap,
        end: bool,
        fields: Option<&hyper::ext::OriginalHeaderFields>,
        reason: Option<&[u8]>,
    ) {
        self.head(
            end,
            fields.map(|fields| {
                fields
                    .iter()
                    .map(|(n, v)| (n.to_vec(), v.to_vec()))
                    .collect()
            }),
            reason,
        );
    }
    fn data(&self, data: &[u8]) {
        self.data(data);
    }
}

impl h2::ext::ResponseBodyCapture for Capture {
    fn head(&self, _: StatusCode, _: &HeaderMap, _: bool) {
        panic!("extended implementation receives the extended callback");
    }
    fn head_with_fields(
        &self,
        _: StatusCode,
        _: &HeaderMap,
        end: bool,
        fields: Option<&h2::ext::OriginalHeaderFields>,
        reason: Option<&[u8]>,
    ) {
        self.head(
            end,
            fields.map(|fields| {
                fields
                    .iter()
                    .map(|(n, v)| (n.to_vec(), v.to_vec()))
                    .collect()
            }),
            reason,
        );
    }
    fn data(&self, data: &[u8]) {
        self.data(data);
    }
}

#[derive(Default)]
struct Legacy(Capture);

impl Legacy {
    fn head(&self, terminal: bool) {
        self.0.head(terminal, None, None);
        self.0.0.lock().unwrap().legacy_heads += 1;
    }
}

impl hyper::ext::ResponseBodyCapture for Legacy {
    fn head(&self, _: StatusCode, _: &HeaderMap, end: bool) {
        self.head(end);
    }
    fn data(&self, data: &[u8]) {
        self.0.data(data);
    }
}
impl h2::ext::ResponseBodyCapture for Legacy {
    fn head(&self, _: StatusCode, _: &HeaderMap, end: bool) {
        self.head(end);
    }
    fn data(&self, data: &[u8]) {
        self.0.data(data);
    }
}

struct Driver(JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl Driver {
    async fn stop(mut self) {
        self.0.abort();
        if let Err(error) = (&mut self.0).await {
            assert!(error.is_cancelled());
        }
    }
}

async fn h1(
    reason: &[u8],
    payload: &[u8],
    preserve: bool,
    capture: Arc<dyn hyper::ext::ResponseBodyCapture>,
) -> Option<Pairs> {
    let mut head = b"HTTP/1.1 200 ".to_vec();
    head.extend_from_slice(reason);
    head.extend_from_slice(
        format!(
            "\r\nX-One: a\r\nX-Two: b\r\nx-oNe: c\r\nContent-Length: {}\r\n\r\n",
            payload.len()
        )
        .as_bytes(),
    );
    let (fields, extension) = h1_wire(&head, payload, preserve, false, capture).await;
    assert_eq!(
        extension.as_deref(),
        if reason == b"OK" { None } else { Some(reason) }
    );
    fields
}

async fn h1_wire(
    head: &[u8],
    payload: &[u8],
    preserve: bool,
    http09: bool,
    capture: Arc<dyn hyper::ext::ResponseBodyCapture>,
) -> (Option<Pairs>, Option<Vec<u8>>) {
    let (client, mut peer) = tokio::io::duplex(65536);
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .preserve_header_case(preserve)
        .http09_responses(http09)
        .handshake(TokioIo::new(client))
        .await
        .unwrap();
    let driver = Driver(tokio::spawn(async move {
        connection.await.unwrap();
    }));
    let mut request = Request::builder()
        .uri("http://owned.invalid/")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let mut completion = hyper::ext::on_response_complete_with_capture(&mut request, capture);
    let response = sender.send_request(request);
    let mut request_head = Vec::new();
    while !request_head.ends_with(b"\r\n\r\n") {
        request_head.push(
            tokio::time::timeout(LIMIT, peer.read_u8())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    peer.write_all(head).await.unwrap();
    peer.write_all(payload).await.unwrap();
    if http09 {
        peer.shutdown().await.unwrap();
    }
    // Framed responses complete with both response future and body unread.
    // HTTP/0.9's EOF decoder instead needs its queued body to be consumed.
    if !http09 {
        assert_eq!(
            tokio::time::timeout(LIMIT, &mut completion)
                .await
                .unwrap()
                .unwrap(),
            StatusCode::OK
        );
    }
    let response = tokio::time::timeout(LIMIT, response)
        .await
        .unwrap()
        .unwrap();
    let extension = response
        .extensions()
        .get::<hyper::ext::ReasonPhrase>()
        .map(|reason| reason.as_bytes().to_vec());
    let fields = response
        .extensions()
        .get::<hyper::ext::OriginalHeaderFields>()
        .map(|fields| {
            fields
                .iter()
                .map(|(n, v)| (n.to_vec(), v.to_vec()))
                .collect()
        });
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        payload
    );
    if http09 {
        assert_eq!(
            tokio::time::timeout(LIMIT, completion)
                .await
                .unwrap()
                .unwrap(),
            StatusCode::OK
        );
    }
    drop(sender);
    drop(peer);
    driver.stop().await;
    (fields, extension)
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![
        (payload.len() >> 16) as u8,
        (payload.len() >> 8) as u8,
        payload.len() as u8,
        kind,
        flags,
    ];
    bytes.extend_from_slice(&stream.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

async fn read_frame(peer: &mut DuplexStream) -> (u8, u32) {
    let mut head = [0; 9];
    peer.read_exact(&mut head).await.unwrap();
    let len = ((head[0] as usize) << 16) | ((head[1] as usize) << 8) | head[2] as usize;
    let mut payload = vec![0; len];
    peer.read_exact(&mut payload).await.unwrap();
    (
        head[3],
        u32::from_be_bytes(head[5..].try_into().unwrap()) & 0x7fff_ffff,
    )
}

async fn h2(payload: &'static [u8], capture: Arc<dyn h2::ext::ResponseBodyCapture>) -> Pairs {
    let (client, mut peer) = tokio::io::duplex(65536);
    let peer_task = Driver(tokio::spawn(async move {
        let mut preface = [0; 24];
        peer.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        peer.write_all(&frame(4, 0, 0, b"")).await.unwrap();
        while read_frame(&mut peer).await != (1, 1) {}
        let mut headers = b"\x88\x00\x05x-one\x01a\x00\x05x-two\x01b\x00\x05x-one\x01c".to_vec();
        headers.extend_from_slice(b"\x0f\x0d\x01");
        headers.push(if payload.is_empty() { b'0' } else { b'2' });
        peer.write_all(&frame(1, 4 | u8::from(payload.is_empty()), 1, &headers))
            .await
            .unwrap();
        if !payload.is_empty() {
            peer.write_all(&frame(0, 1, 1, payload)).await.unwrap();
        }
        // Keep the owned transport alive until the test has inspected completion.
        let mut discarded = [0; 1024];
        while peer.read(&mut discarded).await.unwrap_or(0) != 0 {}
    }));
    let (mut sender, connection) = h2::client::handshake(client).await.unwrap();
    let driver = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let mut request = Request::builder()
        .uri("https://owned.invalid/")
        .body(())
        .unwrap();
    let completion = h2::ext::on_response_complete_with_capture(&mut request, capture);
    let (response, _) = sender.send_request(request, true).unwrap();
    assert_eq!(
        tokio::time::timeout(LIMIT, completion)
            .await
            .unwrap()
            .unwrap(),
        StatusCode::OK
    );
    let response = response.await.unwrap();
    let fields = response
        .extensions()
        .get::<h2::ext::OriginalHeaderFields>()
        .unwrap()
        .iter()
        .map(|(n, v)| (n.to_vec(), v.to_vec()))
        .collect();
    let mut body = response.into_body();
    let mut data = Vec::new();
    while let Some(chunk) = body.data().await {
        data.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(data, payload);
    drop(body);
    drop(sender);
    driver.stop().await;
    peer_task.stop().await;
    fields
}

fn expected(h2: bool, size: u8) -> Pairs {
    if h2 {
        vec![
            (b"x-one".to_vec(), b"a".to_vec()),
            (b"x-two".to_vec(), b"b".to_vec()),
            (b"x-one".to_vec(), b"c".to_vec()),
            (b"content-length".to_vec(), vec![size]),
        ]
    } else {
        vec![
            (b"X-One".to_vec(), b"a".to_vec()),
            (b"X-Two".to_vec(), b"b".to_vec()),
            (b"x-oNe".to_vec(), b"c".to_vec()),
            (b"Content-Length".to_vec(), vec![size]),
        ]
    }
}

#[tokio::test]
async fn h1_observed_pairs_and_reason_precede_unread_completion() {
    for (reason, payload) in [
        (b"Fine".as_slice(), b"".as_slice()),
        (b"".as_slice(), b"".as_slice()),
        (b"OK".as_slice(), b"".as_slice()),
        (b"Fine".as_slice(), b"ab".as_slice()),
        (b"Owned \xff\xe9".as_slice(), b"".as_slice()),
        (b"Owned \xff\xe9".as_slice(), b"ab".as_slice()),
        (b"\xc3\xa9".as_slice(), b"".as_slice()),
        (b" \tOwned \xff\xe9  ".as_slice(), b"".as_slice()),
    ] {
        let capture = Arc::new(Capture::default());
        let fields = h1(reason, payload, true, capture.clone()).await;
        let seen = capture.0.lock().unwrap();
        assert_eq!(seen.fields, fields);
        assert_eq!(
            seen.fields,
            Some(expected(
                false,
                if payload.is_empty() { b'0' } else { b'2' }
            ))
        );
        assert_eq!(seen.reason.as_deref(), Some(reason));
        assert_eq!(seen.data, payload);
        assert_eq!(seen.terminal_head, payload.is_empty());
    }
}

#[tokio::test]
async fn h1_original_fields_are_absent_without_preserve_option() {
    let capture = Arc::new(Capture::default());
    assert!(h1(b"Fine", b"", false, capture.clone()).await.is_none());
    let seen = capture.0.lock().unwrap();
    assert!(seen.fields.is_none());
    assert_eq!(seen.reason.as_deref(), Some(b"Fine".as_slice()));
}

#[tokio::test]
async fn h2_observed_pairs_and_empty_reason_precede_unread_completion() {
    for payload in [b"".as_slice(), b"ab".as_slice()] {
        let capture = Arc::new(Capture::default());
        let fields = h2(payload, capture.clone()).await;
        let seen = capture.0.lock().unwrap();
        assert_eq!(seen.fields.as_ref(), Some(&fields));
        assert_eq!(
            fields,
            expected(true, if payload.is_empty() { b'0' } else { b'2' })
        );
        assert_eq!(seen.reason.as_deref(), Some(b"".as_slice()));
        assert_eq!(seen.data, payload);
        assert_eq!(seen.terminal_head, payload.is_empty());
    }
}

#[tokio::test]
async fn old_head_and_data_implementations_keep_their_callbacks() {
    let h1_capture = Arc::new(Legacy::default());
    h1(b"Fine", b"ab", true, h1_capture.clone()).await;
    let h2_capture = Arc::new(Legacy::default());
    h2(b"ab", h2_capture.clone()).await;
    for capture in [h1_capture, h2_capture] {
        let seen = capture.0.0.lock().unwrap();
        assert_eq!(seen.legacy_heads, 1);
        assert_eq!(seen.data, b"ab");
    }
}

#[tokio::test]
async fn h1_validated_status_line_forms_keep_raw_reason_bytes() {
    for (line, reason) in [
        (b"HTTP/1.1 200\r\n".as_slice(), b"".as_slice()),
        (b"HTTP/1.0 200\r\n".as_slice(), b"".as_slice()),
        (
            b"HTTP/1.1 200 Owned \xff\xe9\n".as_slice(),
            b"Owned \xff\xe9".as_slice(),
        ),
        (
            b"\r\n\nHTTP/1.1 200 \tOwned \xff\xe9 \t\r\n".as_slice(),
            b"\tOwned \xff\xe9 \t".as_slice(),
        ),
        (b"HTTP/1.1 200 OK  \r\n".as_slice(), b"OK  ".as_slice()),
    ] {
        let capture = Arc::new(Capture::default());
        let mut head = line.to_vec();
        head.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        let (_, extension) = h1_wire(&head, b"", true, false, capture.clone()).await;
        assert_eq!(extension.as_deref(), Some(reason));
        assert_eq!(capture.0.lock().unwrap().reason.as_deref(), Some(reason));
    }
}

#[tokio::test]
async fn h09_fallback_has_no_status_line_reason() {
    let capture = Arc::new(Capture::default());
    let (_, extension) = h1_wire(b"", b"owned body", true, true, capture.clone()).await;
    assert!(extension.is_none());
    let seen = capture.0.lock().unwrap();
    assert!(seen.reason.is_none());
    assert_eq!(seen.data, b"owned body");
}
