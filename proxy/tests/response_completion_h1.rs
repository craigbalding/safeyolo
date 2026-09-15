#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty};
    use hyper::client::conn::http1::SendRequest;
    use hyper::ext::{ResponseCompletion, on_response_complete};
    use hyper::{Request, StatusCode};
    use hyper_util::rt::TokioIo;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    const LIMIT: Duration = Duration::from_secs(2);

    async fn connection() -> (SendRequest<Empty<Bytes>>, DuplexStream, JoinHandle<()>) {
        let (client, server) = tokio::io::duplex(65536);
        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client))
            .await
            .unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        (sender, server, driver)
    }

    fn request(method: &str) -> (Request<Empty<Bytes>>, ResponseCompletion) {
        let mut request = Request::builder()
            .method(method)
            .uri("http://fixture.test/")
            .body(Empty::new())
            .unwrap();
        let completion = on_response_complete(&mut request);
        (request, completion)
    }

    async fn read_request(server: &mut DuplexStream) {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(timeout(LIMIT, server.read_u8()).await.unwrap().unwrap());
        }
    }

    async fn pending(completion: &mut ResponseCompletion) {
        assert!(completion.try_result().is_none());
        assert!(
            timeout(Duration::from_millis(20), completion)
                .await
                .is_err()
        );
    }

    async fn cleanup(driver: JoinHandle<()>) {
        driver.abort();
        let _ = driver.await;
    }

    #[tokio::test]
    async fn empty_heads_complete_without_polling_incoming() {
        for (method, response, status) in [
            ("GET", "HTTP/1.1 204 No Content\r\n\r\n", 204),
            (
                "HEAD",
                "HTTP/1.1 500 Failure\r\nContent-Length: 900\r\n\r\n",
                500,
            ),
            ("GET", "HTTP/1.1 304 Not Modified\r\n\r\n", 304),
            (
                "GET",
                "HTTP/1.1 500 Failure\r\nContent-Length: 0\r\n\r\n",
                500,
            ),
            (
                "GET",
                "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: fixture\r\n\r\n",
                101,
            ),
            (
                "CONNECT",
                "HTTP/1.1 200 Connection Established\r\n\r\n",
                200,
            ),
        ] {
            let (mut sender, mut server, driver) = connection().await;
            let (request, mut completion) = request(method);
            let response_future = sender.send_request(request);
            read_request(&mut server).await;
            server.write_all(response.as_bytes()).await.unwrap();
            let response = timeout(LIMIT, response_future).await.unwrap().unwrap();
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(completion.try_result().unwrap().unwrap().as_u16(), status);
            drop(response); // Never poll the body.
            cleanup(driver).await;
        }
    }

    #[tokio::test]
    async fn readiness_probe_preserves_registered_waker() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use std::task::{Context, Wake, Waker};
        use std::{future::Future, pin::Pin};
        struct CountWake(AtomicUsize);
        impl Wake for CountWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let (mut sender, mut server, driver) = connection().await;
        let (request, mut completion) = request("GET");
        let response_future = sender.send_request(request);
        read_request(&mut server).await;
        let count = Arc::new(CountWake(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut completion).poll(&mut cx).is_pending());
        assert!(completion.try_result().is_none());
        server
            .write_all(b"HTTP/1.1 500 Failure\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let response = timeout(LIMIT, response_future).await.unwrap().unwrap();
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert_eq!(
            completion.try_result(),
            Some(Ok(StatusCode::INTERNAL_SERVER_ERROR))
        );
        drop(response);
        cleanup(driver).await;
    }

    #[tokio::test]
    async fn final_fixed_frame_completes_before_body_eof_poll() {
        let (mut sender, mut server, driver) = connection().await;
        let (request, mut completion) = request("GET");
        let response_future = sender.send_request(request);
        read_request(&mut server).await;
        server
            .write_all(b"HTTP/1.1 500 Failure\r\nContent-Length: 2\r\n\r\na")
            .await
            .unwrap();
        let mut response = timeout(LIMIT, response_future).await.unwrap().unwrap();
        assert_eq!(
            timeout(LIMIT, response.body_mut().frame())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap(),
            "a"
        );
        pending(&mut completion).await;
        server.write_all(b"b").await.unwrap();
        assert_eq!(
            timeout(LIMIT, response.body_mut().frame())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap(),
            "b"
        );
        // No additional body poll: the last DATA frame is sufficient.
        drop(response);
        assert_eq!(
            timeout(LIMIT, completion).await.unwrap(),
            Ok(StatusCode::INTERNAL_SERVER_ERROR)
        );
        cleanup(driver).await;
    }

    #[tokio::test]
    async fn chunked_terminal_and_trailers_complete() {
        for terminal in [
            b"0\r\n\r\n".as_slice(),
            b"0\r\nX-Fixture: done\r\n\r\n".as_slice(),
        ] {
            let (mut sender, mut server, driver) = connection().await;
            let (request, mut completion) = request("GET");
            let response_future = sender.send_request(request);
            read_request(&mut server).await;
            server
                .write_all(b"HTTP/1.1 500 Failure\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n")
                .await
                .unwrap();
            let mut response = timeout(LIMIT, response_future).await.unwrap().unwrap();
            assert_eq!(
                timeout(LIMIT, response.body_mut().frame())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()
                    .into_data()
                    .unwrap(),
                "a"
            );
            pending(&mut completion).await;
            server.write_all(terminal).await.unwrap();
            let end = timeout(LIMIT, response.body_mut().frame()).await.unwrap();
            if let Some(end) = end {
                assert!(end.unwrap().is_trailers());
            }
            drop(response);
            assert_eq!(
                timeout(LIMIT, completion).await.unwrap(),
                Ok(StatusCode::INTERNAL_SERVER_ERROR)
            );
            cleanup(driver).await;
        }
    }

    #[tokio::test]
    async fn eof_delimited_completion_differs_from_truncation() {
        for (head, succeeds) in [
            (
                b"HTTP/1.1 500 Failure\r\nConnection: close\r\n\r\n".as_slice(),
                true,
            ),
            (
                b"HTTP/1.1 500 Failure\r\nContent-Length: 2\r\n\r\n".as_slice(),
                false,
            ),
            (
                b"HTTP/1.1 500 Failure\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n".as_slice(),
                false,
            ),
        ] {
            let (mut sender, mut server, driver) = connection().await;
            let (request, mut completion) = request("GET");
            let response_future = sender.send_request(request);
            read_request(&mut server).await;
            server.write_all(head).await.unwrap();
            server.write_all(b"a").await.unwrap();
            let mut response = timeout(LIMIT, response_future).await.unwrap().unwrap();
            assert!(
                timeout(LIMIT, response.body_mut().frame())
                    .await
                    .unwrap()
                    .unwrap()
                    .is_ok()
            );
            pending(&mut completion).await;
            server.shutdown().await.unwrap();
            let body = timeout(LIMIT, response.into_body().collect())
                .await
                .unwrap();
            assert_eq!(body.is_ok(), succeeds);
            let result = timeout(LIMIT, completion).await.unwrap();
            if succeeds {
                assert_eq!(result, Ok(StatusCode::INTERNAL_SERVER_ERROR));
            } else {
                assert!(result.is_err());
            }
            cleanup(driver).await;
        }
    }

    #[tokio::test]
    async fn cancellation_before_completion_aborts() {
        let (mut sender, mut server, driver) = connection().await;
        let (request, mut completion) = request("GET");
        let response_future = sender.send_request(request);
        read_request(&mut server).await;
        server
            .write_all(b"HTTP/1.1 500 Failure\r\nContent-Length: 2\r\n\r\n")
            .await
            .unwrap();
        let response = timeout(LIMIT, response_future).await.unwrap().unwrap();
        pending(&mut completion).await;
        drop(response);
        assert!(timeout(LIMIT, completion).await.unwrap().is_err());
        cleanup(driver).await;
    }

    #[tokio::test]
    async fn canceled_body_drain_cannot_complete_pending_observation() {
        for (head, tail) in [
            (
                b"HTTP/1.1 500 Failure\r\nContent-Length: 1\r\n\r\n".as_slice(),
                b"a".as_slice(),
            ),
            (
                b"HTTP/1.1 500 Failure\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
                b"0\r\n\r\n".as_slice(),
            ),
        ] {
            let (mut sender, mut server, driver) = connection().await;
            let (request, mut completion) = request("GET");
            let response_future = sender.send_request(request);
            read_request(&mut server).await;
            server.write_all(head).await.unwrap();
            let response = timeout(LIMIT, response_future).await.unwrap().unwrap();
            assert!(completion.try_result().is_none());
            server.write_all(tail).await.unwrap();
            assert!(completion.try_result().is_none());
            // The full response is readable, but body demand has not let the
            // parser consume its end. Cancellation wins before the cheap drain.
            drop(response);
            assert!(timeout(LIMIT, completion).await.unwrap().is_err());
            cleanup(driver).await;
        }
    }

    #[tokio::test]
    async fn informational_heads_do_not_complete() {
        let (mut sender, mut server, driver) = connection().await;
        let (request, mut completion) = request("GET");
        let response_future = sender.send_request(request);
        read_request(&mut server).await;
        server
            .write_all(
                b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: fixture\r\n\r\n",
            )
            .await
            .unwrap();
        pending(&mut completion).await;
        server
            .write_all(b"HTTP/1.1 503 Failure\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let response = timeout(LIMIT, response_future).await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            timeout(LIMIT, completion).await.unwrap(),
            Ok(StatusCode::SERVICE_UNAVAILABLE)
        );
        cleanup(driver).await;
    }

    #[tokio::test]
    async fn dropped_and_queued_requests_abort() {
        let (request_value, mut completion) = request("GET");
        drop(request_value);
        assert!(completion.try_result().unwrap().is_err());
        let (client, _server) = tokio::io::duplex(65536);
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client))
            .await
            .unwrap();
        let (request, completion) = request("GET");
        let queued = sender.send_request(request);
        drop(queued);
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        assert!(timeout(LIMIT, completion).await.unwrap().is_err());
        cleanup(driver).await;
    }

    #[tokio::test]
    async fn response_head_error_aborts() {
        for wire in [b"not an HTTP response\r\n\r\n".as_slice(), b"".as_slice()] {
            let (mut sender, mut server, driver) = connection().await;
            let (request, completion) = request("GET");
            let response_future = sender.send_request(request);
            read_request(&mut server).await;
            server.write_all(wire).await.unwrap();
            server.shutdown().await.unwrap();
            assert!(timeout(LIMIT, response_future).await.unwrap().is_err());
            assert!(timeout(LIMIT, completion).await.unwrap().is_err());
            cleanup(driver).await;
        }
    }

    #[tokio::test]
    async fn keepalive_has_one_result_per_request() {
        let (mut sender, mut server, driver) = connection().await;
        for status in [500, 200] {
            sender.ready().await.unwrap();
            let (request, completion) = request("GET");
            let response_future = sender.send_request(request);
            read_request(&mut server).await;
            server
                .write_all(
                    format!("HTTP/1.1 {status} Fixture\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            let response = timeout(LIMIT, response_future).await.unwrap().unwrap();
            assert_eq!(
                timeout(LIMIT, completion).await.unwrap().unwrap().as_u16(),
                status
            );
            drop(response);
        }
        cleanup(driver).await;
    }
}
