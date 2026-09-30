use std::sync::Arc;

use bytes::Bytes;
use flate2::read::ZlibDecoder;
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode};
use serde_json::Value;

use crate::{
    admin_api::{self, Outcome},
    tasks::Registry,
    traffic_view::{RequestInfo, TrafficView},
};

const TOKEN: &str = "owned-har-export-token";

async fn call(view: &Arc<TrafficView>, format: &str) -> Outcome {
    let request = Request::builder()
        .method("GET")
        .uri(format!(
            "/admin/traffic/flows/har%2Fflow/export?format={format}"
        ))
        .header("Authorization", format!("Bearer {TOKEN}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    admin_api::respond_with_view(
        request,
        TOKEN,
        &Registry::default(),
        None,
        None,
        None,
        Some(view),
    )
    .await
    .unwrap()
}

fn flow() -> Arc<TrafficView> {
    let view = Arc::new(TrafficView::new(10, 1 << 20));
    let exchange = view.begin(RequestInfo {
        id: "har/flow".into(),
        connection_id: "endpoint-test".into(),
        agent: None,
        method: "GET".into(),
        url: "http://owned.invalid/export".into(),
        headers: vec![],
        started: 1.0,
    });
    exchange.request_body(Some(b""));
    exchange.response_head(200, vec![("Content-Type".into(), "text/plain".into())]);
    exchange.response_body(Some(b"exported"));
    exchange.finish(None);
    view
}

#[tokio::test]
async fn authenticated_endpoint_streams_har_and_zhar_attachments() {
    let view = flow();
    let har_response = call(&view, "har").await.into_response();
    assert_eq!(har_response.status(), StatusCode::OK);
    assert_eq!(
        har_response.headers()[hyper::header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert_eq!(
        har_response.headers()[hyper::header::CONTENT_DISPOSITION],
        "attachment; filename=\"traffic.har\""
    );
    let har = har_response.into_body().collect().await.unwrap().to_bytes();
    let document: Value = serde_json::from_slice(&har).unwrap();
    assert_eq!(document["log"]["entries"][0]["response"]["status"], 200);

    let zhar_response = call(&view, "zhar").await.into_response();
    assert_eq!(zhar_response.status(), StatusCode::OK);
    assert_eq!(
        zhar_response.headers()[hyper::header::CONTENT_DISPOSITION],
        "attachment; filename=\"traffic.zhar\""
    );
    let compressed = zhar_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let mut decoder = ZlibDecoder::new(compressed.as_ref());
    let mut decompressed = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut decompressed).unwrap();
    assert_eq!(decompressed, har);
}

#[tokio::test]
async fn endpoint_lists_har_formats_in_validation_error() {
    let response = call(&flow(), "unknown").await.into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&body).unwrap();
    let error = value["error"].as_str().unwrap();
    assert!(error.contains("har"));
    assert!(error.contains("zhar"));
}
