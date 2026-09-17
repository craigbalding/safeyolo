use std::{
    io::Cursor,
    io::Write,
    process::{Command, Stdio},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use safeyolo_proxy::{
    Error,
    websocket::{Compression, Event, Message, MessageType, Reader, ReceiveError, Writer},
};
use serde_json::{Value, json};
use tungstenite::protocol::frame::{
    FrameHeader,
    coding::{Control, Data, OpCode},
};

fn frame(opcode: OpCode, final_frame: bool, mask: bool, rsv1: bool, body: &[u8]) -> Vec<u8> {
    let key = mask.then_some([13, 17, 23, 31]);
    let header = FrameHeader {
        opcode,
        is_final: final_frame,
        mask: key,
        rsv1,
        ..FrameHeader::default()
    };
    let mut bytes = Vec::new();
    header.format(body.len() as u64, &mut bytes).unwrap();
    bytes.extend(
        body.iter()
            .enumerate()
            .map(|(index, byte)| byte ^ key.map_or(0, |key| key[index % 4])),
    );
    bytes
}
fn text(bytes: &[u8]) -> Vec<u8> {
    frame(OpCode::Data(Data::Text), true, true, false, bytes)
}

fn handshake_request() -> hyper::Request<()> {
    hyper::Request::builder()
        .uri("/socket?literal=%2F&literal=/")
        .header("host", "owned.example")
        .header("connection", "keep-alive, Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-protocol", "first, second")
        .body(())
        .unwrap()
}
fn handshake_response() -> hyper::Response<()> {
    hyper::Response::builder()
        .status(101)
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        .header("sec-websocket-protocol", "second")
        .body(())
        .unwrap()
}

#[test]
fn handshake_validates_both_peers_and_preserves_selected_subprotocol() {
    use safeyolo_proxy::websocket::Handshake;
    let mut request = handshake_request();
    let target = request.uri().clone();
    request
        .headers_mut()
        .append("connection", "another-token".parse().unwrap());
    let handshake = Handshake::request(&mut request).unwrap();
    assert_eq!(request.uri(), &target);
    let response = handshake_response();
    let selected = handshake.response(&response).unwrap();
    assert_eq!(selected.subprotocol.as_deref(), Some("second"));
    assert_eq!(selected.client, None);
    for (header, value) in [
        ("sec-websocket-accept", "wrong"),
        ("sec-websocket-protocol", "unoffered"),
        ("connection", "keep-alive"),
        ("upgrade", "another-protocol"),
    ] {
        let mut response = handshake_response();
        response
            .headers_mut()
            .insert(header, value.parse().unwrap());
        assert!(handshake.response(&response).is_err());
    }
    for header in ["sec-websocket-key", "sec-websocket-version", "upgrade"] {
        let mut request = handshake_request();
        let value = request.headers()[header].clone();
        request.headers_mut().append(header, value);
        assert!(Handshake::request(&mut request).is_err());
    }
    for key in ["notbase64", "YQ==", "AAAAAAAAAAAAAAAAAAAAAAAA"] {
        let mut request = handshake_request();
        request
            .headers_mut()
            .insert("sec-websocket-key", key.parse().unwrap());
        assert!(Handshake::request(&mut request).is_err());
    }
}

#[test]
fn compression_negotiation_obeys_server_constraints_and_client_hints() {
    use safeyolo_proxy::websocket::Handshake;
    let mut request = handshake_request();
    request.headers_mut().insert("sec-websocket-extensions",r#"unknown; text="x,permessage-deflate;y", permessage-deflate; server_max_window_bits=12; server_no_context_takeover; client_max_window_bits=10"#.parse().unwrap());
    let handshake = Handshake::request(&mut request).unwrap();
    assert_eq!(
        request.headers()["sec-websocket-extensions"],
        "permessage-deflate; server_max_window_bits=12; server_no_context_takeover; client_max_window_bits=10"
    );
    // client_max_window_bits=10 is a hint. RFC7692 permits larger accepted
    // parameters or omission; server bounds and reset requests are mandatory.
    for extension in [
        "permessage-deflate; server_max_window_bits=12; server_no_context_takeover",
        "permessage-deflate; server_max_window_bits=11; server_no_context_takeover; client_max_window_bits=15",
        r#"permessage-deflate; server_max_window_bits="1\2"; server_no_context_takeover; client_max_window_bits="9"; client_no_context_takeover"#,
    ] {
        let mut response = handshake_response();
        response
            .headers_mut()
            .insert("sec-websocket-extensions", extension.parse().unwrap());
        let negotiated = handshake.response(&response).unwrap();
        assert!(negotiated.client.is_some() && negotiated.server.is_some());
    }
    for extension in [
        "permessage-deflate",
        "permessage-deflate; server_max_window_bits=13; server_no_context_takeover",
        "permessage-deflate; server_max_window_bits=12",
        "permessage-deflate; server_max_window_bits=12; server_no_context_takeover; client_max_window_bits",
        "permessage-deflate; server_max_window_bits=12; server_no_context_takeover; mystery=true",
        "permessage-deflate; server_max_window_bits=12; server_max_window_bits=12",
        "permessage-deflate; server_max_window_bits=08; server_no_context_takeover",
        "permessage-deflate; server_max_window_bits=12; server_no_context_takeover, permessage-deflate",
        "unimplemented-extension",
    ] {
        let mut response = handshake_response();
        response
            .headers_mut()
            .insert("sec-websocket-extensions", extension.parse().unwrap());
        assert!(handshake.response(&response).is_err(), "{extension}");
    }
    let handshake = Handshake::request(&mut handshake_request()).unwrap();
    let mut response = handshake_response();
    response.headers_mut().insert(
        "sec-websocket-extensions",
        "permessage-deflate".parse().unwrap(),
    );
    assert!(handshake.response(&response).is_err());
    let mut request = handshake_request();
    request.headers_mut().insert(
        "sec-websocket-extensions",
        r#"unknown; text="x,permessage-deflate;y", permessage-deflate; client_max_window_bits=8"#
            .parse()
            .unwrap(),
    );
    let handshake = Handshake::request(&mut request).unwrap();
    assert!(!request.headers().contains_key("sec-websocket-extensions"));
    assert!(handshake.response(&handshake_response()).is_ok());
    assert!(handshake.response(&response).is_err());
}
async fn next_message<R: tokio::io::AsyncRead + Unpin>(reader: &mut Reader<R>) -> Message {
    match reader.read().await.unwrap() {
        Event::Message(message) => message,
        _ => panic!("expected complete message"),
    }
}

#[tokio::test]
async fn complete_messages_keep_utf8_fragment_boundaries_and_control_frames() {
    let mut wire = frame(
        OpCode::Data(Data::Text),
        false,
        true,
        false,
        b"hello \xf0\x9f",
    );
    wire.extend(frame(
        OpCode::Control(Control::Ping),
        true,
        true,
        false,
        b"owned-ping",
    ));
    wire.extend(frame(
        OpCode::Data(Data::Continue),
        true,
        true,
        false,
        b"\x98\x80",
    ));
    wire.extend(frame(
        OpCode::Control(Control::Pong),
        true,
        true,
        false,
        b"owned-pong",
    ));
    wire.extend(frame(
        OpCode::Control(Control::Close),
        true,
        true,
        false,
        &[3, 232],
    ));
    let mut reader = Reader::new(Cursor::new(wire), true, None);
    assert!(matches!(reader.read().await.unwrap(), Event::Ping(bytes) if bytes == b"owned-ping"));
    let message = next_message(&mut reader).await;
    assert_eq!(message.fragment_count(), 2);
    assert_eq!(message.with_text(str::to_owned).unwrap(), "hello 😀");
    let mut output = Vec::new();
    Writer::new(&mut output, false, None)
        .message(message)
        .await
        .unwrap();
    let message = next_message(&mut Reader::new(Cursor::new(output), false, None)).await;
    assert_eq!(message.fragment_count(), 2);
    assert_eq!(message.with_text(str::to_owned).unwrap(), "hello 😀");
    assert!(matches!(reader.read().await.unwrap(), Event::Pong(bytes) if bytes == b"owned-pong"));
    assert!(matches!(reader.read().await.unwrap(), Event::Close(bytes) if bytes == [3,232]));
}

#[tokio::test]
async fn large_message_and_fragment_index_spill_without_truncation() {
    let payload: Vec<u8> = (0..=255).cycle().take(2 * 1024 * 1024 + 3).collect();
    let wire = frame(OpCode::Data(Data::Binary), true, true, false, &payload);
    let message = next_message(&mut Reader::new(Cursor::new(wire), true, None)).await;
    assert!(message.spilled());
    assert_eq!(message.len(), payload.len() as u64);
    assert_eq!(
        message
            .with_text(|text| text.chars().map(|c| c as u8).collect::<Vec<_>>())
            .unwrap(),
        payload
    );
    let mut output = Vec::new();
    Writer::new(&mut output, false, None)
        .message(message)
        .await
        .unwrap();
    assert_eq!(
        output,
        frame(OpCode::Data(Data::Binary), true, false, false, &payload)
    );
    let mut wire = frame(OpCode::Data(Data::Binary), false, true, false, b"first");
    for _ in 0..9000 {
        wire.extend(frame(OpCode::Data(Data::Continue), false, true, false, b""));
    }
    wire.extend(frame(
        OpCode::Data(Data::Continue),
        true,
        true,
        false,
        b"last",
    ));
    let message = next_message(&mut Reader::new(Cursor::new(wire), true, None)).await;
    assert!(message.spilled());
    assert_eq!(message.len(), 9);
    assert_eq!(message.fragment_count(), 9002);
    assert_eq!(message.with_text(str::to_owned).unwrap(), "firstlast");
}

fn malformed_frames() -> Vec<(Vec<u8>, u16)> {
    let malformed = [
        frame(OpCode::Data(Data::Text), true, false, false, b"unmasked"),
        frame(OpCode::Data(Data::Continue), true, true, false, b"orphan"),
        frame(OpCode::Data(Data::Text), true, true, true, b"unnegotiated"),
        frame(OpCode::Data(Data::Text), true, true, false, b"\xf0\x9f"),
        frame(OpCode::Data(Data::Text), true, true, false, b"\xff"),
        frame(OpCode::Control(Control::Ping), false, true, false, b"ping"),
        frame(OpCode::Control(Control::Ping), true, true, false, &[0; 126]),
        frame(OpCode::Control(Control::Close), true, true, false, &[3]),
        frame(
            OpCode::Control(Control::Close),
            true,
            true,
            false,
            &[3, 237],
        ),
        frame(
            OpCode::Control(Control::Close),
            true,
            true,
            false,
            &[3, 232, 255],
        ),
        vec![0x81, 0xfe, 0, 1, 0, 0, 0, 0, b'x'],
        vec![0x81, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ];
    malformed
        .into_iter()
        .zip([
            1002, 1002, 1002, 1007, 1007, 1002, 1002, 1002, 1002, 1007, 1002, 1002,
        ])
        .collect()
}

#[tokio::test]
async fn invalid_protocol_is_an_error_and_never_an_opaque_message() {
    for (wire, code) in malformed_frames() {
        let failure = Reader::new(Cursor::new(wire), true, None)
            .read()
            .await
            .err()
            .unwrap();
        assert_eq!(failure.close_code(), Some(code));
    }
    let compressed = frame(OpCode::Data(Data::Binary), true, true, true, &[0xff]);
    let failure = Reader::new(
        Cursor::new(compressed),
        true,
        Some(Compression::new(15, false).unwrap()),
    )
    .read()
    .await
    .err()
    .unwrap();
    assert_eq!(failure, ReceiveError::InvalidPayload);
    for wire in [vec![0x81], vec![0x81, 0x81, 0, 0, 0, 0]] {
        let failure = Reader::new(Cursor::new(wire), true, None)
            .read()
            .await
            .err()
            .unwrap();
        assert_eq!(
            failure,
            ReceiveError::Transport(std::io::ErrorKind::UnexpectedEof)
        );
        assert_eq!(failure.close_code(), None);
    }
    let mut incomplete = frame(OpCode::Data(Data::Text), false, true, false, b"first");
    incomplete.extend(text(b"second without continuation"));
    assert!(
        Reader::new(Cursor::new(incomplete), true, None)
            .read()
            .await
            .is_err()
    );
}

#[tokio::test]
async fn compressed_continuations_survive_control_frames_and_bytewise_transport() {
    use tokio::io::AsyncWriteExt;
    for kind in [Data::Text, Data::Binary] {
        for from_client in [false, true] {
            for control in [Control::Ping, Control::Pong] {
                let compression = Some(Compression::new(15, false).unwrap());
                let payload = if kind == Data::Text {
                    "PROJ-12345 😀".repeat(100).into_bytes()
                } else {
                    (0..=255).cycle().take(2048).collect::<Vec<u8>>()
                };
                let split = payload.len() / 2;
                let mut original = frame(
                    OpCode::Data(kind),
                    false,
                    from_client,
                    false,
                    &payload[..split],
                );
                original.extend(frame(
                    OpCode::Data(Data::Continue),
                    true,
                    from_client,
                    false,
                    &payload[split..],
                ));
                let message =
                    next_message(&mut Reader::new(Cursor::new(original), from_client, None)).await;
                let expected = message.with_text(str::to_owned).unwrap();
                let mut encoded = Vec::new();
                Writer::new(&mut encoded, from_client, compression)
                    .message(message)
                    .await
                    .unwrap();
                let mut cursor = Cursor::new(&encoded);
                let (_, length) = FrameHeader::parse(&mut cursor).unwrap().unwrap();
                let split = cursor.position() as usize + length as usize;
                encoded.splice(
                    split..split,
                    frame(
                        OpCode::Control(control),
                        true,
                        from_client,
                        false,
                        b"between-fragments",
                    ),
                );
                let (mut sender, stream) = tokio::io::duplex(1);
                let sending = tokio::spawn(async move {
                    for byte in encoded {
                        sender.write_all(&[byte]).await.unwrap();
                    }
                });
                let mut reader = Reader::new(stream, from_client, compression);
                let received = match reader.read().await.unwrap() {
                    Event::Ping(bytes) if control == Control::Ping => bytes,
                    Event::Pong(bytes) if control == Control::Pong => bytes,
                    _ => panic!("control frame changed during fragmented message"),
                };
                assert_eq!(received, b"between-fragments");
                let message = next_message(&mut reader).await;
                assert_eq!(message.with_text(str::to_owned).unwrap(), expected);
                let mut delivered = Vec::new();
                Writer::new(&mut delivered, from_client, compression)
                    .message(message)
                    .await
                    .unwrap();
                let decoded = next_message(&mut Reader::new(
                    Cursor::new(delivered),
                    from_client,
                    compression,
                ))
                .await;
                assert_eq!(decoded.with_text(str::to_owned).unwrap(), expected);
                sending.await.unwrap();
            }
        }
    }
}

#[tokio::test]
async fn compressed_fragmented_message_is_scanned_after_control_frame() {
    use safeyolo_proxy::inspection::{Direction, MessageType as ScanType, Options, Scanner};

    for direction in [Direction::Request, Direction::Response] {
        let from_client = direction == Direction::Request;
        let compression = Some(Compression::new(15, false).unwrap());
        let mut source = frame(
            OpCode::Data(Data::Text),
            false,
            from_client,
            false,
            b"PROJ-",
        );
        source.extend(frame(
            OpCode::Data(Data::Continue),
            true,
            from_client,
            false,
            b"12345",
        ));
        source.extend(frame(
            OpCode::Data(Data::Text),
            true,
            from_client,
            false,
            b"allowed next message",
        ));
        let mut source_reader = Reader::new(Cursor::new(source), from_client, None);
        let blocked = next_message(&mut source_reader).await;
        let allowed = next_message(&mut source_reader).await;

        // Encode both complete messages with negotiated per-message deflate,
        // then insert a real control frame between the compressed data
        // fragments. The native reader must retain the message inflater across
        // that control event before the scanner sees the complete text.
        let mut encoded = Vec::new();
        Writer::new(&mut encoded, from_client, compression)
            .message(blocked)
            .await
            .unwrap();
        Writer::new(&mut encoded, from_client, compression)
            .message(allowed)
            .await
            .unwrap();
        let mut first = Cursor::new(&encoded);
        let (_, length) = FrameHeader::parse(&mut first).unwrap().unwrap();
        let split = first.position() as usize + length as usize;
        encoded.splice(
            split..split,
            frame(
                OpCode::Control(Control::Ping),
                true,
                from_client,
                false,
                b"between-fragments",
            ),
        );

        let mut reader = Reader::new(Cursor::new(encoded), from_client, compression);
        assert!(matches!(
            reader.read().await.unwrap(),
            Event::Ping(bytes) if bytes == b"between-fragments"
        ));
        let scanner = Scanner::default();
        scanner
            .load_policy_config(&json!({
                "scan_patterns": [{
                    "name": "owned-marker",
                    "pattern": "PROJ-12345",
                    "scope": "body",
                    "action": "block"
                }]
            }))
            .unwrap();
        let options = if direction == Direction::Request {
            Options {
                block_websocket_request: Some(true),
                ..Options::default()
            }
        } else {
            Options {
                block_websocket_response: Some(true),
                ..Options::default()
            }
        };
        let blocked = next_message(&mut reader).await;
        let decision = blocked
            .with_text(|text| scanner.scan_websocket_text(direction, ScanType::Text, text, options))
            .unwrap()
            .unwrap();
        assert!(decision.drop_message);
        assert_eq!(decision.finding.unwrap().direction, direction);
        let allowed = next_message(&mut reader).await;
        let decision = allowed
            .with_text(|text| scanner.scan_websocket_text(direction, ScanType::Text, text, options))
            .unwrap()
            .unwrap();
        assert!(!decision.drop_message);
        let mut forwarded = Vec::new();
        Writer::new(&mut forwarded, !from_client, None)
            .message(allowed)
            .await
            .unwrap();
        let delivered =
            next_message(&mut Reader::new(Cursor::new(forwarded), !from_client, None)).await;
        assert_eq!(
            delivered.with_text(str::to_owned).unwrap(),
            "allowed next message"
        );
    }
}

#[tokio::test]
async fn rfc_deflate_blocks_and_context_survive_final_block_markers() {
    let compression = Some(Compression::new(15, false).unwrap());
    // RFC 7692 sections 7.2.3.1-5, including BFINAL=1 followed by a block
    // referencing history, and an uncompressed message between compressed ones.
    let hello = [0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];
    let from_history = [0xf2, 0x00, 0x11, 0x00, 0x00];
    let final_hello = [0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00];
    let stored = [0, 5, 0, 0xfa, 0xff, b'H', b'e', b'l', b'l', b'o', 0];
    let split_blocks = [
        0xf2, 0x48, 0x05, 0, 0, 0, 0xff, 0xff, 0xca, 0xc9, 0xc9, 0x07, 0,
    ];
    for initial in [
        hello.as_slice(),
        final_hello.as_slice(),
        stored.as_slice(),
        split_blocks.as_slice(),
    ] {
        let mut wire = frame(OpCode::Data(Data::Text), true, false, true, initial);
        wire.extend(frame(
            OpCode::Data(Data::Text),
            true,
            false,
            false,
            b"uncompressed",
        ));
        wire.extend(frame(
            OpCode::Data(Data::Text),
            true,
            false,
            true,
            &from_history,
        ));
        let mut reader = Reader::new(Cursor::new(wire), false, compression);
        for expected in ["Hello", "uncompressed", "Hello"] {
            assert_eq!(
                next_message(&mut reader)
                    .await
                    .with_text(str::to_owned)
                    .unwrap(),
                expected
            );
        }
    }
}

#[tokio::test]
async fn compression_keeps_independent_receive_and_forwarded_message_dictionaries() {
    for bits in 9..=15 {
        for reset in [false, true] {
            let compression = Some(Compression::new(bits, reset).unwrap());
            let payload = "repeated text for context takeover ".repeat(4000);
            let mut source = Vec::new();
            let mut encoder = Writer::new(&mut source, true, compression);
            for index in 0..3 {
                let wire = text(format!("{index}:{payload}").as_bytes());
                let message = next_message(&mut Reader::new(Cursor::new(wire), true, None)).await;
                encoder.message(message).await.unwrap();
            }
            let mut reader = Reader::new(Cursor::new(source), true, compression);
            let mut delivered = Vec::new();
            let mut writer = Writer::new(&mut delivered, false, compression);
            for index in 0..3 {
                let message = next_message(&mut reader).await;
                assert!(message.spilled());
                assert_eq!(
                    message.with_text(str::to_owned).unwrap(),
                    format!("{index}:{payload}")
                );
                if index != 1 {
                    writer.message(message).await.unwrap();
                }
            }
            let mut receiver = Reader::new(Cursor::new(delivered), false, compression);
            for index in [0, 2] {
                assert_eq!(
                    next_message(&mut receiver)
                        .await
                        .with_text(str::to_owned)
                        .unwrap(),
                    format!("{index}:{payload}")
                );
            }
        }
    }
}

#[tokio::test]
async fn complete_fragmented_payload_reaches_scanner_before_any_forwarding() {
    use safeyolo_proxy::inspection::{Direction, MessageType as ScanType, Options, Scanner};
    let scanner = Scanner::default();
    scanner.load_policy_config(&json!({"scan_patterns":[{"name":"owned-marker","pattern":"PROJ-12345","scope":"body","action":"block"}]})).unwrap();
    let mut wire = frame(OpCode::Data(Data::Text), false, true, false, b"PROJ-");
    wire.extend(frame(
        OpCode::Data(Data::Continue),
        true,
        true,
        false,
        b"12345",
    ));
    wire.extend(text(b"allowed next message"));
    let mut reader = Reader::new(Cursor::new(wire), true, None);
    let mut forwarded = Vec::new();
    let mut writer = Writer::new(&mut forwarded, false, None);
    for _ in 0..2 {
        let message = next_message(&mut reader).await;
        let decision = message
            .with_text(|text| {
                scanner.scan_websocket_text(
                    Direction::Request,
                    ScanType::Text,
                    text,
                    Options {
                        block_websocket_request: Some(true),
                        ..Options::default()
                    },
                )
            })
            .unwrap()
            .unwrap();
        if !decision.drop_message {
            writer.message(message).await.unwrap();
        }
    }
    assert_eq!(
        forwarded,
        frame(
            OpCode::Data(Data::Text),
            true,
            false,
            false,
            b"allowed next message"
        )
    );
}

fn python(program: &str, input: &Value) -> Value {
    let python =
        std::env::var("SAFEYOLO_POLICY_PYTHON").expect("set historical Python interpreter");
    let mut command = Command::new(python)
        .args(["-c", program])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    command
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let result = command.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

#[tokio::test]
#[ignore = "historical Python wsproto close-code oracle"]
async fn malformed_frames_keep_the_historical_protocol_and_payload_close_codes() {
    let mut rows: Vec<_> = malformed_frames()
        .into_iter()
        .map(|(wire, code)| json!({"wire": STANDARD.encode(wire), "code": code, "compressed": false}))
        .collect();
    rows.push(json!({
        "wire": STANDARD.encode(frame(OpCode::Data(Data::Binary), true, true, true, &[0xff])),
        "code": 1007, "compressed": true,
    }));
    let codes = python(
        r#"
import base64,json,sys
from wsproto.connection import Connection,ConnectionType
from wsproto.events import CloseConnection
from wsproto.extensions import PerMessageDeflate
out=[]
for row in json.load(sys.stdin):
 extensions=[]
 if row['compressed']:
  extension=PerMessageDeflate();extension.finalize('permessage-deflate');extensions.append(extension)
 connection=Connection(ConnectionType.SERVER,extensions)
 connection.receive_data(base64.b64decode(row['wire']))
 out.append([int(event.code) for event in connection.events() if isinstance(event,CloseConnection)])
print(json.dumps(out))
"#,
        &json!(rows),
    );
    for (row, codes) in rows.iter().zip(codes.as_array().unwrap()) {
        assert_eq!(codes, &json!([row["code"]]));
        let compression = row["compressed"]
            .as_bool()
            .unwrap()
            .then(|| Compression::new(15, false).unwrap());
        let failure = Reader::new(
            Cursor::new(STANDARD.decode(row["wire"].as_str().unwrap()).unwrap()),
            true,
            compression,
        )
        .read()
        .await
        .err()
        .unwrap();
        assert_eq!(json!(failure.close_code()), row["code"]);
    }
}

#[test]
fn spool_failure_is_a_local_error_and_cannot_yield_a_partial_message() {
    const CHILD: &str = "SAFEYOLO_WS_SPOOL_FAILURE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let directory = tempfile::tempdir().unwrap();
        let result = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "spool_failure_is_a_local_error_and_cannot_yield_a_partial_message",
            ])
            .env(CHILD, "1")
            .env("TMPDIR", directory.path().join("missing"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stdout)
        );
        return;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let wire = frame(
            OpCode::Data(Data::Binary),
            true,
            true,
            false,
            &[0; 128 * 1024],
        );
        let error = Reader::new(Cursor::new(wire), true, None)
            .read()
            .await
            .err()
            .unwrap();
        assert_eq!(error, ReceiveError::Storage);
        assert_eq!(error.close_code(), Some(1011));
    });
}

#[tokio::test]
#[ignore = "historical Python wsproto frame/compression oracle"]
async fn compressed_frames_roundtrip_with_actual_python_wsproto() -> Result<(), Error> {
    let cases = python(
        r#"
import base64,json
from wsproto.frame_protocol import FrameProtocol,Opcode
from wsproto.extensions import PerMessageDeflate
rows=[]
for bits in range(9,16):
 for reset in [False,True]:
  for client in [False,True]:
   e=PerMessageDeflate(client_no_context_takeover=reset,server_no_context_takeover=reset,client_max_window_bits=bits,server_max_window_bits=bits)
   e.finalize('permessage-deflate;client_max_window_bits=%s;server_max_window_bits=%s'%(bits,bits))
   p=FrameProtocol(client,[e]);wire=b'';expected=[]
   for i in range(3):
    value=(str(i)+':owned-café-'*3000).encode();expected.append(value.decode())
    wire+=p.send_data(value[:10000].decode(),fin=False)
    wire+=p.send_data(value[10000:].decode(),fin=True)
   rows.append(dict(bits=bits,reset=reset,client=client,wire=base64.b64encode(wire).decode(),expected=expected))
print(json.dumps(rows))
"#,
        &json!(null),
    );
    let mut outputs = Vec::new();
    for row in cases.as_array().unwrap() {
        let compression = Some(Compression::new(
            row["bits"].as_u64().unwrap() as u8,
            row["reset"].as_bool().unwrap(),
        )?);
        let client = row["client"].as_bool().unwrap();
        let mut reader = Reader::new(
            Cursor::new(STANDARD.decode(row["wire"].as_str().unwrap())?),
            client,
            compression,
        );
        let mut wire = Vec::new();
        let mut writer = Writer::new(&mut wire, client, compression);
        for expected in row["expected"].as_array().unwrap() {
            let message = next_message(&mut reader).await;
            assert_eq!(message.kind, MessageType::Text);
            assert_eq!(
                message.with_text(str::to_owned)?,
                expected.as_str().unwrap()
            );
            writer.message(message).await?;
        }
        outputs.push(json!({"wire":STANDARD.encode(wire),"bits":row["bits"],"reset":row["reset"],"client":client,"expected":row["expected"]}));
    }
    let checked = python(
        r#"
import base64,json,sys
from wsproto.frame_protocol import FrameProtocol,Opcode
from wsproto.extensions import PerMessageDeflate
count=0
for row in json.load(sys.stdin):
 e=PerMessageDeflate(client_no_context_takeover=row['reset'],server_no_context_takeover=row['reset'],client_max_window_bits=row['bits'],server_max_window_bits=row['bits'])
 e.finalize('permessage-deflate;client_max_window_bits=%s;server_max_window_bits=%s'%(row['bits'],row['bits']))
 p=FrameProtocol(not row['client'],[e]);p.receive_bytes(base64.b64decode(row['wire']));observed=[];message=''
 for frame in p.received_frames():
  assert frame.opcode == Opcode.TEXT
  message+=frame.payload
  if frame.message_finished:observed.append(message);message=''
 assert observed==row['expected'],(row,observed)
 count+=len(observed)
print(json.dumps(count))
"#,
        &Value::Array(outputs),
    );
    assert_eq!(checked, 84);
    Ok(())
}
