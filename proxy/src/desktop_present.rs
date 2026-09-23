//! Narrow host-operation boundary for native desktop presentation.
//!
//! The Rust proxy never launches a guest command itself. When the host
//! launcher supplies the trusted SafeYolo Python interpreter, this boundary
//! owns one long-lived presenter helper and sends it validated stable agent
//! IDs over a line-oriented protocol. The helper must outlive each request:
//! the managed preview server is owned by its `DesktopPresenter` instance.
//! Without that host capability the operation is explicitly unavailable.

use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Debug)]
pub(crate) enum Error {
    Unavailable,
    NotFound,
    Failed,
    Transport,
    Protocol,
}

struct PresenterOwner {
    child: Arc<Mutex<Child>>,
    io: Mutex<PresenterIo>,
}

struct PresenterIo {
    input: BufWriter<ChildStdin>,
    output: BufReader<ChildStdout>,
    retired: bool,
}

static PRESENTER: Mutex<Option<Arc<PresenterOwner>>> = Mutex::new(None);

pub(crate) fn valid_agent_id(agent_id: &str) -> bool {
    !agent_id.is_empty()
        && agent_id.len() <= 128
        && agent_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(crate) fn available() -> bool {
    std::env::var_os("SAFEYOLO_DESKTOP_PRESENTER_PYTHON").is_some_and(|value| {
        let path = Path::new(&value);
        path.is_absolute() && path.is_file()
    })
}

fn spawn_presenter(python: &Path) -> Result<PresenterOwner, Error> {
    let mut child = Command::new(python)
        .args(["-m", "safeyolo.desktop_presenter_rpc", "--daemon"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|_| Error::Unavailable)?;
    let Some(input) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error::Unavailable);
    };
    let Some(output) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error::Unavailable);
    };
    Ok(PresenterOwner {
        child: Arc::new(Mutex::new(child)),
        io: Mutex::new(PresenterIo {
            input: BufWriter::new(input),
            output: BufReader::new(output),
            retired: false,
        }),
    })
}

fn terminate_presenter(owner: Arc<PresenterOwner>) {
    let Ok(mut child) = owner.child.lock() else {
        return;
    };
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
}

fn decode_response(value: Value) -> Result<Value, Error> {
    if let Some(kind) = value.get("kind").and_then(Value::as_str) {
        return match kind {
            "not_found" => Err(Error::NotFound),
            "unavailable" => Err(Error::Unavailable),
            "invalid" | "failed" => Err(Error::Failed),
            _ => Err(Error::Protocol),
        };
    }
    let object = value.as_object().ok_or(Error::Protocol)?;
    for key in ["agent_id", "agent", "url", "unlock_code"] {
        if !object.get(key).is_some_and(Value::is_string) {
            return Err(Error::Protocol);
        }
    }
    if !object.get("reused").is_some_and(Value::is_boolean) {
        return Err(Error::Protocol);
    }
    Ok(value)
}

fn request(owner: &PresenterOwner, agent_id: &str) -> Result<Value, Error> {
    let Ok(mut io) = owner.io.lock() else {
        return Err(Error::Transport);
    };
    if io.retired {
        return Err(Error::Transport);
    }
    let result = (|| {
        serde_json::to_writer(&mut io.input, &json!({"agent_id": agent_id}))
            .map_err(|_| Error::Transport)?;
        io.input.write_all(b"\n").map_err(|_| Error::Transport)?;
        io.input.flush().map_err(|_| Error::Transport)?;
        let mut line = String::new();
        if io
            .output
            .read_line(&mut line)
            .map_err(|_| Error::Transport)?
            == 0
        {
            return Err(Error::Transport);
        }
        let value: Value = serde_json::from_str(&line).map_err(|_| Error::Protocol)?;
        let value = decode_response(value)?;
        // The accepted listener identity selects the target. The helper may
        // return a durable agent_id, but its human-facing `agent` must still
        // be the requested listener name.
        if value.get("agent").and_then(Value::as_str) != Some(agent_id) {
            return Err(Error::Protocol);
        }
        Ok(value)
    })();
    // A waiting sibling request must not write to a helper whose response
    // stream has become untrustworthy while the owner is being retired.
    if matches!(result, Err(Error::Transport | Error::Protocol)) {
        io.retired = true;
    }
    result
}

pub(crate) async fn present(agent_id: String) -> Result<Value, Error> {
    tokio::task::spawn_blocking(move || {
        let Some(python) = std::env::var_os("SAFEYOLO_DESKTOP_PRESENTER_PYTHON") else {
            return Err(Error::Unavailable);
        };
        let python = Path::new(&python);
        if !python.is_absolute() || !python.is_file() {
            return Err(Error::Unavailable);
        }
        let mut presenter = PRESENTER.lock().map_err(|_| Error::Failed)?;
        if presenter.is_none() {
            *presenter = Some(Arc::new(spawn_presenter(python)?));
        }
        let owner = presenter.as_ref().expect("presenter initialized").clone();
        drop(presenter);
        let result = request(&owner, &agent_id);
        if matches!(result, Err(Error::Transport | Error::Protocol))
            && let Ok(mut presenter) = PRESENTER.lock()
            && presenter
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &owner))
        {
            presenter.take().expect("matching presenter is installed");
            // Do not start a replacement before this helper has closed
            // the previews it owns and exited.
            stop_presenter(owner);
        }
        result
    })
    .await
    .map_err(|_| Error::Failed)?
}

/// Close the host helper and its managed previews during proxy shutdown.
pub(crate) fn shutdown() {
    let Ok(mut presenter) = PRESENTER.lock() else {
        return;
    };
    let Some(owner) = presenter.take() else {
        return;
    };
    // The global owner stays unavailable until the old helper has stopped.
    stop_presenter(owner);
}

fn stop_presenter(owner: Arc<PresenterOwner>) {
    // A request may own the protocol lock while blocked waiting for the
    // helper's response.  In that case the shutdown message cannot be sent;
    // killing the independently owned child is the only bounded way to
    // release the request and reclaim the helper.
    let shutdown_sent = owner
        .io
        .try_lock()
        .ok()
        .and_then(|mut io| {
            (serde_json::to_writer(&mut io.input, &json!({"shutdown": true})).is_ok()
                && io.input.write_all(b"\n").is_ok()
                && io.input.flush().is_ok())
            .then_some(())
        })
        .is_some();
    if shutdown_sent {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let exited = owner
                .child
                .lock()
                .ok()
                .and_then(|mut child| child.try_wait().ok())
                .flatten();
            match exited {
                Some(_) => break,
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }
    terminate_presenter(owner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, net::TcpStream, os::unix::fs::PermissionsExt, sync::OnceLock};

    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("desktop test lock")
    }

    fn fixture_script(response: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().expect("fixture directory");
        let script = directory.path().join("desktop-presenter-fixture");
        let body = format!(
            "#!/bin/sh\nIFS= read -r request\nprintf '%s %s %s\\n' \"$1\" \"$2\" \"$3\" > \"$0.args\"\nprintf '%s\\n' '{}'\n",
            response
        );
        fs::write(&script, body).expect("fixture script");
        let mut permissions = fs::metadata(&script)
            .expect("fixture metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).expect("fixture executable");
        (directory, script)
    }

    fn preview_fixture(protocol_failure: bool) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().expect("fixture directory");
        let script = directory.path().join("desktop-presenter-preview");
        let body = format!(
            r#"#!/usr/bin/env python3
import http.server
import json
import pathlib
import sys
import threading

class Preview(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"preview-alive")

    def log_message(self, *_args):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Preview)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
url = "http://127.0.0.1:%s/vnc.html" % server.server_port
seen = False
for line in sys.stdin:
    request = json.loads(line)
    if request.get("shutdown"):
        server.shutdown()
        server.server_close()
        pathlib.Path(__file__ + ".closed").write_text("closed")
        print('{{"status":"stopped"}}', flush=True)
        break
    if request["agent_id"] == "bob":
        print("not-json" if {protocol_failure} else '{{"kind":"failed","error":"fixture"}}', flush=True)
    else:
        print(json.dumps({{"agent_id":"durable-alice","agent":"alice","url":url,
                          "unlock_code":"fixture","reused":seen}}), flush=True)
        seen = True
"#,
            protocol_failure = if protocol_failure { "True" } else { "False" },
        );
        fs::write(&script, body).expect("preview fixture");
        let mut permissions = fs::metadata(&script)
            .expect("fixture metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).expect("fixture executable");
        (directory, script)
    }

    fn preview_replies(url: &str) -> bool {
        let port = url
            .split(':')
            .nth(2)
            .and_then(|value| value.split('/').next())
            .and_then(|value| value.parse::<u16>().ok())
            .expect("preview URL port");
        let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
            return false;
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        stream
            .write_all(b"GET /vnc.html HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .expect("preview request");
        let mut response = String::new();
        std::io::Read::read_to_string(&mut stream, &mut response).expect("preview response");
        response.starts_with("HTTP/1.0 200") && response.contains("preview-alive")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn typed_sibling_failure_keeps_shared_preview_alive() {
        let _lock = test_lock();
        shutdown();
        let (_directory, script) = preview_fixture(false);
        unsafe { std::env::set_var("SAFEYOLO_DESKTOP_PRESENTER_PYTHON", &script) };

        let first = present("alice".to_owned()).await.expect("first preview");
        let url = first["url"].as_str().expect("preview URL").to_owned();
        let owner = PRESENTER.lock().unwrap().as_ref().unwrap().clone();
        let original_pid = owner.child.lock().unwrap().id();
        assert!(preview_replies(&url), "initial preview must serve requests");

        assert!(matches!(
            present("bob".to_owned()).await,
            Err(Error::Failed)
        ));
        let current = PRESENTER.lock().unwrap().as_ref().unwrap().clone();
        assert_eq!(current.child.lock().unwrap().id(), original_pid);
        assert!(!script.with_extension("closed").exists());
        assert!(
            preview_replies(&url),
            "failed sibling must not close preview"
        );

        let again = present("alice".to_owned()).await.expect("next request");
        assert_eq!(again["url"], url);
        assert_eq!(again["reused"], true);
        assert!(preview_replies(&url));
        shutdown();
        assert!(script.with_extension("closed").exists());
        assert!(!preview_replies(&url), "shutdown must close preview");
        unsafe { std::env::remove_var("SAFEYOLO_DESKTOP_PRESENTER_PYTHON") };
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn broken_protocol_closes_owned_preview_before_retiring_helper() {
        let _lock = test_lock();
        shutdown();
        let (_directory, script) = preview_fixture(true);
        unsafe { std::env::set_var("SAFEYOLO_DESKTOP_PRESENTER_PYTHON", &script) };

        let first = present("alice".to_owned()).await.expect("first preview");
        let url = first["url"].as_str().expect("preview URL").to_owned();
        assert!(preview_replies(&url));
        assert!(matches!(
            present("bob".to_owned()).await,
            Err(Error::Protocol)
        ));
        assert!(PRESENTER.lock().unwrap().is_none());
        assert!(
            script.with_extension("closed").exists(),
            "helper must close its live preview before exit"
        );
        assert!(!preview_replies(&url));
        unsafe { std::env::remove_var("SAFEYOLO_DESKTOP_PRESENTER_PYTHON") };
    }

    #[test]
    fn helper_invocation_is_fixed_and_response_target_is_authorized() {
        let _lock = test_lock();
        let response = r#"{"agent_id":"ag-durable","agent":"alice","url":"http://127.0.0.1:1/vnc.html","unlock_code":"fixture","reused":false}"#;
        let (_directory, script) = fixture_script(response);
        let owner = Arc::new(spawn_presenter(&script).expect("fixture helper starts"));
        let result = request(&owner, "alice").expect("authorized target");
        assert_eq!(result["agent"], "alice");
        assert_eq!(result["agent_id"], "ag-durable");
        terminate_presenter(owner);
        assert_eq!(
            fs::read_to_string(script.with_extension("args")).expect("helper arguments"),
            "-m safeyolo.desktop_presenter_rpc --daemon\n"
        );
    }

    #[test]
    fn helper_cannot_redirect_presentation_to_another_agent() {
        let _lock = test_lock();
        let response = r#"{"agent_id":"ag-other","agent":"bob","url":"http://127.0.0.1:1/vnc.html","unlock_code":"fixture","reused":false}"#;
        let (_directory, script) = fixture_script(response);
        let owner = Arc::new(spawn_presenter(&script).expect("fixture helper starts"));
        assert!(matches!(request(&owner, "alice"), Err(Error::Protocol)));
        terminate_presenter(owner);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // Serialize process-wide presenter environment and fixture state across bounded awaits.
    async fn shutdown_reclaims_helper_after_canceled_blocked_request() {
        let _lock = test_lock();
        let directory = tempfile::tempdir().expect("fixture directory");
        let script = directory.path().join("desktop-presenter-blocked");
        fs::write(
            &script,
            "#!/bin/sh\nIFS= read -r request\nprintf started > \"$0.started\"\nIFS= read -r never\n",
        )
        .expect("fixture script");
        let mut permissions = fs::metadata(&script)
            .expect("fixture metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).expect("fixture executable");
        // The test lock prevents other desktop tests from observing this
        // process-wide fixture override.
        unsafe { std::env::set_var("SAFEYOLO_DESKTOP_PRESENTER_PYTHON", &script) };

        let request = tokio::spawn(present("alice".to_owned()));
        let marker = script.with_extension("started");
        let deadline = Instant::now() + Duration::from_secs(1);
        while !marker.exists() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(marker.exists(), "helper must receive the request");
        request.abort();
        let _ = request.await;

        tokio::time::timeout(
            Duration::from_secs(1),
            tokio::task::spawn_blocking(shutdown),
        )
        .await
        .expect("shutdown must not wait on the canceled helper response")
        .expect("shutdown worker must join");
        assert!(PRESENTER.lock().expect("presenter lock").is_none());
        unsafe { std::env::remove_var("SAFEYOLO_DESKTOP_PRESENTER_PYTHON") };
    }
}
