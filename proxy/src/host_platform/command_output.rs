//! Bounded output and transport deadlines for captured guest commands.

use std::{io, os::unix::process::ExitStatusExt};

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) async fn wait_guest_command_output_bounded(
    mut child: tokio::process::Child,
    timeout: std::time::Duration,
    limit: usize,
) -> io::Result<serde_json::Value> {
    use tokio::io::AsyncReadExt;

    async fn capture(
        mut pipe: impl tokio::io::AsyncRead + Unpin,
        output: &mut Vec<u8>,
        truncated: &mut bool,
        limit: usize,
    ) -> io::Result<()> {
        let mut buffer = [0; 8192];
        loop {
            let count = pipe.read(&mut buffer).await?;
            if count == 0 {
                return Ok(());
            }
            let retained = count.min(limit.saturating_sub(output.len()));
            output.extend_from_slice(&buffer[..retained]);
            *truncated |= retained != count;
        }
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("stderr unavailable"))?;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let (mut out_truncated, mut err_truncated) = (false, false);
    let result = tokio::time::timeout(timeout, async {
        let (status, (), ()) = tokio::try_join!(
            child.wait(),
            capture(stdout, &mut out, &mut out_truncated, limit),
            capture(stderr, &mut err, &mut err_truncated, limit),
        )?;
        Ok::<_, io::Error>(status)
    })
    .await;
    let (state, exit_code, transport_exit_code, transport_signal) = match result {
        Ok(Ok(status)) => {
            let code = status.code();
            let signal = status.signal();
            if signal.is_some() {
                ("transport_cancelled", None, code, signal)
            } else if cfg!(target_os = "macos") && code == Some(255) {
                // SSH reserves 255 for transport failure. A guest command
                // can also exit 255, so this status cannot verify completion.
                ("transport_error", None, code, signal)
            } else {
                ("completed", code, code, signal)
            }
        }
        Ok(Err(_)) => {
            let _ = child.start_kill();
            ("transport_error", None, None, None)
        }
        Err(_) => {
            let _ = child.start_kill();
            ("timed_out", None, None, None)
        }
    };
    Ok(serde_json::json!({"state":state,"exit_code":exit_code,
        "transport_exit_code":transport_exit_code,"transport_signal":transport_signal,
        "stdout":String::from_utf8_lossy(&out),"stderr":String::from_utf8_lossy(&err),
        "stdout_truncated":out_truncated,"stderr_truncated":err_truncated,
        "guest_descendants_terminated":null}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_guest_output_drains_both_streams_and_preserves_failure_status() {
        let child = tokio::process::Command::new("python3")
            .args([
                "-c",
                "import os; os.write(1,b'a'*131072); os.write(2,b'b'*131072); raise SystemExit(7)",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let output =
            wait_guest_command_output_bounded(child, std::time::Duration::from_secs(5), 32)
                .await
                .unwrap();
        assert_eq!(output["state"], "completed");
        assert_eq!(output["exit_code"], 7);
        assert_eq!(output["stdout"], "a".repeat(32));
        assert_eq!(output["stderr"], "b".repeat(32));
        assert_eq!(output["stdout_truncated"], true);
        assert_eq!(output["stderr_truncated"], true);
    }

    #[tokio::test]
    async fn bounded_guest_output_reports_transport_timeout_without_a_completion_claim() {
        let child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "printf prefix; exec sleep 10"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let output =
            wait_guest_command_output_bounded(child, std::time::Duration::from_millis(100), 32)
                .await
                .unwrap();
        assert_eq!(output["state"], "timed_out");
        assert!(output["exit_code"].is_null());
        assert!(output["guest_descendants_terminated"].is_null());
    }

    #[tokio::test]
    async fn a_signalled_transport_does_not_report_command_completion() {
        let mut child = tokio::process::Command::new("sleep")
            .arg("10")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        child.start_kill().unwrap();
        let output =
            wait_guest_command_output_bounded(child, std::time::Duration::from_secs(5), 32)
                .await
                .unwrap();
        assert_eq!(output["state"], "transport_cancelled");
        assert_eq!(output["transport_signal"], libc::SIGKILL);
        assert!(output["exit_code"].is_null());
        assert!(output["guest_descendants_terminated"].is_null());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn ssh_status_255_leaves_command_completion_unverified() {
        let child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "exit 255"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let output =
            wait_guest_command_output_bounded(child, std::time::Duration::from_secs(5), 32)
                .await
                .unwrap();
        assert_eq!(output["state"], "transport_error");
        assert_eq!(output["transport_exit_code"], 255);
        assert!(output["exit_code"].is_null());
    }
}
