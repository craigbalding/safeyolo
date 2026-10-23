//! Keep Codex routing discovery alive through an explicit credential decision.

use super::*;

pub(super) fn routing_discovery(method: &Method, path: &str) -> bool {
    method == Method::GET && path.split('?').next() == Some("/backend-api/wham/accounts/check")
}

pub(super) async fn wait_for_decision(
    state: &RuntimeState,
    approval_id: &str,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<bool, Error> {
    // The client keeps its own HTTP deadline. On expiry, return the ordinary
    // approval response. This waiter never sends application bytes upstream.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if *stop.borrow() {
            return Ok(false);
        }
        let state = state.clone();
        let id = approval_id.to_owned();
        let read = tokio::task::spawn_blocking(move || -> Result<_, Error> {
            let runtime = state.read().map_err(|_| "runtime unavailable")?.clone();
            let policy = runtime.policy.as_ref().ok_or("policy unavailable")?;
            let record = crate::approvals::pending::lookup(&runtime.audit, &id)?
                .ok_or("credential approval unavailable")?;
            Ok(crate::approvals::pending::current_view(
                &runtime.audit,
                policy,
                &record,
                Some(&state),
            )?)
        });
        let view = tokio::select! {
            result = read => result??,
            _ = tokio::time::sleep_until(deadline) => return Ok(false),
            _ = stop.changed() => return Ok(false),
        };
        match view["status"].as_str() {
            Some("approved") => return Ok(view["grant_active"] != false),
            Some("pending") => {}
            _ => return Ok(false),
        }
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return Ok(false),
            _ = stop.changed() => return Ok(false),
            _ = tokio::time::sleep(Duration::from_millis(50)) => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_read_only_routing_query_waits() {
        for path in [
            "/backend-api/wham/accounts/check",
            "/backend-api/wham/accounts/check?workspace_id=fixture",
        ] {
            assert!(routing_discovery(&Method::GET, path));
            assert!(!routing_discovery(&Method::POST, path));
        }
        for path in [
            "/backend-api/codex/responses",
            "/backend-api/wham/accounts/check/extra",
            "/other?path=/backend-api/wham/accounts/check",
        ] {
            assert!(!routing_discovery(&Method::GET, path));
        }
    }
}
