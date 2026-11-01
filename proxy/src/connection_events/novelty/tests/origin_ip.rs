use super::*;

fn ip_indicators(rows: &[Value]) -> Vec<&Value> {
    indicators(rows)
        .into_iter()
        .filter(|row| row["details"]["rule"] == "origin_ip.first_observation.v1")
        .collect()
}

// These fixtures stay below capacity. Audit order determines each first peer.
pub(super) fn assert_first_events(rows: &[Value], count: usize) {
    let mut seen = std::collections::HashSet::new();
    let expected: Vec<_> = rows
        .iter()
        .filter(|row| {
            if row["event"] != "network.connection"
                || row["details"]["state"] != "open"
                || row["details"]["leg"] != "proxy_to_upstream"
                || row["details"]["attribution"]["attribution_status"] != "resolved"
            {
                return false;
            }
            let Some(peer) = row["details"]["resolved_origin_peer"].as_str() else {
                return false;
            };
            let peer: std::net::SocketAddr = peer.parse().unwrap();
            seen.insert((
                row["details"]["runtime_id"].to_string(),
                row["agent"].to_string(),
                peer.ip().to_canonical(),
            ))
        })
        .collect();
    let clues = ip_indicators(rows);
    assert_eq!(clues.len(), count);
    assert_eq!(clues.len(), expected.len());
    for (clue, source) in clues.iter().zip(expected) {
        assert_eq!(clue["details"]["indicator_type"], "origin_ip_novelty");
        assert_eq!(clue["details"]["confidence"], 1.0);
        assert_eq!(
            clue["details"]["novelty"]["current"]["event_id"],
            source["event_id"]
        );
        let evidence = &clue["details"]["novelty"];
        assert_observation(rows, clue, &evidence["current"], false);
        for field in [
            "destination",
            "route",
            "verification_name",
            "previous",
            "client",
        ] {
            assert!(evidence[field].is_null(), "{field}");
        }
        for field in [
            "cert_sha256",
            "spki_sha256",
            "negotiation",
            "client_fingerprint",
        ] {
            assert!(evidence["current"][field].is_null(), "{field}");
        }
        assert!(source["details"]["tls_sessions"].is_null());
        let source_index = rows
            .iter()
            .position(|row| row["event_id"] == source["event_id"])
            .unwrap();
        let clue_index = rows
            .iter()
            .position(|row| std::ptr::eq(row, *clue))
            .unwrap();
        assert!(source_index < clue_index);
    }
}

#[test]
fn canonical_origin_ips_share_fifo_and_repeats_do_not_refresh_age() {
    let mut history = History {
        capacity: 2,
        ..History::default()
    };
    let a: IpAddr = "192.0.2.1".parse().unwrap();
    let b: IpAddr = "2001:db8::1".parse().unwrap();
    let first = history.origin_ip("alice", a, observation("first")).unwrap();
    assert!(first.valid(Some("first")));
    assert_eq!(first.current.origin_ip, Some(a));
    assert!(
        history
            .origin_ip(
                "alice",
                "::ffff:192.0.2.1".parse().unwrap(),
                observation("mapped")
            )
            .is_none()
    );
    assert!(history.origin_ip("alice", b, observation("v6")).is_some());
    assert!(
        history
            .origin_ip(
                "alice",
                "2001:0db8:0:0:0:0:0:1".parse().unwrap(),
                observation("expanded")
            )
            .is_none()
    );
    assert!(
        history
            .origin_ip("alice", a, observation("repeat"))
            .is_none()
    );
    let destination = key("alice", "origin.invalid:80");
    history.destination(&destination, observation("destination"));
    assert!(!history.entries.contains_key(&Key::OriginIp {
        agent: "alice".into(),
        ip: a
    }));
    assert!(
        history
            .origin_ip("alice", b, observation("retained"))
            .is_none()
    );
    assert!(
        history
            .origin_ip("alice", a, observation("evicted"))
            .is_some()
    );
    assert!(
        history
            .origin_ip("bob", a, observation("other-agent"))
            .is_some()
    );
    assert!(!history.entries.contains_key(&destination));
    assert_eq!(history.entries.len(), 2);
    assert_eq!(history.oldest.len(), 2);
}

async fn serve_origin(listener: TcpListener, tls: Option<Arc<rustls::ServerConfig>>, count: usize) {
    for _ in 0..count {
        let (socket, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
        let mut stream: crate::tunnels::BoxStream = match &tls {
            Some(tls) => Box::new(
                tokio_rustls::TlsAcceptor::from(tls.clone())
                    .accept(socket)
                    .await
                    .unwrap(),
            ),
            None => Box::new(socket),
        };
        assert!(head(&mut stream).await.starts_with(b"GET /path HTTP/1.1"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nunchanged",
            )
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn native_origin_ip_plaintext_tls_ports_names_agents_reload_and_restart() {
    for tls in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let (first, a, second, b) = two_origin_ips().await;
        let (other_port, a2) = crate::test_owned_endpoint::bind_on(a.ip()).await;
        let named = TcpListener::bind((b.ip(), 0)).await.unwrap();
        let b2 = named.local_addr().unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let (pem_a, tls_a, _) = tls_origin(&a.ip().to_string(), &key, 1);
        let (pem_b, tls_b, _) = tls_origin(&b.ip().to_string(), &key, 2);
        let (pem_named, tls_named, _) = tls_origin("localhost", &key, 3);
        let peers = [
            tokio::spawn(serve_origin(first, tls.then_some(tls_a.clone()), 3)),
            tokio::spawn(serve_origin(other_port, tls.then_some(tls_a), 1)),
            tokio::spawn(serve_origin(second, tls.then_some(tls_b), 4)),
            tokio::spawn(serve_origin(named, tls.then_some(tls_named), 1)),
        ];
        let mut configuration =
            tls_proxy_config(directory.path(), &format!("{pem_a}{pem_b}{pem_named}"));
        configuration.network_guard_enabled = false;
        for (agent, source_id) in [("bob", "192.0.2.21"), ("unknown", "192.0.2.22")] {
            configuration.listeners.push(crate::config::AgentListener {
                agent_id: agent.into(),
                source_id: Some(source_id.into()),
                socket_path: directory.path().join(format!("{agent}.sock")),
            });
        }
        let scheme = if tls { "https" } else { "http" };
        let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
        let runtime = proxy.runtime.read().unwrap().clone();
        for (agent, address) in [
            ("alice", a),
            ("alice", a),
            ("alice", a2),
            ("unknown", b),
            ("bob", b),
            ("alice", b),
        ] {
            request(directory.path(), agent, &format!("{scheme}://{address}")).await;
        }
        request(
            directory.path(),
            "alice",
            &format!("{scheme}://localhost:{}", b2.port()),
        )
        .await;
        let rows = records(&runtime, directory.path());
        assert_first_events(&rows, 3);
        let clues = ip_indicators(&rows);
        assert_eq!(clues[0]["agent"], "alice");
        assert_eq!(
            clues[0]["details"]["novelty"]["current"]["origin_ip"],
            a.ip().to_canonical().to_string()
        );
        assert_eq!(clues[1]["agent"], "bob");
        assert_eq!(clues[2]["agent"], "alice");
        assert_eq!(
            clues[2]["details"]["novelty"]["current"]["origin_ip"],
            b.ip().to_string()
        );
        assert!(rows.iter().any(|row| row["event"] == "network.connection"
            && row["details"]["requested_target"] == format!("localhost:{}", b2.port())
            && row["details"]["resolved_origin_peer"] == b2.to_string()));
        proxy.reload(configuration.clone()).await.unwrap();
        request(directory.path(), "alice", &format!("{scheme}://{a}")).await;
        proxy.shutdown().await;
        assert_first_events(&records(&runtime, directory.path()), 3);
        let proxy = Proxy::start(configuration).await.unwrap();
        let restarted = proxy.runtime.read().unwrap().clone();
        assert_ne!(restarted.instance_id, runtime.instance_id);
        request(directory.path(), "alice", &format!("{scheme}://{b}")).await;
        proxy.shutdown().await;
        let rows = records(&restarted, directory.path());
        assert_first_events(&rows, 4);
        assert_eq!(
            ip_indicators(&rows)
                .iter()
                .filter(|row| row["details"]["runtime_id"] == restarted.instance_id)
                .count(),
            1
        );
        for peer in peers {
            timeout(LIMIT, peer).await.unwrap().unwrap();
        }
    }
}
