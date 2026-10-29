//! Bounded metadata comparisons owned by the native connection namespace.

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{
    ConnectionIdentity, audit,
    security_indicators::{self, Indicator},
    tls_identity::{ClientHello, TlsSession},
};

use super::ConnectionEvents;

pub(crate) const CAPACITY: usize = 4096;
const SCOPE: &str = "runtime_fifo";

pub(super) struct Destination {
    authority: String,
    route: &'static str,
}

impl Destination {
    pub(super) fn new(host: &str, port: u16, route: &'static str) -> Self {
        let host = normalize_host(host);
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        Self { authority, route }
    }
}

fn normalize_host(host: &str) -> String {
    host.parse::<std::net::IpAddr>().map_or_else(
        |_| host.trim_end_matches('.').to_ascii_lowercase(),
        |ip| ip.to_string(),
    )
}

#[derive(Clone, Hash, Eq, PartialEq)]
enum Key {
    Destination {
        agent: String,
        destination: String,
        route: &'static str,
    },
    Client(String),
}

impl Key {
    fn destination_and_route(&self) -> (Option<String>, Option<String>) {
        match self {
            Self::Destination {
                destination, route, ..
            } => (Some(destination.clone()), Some((*route).into())),
            Self::Client(_) => (None, None),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Observation {
    pub(crate) connection_id: String,
    pub(crate) event_id: String,
    pub(crate) cert_sha256: Option<String>,
    pub(crate) spki_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) negotiation: Option<Negotiation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) client_fingerprint: Option<ClientFingerprint>,
}

#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientFingerprint {
    ja3: String,
    ja4: String,
}

impl ClientFingerprint {
    fn valid(&self) -> bool {
        self.ja3.len() == 32
            && self
                .ja3
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && self.ja4.len() == 36
            && self
                .ja4
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    }
}

#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Negotiation {
    version: String,
    // Null inside a measured negotiation means that no ALPN was negotiated.
    alpn: Option<String>,
}

impl Observation {
    pub(super) fn new(connection_id: &str, event_id: String) -> Self {
        Self {
            connection_id: connection_id.into(),
            event_id,
            cert_sha256: None,
            spki_sha256: None,
            negotiation: None,
            client_fingerprint: None,
        }
    }

    fn valid(&self) -> bool {
        let hash = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        };
        !self.connection_id.trim().is_empty()
            && !self.event_id.trim().is_empty()
            && self.event_id.len() <= 128
            && self.cert_sha256.as_deref().is_none_or(hash)
            && self.spki_sha256.as_deref().is_none_or(hash)
            && (self.spki_sha256.is_none() || self.cert_sha256.is_some())
            && self.client_fingerprint.as_ref().is_none_or(|value| {
                value.valid()
                    && self.cert_sha256.is_none()
                    && self.spki_sha256.is_none()
                    && self.negotiation.is_none()
            })
            && self.negotiation.as_ref().is_none_or(|value| {
                !value.version.trim().is_empty()
                    && value.version.len() <= 1024
                    && value.alpn.as_ref().is_none_or(|alpn| alpn.len() <= 1024)
                    && self.cert_sha256.is_none()
                    && self.spki_sha256.is_none()
            })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Evidence {
    pub(crate) history_scope: String,
    pub(crate) history_capacity: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) route: Option<String>,
    pub(crate) verification_name: Option<String>,
    pub(crate) current: Observation,
    pub(crate) previous: Option<Observation>,
}

impl Evidence {
    pub(crate) fn valid(&self, connection_id: Option<&str>) -> bool {
        self.history_scope == SCOPE
            && (1..=CAPACITY).contains(&self.history_capacity)
            && connection_id == Some(self.current.connection_id.as_str())
            && self.current.valid()
            && if self.current.client_fingerprint.is_some() {
                self.valid_client_fingerprint()
            } else {
                self.valid_destination()
            }
    }

    fn valid_client_fingerprint(&self) -> bool {
        self.destination.is_none()
            && self.route.is_none()
            && self.verification_name.is_none()
            && self.previous.as_ref().is_none_or(|previous| {
                previous.valid()
                    && previous.event_id != self.current.event_id
                    && previous.client_fingerprint.is_some()
                    && previous.client_fingerprint != self.current.client_fingerprint
            })
    }

    fn valid_destination(&self) -> bool {
        self.destination
            .as_ref()
            .is_some_and(|name| !name.trim().is_empty())
            && matches!(
                self.route.as_deref(),
                Some("direct" | "parent" | "provider")
            )
            && match &self.previous {
                None => {
                    self.verification_name.is_none()
                        && self.current.cert_sha256.is_none()
                        && self.current.spki_sha256.is_none()
                        && self.current.negotiation.is_none()
                }
                Some(previous) => {
                    previous.valid()
                        && previous.event_id != self.current.event_id
                        && self
                            .verification_name
                            .as_ref()
                            .is_some_and(|name| !name.trim().is_empty())
                        && match (&previous.negotiation, &self.current.negotiation) {
                            (Some(a), Some(b)) => a != b,
                            (None, None) => {
                                previous.cert_sha256.is_some()
                                    && self.current.cert_sha256.is_some()
                                    && (previous.cert_sha256 != self.current.cert_sha256
                                        || matches!(
                                            (&previous.spki_sha256, &self.current.spki_sha256),
                                            (Some(a), Some(b)) if a != b
                                        ))
                            }
                            _ => false,
                        }
                }
            }
    }
}

struct TlsObservation {
    verification_name: String,
    observation: Observation,
}

#[derive(Default)]
struct TlsHistory {
    certificate: Option<TlsObservation>,
    negotiation: Option<TlsObservation>,
    client_fingerprint: Option<Observation>,
}

pub(super) struct History {
    entries: HashMap<Key, TlsHistory>,
    oldest: VecDeque<Key>,
    capacity: usize,
}

impl Default for History {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            oldest: VecDeque::new(),
            capacity: CAPACITY,
        }
    }
}

impl History {
    fn insert(&mut self, key: &Key, entry: TlsHistory) {
        while self.entries.len() >= self.capacity {
            let oldest = self.oldest.pop_front().expect("bounded history entry");
            self.entries.remove(&oldest);
        }
        self.oldest.push_back(key.clone());
        self.entries.insert(key.clone(), entry);
    }

    fn destination(&mut self, key: &Key, current: Observation) -> Option<Evidence> {
        if self.entries.contains_key(key) {
            return None;
        }
        self.insert(key, TlsHistory::default());
        let (destination, route) = key.destination_and_route();
        Some(Evidence {
            history_scope: SCOPE.into(),
            history_capacity: self.capacity,
            destination,
            route,
            verification_name: None,
            current,
            previous: None,
        })
    }

    fn client_fingerprint(
        &mut self,
        agent: &str,
        hello: &ClientHello,
        mut current: Observation,
    ) -> Option<Evidence> {
        if !hello.valid() {
            return None;
        }
        current.client_fingerprint = Some(ClientFingerprint {
            ja3: hello.ja3.clone(),
            ja4: hello.ja4.clone(),
        });
        let key = Key::Client(agent.into());
        let previous = match self.entries.get_mut(&key) {
            Some(entry) => entry.client_fingerprint.replace(current.clone()),
            None => {
                self.insert(
                    &key,
                    TlsHistory {
                        client_fingerprint: Some(current.clone()),
                        ..TlsHistory::default()
                    },
                );
                None
            }
        };
        let evidence = Evidence {
            history_scope: SCOPE.into(),
            history_capacity: self.capacity,
            destination: None,
            route: None,
            verification_name: None,
            current,
            previous,
        };
        evidence
            .valid(Some(&evidence.current.connection_id))
            .then_some(evidence)
    }

    fn certificate(
        &mut self,
        key: &Key,
        name: &str,
        session: &TlsSession,
        mut current: Observation,
    ) -> Option<Evidence> {
        // A resumed chain may be cached by rustls. Parent TLS is a different
        // peer, and absence is not a measured certificate change.
        if session.peer != "origin"
            || !matches!(
                session.handshake_kind.as_deref(),
                Some("Full" | "FullWithHelloRetryRequest")
            )
        {
            return None;
        }
        let cert = session.leaf_certificate.as_ref()?;
        let baseline = &mut self.entries.get_mut(key)?.certificate;
        current.cert_sha256 = Some(cert.cert_sha256.clone());
        current.spki_sha256 = cert.spki_sha256.clone();
        Self::compare(self.capacity, key, name, baseline, current)
    }

    fn negotiation(
        &mut self,
        key: &Key,
        name: &str,
        session: &TlsSession,
        mut current: Observation,
    ) -> Option<Evidence> {
        // Resumption still measures these negotiated values on this connection.
        // No session or missing version cannot establish even a no-ALPN result.
        if session.peer != "origin"
            || !matches!(
                session.handshake_kind.as_deref(),
                Some("Full" | "FullWithHelloRetryRequest" | "Resumed")
            )
        {
            return None;
        }
        current.negotiation = Some(Negotiation {
            version: session.version.clone()?,
            alpn: session.alpn.clone(),
        });
        if !current.valid() {
            return None;
        }
        let baseline = &mut self.entries.get_mut(key)?.negotiation;
        Self::compare(self.capacity, key, name, baseline, current)
    }

    fn compare(
        capacity: usize,
        key: &Key,
        name: &str,
        baseline: &mut Option<TlsObservation>,
        current: Observation,
    ) -> Option<Evidence> {
        let verification_name = normalize_host(name);
        let previous = baseline.replace(TlsObservation {
            verification_name: verification_name.clone(),
            observation: current.clone(),
        })?;
        if previous.verification_name != verification_name {
            return None;
        }
        let (destination, route) = key.destination_and_route();
        let evidence = Evidence {
            history_scope: SCOPE.into(),
            history_capacity: capacity,
            destination,
            route,
            verification_name: Some(verification_name),
            current,
            previous: Some(previous.observation),
        };
        evidence
            .valid(Some(&evidence.current.connection_id))
            .then_some(evidence)
    }
}

impl ConnectionEvents {
    pub(super) fn observe_client_fingerprint(
        &self,
        history: &mut History,
        identity: &ConnectionIdentity,
        hello: &ClientHello,
        current: Observation,
    ) {
        let Some(agent) = identity.request_agent() else {
            return;
        };
        let Some(evidence) = history.client_fingerprint(agent, hello, current) else {
            return;
        };
        let change = evidence.previous.is_some();
        security_indicators::emit(
            self,
            identity,
            None,
            None,
            Indicator {
                indicator_type: if change {
                    "tls_client_fingerprint_change"
                } else {
                    "tls_client_fingerprint_novelty"
                },
                sensor: "connection-history.v1",
                rule: if change {
                    "tls.client_fingerprint_changed.v1"
                } else {
                    "tls.client_fingerprint_first_observation.v1"
                },
                confidence: 1.0,
                severity: audit::Severity::Low,
                summary: if change {
                    "Client TLS fingerprint changed in bounded runtime history"
                } else {
                    "First client TLS fingerprint observation in bounded runtime history"
                },
                connection_id: Some(&evidence.current.connection_id),
                direction: None,
                evidence_hash: None,
                content: None,
                source: None,
                novelty: Some(&evidence),
            },
        );
    }

    pub(super) fn observe_destination(
        &self,
        history: &mut History,
        identity: &ConnectionIdentity,
        destination: Option<&Destination>,
        current: Observation,
        tls: Option<(&str, &TlsSession)>,
    ) {
        let (Some(agent), Some(destination)) = (identity.request_agent(), destination) else {
            return;
        };
        let key = Key::Destination {
            agent: agent.into(),
            destination: destination.authority.clone(),
            route: destination.route,
        };
        let evidence = match tls {
            None => [history.destination(&key, current), None],
            Some((name, session)) => [
                history.certificate(&key, name, session, current.clone()),
                history.negotiation(&key, name, session, current),
            ],
        };
        for evidence in evidence.into_iter().flatten() {
            let change = evidence.previous.is_some();
            let negotiation = evidence.current.negotiation.is_some();
            // Keep comparison and submission in one order across reconnects.
            security_indicators::emit(
                self,
                identity,
                None,
                None,
                Indicator {
                    indicator_type: if negotiation {
                        "tls_negotiation_change"
                    } else if change {
                        "tls_identity_change"
                    } else {
                        "destination_novelty"
                    },
                    sensor: "connection-history.v1",
                    rule: if negotiation {
                        "tls.origin_negotiation_changed.v1"
                    } else if change {
                        "tls.origin_identity_changed.v1"
                    } else {
                        "destination.first_observation.v1"
                    },
                    confidence: 1.0,
                    severity: audit::Severity::Low,
                    summary: if negotiation {
                        "Origin TLS version or negotiated ALPN changed in bounded runtime history"
                    } else if change {
                        "Upstream certificate or public key changed in bounded runtime history"
                    } else {
                        "First destination observation in bounded runtime history"
                    },
                    connection_id: Some(&evidence.current.connection_id),
                    direction: None,
                    evidence_hash: None,
                    content: None,
                    source: None,
                    novelty: Some(&evidence),
                },
            );
        }
    }
}

#[cfg(test)]
mod tests;
