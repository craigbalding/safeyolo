//! Bounded metadata comparisons owned by the native connection namespace.

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{
    ConnectionIdentity, audit,
    security_indicators::{self, Indicator},
    tls_identity::TlsSession,
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
struct Key {
    agent: String,
    destination: String,
    route: &'static str,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Observation {
    pub(crate) connection_id: String,
    pub(crate) event_id: String,
    pub(crate) cert_sha256: Option<String>,
    pub(crate) spki_sha256: Option<String>,
}

impl Observation {
    pub(super) fn new(connection_id: &str, event_id: String) -> Self {
        Self {
            connection_id: connection_id.into(),
            event_id,
            cert_sha256: None,
            spki_sha256: None,
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
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Evidence {
    pub(crate) history_scope: String,
    pub(crate) history_capacity: usize,
    pub(crate) destination: String,
    pub(crate) route: String,
    pub(crate) verification_name: Option<String>,
    pub(crate) current: Observation,
    pub(crate) previous: Option<Observation>,
}

impl Evidence {
    pub(crate) fn valid(&self, connection_id: Option<&str>) -> bool {
        self.history_scope == SCOPE
            && (1..=CAPACITY).contains(&self.history_capacity)
            && !self.destination.trim().is_empty()
            && matches!(self.route.as_str(), "direct" | "parent" | "provider")
            && connection_id == Some(self.current.connection_id.as_str())
            && self.current.valid()
            && match &self.previous {
                None => {
                    self.verification_name.is_none()
                        && self.current.cert_sha256.is_none()
                        && self.current.spki_sha256.is_none()
                }
                Some(previous) => {
                    previous.valid()
                        && previous.event_id != self.current.event_id
                        && self
                            .verification_name
                            .as_ref()
                            .is_some_and(|name| !name.trim().is_empty())
                        && previous.cert_sha256.is_some()
                        && self.current.cert_sha256.is_some()
                        && (previous.cert_sha256 != self.current.cert_sha256
                            || matches!(
                                (&previous.spki_sha256, &self.current.spki_sha256),
                                (Some(a), Some(b)) if a != b
                            ))
                }
            }
    }
}

struct CertificateObservation {
    verification_name: String,
    observation: Observation,
}

pub(super) struct History {
    entries: HashMap<Key, Option<CertificateObservation>>,
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
    fn destination(&mut self, key: &Key, current: Observation) -> Option<Evidence> {
        if self.entries.contains_key(key) {
            return None;
        }
        while self.entries.len() >= self.capacity {
            self.entries.remove(&self.oldest.pop_front()?);
        }
        self.oldest.push_back(key.clone());
        self.entries.insert(key.clone(), None);
        Some(Evidence {
            history_scope: SCOPE.into(),
            history_capacity: self.capacity,
            destination: key.destination.clone(),
            route: key.route.into(),
            verification_name: None,
            current,
            previous: None,
        })
    }

    fn tls(
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
        let baseline = self.entries.get_mut(key)?;
        current.cert_sha256 = Some(cert.cert_sha256.clone());
        current.spki_sha256 = cert.spki_sha256.clone();
        let verification_name = normalize_host(name);
        let previous = baseline.replace(CertificateObservation {
            verification_name: verification_name.clone(),
            observation: current.clone(),
        })?;
        if previous.verification_name != verification_name {
            return None;
        }
        let evidence = Evidence {
            history_scope: SCOPE.into(),
            history_capacity: self.capacity,
            destination: key.destination.clone(),
            route: key.route.into(),
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
        let key = Key {
            agent: agent.into(),
            destination: destination.authority.clone(),
            route: destination.route,
        };
        let evidence = match tls {
            None => history.destination(&key, current),
            Some((name, session)) => history.tls(&key, name, session, current),
        };
        let Some(evidence) = evidence else { return };
        let change = evidence.previous.is_some();
        // Keep comparison and submission in one order across reconnects.
        security_indicators::emit(
            self,
            identity,
            None,
            None,
            Indicator {
                indicator_type: if change {
                    "tls_identity_change"
                } else {
                    "destination_novelty"
                },
                sensor: "connection-history.v1",
                rule: if change {
                    "tls.origin_identity_changed.v1"
                } else {
                    "destination.first_observation.v1"
                },
                confidence: 1.0,
                severity: audit::Severity::Low,
                summary: if change {
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

#[cfg(test)]
mod tests;
