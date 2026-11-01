//! Short-lived hashed overlap with an authenticated Claude messages request.

use std::{
    collections::{BTreeSet, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};

use ring::digest::{Context, SHA256};

use super::{Failure, normalized_text};
use crate::{
    ConnectionIdentity, security_indicators::SourceEvidence, services::CredentialSelection,
};

const TTL: Duration = Duration::from_secs(300);
const MAX_SOURCES: usize = 64;
const MAX_FINGERPRINTS: usize = 256;
const MIN_FINGERPRINTS: usize = 8;
const MIN_MATCHES: usize = 4;
const SHINGLE_WORDS: usize = 5;

pub(crate) fn is_claude_messages(
    selected: &CredentialSelection,
    agent: Option<&str>,
    scheme: &str,
    host: &str,
    method: &str,
    path: &str,
) -> bool {
    agent == Some(selected.agent.as_str())
        && selected.service == "claude"
        && selected.capability == "inference"
        && scheme == "https"
        && host == "api.anthropic.com"
        && method == "POST"
        && path.split('?').next() == Some("/v1/messages")
}

struct Source {
    agent: String,
    observed: Instant,
    evidence: SourceEvidence,
    fingerprints: Vec<[u8; 32]>,
}

#[derive(Default)]
pub(crate) struct Exposure {
    sources: Mutex<VecDeque<Source>>,
}

fn fingerprints(content: &[u8]) -> Result<Vec<[u8; 32]>, Failure> {
    let Some((text, _)) = normalized_text(content)? else {
        return Ok(Vec::new());
    };
    if text.len() < 160 {
        return Ok(Vec::new());
    }
    let words: Vec<_> = text
        .split(|byte| !byte.is_ascii_alphanumeric())
        .filter(|word| (2..=64).contains(&word.len()))
        .take(MAX_FINGERPRINTS + SHINGLE_WORDS - 1)
        .collect();
    if words.iter().copied().collect::<BTreeSet<_>>().len() < 16 {
        return Ok(Vec::new());
    }
    let mut hashes = Vec::new();
    for window in words.windows(SHINGLE_WORDS).take(MAX_FINGERPRINTS) {
        if window.iter().map(|word| word.len()).sum::<usize>() < 24
            || window.iter().copied().collect::<BTreeSet<_>>().len() < 4
        {
            continue;
        }
        let mut hash = Context::new(&SHA256);
        for word in window {
            hash.update(word);
            hash.update(b" ");
        }
        let mut bytes = [0; 32];
        bytes.copy_from_slice(hash.finish().as_ref());
        hashes.push(bytes);
    }
    hashes.sort_unstable();
    hashes.dedup();
    Ok(hashes)
}

impl Exposure {
    pub(super) fn remember(
        &self,
        identity: &ConnectionIdentity,
        mut evidence: SourceEvidence,
        content: &[u8],
        now: Instant,
    ) -> Result<(), Failure> {
        let Some(agent) = identity.request_agent() else {
            return Ok(());
        };
        let fingerprints = fingerprints(content)?;
        if fingerprints.len() < MIN_FINGERPRINTS {
            return Ok(());
        }
        evidence.source_fingerprints = fingerprints.len();
        let mut sources = self
            .sources
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        sources.retain(|source| now.saturating_duration_since(source.observed) < TTL);
        while sources.len() >= MAX_SOURCES {
            sources.pop_front();
        }
        sources.push_back(Source {
            agent: agent.to_owned(),
            observed: now,
            evidence,
            fingerprints,
        });
        Ok(())
    }

    pub(super) fn find(
        &self,
        identity: &ConnectionIdentity,
        content: &[u8],
        now: Instant,
    ) -> Result<Option<SourceEvidence>, Failure> {
        let Some(agent) = identity.request_agent() else {
            return Ok(None);
        };
        let fingerprints = fingerprints(content)?;
        let mut sources = self
            .sources
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        sources.retain(|source| now.saturating_duration_since(source.observed) < TTL);
        let mut best = None;
        for source in sources.iter().rev().filter(|source| source.agent == agent) {
            let matched = source
                .fingerprints
                .iter()
                .filter(|hash| fingerprints.binary_search(hash).is_ok())
                .count();
            if matched >= MIN_MATCHES
                && matched * 2 >= source.fingerprints.len()
                && best
                    .as_ref()
                    .is_none_or(|prior: &SourceEvidence| matched > prior.matched_fingerprints)
            {
                let mut evidence = source.evidence.clone();
                evidence.matched_fingerprints = matched;
                best = Some(evidence);
            }
        }
        Ok(best)
    }
}

#[cfg(test)]
mod tests;
