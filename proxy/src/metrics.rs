//! Reached HTTP metrics and source report formats. The runtime owns one shared
//! collector and retains the returned request timestamp per exchange.

use std::{
    fmt,
    sync::{Mutex, MutexGuard},
};

use indexmap::IndexMap;
use num_bigint::BigInt;
use serde_json::Value;
use zeroize::Zeroize;

use crate::{
    circuits::{CircuitValue as C, ErrorKind as NumericError},
    network_guard::sanitize_with_limit,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Poisoned,
    Type,
    Overflow,
    Compatibility,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(ErrorKind);
impl Error {
    pub fn kind(self) -> ErrorKind {
        self.0
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("metrics operation failed")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Default)]
struct Domain {
    requests: BigInt,
    successes: BigInt,
    credential: BigInt,
    yara: BigInt,
    pattern: BigInt,
    injection: BigInt,
    upstream_429: BigInt,
    upstream_5xx: BigInt,
    timeouts: BigInt,
    // None is the source's initial integer 0, despite its float annotations.
    latency_sum: Option<f64>,
    latency_count: BigInt,
    latency_max: Option<f64>,
}
impl Domain {
    fn success_rate(&self) -> Result<f64> {
        if self.requests == BigInt::from(0) {
            Ok(1.0)
        } else {
            ratio(&self.successes, &self.requests)
        }
    }
    fn average(&self) -> Result<C> {
        if self.latency_count == BigInt::from(0) {
            Ok(0.into())
        } else {
            divide(
                C::Float(self.latency_sum.unwrap_or(0.0)),
                &self.latency_count,
            )
        }
    }
    fn document(&self) -> Result<C> {
        Ok(object([
            ("requests", self.requests.clone().into()),
            ("successes", self.successes.clone().into()),
            ("success_rate", C::Float(rounded(self.success_rate()?, 3))),
            (
                "blocked",
                object([
                    ("credential", self.credential.clone().into()),
                    ("yara", self.yara.clone().into()),
                    ("pattern", self.pattern.clone().into()),
                    ("injection", self.injection.clone().into()),
                ]),
            ),
            (
                "upstream_errors",
                object([
                    ("429s", self.upstream_429.clone().into()),
                    ("5xx", self.upstream_5xx.clone().into()),
                    ("timeouts", self.timeouts.clone().into()),
                ]),
            ),
            (
                "latency_ms",
                object([
                    ("avg", round_value(self.average()?, 1)),
                    (
                        "max",
                        self.latency_max
                            .map_or(0.into(), |n| C::Float(rounded(n, 1))),
                    ),
                ]),
            ),
        ]))
    }
}

struct State {
    started: f64,
    total: BigInt,
    success: BigInt,
    blocked: BigInt,
    error: BigInt,
    sources: IndexMap<String, BigInt>,
    domains: IndexMap<String, Domain>,
}
impl Drop for State {
    fn drop(&mut self) {
        for (mut name, _) in self.sources.drain(..) {
            name.zeroize();
        }
        for (mut name, _) in self.domains.drain(..) {
            name.zeroize();
        }
    }
}

pub struct Metrics {
    state: Mutex<State>,
}
impl Metrics {
    /// Sample the source uptime origin once at process-owner creation.
    pub fn new(clock: impl FnOnce() -> f64) -> Self {
        Self {
            state: Mutex::new(State {
                started: clock(),
                total: 0.into(),
                success: 0.into(),
                blocked: 0.into(),
                error: 0.into(),
                sources: IndexMap::new(),
                domains: IndexMap::new(),
            }),
        }
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| Error(ErrorKind::Poisoned))
    }

    /// Called only when the late source request hook is reached. The returned
    /// clock value replaces this exchange's previous metrics_start_time.
    pub fn request(&self, host: &str, clock: impl FnOnce() -> f64) -> Result<f64> {
        let mut state = self.lock()?;
        state.total += 1;
        state.domains.entry(host.into()).or_default().requests += 1;
        drop(state);
        Ok(clock())
    }

    /// This observes the validated response hook, not transport errors or
    /// bytes delivered to a client. A response can precede its request hook.
    pub fn response(
        &self,
        host: &str,
        start: Option<f64>,
        blocked_by: Option<&C>,
        status: Option<u16>,
        clock: impl FnOnce() -> f64,
    ) -> Result<()> {
        let mut state = self.lock()?;
        state.domains.entry(host.into()).or_default();
        drop(state);
        let elapsed = start
            .filter(|start| *start != 0.0)
            .map_or(0.0, |start| (clock() - start) * 1000.0);
        let mut state = self.lock()?;
        if let Some(blocked) = blocked_by.filter(|value| value.truthy()) {
            state.blocked += 1;
            let source = match blocked {
                C::Other(Value::String(source)) => source,
                C::Array(_) | C::Object(_) | C::Other(Value::Array(_) | Value::Object(_)) => {
                    return Err(Error(ErrorKind::Type));
                }
                // Source hashable nonstring keys are not produced by the live
                // native pipeline. Preserve reached partial effects and expose
                // the representation gap instead of coercing a block source.
                _ => return Err(Error(ErrorKind::Compatibility)),
            };
            let stats = state.domains.get_mut(host).expect("inserted domain");
            match source.as_str() {
                "credential-guard" => stats.credential += 1,
                "yara-scanner" => stats.yara += 1,
                "pattern-scanner" => stats.pattern += 1,
                "prompt-injection" => stats.injection += 1,
                _ => {}
            }
            *state.sources.entry(source.clone()).or_default() += 1;
            return Ok(());
        }
        let Some(status) = status else {
            return Ok(());
        };
        if status == 429 {
            state.domains.get_mut(host).unwrap().upstream_429 += 1;
        } else if status >= 500 {
            let stats = state.domains.get_mut(host).unwrap();
            stats.upstream_5xx += 1;
            if status == 504 {
                stats.timeouts += 1;
                state.error += 1;
            }
        } else if status < 400 {
            state.success += 1;
            let stats = state.domains.get_mut(host).unwrap();
            stats.successes += 1;
            stats.latency_sum = Some(stats.latency_sum.unwrap_or(0.0) + elapsed);
            stats.latency_count += 1;
            // Python max(old, new) retains the first operand on equal/NaN.
            if elapsed > stats.latency_max.unwrap_or(0.0) {
                stats.latency_max = Some(elapsed);
            }
        }
        Ok(())
    }

    /// Source's basic operator report does not sample the clock.
    pub fn get_stats(&self) -> Result<C> {
        let state = self.lock()?;
        Ok(object([
            ("requests_total", state.total.clone().into()),
            ("requests_success", state.success.clone().into()),
            ("requests_blocked", state.blocked.clone().into()),
            ("blocks_by_source", sources(&state)),
            ("domains_tracked", BigInt::from(state.domains.len()).into()),
        ]))
    }

    /// Full source JSON rendering remains available to an explicit caller;
    /// this component installs no HTTP endpoint.
    pub fn get_json(&self, clock: impl FnOnce() -> f64) -> Result<C> {
        let now = clock();
        let state = self.lock()?;
        let mut domains: Vec<_> = state.domains.iter().collect();
        domains.sort_by(|left, right| right.1.requests.cmp(&left.1.requests));
        let mut problems = Vec::new();
        for (host, stats) in &domains {
            let mut issues = Vec::new();
            let rate = stats.success_rate()?;
            if rate < 0.9 && stats.requests > BigInt::from(10) {
                issues.push(text(&format!(
                    "low_success_rate:{}%",
                    fixed(rate * 100.0, 1)
                )));
            }
            if stats.upstream_429 > BigInt::from(5) {
                issues.push(text(&format!("upstream_429s:{}", stats.upstream_429)));
            }
            if !issues.is_empty() {
                problems.push(object([
                    ("domain", text(host)),
                    ("issues", C::Array(issues)),
                ]));
            }
        }
        let denominator = state.total.clone().max(1.into());
        Ok(object([
            ("uptime_seconds", C::Float(rounded(now - state.started, 1))),
            (
                "summary",
                object([
                    ("requests_total", state.total.clone().into()),
                    ("requests_success", state.success.clone().into()),
                    ("requests_blocked", state.blocked.clone().into()),
                    ("requests_error", state.error.clone().into()),
                    ("blocks_by_source", sources(&state)),
                    (
                        "success_rate",
                        C::Float(rounded(ratio(&state.success, &denominator)?, 3)),
                    ),
                    ("domains_tracked", BigInt::from(state.domains.len()).into()),
                ]),
            ),
            ("problem_domains", C::Array(problems)),
            (
                "domains",
                C::Object(
                    domains
                        .into_iter()
                        .take(20)
                        .map(|(host, stats)| Ok((host.clone(), stats.document()?)))
                        .collect::<Result<_>>()?,
                ),
            ),
        ]))
    }

    pub fn get_prometheus(&self, clock: impl FnOnce() -> f64) -> Result<String> {
        let now = clock();
        let state = self.lock()?;
        let mut lines = vec![
            "# HELP safeyolo_uptime_seconds Proxy uptime".into(),
            "# TYPE safeyolo_uptime_seconds gauge".into(),
            format!("safeyolo_uptime_seconds {}", fixed(now - state.started, 1)),
            "# HELP safeyolo_requests_total Total requests".into(),
            "# TYPE safeyolo_requests_total counter".into(),
            format!("safeyolo_requests_total {}", state.total),
            "# HELP safeyolo_requests_success Successful requests".into(),
            "# TYPE safeyolo_requests_success counter".into(),
            format!("safeyolo_requests_success {}", state.success),
            "# HELP safeyolo_requests_blocked Blocked requests".into(),
            "# TYPE safeyolo_requests_blocked counter".into(),
            format!("safeyolo_requests_blocked {}", state.blocked),
        ];
        if !state.sources.is_empty() {
            lines.extend([
                String::new(),
                "# HELP safeyolo_blocks_by_source Blocked requests by addon source".into(),
                "# TYPE safeyolo_blocks_by_source counter".into(),
            ]);
            let mut sources: Vec<_> = state.sources.iter().collect();
            sources.sort_by(|left, right| left.0.cmp(right.0));
            for (source, count) in sources {
                lines.push(format!(
                    "safeyolo_blocks_by_source{{source=\"{}\"}} {count}",
                    sanitize_with_limit(source, 64)
                ));
            }
        }
        lines.extend([
            String::new(),
            "# HELP safeyolo_domain_requests_total Requests per domain".into(),
            "# TYPE safeyolo_domain_requests_total counter".into(),
        ]);
        for (host, stats) in &state.domains {
            lines.push(format!(
                "safeyolo_domain_requests_total{{domain=\"{}\"}} {}",
                sanitize_with_limit(host, 253),
                stats.requests
            ));
        }
        lines.extend([
            String::new(),
            "# HELP safeyolo_domain_success_rate Success rate per domain".into(),
            "# TYPE safeyolo_domain_success_rate gauge".into(),
        ]);
        for (host, stats) in &state.domains {
            lines.push(format!(
                "safeyolo_domain_success_rate{{domain=\"{}\"}} {}",
                sanitize_with_limit(host, 253),
                fixed(stats.success_rate()?, 3)
            ));
        }
        lines.extend([
            String::new(),
            "# HELP safeyolo_domain_latency_avg_ms Average latency per domain".into(),
            "# TYPE safeyolo_domain_latency_avg_ms gauge".into(),
        ]);
        for (host, stats) in &state.domains {
            let value = match stats.average()? {
                C::Float(value) => value,
                _ => 0.0,
            };
            lines.push(format!(
                "safeyolo_domain_latency_avg_ms{{domain=\"{}\"}} {}",
                sanitize_with_limit(host, 253),
                fixed(value, 1)
            ));
        }
        Ok(lines.join("\n") + "\n")
    }
}

fn divide(numerator: C, denominator: &BigInt) -> Result<C> {
    numerator
        .divide(&C::Integer(denominator.clone()))
        .map_err(|error| {
            Error(match error.kind() {
                NumericError::Type => ErrorKind::Type,
                NumericError::Overflow => ErrorKind::Overflow,
                _ => ErrorKind::Compatibility,
            })
        })
}
fn ratio(numerator: &BigInt, denominator: &BigInt) -> Result<f64> {
    let C::Float(value) = divide(numerator.clone().into(), denominator)? else {
        unreachable!("true division")
    };
    Ok(value)
}
fn rounded(value: f64, places: usize) -> f64 {
    if value.is_finite() {
        format!("{value:.places$}")
            .parse()
            .expect("formatted float")
    } else {
        value
    }
}
fn round_value(value: C, places: usize) -> C {
    if let C::Float(value) = value {
        C::Float(rounded(value, places))
    } else {
        value
    }
}
fn fixed(value: f64, places: usize) -> String {
    if value.is_nan() {
        "nan".into()
    } else {
        format!("{value:.places$}")
    }
}
fn text(value: &str) -> C {
    C::Other(Value::String(value.into()))
}
fn object<const N: usize>(fields: [(&str, C); N]) -> C {
    C::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}
fn sources(state: &State) -> C {
    C::Object(
        state
            .sources
            .iter()
            .map(|(key, count)| (key.clone(), count.clone().into()))
            .collect(),
    )
}

#[cfg(test)]
mod tests;
