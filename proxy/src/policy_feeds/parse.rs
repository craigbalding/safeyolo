//! Format-specific normalization. URL/IP/RPZ/adblock data never becomes a host
//! exclusion by stripping syntax or guessing a different feed format.

use super::{Format, Metadata, Scope, Source};
use crate::Error;
use std::collections::BTreeSet;

pub(super) struct ParsedFeed {
    pub(super) entries: Vec<String>,
    pub(super) provider_observed_at: Option<u64>,
    pub(super) provider_version: Option<String>,
}

pub(super) fn entries(source: &Source, body: &[u8]) -> Result<ParsedFeed, Error> {
    if body.len() as u64 > source.max_bytes {
        return Err("feed response exceeds max_bytes".into());
    }
    let body = std::str::from_utf8(body).map_err(|_| "feed response is not UTF-8")?;
    let mut entries = BTreeSet::new();
    let mut provider_time = None;
    let mut provider_version = None;
    for (line_number, line) in body.lines().enumerate() {
        let line = line.trim();
        if line.starts_with('#') {
            if matches!(source.metadata, Metadata::Hagezi) {
                if provider_time.is_none()
                    && let Some(date) = line.strip_prefix("# Last modified: ")
                {
                    provider_time = Some(parse_date(
                        date,
                        "[day] [month repr:short] [year] [hour]:[minute] UTC",
                    )?);
                }
                if provider_version.is_none()
                    && let Some(version) = line.strip_prefix("# Version: ")
                {
                    if version.len() > 128
                        || !version.bytes().all(|b| b.is_ascii_digit() || b == b'.')
                    {
                        return Err("invalid provider dataset version".into());
                    }
                    provider_version = Some(version.to_owned());
                }
            } else if matches!(source.metadata, Metadata::Stevenblack)
                && provider_time.is_none()
                && let Some(date) = line.strip_prefix("# Date: ")
            {
                provider_time = Some(parse_date(
                    date,
                    "[day] [month repr:long] [year] [hour]:[minute]:[second] (UTC)",
                )?);
            }
            continue;
        }
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        let invalid = || -> Error {
            format!(
                "feed entry on line {} does not match its declared format/scope",
                line_number + 1
            )
            .into()
        };
        let names: Vec<&str> = match source.format {
            Format::Domains => vec![line],
            Format::Wildcard => vec![line.strip_prefix("*.").ok_or_else(invalid)?],
            Format::Hosts => {
                let mut fields = line.split_whitespace();
                let address = fields.next().ok_or_else(invalid)?;
                let names: Vec<_> = fields.collect();
                if address
                    .split('%')
                    .next()
                    .is_none_or(|address| address.parse::<std::net::IpAddr>().is_err())
                {
                    return Err(invalid());
                }
                if names.is_empty() {
                    return Err(invalid());
                }
                // Standard hosts-file boilerplate carries no threat evidence.
                if names.iter().all(|name| {
                    matches!(
                        *name,
                        "localhost"
                            | "localhost.localdomain"
                            | "local"
                            | "broadcasthost"
                            | "0.0.0.0"
                            | "ip6-localhost"
                            | "ip6-loopback"
                            | "ip6-localnet"
                            | "ip6-mcastprefix"
                            | "ip6-allnodes"
                            | "ip6-allrouters"
                            | "ip6-allhosts"
                    )
                }) {
                    continue;
                }
                names
            }
        };
        for name in names {
            let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
            if !dns_name(&name) {
                return Err(invalid());
            }
            let entry = match source.scope {
                Scope::Hostname => name,
                Scope::DomainSuffix => format!("*.{name}"),
            };
            entries.insert(entry);
            if entries.len() > source.max_entries {
                return Err("feed exceeds max_entries".into());
            }
        }
    }
    if entries.len() < source.min_entries {
        return Err("feed has fewer than min_entries (unexpected empty or incomplete data)".into());
    }
    if !matches!(source.metadata, Metadata::None) && provider_time.is_none() {
        return Err("feed is missing its configured provider evidence timestamp".into());
    }
    Ok(ParsedFeed {
        entries: entries.into_iter().collect(),
        provider_observed_at: provider_time,
        provider_version,
    })
}
fn dns_name(name: &str) -> bool {
    name.len() <= 253
        && name.contains('.')
        && name.parse::<std::net::IpAddr>().is_err()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        })
}
fn parse_date(value: &str, description: &str) -> Result<u64, Error> {
    let format =
        time::format_description::parse_borrowed::<2>(description).expect("fixed date format");
    let date = time::PrimitiveDateTime::parse(value, &format)
        .map_err(|_| "invalid provider evidence timestamp")?;
    u64::try_from(date.assume_utc().unix_timestamp())
        .map_err(|_| "provider evidence timestamp predates the epoch".into())
}
pub(super) fn validate_change(old: &[String], new: &[String], limit: u8) -> Result<(), Error> {
    // Jaccard distance: additions and removals divided by the union. Both
    // inputs are sorted and unique. No extra feed-sized set is needed here.
    let (mut a, mut b, mut changed, mut union) = (0, 0, 0u128, 0u128);
    while a < old.len() || b < new.len() {
        union += 1;
        match (old.get(a), new.get(b)) {
            (Some(x), Some(y)) if x == y => {
                a += 1;
                b += 1;
            }
            (Some(x), Some(y)) if x < y => {
                changed += 1;
                a += 1;
            }
            (Some(_), Some(_)) => {
                changed += 1;
                b += 1;
            }
            (Some(_), None) => {
                changed += 1;
                a += 1;
            }
            (None, Some(_)) => {
                changed += 1;
                b += 1;
            }
            (None, None) => unreachable!(),
        }
    }
    if changed * 100 > union * u128::from(limit) {
        return Err("feed membership change exceeds max_change_percent; accepted data retained; inspect the provider and deliberately revise the source limit if appropriate".into());
    }
    Ok(())
}
