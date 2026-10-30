//! GitHub references remain external descriptions, separate from local work truth.
use super::WorkError;
use serde_json::{Value, json};

pub(crate) struct Reference {
    pub url: String,
    pub api_url: String,
    pub title: String,
}

impl Reference {
    pub fn parse(input: &str) -> Result<Self, WorkError> {
        let invalid = || {
            WorkError(
                400,
                "expected a GitHub issue or pull request HTTPS URL".into(),
            )
        };
        let path = input
            .split(['?', '#'])
            .next()
            .unwrap_or("")
            .strip_prefix("https://github.com/")
            .ok_or_else(invalid)?;
        let parts = path.trim_end_matches('/').split('/').collect::<Vec<_>>();
        let [owner, repo, kind, number] = parts.as_slice() else {
            return Err(invalid());
        };
        let name = |value: &str| {
            !value.is_empty()
                && value != "."
                && value != ".."
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        };
        if input.len() > 1024
            || !name(owner)
            || !name(repo)
            || !matches!(*kind, "issues" | "pull")
            || !number.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(invalid());
        }
        let number = number
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(invalid)?;
        let endpoint = if *kind == "pull" { "pulls" } else { "issues" };
        Ok(Self {
            url: format!("https://github.com/{owner}/{repo}/{kind}/{number}"),
            api_url: format!("https://api.github.com/repos/{owner}/{repo}/{endpoint}/{number}"),
            title: format!("GitHub {owner}/{repo}#{number}"),
        })
    }

    pub fn create(&self) -> Value {
        json!({"action":"create","title":self.title,"external_ref":self.url})
    }

    pub fn metadata(&self, document: &Value) -> Result<Value, WorkError> {
        let title = document["title"]
            .as_str()
            .ok_or_else(|| WorkError(502, "GitHub returned no title".into()))?;
        let state = document["state"]
            .as_str()
            .filter(|s| matches!(*s, "open" | "closed"))
            .ok_or_else(|| WorkError(502, "GitHub returned an invalid state".into()))?;
        let mut end = title.len().min(512);
        while !title.is_char_boundary(end) {
            end -= 1;
        }
        Ok(
            json!({"source":"github","status":"available","url":self.url,
            "title":crate::coord_timeline::visible(&title[..end]),"title_truncated":end<title.len(),
            "state":state,"observed_at":super::now()}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn references_are_canonical_and_cannot_select_another_destination() {
        let reference =
            Reference::parse("https://github.com/owner/repo/pull/0013#discussion").unwrap();
        assert_eq!(reference.url, "https://github.com/owner/repo/pull/13");
        assert_eq!(
            reference.api_url,
            "https://api.github.com/repos/owner/repo/pulls/13"
        );
        assert_eq!(reference.create()["external_ref"], reference.url);
        for invalid in [
            "http://github.com/o/r/issues/1",
            "https://github.com.evil/o/r/issues/1",
            "https://github.com@evil/o/r/issues/1",
            "https://github.com/o/../issues/1",
            "https://github.com/o/r/issues/0",
            "https://github.com/o/r/issues/-1",
            "https://github.com/o/r/issues/1/other",
            "https://github.com/o/r/issues/%31",
            "https://github.com/o/r/issues/18446744073709551616",
        ] {
            assert!(Reference::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn metadata_is_bounded_inert_and_contains_no_rich_description_or_candidate() {
        let reference = Reference::parse("https://github.com/o/r/issues/1").unwrap();
        let metadata = reference.metadata(&json!({"title":format!("\u{001b}[2J\u{202e}{}","π".repeat(400)),
            "state":"closed","body":"PRIVATE BODY","assignees":["mallory"],"head":{"sha":"new-candidate"},"html_url":"https://evil"})).unwrap();
        assert_eq!(metadata["url"], reference.url);
        assert_eq!(metadata["state"], "closed");
        assert_eq!(metadata["title_truncated"], true);
        let text = metadata.to_string();
        assert!(!text.contains(['\u{001b}', '\u{202e}']));
        for omitted in ["PRIVATE BODY", "mallory", "new-candidate", "evil"] {
            assert!(!text.contains(omitted));
        }
        assert!(
            reference
                .metadata(&json!({"title":"test","state":"claimed"}))
                .is_err()
        );
        assert!(reference.metadata(&json!({"state":"open"})).is_err());
    }
}
