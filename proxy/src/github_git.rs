//! GitHub smart HTTP has two wire requests for one repository operation.
//! Policy and grants use the canonical POST endpoint for both requests.

use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct GitHubRequest {
    pub repository: String,
    pub operation: String,
    pub path: String,
    pub discovery: bool,
}

impl GitHubRequest {
    pub fn parse(method: &str, target: &str) -> Option<Self> {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let parts: Vec<_> = path.strip_prefix('/')?.split('/').collect();
        let [owner, repository, endpoint @ ..] = parts.as_slice() else {
            return None;
        };
        let owner = owner.to_ascii_lowercase();
        let repository = repository.to_ascii_lowercase();
        let repository = repository.strip_suffix(".git").unwrap_or(&repository);
        // URL decoding and path-trick rejection belong to the existing gateway
        // boundary. These are GitHub's literal owner/repository path components.
        if [owner.as_str(), repository].iter().any(|part| {
            part.is_empty()
                || matches!(*part, "." | "..")
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        }) {
            return None;
        }
        let (operation, discovery) = match (method, endpoint, query) {
            ("GET", ["info", "refs"], "service=git-upload-pack") => ("git-upload-pack", true),
            ("GET", ["info", "refs"], "service=git-receive-pack") => ("git-receive-pack", true),
            ("POST", ["git-upload-pack"], "") => ("git-upload-pack", false),
            ("POST", ["git-receive-pack"], "") => ("git-receive-pack", false),
            _ => return None,
        };
        Some(Self {
            repository: format!("{owner}/{repository}"),
            operation: operation.into(),
            path: format!("/{owner}/{repository}.git/{operation}"),
            discovery,
        })
    }

    pub fn action(&self) -> &'static str {
        if self.operation == "git-receive-pack" {
            "push"
        } else {
            "fetch"
        }
    }
}
