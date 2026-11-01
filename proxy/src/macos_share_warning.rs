//! Advice for operator-selected VirtioFS shares; never changes share admission.

use std::{fs, path::Path};

pub(crate) fn broad_share_warning(path: &Path, home: Option<&Path>) -> Option<String> {
    // Advice is best effort. Ordinary workspace/mount validation owns errors;
    // an unreadable entry must not turn this heuristic into a launch restriction.
    let path = path.canonicalize().ok()?;
    let home = home.and_then(|home| home.canonicalize().ok());
    let home_or_root = path.parent().is_none() || home.as_ref() == Some(&path);
    if !home_or_root {
        // A repository can contain submodules or nested worktrees. Its own
        // metadata identifies the intended scope, including a .git worktree file.
        if path.join(".git").exists() {
            return None;
        }
        let repositories = fs::read_dir(&path)
            .ok()?
            .flatten()
            .filter(|entry| entry.path().join(".git").exists())
            .take(2)
            .count();
        if repositories < 2 {
            return None;
        }
    }
    Some(format!(
        "Warning: broad writable macOS VirtioFS share: {}. Prefer a repository or worktree to reduce host file-table pressure (ENFILE) and write access to unrelated files. This share remains allowed.",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warns_for_home_root_and_multiple_repositories() {
        let fixture = tempfile::tempdir().unwrap();
        let home = fixture.path();
        assert!(broad_share_warning(home, Some(home)).is_some());
        assert!(broad_share_warning(Path::new("/"), Some(home)).is_some());
        fs::create_dir_all(home.join("projects/repo/.git")).unwrap();
        fs::create_dir(home.join("projects/worktree")).unwrap();
        fs::write(home.join("projects/worktree/.git"), "gitdir: elsewhere").unwrap();
        let warning = broad_share_warning(&home.join("projects"), Some(home)).unwrap();
        assert!(warning.contains("ENFILE"));
        assert!(warning.contains("write access to unrelated files"));
        assert!(warning.contains("remains allowed"));
    }

    #[test]
    fn repository_and_worktree_roots_remain_quiet() {
        let fixture = tempfile::tempdir().unwrap();
        let repo = fixture.path().join("repo");
        fs::create_dir_all(repo.join(".git")).unwrap();
        for child in ["submodule", "nested-worktree"] {
            fs::create_dir(repo.join(child)).unwrap();
            fs::write(repo.join(child).join(".git"), "gitdir: elsewhere").unwrap();
        }
        assert!(broad_share_warning(&repo, None).is_none());
        let worktree = fixture.path().join("worktree");
        fs::create_dir(&worktree).unwrap();
        fs::write(worktree.join(".git"), "gitdir: elsewhere").unwrap();
        assert!(broad_share_warning(&worktree, None).is_none());
    }

    #[test]
    fn detection_is_shallow_and_missing_paths_do_not_block() {
        let fixture = tempfile::tempdir().unwrap();
        for child in ["one/repo", "two/repo"] {
            fs::create_dir_all(fixture.path().join(child).join(".git")).unwrap();
        }
        assert!(broad_share_warning(fixture.path(), None).is_none());
        assert!(broad_share_warning(&fixture.path().join("absent"), None).is_none());
    }
}
