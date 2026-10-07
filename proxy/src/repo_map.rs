//! Working-tree orientation for staged coding agents, using Git and source text.
use crate::Error;
use std::{
    ffi::{OsStr, OsString},
    fs,
    io::Read,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    process::Command,
};

fn git(directory: &Path, args: &[&str]) -> Result<Vec<u8>, Error> {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "repo-map Git operation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}
fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect()
}
fn text(path: &Path) -> Result<Option<String>, Error> {
    // Like the original query, binary and oversized files contribute their
    // paths, not their contents. Symbol locations are lexical observations.
    let info = fs::symlink_metadata(path)?;
    if !info.is_file() || info.len() > 1_000_000 {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(1_000_001)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1_000_000 || bytes.contains(&0) {
        return Ok(None);
    }
    Ok(String::from_utf8(bytes).ok())
}
fn symbols(source: &str) -> Vec<(usize, String)> {
    let pattern=regex::Regex::new(r"^\s*(?:(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+|(?:async\s+)?def\s+|class\s+|(?:public\s+|private\s+|static\s+)*func\s+|function\s+)([A-Za-z_][A-Za-z0-9_]*)|^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\{").expect("constant symbol pattern");
    source
        .lines()
        .enumerate()
        .filter_map(|(line, text)| {
            pattern
                .captures(text)
                .and_then(|matched| matched.get(1).or_else(|| matched.get(2)))
                .map(|name| (line + 1, name.as_str().to_owned()))
        })
        .collect()
}
#[derive(Debug)]
struct File {
    path: String,
    source: Option<String>,
    score: usize,
    reasons: Vec<String>,
}

pub fn run(args: &[OsString]) -> Result<(), Error> {
    if args == [OsString::from("--help")] {
        println!(
            "repo-map [PATH ...] [--query TEXT] [--hints FILE] [--limit N]\nMap Git working-tree files and lexical symbol locations, or rank locations for a task. Repository-authored guidance is reported separately. No Python or model is used."
        );
        return Ok(());
    }
    let mut query = None;
    let mut hints = None;
    let mut limit = 10usize;
    let mut paths = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--query") => {
                query = Some(
                    args.next()
                        .ok_or("--query requires text")?
                        .to_str()
                        .ok_or("query must be UTF-8 text")?
                        .to_owned(),
                )
            }
            Some("--hints") => {
                hints = Some(PathBuf::from(args.next().ok_or("--hints requires a file")?))
            }
            Some("--limit") => {
                limit = args
                    .next()
                    .ok_or("--limit requires a number")?
                    .to_str()
                    .ok_or("limit must be a number")?
                    .parse()?;
                if limit == 0 {
                    return Err("--limit must be positive".into());
                }
            }
            Some("--") => {
                paths.extend(args.map(PathBuf::from));
                break;
            }
            Some(value) if value.starts_with('-') => {
                return Err(format!("unknown repo-map option: {value}").into());
            }
            _ => paths.push(PathBuf::from(arg)),
        }
    }
    if paths.is_empty() {
        paths.push(std::env::current_dir()?);
    }
    let first = paths[0].canonicalize()?;
    let start = if first.is_dir() {
        first.as_path()
    } else {
        first.parent().ok_or("path has no parent")?
    };
    let mut root = git(start, &["rev-parse", "--show-toplevel"])?;
    if root.last() == Some(&b'\n') {
        root.pop();
    }
    let root = PathBuf::from(OsString::from_vec(root));
    let mut scopes = Vec::new();
    for path in paths {
        let path = path.canonicalize()?;
        let scope = path
            .strip_prefix(&root)
            .map_err(|_| "all paths must belong to the same Git working tree")?;
        scopes.push(scope.to_owned());
    }
    let head = String::from_utf8(git(&root, &["rev-parse", "--verify", "HEAD"])?)?
        .trim()
        .to_owned();
    let names = git(
        &root,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    )?;
    let terms = query.as_deref().map(words).unwrap_or_default();
    let mut names: Vec<_> = names
        .split(|b| *b == 0)
        .filter(|name| !name.is_empty())
        .collect();
    names.sort_unstable();
    names.dedup();
    let mut files = Vec::new();
    for name in names {
        let path = Path::new(OsStr::from_bytes(name));
        let name = path.to_string_lossy().into_owned();
        if !scopes
            .iter()
            .any(|scope| scope.as_os_str().is_empty() || path.starts_with(scope))
        {
            continue;
        }
        let source = match text(&root.join(path)) {
            Ok(source) => source,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        let lower = name.to_lowercase();
        let body = source.as_deref().unwrap_or("").to_lowercase();
        let mut score = 0;
        let mut reasons = Vec::new();
        for term in &terms {
            if lower.contains(term) {
                score += 10;
                reasons.push(format!("path={term}"));
            }
            if body.contains(term) {
                score += 1;
                reasons.push(format!("text={term}"));
            }
        }
        files.push(File {
            path: name,
            source,
            score,
            reasons,
        });
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    println!(
        "# repo-map head={head} files={} symbols=lexical",
        files.len()
    );
    let hints = if let Some(path) = hints {
        Some(path)
    } else {
        let path = root.join("repo-map.toml");
        if path.try_exists()? {
            Some(path)
        } else {
            // Retain the staged tool's project-specific fallback. A
            // checkout's own guidance always wins; other projects do not
            // inherit SafeYolo's repository instructions.
            let bundled = std::env::current_exe()?
                .parent()
                .ok_or("repo-map executable has no parent")?
                .join("repo-map.toml");
            match (
                fs::read_to_string(&bundled),
                fs::read_to_string(root.join("pyproject.toml")),
            ) {
                (Ok(hints), Ok(project)) => {
                    let hints = crate::policy::parse_toml_document(&hints)?;
                    let project = crate::policy::parse_toml_document(&project)?;
                    (hints["project"].is_string() && hints["project"] == project["project"]["name"])
                        .then_some(bundled)
                }
                _ => None,
            }
        }
    };
    if let Some(hints) = hints {
        let guidance = crate::policy::parse_toml_document(&fs::read_to_string(&hints)?)?;
        if guidance["version"] != 1 {
            return Err("unsupported repo-map guidance version".into());
        }
        for hint in guidance["hints"]
            .as_array()
            .ok_or("repo-map hints must be an array")?
        {
            let triggers = hint["triggers"]
                .as_array()
                .ok_or("repo-map hint triggers must be strings")?;
            let selected = triggers
                .iter()
                .map(|trigger| {
                    trigger
                        .as_str()
                        .ok_or("repo-map hint trigger must be a string")
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|trigger| {
                    query
                        .as_deref()
                        .is_some_and(|query| query.to_lowercase().contains(&trigger.to_lowercase()))
                })
                .collect::<Vec<_>>();
            if selected.is_empty() {
                continue;
            }
            println!(
                "GUIDANCE [{}] {} (repository-authored; source={})",
                hint["id"].as_str().ok_or("hint id is missing")?,
                hint["advice"].as_str().ok_or("hint advice is missing")?,
                hint["source"].as_str().ok_or("hint source is missing")?
            );
            let paths = hint["paths"]
                .as_array()
                .ok_or("hint paths must be an array")?;
            for path in paths {
                let path = path.as_str().ok_or("hint path must be a string")?;
                for file in &mut files {
                    if file.path.starts_with(path) {
                        file.score += 20;
                        file.reasons.push(format!(
                            "guidance={}",
                            hint["id"].as_str().unwrap_or_default()
                        ));
                    }
                }
            }
        }
    }
    if query.is_some() {
        files.retain(|file| file.score > 0);
        files.sort_by(|a, b| b.score.cmp(&a.score).then(a.path.cmp(&b.path)));
        files.truncate(limit);
    }
    for file in files {
        let category = if file.path.contains("tests/") || file.path.contains("/test_") {
            "test"
        } else if file.path.starts_with("docs/") || file.path.ends_with(".md") {
            "documentation"
        } else {
            "implementation"
        };
        println!(
            "- {} [{}; {}]",
            file.path,
            category,
            file.reasons.join(", ")
        );
        if let Some(source) = file.source {
            let selected = symbols(&source);
            for (line, name) in &selected {
                println!("  symbol {name} @{line}");
            }
            if let Some(query) = &query {
                for (line, name) in selected {
                    if query
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .any(|term| term == name)
                    {
                        println!("  SOURCE PREVIEW (lexical match) {}:{line}", file.path);
                        for text in source.lines().skip(line - 1).take(60) {
                            println!("    {text}");
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_symbol_locations_include_changed_rust_and_retained_languages() {
        assert_eq!(
            symbols(
                "pub(crate) async fn start_agent() {}\ndef repair():\nclass Fixture:\nfunction stage() {\nstage_input() {\n"
            ),
            vec![
                (1, "start_agent".into()),
                (2, "repair".into()),
                (3, "Fixture".into()),
                (4, "stage".into()),
                (5, "stage_input".into())
            ]
        );
    }
}
