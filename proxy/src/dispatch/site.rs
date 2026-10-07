//! Read-only validation of retained site sources and publication paths.
use super::*;
use percent_encoding::percent_decode_str;

struct Page {
    path: PathBuf,
    front: Value,
    content: String,
}

pub(super) fn paths(root: &Path, result: &mut Vec<PathBuf>) -> Result<(), Error> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return Err("symlinks are not allowed in the publication tree".into());
        }
        if kind.is_dir() {
            paths(&entry.path(), result)?;
        } else if kind.is_file() {
            result.push(entry.path());
        } else {
            return Err("publication files must be regular files".into());
        }
    }
    result.sort();
    Ok(())
}

fn front_matter(content: &str) -> Result<Value, Error> {
    let mut lines = content.lines();
    if lines.next() != Some("---") {
        return Err("Markdown page has no YAML front matter".into());
    }
    let mut front = String::new();
    let mut closed = false;
    for line in lines {
        if line == "---" {
            closed = true;
            break;
        }
        front.push_str(line);
        front.push('\n');
    }
    if !closed {
        return Err("YAML front matter is not closed".into());
    }
    let front = crate::policy::parse_yaml(&front)?;
    if !front.is_object() {
        return Err("YAML front matter must be a mapping".into());
    }
    Ok(front)
}

fn content_path(path: &str) -> Result<bool, Error> {
    Ok(
        Regex::new(r"^(?:_sources/dispatch/[^/]+\.json|(?:dispatch|snapshots|topics)/[^/]+\.md)$")?
            .is_match(path),
    )
}

pub fn validate_scope(paths: &[String]) -> Result<(), Error> {
    for path in paths {
        if !content_path(path.strip_prefix("site/").unwrap_or_default())? {
            return Err(format!(
                "publication branch changed paths outside the fixed site content allowlist: {path}"
            )
            .into());
        }
    }
    Ok(())
}

pub fn validate_site(root: &Path) -> Result<(), Error> {
    if !fs::symlink_metadata(root)?.is_dir() {
        return Err("site root must be a regular directory".into());
    }
    let mut all_paths = Vec::new();
    paths(root, &mut all_paths)?;
    let mut expected: BTreeMap<PathBuf, ((Date, Date, PathBuf), String)> = BTreeMap::new();
    let mut periods = BTreeSet::new();
    let mut actual = BTreeSet::new();
    let mut pages = Vec::new();
    for path in &all_paths {
        let relative = path.strip_prefix(root)?;
        let name = relative.to_str().ok_or("publication paths must be UTF-8")?;
        if !["CNAME", "_config.yml", "index.md"].contains(&name) && !content_path(name)? {
            return Err(format!(
                "{}: file is outside the fixed site allowlist",
                path.display()
            )
            .into());
        }
        let content = read_regular(path, usize::MAX - 1)?;
        validate_publication_text(&content)?;
        if name.starts_with("_sources/dispatch/") {
            let manifest = load_manifest(path)?;
            let period = &manifest.period;
            if !periods.insert((period.kind.clone(), period.start, period.end)) {
                return Err("duplicate Dispatch period".into());
            }
            let rank = (period.end, period.start, relative.to_owned());
            for file in generate_files(&manifest)? {
                let is_topic = file.relative_path.starts_with("topics");
                if let Some((old_rank, _)) = expected.get(&file.relative_path) {
                    if !is_topic {
                        return Err("duplicate generated path".into());
                    }
                    if (old_rank.0, old_rank.1) == (rank.0, rank.1) {
                        return Err("ambiguous same-period topic".into());
                    }
                    if *old_rank > rank {
                        continue;
                    }
                }
                expected.insert(file.relative_path, (rank.clone(), file.content));
            }
        } else if path.extension().is_some_and(|s| s == "md") {
            if name != "index.md" {
                actual.insert(relative.to_owned());
            }
            pages.push(Page {
                path: relative.to_owned(),
                front: front_matter(&content)?,
                content,
            });
        }
    }
    if actual != expected.keys().cloned().collect() {
        return Err("generated path mismatch; missing or stale generated paths".into());
    }
    for page in &pages {
        if let Some((_, expected)) = expected.get(&page.path)
            && expected != &page.content
        {
            return Err(format!("{}: generated content is stale", page.path.display()).into());
        }
    }
    validate_links(root, &pages)
}

fn validate_links(root: &Path, pages: &[Page]) -> Result<(), Error> {
    let mut permalinks = BTreeSet::new();
    for page in pages {
        if let Some(permalink) = page.front["permalink"].as_str() {
            if !permalink.starts_with('/')
                || !permalink.ends_with('/')
                || Path::new(permalink)
                    .components()
                    .any(|part| part == Component::ParentDir)
            {
                return Err("permalink must be an absolute directory path inside the site".into());
            }
            if !permalinks.insert(permalink) {
                return Err("duplicate permalink".into());
            }
        }
    }
    let links = Regex::new(r"\[(?:\\.|[^\]\\\n])+\]\(([^)\n]+)\)")?;
    let url_scheme = Regex::new(r"^[A-Za-z][A-Za-z0-9+.-]*:")?;
    for page in pages {
        let mut fence = None;
        for line in page.content.lines() {
            let trimmed = line.trim_start();
            let ticks = trimmed.bytes().take_while(|c| *c == b'`').count();
            if let Some(opening) = fence {
                if ticks >= opening && trimmed[ticks..].trim().is_empty() {
                    fence = None;
                }
                continue;
            }
            if ticks >= 3 {
                fence = Some(ticks);
                continue;
            }
            for capture in links.captures_iter(line) {
                let Some(full) = capture.get(0) else {
                    continue;
                };
                let backslashes = line[..full.start()]
                    .bytes()
                    .rev()
                    .take_while(|c| *c == b'\\')
                    .count();
                if backslashes % 2 == 1 || line[..full.start()].ends_with('!') {
                    continue;
                }
                let destination = capture[1].trim();
                let destination = destination
                    .strip_prefix('<')
                    .and_then(|d| d.strip_suffix('>'))
                    .unwrap_or(destination);
                if url_scheme.is_match(destination) {
                    validate_public_url(destination)?;
                    continue;
                }
                if destination.starts_with("//") {
                    return Err("protocol-relative links are not allowed".into());
                }
                if destination.starts_with('#') {
                    continue;
                }
                let raw_path = destination.split(['?', '#']).next().unwrap_or_default();
                let decoded = percent_decode_str(raw_path).decode_utf8()?;
                if decoded.is_empty() {
                    continue;
                }
                let public = if decoded.starts_with('/') {
                    decoded.into_owned()
                } else {
                    format!(
                        "{}{decoded}",
                        page.front["permalink"].as_str().unwrap_or("/")
                    )
                };
                if public.ends_with('/') && permalinks.contains(public.as_str()) {
                    continue;
                }
                let relative = Path::new(public.trim_start_matches('/'));
                if relative
                    .components()
                    .any(|p| !matches!(p, Component::Normal(_) | Component::CurDir))
                {
                    return Err("link escapes the site".into());
                }
                if !root.join(relative).is_file() {
                    return Err(format!("broken local link {destination}").into());
                }
            }
        }
    }
    Ok(())
}

pub(super) fn run(arguments: &[String]) -> Result<(), Error> {
    let mut root = PathBuf::from("site");
    let mut base = None;
    let mut args = arguments.iter();
    let mut seen = BTreeSet::new();
    while let Some(option) = args.next() {
        if !seen.insert(option) {
            return Err(format!("duplicate {option} option").into());
        }
        match option.as_str() {
            "--site-root" => {
                root = PathBuf::from(args.next().ok_or("--site-root requires a path")?)
            }
            "--publication-base" => {
                base = Some(
                    args.next()
                        .ok_or("--publication-base requires a revision")?,
                )
            }
            _ => return Err(format!("unknown site check option: {option}").into()),
        }
    }
    validate_site(&root)?;
    if let Some(base) = base {
        let output = std::process::Command::new("git")
            .args([
                "diff",
                "--name-only",
                "-z",
                "--diff-filter=ACMRTUXBD",
                &format!("{base}...HEAD"),
                "--",
            ])
            .output()?;
        if !output.status.success() {
            return Err("cannot read publication changed paths from Git".into());
        }
        let paths = String::from_utf8(output.stdout)?
            .split('\0')
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        validate_scope(&paths)?;
    }
    println!("Dispatch site validation passed.");
    Ok(())
}
