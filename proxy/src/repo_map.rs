//! Native working-tree maps and task queries. Repository guidance is advisory.
use crate::Error;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fmt::Write,
    fs,
    io::Read,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::OpenOptionsExt,
    },
    path::{Path, PathBuf},
    process::Command,
    sync::LazyLock,
    time::Instant,
};
use tree_sitter::{Node, Parser};
use unicode_normalization::UnicodeNormalization;

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

fn words(text: &str, task: bool) -> BTreeMap<String, usize> {
    static REFERENCES: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)\b(?:pull[\s_-]+requests?|prs?|issues?)[\s:/#_-]*\d+\b|#\d+\b")
            .expect("constant work reference pattern")
    });
    static TOKENS: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"[A-Za-z][A-Za-z0-9_.\-/]*|[0-9]+(?:\.[0-9]+)*")
            .expect("constant word pattern")
    });
    static STOPS: LazyLock<BTreeSet<&'static str>> = LazyLock::new(|| {
        "about actual after again against also and any already an are around as at be before being both but by can change changes current do does each ensure every existing for from has have if in into is it its keep make may more must no not of on one only or other our outcome over preserve required same should than that the their then this through to under up use using was we what when where which will with without work workflow you"
            .split_whitespace().collect()
    });
    let text = if task {
        REFERENCES.replace_all(text, " ")
    } else {
        text.into()
    };
    let mut result = BTreeMap::new();
    for token in TOKENS.find_iter(&text) {
        let token = token.as_str();
        let mut pieces = BTreeSet::from([token.trim_matches(['.', '/', '-']).to_lowercase()]);
        for piece in token.split(['.', '/', '-', '_']) {
            let mut camel = String::new();
            let mut previous = None::<char>;
            for ch in piece.chars() {
                if ch.is_uppercase()
                    && previous.is_some_and(|p| p.is_lowercase() || p.is_ascii_digit())
                {
                    camel.push(' ');
                }
                camel.push(ch);
                previous = Some(ch);
            }
            pieces.extend(camel.split_whitespace().map(str::to_lowercase));
        }
        for piece in pieces {
            if piece.len() >= 2 && (!task || !STOPS.contains(piece.as_str())) {
                *result.entry(piece).or_insert(0) += 1;
            }
        }
    }
    result
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Symbol {
    name: String,
    qualified: String,
    kind: String,
    line: usize,
    end: usize,
    preview_start: usize,
    signature: String,
    decorators: Vec<String>,
    map_depth: Option<usize>,
}
impl Symbol {
    fn range(&self, preview: bool) -> String {
        let start = if preview {
            self.preview_start
        } else {
            self.line
        };
        if start == self.end {
            format!("@{start}")
        } else {
            format!("@{start}-{}", self.end)
        }
    }
    fn exact(&self, path: &str, query: &str) -> bool {
        let module = Path::new(path)
            .with_extension("")
            .to_string_lossy()
            .replace('/', ".");
        let module = module.strip_suffix(".__init__").unwrap_or(&module);
        let qualified = format!("{module}.{}", self.qualified);
        qualified == query || qualified.ends_with(&format!(".{query}"))
    }
}
fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}
fn children(node: Node<'_>) -> Vec<Node<'_>> {
    node.named_children(&mut node.walk()).collect()
}
fn parameter(node: Node<'_>, source: &str) -> String {
    let name = node
        .child_by_field_name("name")
        .or_else(|| node.named_child(0));
    match node.kind() {
        "default_parameter" => name
            .map(|n| node_text(n, source))
            .unwrap_or("")
            .nfkc()
            .collect(),
        "typed_parameter" | "typed_default_parameter" => {
            let name: String = name
                .map(|n| node_text(n, source))
                .unwrap_or("")
                .nfkc()
                .collect();
            let annotation = node
                .child_by_field_name("type")
                .map(|n| node_text(n, source))
                .unwrap_or("");
            format!("{name}: {annotation}")
        }
        _ => node_text(node, source).nfkc().collect(),
    }
}
fn python_nodes(
    node: Node<'_>,
    source: &str,
    parents: &[String],
    map_depth: Option<usize>,
    output: &mut Vec<Symbol>,
) {
    let wrapped = node.kind() == "decorated_definition";
    let definition = if wrapped {
        node.child_by_field_name("definition").unwrap_or(node)
    } else {
        node
    };
    if matches!(
        definition.kind(),
        "function_definition" | "class_definition"
    ) {
        let Some(name_node) = definition.child_by_field_name("name") else {
            return;
        };
        let name: String = node_text(name_node, source).nfkc().collect();
        let mut qualified = parents.to_vec();
        qualified.push(name.clone());
        let class = definition.kind() == "class_definition";
        let signature = if class {
            let bases = definition
                .child_by_field_name("superclasses")
                .map(|n| {
                    children(n)
                        .into_iter()
                        .filter(|n| n.kind() != "keyword_argument")
                        .map(|n| node_text(n, source))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if bases.is_empty() {
                format!("class {name}")
            } else {
                format!("class {name}({})", bases.join(", "))
            }
        } else {
            let mut params = definition
                .child_by_field_name("parameters")
                .map(|n| {
                    children(n)
                        .into_iter()
                        .filter(|n| n.kind() != "comment")
                        .map(|n| parameter(n, source))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if map_depth == Some(1)
                && params.first().is_some_and(|p| {
                    ["self", "cls"].contains(&p.split(':').next().unwrap_or("").trim())
                })
            {
                params.remove(0);
                if params.first().is_some_and(|p| p == "/") {
                    params.remove(0);
                }
            }
            let returns = definition
                .child_by_field_name("return_type")
                .map(|n| format!(" -> {}", node_text(n, source)))
                .unwrap_or_default();
            let asynchronous = if definition
                .children(&mut definition.walk())
                .any(|child| child.kind() == "async")
            {
                "async "
            } else {
                ""
            };
            format!("{asynchronous}def {name}({}){returns}", params.join(", "))
        };
        output.push(Symbol {
            name,
            qualified: qualified.join("."),
            kind: if class { "class" } else { "function" }.into(),
            line: definition.start_position().row + 1,
            end: definition.end_position().row + 1,
            preview_start: node.start_position().row + 1,
            signature,
            decorators: if wrapped {
                children(node)
                    .into_iter()
                    .filter(|n| n.kind() == "decorator")
                    .map(|n| node_text(n, source).into())
                    .collect()
            } else {
                vec![]
            },
            map_depth,
        });
        if let Some(body) = definition.child_by_field_name("body") {
            for child in children(body) {
                let depth = if class && map_depth == Some(0) {
                    Some(1)
                } else {
                    None
                };
                python_nodes(child, source, &qualified, depth, output);
            }
        }
        return;
    }
    if node.kind() == "expression_statement" && map_depth == Some(1) {
        for child in children(node) {
            if child.kind() == "assignment"
                && let Some(annotation) = child.child_by_field_name("type")
                && let Some(name) = child.child_by_field_name("left")
                && name.kind() == "identifier"
            {
                let name: String = node_text(name, source).nfkc().collect();
                output.push(Symbol {
                    qualified: format!("{}.{name}", parents.join(".")),
                    signature: format!("{name}: {}", node_text(annotation, source)),
                    name,
                    kind: "attribute".into(),
                    line: child.start_position().row + 1,
                    end: child.start_position().row + 1,
                    preview_start: child.start_position().row + 1,
                    decorators: vec![],
                    map_depth,
                });
            }
        }
    }
    // Nested definitions remain queryable, but only module definitions and
    // direct class members belong in the structural map.
    for child in children(node) {
        python_nodes(child, source, parents, None, output);
    }
}
fn symbols(path: &Path, source: &str) -> Result<(Vec<Symbol>, Vec<String>), Error> {
    if path.extension() == Some(OsStr::new("py")) {
        let mut parser = Parser::new();
        parser.set_language(&tree_sitter_python::LANGUAGE.into())?;
        let tree = parser
            .parse(source, None)
            .ok_or("Python symbol parsing interrupted")?;
        if tree.root_node().has_error() {
            return Ok((vec![], vec![]));
        }
        let mut output = Vec::new();
        let mut imports = Vec::new();
        for child in children(tree.root_node()) {
            if matches!(child.kind(), "import_statement" | "import_from_statement") {
                let text = node_text(child, source);
                if text.starts_with("from .")
                    || text.starts_with("from safeyolo ")
                    || text.starts_with("from safeyolo.")
                {
                    imports.push(text.into());
                } else if child.kind() == "import_statement" {
                    let names: Vec<_> = children(child)
                        .into_iter()
                        .map(|n| node_text(n, source))
                        .filter(|n| {
                            *n == "safeyolo"
                                || n.starts_with("safeyolo.")
                                || n.starts_with("safeyolo as ")
                        })
                        .collect();
                    if !names.is_empty() {
                        imports.push(format!("import {}", names.join(", ")));
                    }
                }
            }
            python_nodes(child, source, &[], Some(0), &mut output);
        }
        return Ok((output, imports));
    }
    static PATTERN: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^\s*(?:(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+|(?:public\s+|private\s+|static\s+)*func\s+|function\s+)([A-Za-z_][A-Za-z0-9_]*)|^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\{").expect("constant symbol pattern")
    });
    static ASSIGNMENT: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=")
            .expect("constant shell assignment pattern")
    });
    let mut output = Vec::new();
    for (index, line) in source.lines().enumerate() {
        let shell = path.extension() == Some(OsStr::new("sh"))
            || path.file_name() == Some(OsStr::new("Makefile"));
        let found = PATTERN
            .captures(line)
            .and_then(|c| c.get(1).or_else(|| c.get(2)))
            .map(|n| (n.as_str(), "function"))
            .or_else(|| {
                if shell {
                    ASSIGNMENT
                        .captures(line)
                        .and_then(|c| c.get(1))
                        .map(|n| (n.as_str(), "variable"))
                } else {
                    None
                }
            });
        if let Some((name, kind)) = found {
            output.push(Symbol {
                name: name.into(),
                qualified: name.into(),
                kind: kind.into(),
                line: index + 1,
                end: index + 1,
                preview_start: index + 1,
                signature: format!("{kind} {name}()"),
                decorators: vec![],
                map_depth: (kind == "function").then_some(0),
            });
        }
    }
    Ok((output, vec![]))
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Indexed {
    // Discard derived entries produced before Python-name/async semantics
    // were corrected, even when the source content itself is unchanged.
    #[serde(default)]
    version: u8,
    digest: String,
    terms: BTreeMap<String, usize>,
    symbols: Vec<Symbol>,
    imports: Vec<String>,
}
struct File {
    relative: PathBuf,
    path: String,
    path_terms: BTreeMap<String, usize>,
    source: Option<String>,
    indexed: Indexed,
    score: f64,
    reasons: Vec<String>,
    exact: Vec<usize>,
}
fn category(path: &str) -> &'static str {
    if path.split('/').any(|part| part == "tests")
        || Path::new(path)
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("test_"))
    {
        "test"
    } else if path.ends_with(".md") {
        "documentation"
    } else {
        "implementation"
    }
}
fn head(root: &Path) -> String {
    git(root, &["rev-parse", "--verify", "HEAD"])
        .ok()
        .and_then(|v| String::from_utf8(v).ok())
        .map(|s| s.trim().into())
        .unwrap_or_else(|| "unborn".into())
}
fn files(
    root: &Path,
    query: bool,
    scopes: &[(PathBuf, bool)],
) -> Result<(Vec<File>, usize, usize), Error> {
    let names = git(
        root,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    )?;
    let mut names: Vec<_> = names.split(|b| *b == 0).filter(|b| !b.is_empty()).collect();
    names.sort_unstable();
    names.dedup();
    let cache_path = std::env::var_os("HOME").map(PathBuf::from).map(|home| {
        home.join(".cache/safeyolo/repo-map").join(format!(
            "native-{}.json",
            &crate::coord_setup::sha256(root.as_os_str().as_bytes())[..16]
        ))
    });
    let cached: BTreeMap<String, Indexed> = if query {
        cache_path
            .as_ref()
            .and_then(|p| fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    } else {
        BTreeMap::new()
    };
    let mut updated = BTreeMap::new();
    let mut output = Vec::new();
    let mut indexed_count = 0;
    let mut cached_count = 0;
    for name in names {
        let path = Path::new(OsStr::from_bytes(name));
        if !query
            && !scopes
                .iter()
                .any(|(scope, _)| scope.as_os_str().is_empty() || path.starts_with(scope))
        {
            continue;
        }
        // Resolve links before opening: internal aliases remain useful; outside,
        // broken and looping aliases never disclose off-tree source.
        let resolved = match root.join(path).canonicalize() {
            Ok(p) if p.starts_with(root) => p,
            _ => continue,
        };
        let file = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&resolved)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        let info = file.metadata()?;
        if !info.is_file() {
            continue;
        }
        let mut bytes = Vec::new();
        if !query {
            file.take(u64::MAX).read_to_end(&mut bytes)?;
        } else if info.len() <= 1_000_000 {
            file.take(1_000_001).read_to_end(&mut bytes)?;
        }
        let source = if (query && (info.len() > 1_000_000 || bytes.len() > 1_000_000))
            || bytes.contains(&0)
        {
            None
        } else {
            String::from_utf8(bytes.clone()).ok()
        };
        let key = crate::coord_setup::sha256(name);
        let digest = crate::coord_setup::sha256(&bytes);
        let line_count = source.as_deref().unwrap_or("").lines().count();
        let indexed = if let Some(entry) = cached.get(&key).filter(|entry| {
            entry.version == 1
                && entry.digest == digest
                && entry.symbols.iter().all(|symbol| {
                    symbol.preview_start > 0
                        && symbol.preview_start <= symbol.line
                        && symbol.line <= symbol.end
                        && symbol.end <= line_count
                })
        }) {
            cached_count += 1;
            entry.clone()
        } else {
            indexed_count += 1;
            let (symbols, imports) = symbols(path, source.as_deref().unwrap_or(""))?;
            Indexed {
                version: 1,
                digest,
                terms: words(source.as_deref().unwrap_or(""), false),
                symbols,
                imports,
            }
        };
        updated.insert(key, indexed.clone());
        let path_text = path.to_string_lossy().into_owned();
        let path_terms = if query {
            words(&path_text, false)
        } else {
            BTreeMap::new()
        };
        output.push(File {
            relative: path.to_owned(),
            path: path_text,
            path_terms,
            source,
            indexed,
            score: 0.0,
            reasons: vec![],
            exact: vec![],
        });
    }
    if query
        && (indexed_count > 0 || cached.keys().ne(updated.keys()))
        && let Some(path) = cache_path
    {
        // Cache availability is not repository-map availability. Atomic updates
        // keep concurrent queries from observing a partially written cache.
        if let Some(parent) = path.parent()
            && fs::create_dir_all(parent).is_ok()
        {
            let _ = crate::guest_commands::write_json(&path, &serde_json::to_value(updated)?);
        }
    }
    Ok((output, indexed_count, cached_count))
}
fn map(scope: &Path, overview: bool, files: &[File], elapsed: u128) {
    let scope_text = if scope.as_os_str().is_empty() {
        ".".into()
    } else {
        scope.to_string_lossy()
    };
    let selected: Vec<_> = files
        .iter()
        .filter(|f| scope.as_os_str().is_empty() || f.relative.starts_with(scope))
        .filter(|f| {
            !scope.as_os_str().is_empty()
                || (category(&f.path) != "test"
                    && !f.path.starts_with("cli/src/safeyolo/agent_context/"))
        })
        .collect();
    let mut output = Vec::new();
    let mut count = 0;
    for file in &selected {
        let symbols: Vec<_> = file
            .indexed
            .symbols
            .iter()
            .filter(|s| {
                if overview {
                    s.map_depth == Some(0) && !s.name.starts_with('_')
                } else {
                    s.map_depth.is_some()
                }
            })
            .collect();
        count += symbols.len();
        if overview {
            let mut shown: Vec<_> = symbols
                .iter()
                .take(4)
                .map(|s| {
                    let label = if file.path.ends_with(".py") {
                        if s.kind == "class" {
                            format!("class {}", s.name)
                        } else {
                            format!(
                                "{}def {}",
                                if s.signature.starts_with("async ") {
                                    "async "
                                } else {
                                    ""
                                },
                                s.name
                            )
                        }
                    } else {
                        s.signature.clone()
                    };
                    format!("{label} {}", s.range(false))
                })
                .collect();
            if symbols.len() > shown.len() {
                shown.push(format!("+{} symbols", symbols.len() - shown.len()));
            }
            if category(&file.path) == "test" || shown.is_empty() {
                output.push(file.path.clone());
            } else {
                output.push(format!("{} | {}", file.path, shown.join("; ")));
            }
        } else {
            output.push(file.path.clone());
            for import in file.indexed.imports.iter().take(8) {
                output.push(format!("  uses {import}"));
            }
            if file.indexed.imports.len() > 8 {
                output.push(format!(
                    "  uses +{} internal imports",
                    file.indexed.imports.len() - 8
                ));
            }
            for symbol in symbols {
                let indent = " ".repeat(2 + symbol.map_depth.unwrap_or_default() * 2);
                for decorator in &symbol.decorators {
                    output.push(format!("{indent}{decorator}"));
                }
                output.push(format!(
                    "{indent}{} {}",
                    symbol.signature,
                    symbol.range(false)
                ));
            }
        }
    }
    println!(
        "# repo-map scope={scope_text} mode={} files={} symbols={count} elapsed_ms={elapsed}",
        if overview { "overview" } else { "detail" },
        selected.len()
    );
    if overview {
        println!("# pass repository-relative paths for private symbols and class methods");
    }
    for line in output {
        println!("{line}");
    }
}

struct Hint {
    id: String,
    triggers: Vec<String>,
    advice: String,
    paths: Vec<String>,
    source: String,
    strength: usize,
}
fn hints_path(root: &Path, requested: Option<PathBuf>) -> Result<Option<PathBuf>, Error> {
    if let Some(path) = requested {
        return Ok(path.try_exists()?.then_some(path));
    }
    let local = root.join("repo-map.toml");
    if local.try_exists()? {
        return Ok(Some(local));
    }
    let bundled = std::env::current_exe()?
        .parent()
        .ok_or("repo-map executable has no parent")?
        .join("repo-map.toml");
    match (
        fs::read_to_string(&bundled),
        fs::read_to_string(root.join("pyproject.toml")),
    ) {
        (Ok(hints), Ok(project)) => {
            let (Ok(hints), Ok(project)) = (
                crate::policy::parse_toml_document(&hints),
                crate::policy::parse_toml_document(&project),
            ) else {
                return Ok(None);
            };
            Ok(
                (hints["project"].is_string() && hints["project"] == project["project"]["name"])
                    .then_some(bundled),
            )
        }
        _ => Ok(None),
    }
}
fn hints(path: Option<&Path>, terms: &BTreeMap<String, usize>) -> Result<Vec<Hint>, Error> {
    let Some(path) = path else {
        return Ok(vec![]);
    };
    let document = crate::policy::parse_toml_document(&fs::read_to_string(path)?)?;
    if document["version"] != 1 {
        return Err("unsupported repo-map guidance version".into());
    }
    let mut output = Vec::new();
    let values = match document.get("hints") {
        None => &[][..],
        Some(value) => value
            .as_array()
            .ok_or("repo-map hints must be an array")?
            .as_slice(),
    };
    for hint in values {
        let text = |key| {
            hint[key]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("repo-map hint {key} must be text"))
        };
        let triggers = hint["triggers"]
            .as_array()
            .ok_or("repo-map hint triggers must be strings")?;
        let selected: Vec<_> = triggers
            .iter()
            .map(|t| t.as_str().ok_or("repo-map hint trigger must be text"))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|trigger| {
                let needed = words(trigger, false);
                !needed.is_empty() && needed.keys().all(|key| terms.contains_key(key))
            })
            .map(str::to_owned)
            .collect();
        if selected.is_empty() {
            continue;
        }
        let paths = hint
            .get("paths")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .map(|p| {
                p.as_str()
                    .map(str::to_owned)
                    .ok_or("repo-map hint path must be text")
            })
            .collect::<Result<Vec<_>, _>>()?;
        let strength = selected.iter().map(|s| words(s, false).len()).sum();
        output.push(Hint {
            id: text("id")?,
            triggers: selected,
            advice: text("advice")?,
            paths,
            source: text("source")?,
            strength,
        });
    }
    output.sort_by(|a, b| b.strength.cmp(&a.strength).then(a.id.cmp(&b.id)));
    output.truncate(3);
    Ok(output)
}
fn excerpt(
    output: &mut String,
    file: &File,
    start: usize,
    end: usize,
    limit: usize,
) -> Result<(), Error> {
    let source: Vec<_> = file
        .source
        .as_deref()
        .unwrap_or("")
        .lines()
        .enumerate()
        .skip(start.saturating_sub(1))
        .take(end - start + 1)
        .collect();
    let tail = 10.min(limit / 3);
    for (i, (index, text)) in source.iter().enumerate() {
        if source.len() > limit && i >= limit - tail && i < source.len() - tail {
            if i == limit - tail {
                writeln!(
                    output,
                    "... {} lines omitted; full range {start}-{end} ...",
                    source.len() - limit
                )?;
            }
            continue;
        }
        writeln!(output, "{}: {text}", index + 1)?;
    }
    Ok(())
}
fn query(
    root: &Path,
    query: &str,
    path: Option<PathBuf>,
    limit: usize,
    mut files: Vec<File>,
    counts: (usize, usize),
    started: Instant,
) -> Result<(), Error> {
    let (indexed, cached) = counts;
    let terms = words(query, true);
    let path = hints_path(root, path)?;
    let hints = hints(path.as_deref(), &terms)?;
    let total = files.len().max(1) as f64;
    let average = files
        .iter()
        .map(|f| f.indexed.terms.values().sum::<usize>())
        .sum::<usize>() as f64
        / total;
    let mut weights: Vec<_> = terms
        .iter()
        .filter_map(|(term, count)| {
            let frequency = files
                .iter()
                .filter(|f| f.indexed.terms.contains_key(term) || f.path_terms.contains_key(term))
                .count() as f64;
            (frequency > 0.0).then(|| {
                (
                    (1.0 + (total - frequency + 0.5) / (frequency + 0.5)).ln()
                        * (1.0 + (*count).min(5) as f64).ln_1p(),
                    term,
                )
            })
        })
        .collect();
    weights.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(b.1)));
    weights.truncate(32);
    let exact_query = query.trim().strip_suffix("()").unwrap_or(query.trim());
    for file in &mut files {
        let length = file.indexed.terms.values().sum::<usize>() as f64;
        for (weight, term) in &weights {
            if let Some(count) = file.indexed.terms.get(*term) {
                let count = *count as f64;
                file.score += weight * count * 2.2
                    / (count + 1.2 * (0.25 + 0.75 * length / average.max(1.0)));
                file.reasons.push(format!("text={term}"));
            }
            if file.path_terms.contains_key(*term) {
                file.score += 2.5 * weight;
                file.reasons.push(format!("path={term}"));
            }
        }
        for hint in &hints {
            for (index, path) in hint.paths.iter().enumerate() {
                if file.path == *path || (path.ends_with('/') && file.path.starts_with(path)) {
                    file.score += if path.ends_with('/') {
                        4.0 + hint.strength.min(4) as f64
                    } else {
                        42.0 + ((hint.paths.len() - index) * 5 + (hint.strength * 2).min(18)) as f64
                    };
                    file.reasons.push(format!("guidance={}", hint.id));
                    break;
                }
            }
        }
        file.exact = file
            .indexed
            .symbols
            .iter()
            .enumerate()
            .filter(|(_, s)| s.kind != "attribute" && s.exact(&file.path, exact_query))
            .map(|(i, _)| i)
            .collect();
    }
    let mut ranked: Vec<_> = files
        .iter()
        .filter(|f| f.score > 0.0 || !f.exact.is_empty())
        .collect();
    ranked.sort_by(|a, b| {
        a.exact
            .is_empty()
            .cmp(&b.exact.is_empty())
            .then(b.score.total_cmp(&a.score))
            .then(a.path.cmp(&b.path))
    });
    let mut selected: Vec<_> = ranked
        .iter()
        .copied()
        .filter(|f| !f.exact.is_empty())
        .take(limit)
        .collect();
    if selected.is_empty() {
        let support_limit = if ranked.iter().any(|f| category(&f.path) != "implementation") {
            (limit / 3).clamp(1, 3)
        } else {
            0
        };
        let mut parents = BTreeMap::new();
        for file in ranked
            .iter()
            .copied()
            .filter(|f| category(&f.path) == "implementation")
        {
            if selected.len() >= limit - support_limit {
                break;
            }
            let count = parents.entry(Path::new(&file.path).parent()).or_insert(0);
            if *count < 3 {
                selected.push(file);
                *count += 1;
            }
        }
        let mut support = Vec::new();
        for kind in ["test", "documentation"] {
            if support.len() < support_limit
                && let Some(file) = ranked.iter().copied().find(|f| category(&f.path) == kind)
            {
                support.push(file);
            }
        }
        selected.extend(support);
        for file in &ranked {
            if selected.len() == limit {
                break;
            }
            if !selected.iter().any(|s| std::ptr::eq(*s, *file)) {
                selected.push(*file);
            }
        }
    }
    // Prepare the same report before timing it, including selected-symbol
    // ranking and definition/usage rendering rather than indexing alone.
    let mut output = String::new();
    if let Some(path) = path {
        writeln!(output, "# guidance_file={}", path.display())?;
    }
    if !hints.is_empty() {
        writeln!(output, "GUIDANCE (repository-authored, not syntax-derived)")?;
        for hint in &hints {
            writeln!(
                output,
                "- [{}] {}\n  matched: {}; source: {}",
                hint.id,
                hint.advice,
                hint.triggers.join(", "),
                hint.source
            )?;
            if !hint.paths.is_empty() {
                writeln!(
                    output,
                    "  related: {}",
                    hint.paths
                        .iter()
                        .take(4)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )?;
            }
        }
    }
    for (kind, heading) in [
        ("implementation", "LIKELY IMPLEMENTATION"),
        ("test", "RELATED TESTS"),
        ("documentation", "RELATED DOCUMENTATION"),
    ] {
        let group: Vec<_> = selected
            .iter()
            .copied()
            .filter(|f| category(&f.path) == kind)
            .collect();
        if group.is_empty() {
            continue;
        }
        writeln!(
            output,
            "\n{heading} (lexical + repository guidance; returned-file symbols)"
        )?;
        for file in group {
            writeln!(output, "- {} [{}]", file.path, file.reasons.join("; "))?;
            let mut relevant: Vec<_> = file
                .indexed
                .symbols
                .iter()
                .filter(|s| s.kind != "attribute")
                .collect();
            if !file.exact.is_empty() {
                relevant = file
                    .exact
                    .iter()
                    .map(|i| &file.indexed.symbols[*i])
                    .collect();
            } else {
                relevant.sort_by_cached_key(|s| {
                    std::cmp::Reverse(
                        words(&s.name, false)
                            .keys()
                            .filter(|key| terms.contains_key(*key))
                            .count(),
                    )
                });
            }
            for symbol in relevant.into_iter().take(5) {
                writeln!(
                    output,
                    "  {} {} {}",
                    symbol.kind,
                    symbol.name,
                    symbol.range(true)
                )?;
            }
        }
    }
    let mut preview = false;
    for file in selected {
        for index in &file.exact {
            let symbol = &file.indexed.symbols[*index];
            writeln!(
                output,
                "\nDEFINITION {}:{}-{}",
                file.path, symbol.preview_start, symbol.end
            )?;
            excerpt(&mut output, file, symbol.preview_start, symbol.end, 60)?;
            preview = true;
        }
    }
    if preview {
        let usage =
            regex::Regex::new(&format!(r"(?:^|[^\w.]){}\s*\(", regex::escape(exact_query)))?;
        static DECLARATION: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"\b(?:def|class)\s").expect("constant declaration pattern")
        });
        let mut examples: Vec<_> = files.iter().collect();
        examples.sort_by_key(|f| (category(&f.path) != "test", &f.path));
        'example: for file in examples {
            for (index, line) in file.source.as_deref().unwrap_or("").lines().enumerate() {
                if usage.is_match(line) && !DECLARATION.is_match(line) {
                    writeln!(
                        output,
                        "\nEXAMPLE USE (text match; binding not verified) {}:{}",
                        file.path,
                        index + 1
                    )?;
                    excerpt(&mut output, file, index.max(1), index + 7, 8)?;
                    break 'example;
                }
            }
        }
    }
    let revision = head(root);
    let elapsed = started.elapsed().as_millis();
    println!(
        "# repo-map mode=query head={revision} files={} indexed={indexed} cached={cached} elapsed_ms={elapsed} symbols=lexical",
        files.len()
    );
    print!("{output}");
    Ok(())
}

pub fn run(args: &[OsString]) -> Result<(), Error> {
    let started = Instant::now();
    if args == [OsString::from("--help")] {
        println!(
            "repo-map [PATH ...] [--query TEXT] [--hints FILE] [--limit N]\nMap Git working-tree files and symbols, or rank implementation, tests and documentation for a task. Exact symbols show bounded definitions and a lexical use. Repository-authored guidance is separate. No Python or model is used."
        );
        return Ok(());
    }
    let mut task = None;
    let mut hints = None;
    let mut limit = 10usize;
    let mut paths = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--query") => {
                task = Some(
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
    if task.is_some() && paths.len() > 1 {
        return Err("--query accepts at most one repository path".into());
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
    let mut root = git(start, &["rev-parse", "--show-toplevel"])
        .map_err(|_| "not inside a Git working tree")?;
    if root.last() == Some(&b'\n') {
        root.pop();
    }
    let root = PathBuf::from(OsString::from_vec(root)).canonicalize()?;
    let mut scopes = Vec::new();
    for path in paths {
        let path = path.canonicalize()?;
        let scope = path
            .strip_prefix(&root)
            .map_err(|_| "all paths must belong to the same Git working tree")?;
        if !scopes.iter().any(|(existing, _)| existing == scope) {
            scopes.push((scope.to_owned(), path.is_dir()));
        }
    }
    let (files, indexed, cached) = files(&root, task.is_some(), &scopes)?;
    if let Some(task) = task {
        return query(
            &root,
            &task,
            hints,
            limit,
            files,
            (indexed, cached),
            started,
        );
    }
    for (scope, overview) in &scopes {
        if scopes
            .iter()
            .any(|(other, _)| other != scope && other.starts_with(scope))
        {
            continue;
        }
        map(scope, *overview, &files, started.elapsed().as_millis());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_symbols_follow_syntax_and_ignore_embedded_definitions() {
        let source = "class Service:\n    @staticmethod\n    def create(\n        target: str = 'default',\n        /,\n        *,\n        force: bool = False,\n    ) -> str:\n        return target\n\ndef outer():\n    text = '''\ndef phantom():\n    pass\n'''\n    def nested():\n        return 42\n    return nested()\n";
        let (symbols, _) = symbols(Path::new("fixture.py"), source).unwrap();
        assert_eq!(
            symbols
                .iter()
                .map(|s| s.qualified.as_str())
                .collect::<Vec<_>>(),
            ["Service", "Service.create", "outer", "outer.nested"]
        );
        assert_eq!(
            symbols[1].signature,
            "def create(target: str, /, *, force: bool) -> str"
        );
        assert_eq!(symbols[1].preview_start, 2);
        assert_eq!(symbols[1].end, 9);
        assert!(symbols[3].map_depth.is_none());
    }

    #[test]
    fn native_symbol_locations_include_rust_and_shell() {
        let (rust, _) = symbols(
            Path::new("fixture.rs"),
            "pub(crate) async fn start_agent() {}\n",
        )
        .unwrap();
        assert_eq!(rust[0].name, "start_agent");
        let (shell, _) = symbols(
            Path::new("fixture.sh"),
            "function stage() {\n}\nstage_input() {\n}\nINPUT=value\n",
        )
        .unwrap();
        assert_eq!(
            shell
                .iter()
                .map(|s| (s.line, s.name.as_str()))
                .collect::<Vec<_>>(),
            [(1, "stage"), (3, "stage_input"), (5, "INPUT")]
        );
    }

    #[test]
    fn invalid_python_reports_no_syntax_derived_symbols() {
        let (symbols, _) =
            symbols(Path::new("fixture.py"), "def broken(:\n    return 42\n").unwrap();
        assert!(symbols.is_empty());
    }
}
