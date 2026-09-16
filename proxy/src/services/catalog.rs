//! One strict catalog attempt and its pre-read metadata, without publication.
use std::{
    collections::BTreeMap,
    fmt, io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use serde_json::Value;

use super::{Registry, ServiceDefinition};

pub(crate) type CatalogMetadata = BTreeMap<PathBuf, (i128, u64)>;

pub(crate) struct CatalogLoad {
    pub metadata: CatalogMetadata,
    pub result: Result<Registry, ServiceLoadError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProblemOrigin {
    Directory,
    File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProblemKind {
    MissingBuiltin,
    NotDirectory,
    Io(io::ErrorKind),
    UnicodeDecode,
    Empty,
    NotMapping,
    Duplicate,
    NativeYaml,
    NativeSchema,
    NativePath,
}

/// Diagnostics are an explicit audited projection, not an ordinary Debug value.
pub(crate) struct ServiceLoadProblem {
    pub path: PathBuf,
    pub origin: ProblemOrigin,
    pub kind: ProblemKind,
    pub message: String,
}
impl ProblemKind {
    pub fn error_type(&self) -> &'static str {
        match self {
            ProblemKind::MissingBuiltin => "FileNotFoundError",
            ProblemKind::NotDirectory => "NotADirectoryError",
            ProblemKind::Io(io::ErrorKind::NotFound) => "FileNotFoundError",
            ProblemKind::Io(io::ErrorKind::PermissionDenied) => "PermissionError",
            ProblemKind::Io(io::ErrorKind::IsADirectory) => "IsADirectoryError",
            ProblemKind::Io(io::ErrorKind::NotADirectory) => "NotADirectoryError",
            ProblemKind::Io(io::ErrorKind::WouldBlock) => "BlockingIOError",
            ProblemKind::Io(_) => "NativeIoError",
            ProblemKind::UnicodeDecode => "UnicodeDecodeError",
            ProblemKind::Empty | ProblemKind::Duplicate => "ValueError",
            ProblemKind::NotMapping => "TypeError",
            ProblemKind::NativeYaml => "NativeYamlError",
            ProblemKind::NativeSchema => "NativeServiceSchemaError",
            ProblemKind::NativePath => "NativePathError",
        }
    }
}

pub(crate) struct ServiceLoadError {
    pub problems: Vec<ServiceLoadProblem>,
}
impl fmt::Debug for ServiceLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceLoadError")
    }
}
impl fmt::Display for ServiceLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let files = self
            .problems
            .iter()
            .filter(|problem| problem.origin == ProblemOrigin::File)
            .count();
        write!(
            formatter,
            "service definitions are invalid ({files} file problems, {} directory problems)",
            self.problems.len() - files
        )
    }
}
impl std::error::Error for ServiceLoadError {}

impl Registry {
    /// Submit each file problem immediately, then retain every problem in source
    /// order. The observer contains its own audit errors; it cannot veto loading.
    pub(crate) fn load_directories(
        builtin: &Path,
        user: &Path,
        on_file_problem: &mut impl FnMut(&ServiceLoadProblem),
    ) -> CatalogLoad {
        let metadata = scan_service_files(builtin, user);
        let mut problems = Vec::new();
        let mut registry = Self::default();
        if !builtin.is_dir() {
            problems.push(problem(
                builtin,
                ProblemOrigin::Directory,
                ProblemKind::MissingBuiltin,
                "packaged builtin service directory is missing".into(),
            ));
        }
        for directory in [builtin, user] {
            match std::fs::metadata(directory) {
                Ok(metadata) if metadata.is_dir() => (),
                Ok(_) => {
                    problems.push(problem(
                        directory,
                        ProblemOrigin::Directory,
                        ProblemKind::NotDirectory,
                        "service source is not a directory".into(),
                    ));
                    continue;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) =>
                {
                    continue;
                }
                Err(error) => {
                    problems.push(problem(
                        directory,
                        ProblemOrigin::Directory,
                        ProblemKind::Io(error.kind()),
                        error.to_string(),
                    ));
                    continue;
                }
            }
            let mut names = BTreeMap::<String, PathBuf>::new();
            for path in source_files(directory) {
                let loaded = read_service(&path).and_then(|service| {
                    if let Some(previous) = names.get(&service.name) {
                        return Err(problem(
                            &path,
                            ProblemOrigin::File,
                            ProblemKind::Duplicate,
                            format!(
                                "duplicate service name {} in {} and {}",
                                crate::agent_api::repr(&service.name),
                                basename(previous),
                                basename(&path)
                            ),
                        ));
                    }
                    Ok(service)
                });
                match loaded {
                    Ok(service) => {
                        names.insert(service.name.clone(), path.clone());
                        registry.source_by_service.insert(
                            service.name.clone(),
                            path.to_str().expect("read_service validates paths").into(),
                        );
                        if !registry.services.contains_key(&service.name) {
                            registry.order.push(service.name.clone());
                        }
                        registry.services.insert(service.name.clone(), service);
                    }
                    Err(problem) => {
                        on_file_problem(&problem);
                        problems.push(problem);
                    }
                }
            }
        }
        CatalogLoad {
            metadata,
            result: if problems.is_empty() {
                Ok(registry)
            } else {
                Err(ServiceLoadError { problems })
            },
        }
    }
}

/// Source metadata-only change detection; failed stat entries contribute nothing.
/// Capture this before reading any definition, including on a rejected attempt.
pub(crate) fn scan_service_files(builtin: &Path, user: &Path) -> CatalogMetadata {
    let mut state = BTreeMap::new();
    for directory in [builtin, user] {
        if !directory.is_dir() {
            continue;
        }
        for path in source_files(directory) {
            if let Ok(metadata) = std::fs::metadata(&path) {
                state.insert(
                    path,
                    (
                        i128::from(metadata.mtime()) * 1_000_000_000
                            + i128::from(metadata.mtime_nsec()),
                        metadata.size(),
                    ),
                );
            }
        }
    }
    state
}

fn source_files(directory: &Path) -> Vec<PathBuf> {
    // pathlib's top-level glob suppresses scandir OSError, including failure
    // partway through collecting directory entries. Matched read errors differ.
    let Ok(entries) =
        std::fs::read_dir(directory).and_then(|entries| entries.collect::<io::Result<Vec<_>>>())
    else {
        return Vec::new();
    };
    let mut paths: Vec<_> = entries
        .into_iter()
        .filter(|entry| entry.file_name().as_encoded_bytes().ends_with(b".yaml"))
        .map(|entry| entry.path())
        .collect();
    paths.sort();
    paths
}

fn read_service(path: &Path) -> Result<ServiceDefinition, ServiceLoadProblem> {
    let failure = |kind, message| problem(path, ProblemOrigin::File, kind, message);
    if path.to_str().is_none() {
        return Err(failure(
            ProblemKind::NativePath,
            "service source filename is not representable".into(),
        ));
    }
    let bytes = std::fs::read(path)
        .map_err(|error| failure(ProblemKind::Io(error.kind()), error.to_string()))?;
    let contents = String::from_utf8(bytes)
        .map_err(|error| failure(ProblemKind::UnicodeDecode, error.utf8_error().to_string()))?;
    let raw = crate::policy::parse_yaml(&contents)
        .map_err(|error| failure(ProblemKind::NativeYaml, error.to_string()))?;
    if raw == Value::Null {
        return Err(failure(
            ProblemKind::Empty,
            "service definition is empty".into(),
        ));
    }
    if !raw.is_object() {
        return Err(failure(
            ProblemKind::NotMapping,
            "service definition must be a YAML mapping".into(),
        ));
    }
    ServiceDefinition::from_value(raw)
        .map_err(|error| failure(ProblemKind::NativeSchema, error.to_string()))
}

fn problem(
    path: &Path,
    origin: ProblemOrigin,
    kind: ProblemKind,
    message: String,
) -> ServiceLoadProblem {
    ServiceLoadProblem {
        path: path.into(),
        origin,
        kind,
        message,
    }
}

fn basename(path: &Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .expect("read_service validates paths")
}
