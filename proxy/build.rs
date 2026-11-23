use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[path = "../scripts/rust_build_identity.rs"]
mod build_identity;

fn sources(path: &Path, paths: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(path).expect("read implementation sources") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            sources(&path, paths);
        } else if path.extension().is_some_and(|extension| extension == "rs")
            || path.file_name().is_some_and(|name| name == "Cargo.toml")
        {
            paths.push(path);
        }
    }
}

fn main() {
    // The installed definitions include validators and availability owners,
    // including source edits that have not yet received a Git commit.
    let mut paths = vec![
        PathBuf::from("Cargo.toml"),
        PathBuf::from("Cargo.lock"),
        PathBuf::from("build.rs"),
        PathBuf::from("../scripts/rust_build_identity.rs"),
        PathBuf::from("../host-executor/Cargo.toml"),
    ];
    sources(Path::new("src"), &mut paths);
    sources(Path::new("vendor"), &mut paths);
    // Host package/schema types and their validators also back installed
    // capability discovery. Their changes must stale prior definition inputs.
    sources(Path::new("../host-executor/src"), &mut paths);
    paths.sort();
    let mut hash = Sha256::new();
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=vendor");
    println!("cargo:rerun-if-changed=../host-executor/src");
    for path in paths {
        println!("cargo:rerun-if-changed={}", path.display());
        hash.update(path.to_string_lossy().as_bytes());
        hash.update([0]);
        hash.update(std::fs::read(&path).expect("read definition source"));
        hash.update([0]);
    }
    let version: String = hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    println!("cargo:rustc-env=SAFEYOLO_DEFINITION_VERSION={version}");
    build_identity::emit();
}
