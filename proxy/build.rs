use sha2::{Digest, Sha256};
use std::env;
use std::path::{Path, PathBuf};

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
    ];
    sources(Path::new("src"), &mut paths);
    sources(Path::new("vendor"), &mut paths);
    paths.sort();
    let mut hash = Sha256::new();
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=vendor");
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
    println!("cargo:rerun-if-env-changed=SAFEYOLO_BUILD_REVISION");
    let revision = env::var("SAFEYOLO_BUILD_REVISION")
        .unwrap_or_else(|_| "unknown".to_string())
        .to_ascii_lowercase();
    assert!(
        revision == "unknown"
            || ((revision.len() == 40 || revision.len() == 64)
                && revision.bytes().all(|byte| byte.is_ascii_hexdigit())),
        "SAFEYOLO_BUILD_REVISION must be a full Git object ID"
    );
    println!("cargo:rustc-env=SAFEYOLO_BUILD_REVISION={revision}");
    let profile = env::var("PROFILE").expect("Cargo supplies the build profile");
    let profile = if profile == "release" {
        "production"
    } else {
        "debug"
    };
    println!("cargo:rustc-env=SAFEYOLO_BUILD_PROFILE={profile}");
}
