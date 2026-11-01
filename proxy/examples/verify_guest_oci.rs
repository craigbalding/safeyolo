//! Verify a complete local OCI guest layout without registry access or installation.

use safeyolo_proxy::{
    Error,
    guest_oci::{self, GuestIndex},
};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

fn blob(layout: &Path, digest: &str) -> Result<PathBuf, Error> {
    Ok(layout
        .join("blobs/sha256")
        .join(guest_oci::sha256_hex(digest)?))
}

fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: verify_guest_oci OCI_LAYOUT INDEX_DIGEST HOST_COMPATIBILITY".into());
    }
    let layout = Path::new(&args[0]);
    let bytes = fs::read(blob(layout, &args[1])?)?;
    let index = GuestIndex::parse(&bytes, &args[1], &args[2])?;
    let manifests: Vec<_> = index
        .platforms()
        .map(|platform| {
            fs::read(blob(layout, &index.manifest(platform)?.digest)?).map_err(Error::from)
        })
        .collect::<Result<_, _>>()?;
    let children = index.validate_children(manifests.iter().map(Vec::as_slice))?;
    for child in children {
        child.validate_config(&fs::read(blob(layout, &child.config.digest)?)?)?;
        child
            .archive
            .verify(File::open(blob(layout, &child.archive.digest)?)?)?;
        let (os, architecture) = child.platform.os_architecture();
        println!(
            "verified {os}/{architecture} child={} archive={} size={}",
            index.manifest(child.platform)?.digest,
            child.archive.digest,
            child.archive.size
        );
    }
    println!(
        "verified index={} version={} compatibility={}",
        index.identity.digest, index.annotations.version, index.annotations.compatibility
    );
    Ok(())
}
