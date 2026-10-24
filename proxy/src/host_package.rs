//! Stream a verified host package through the gzip decoder already in the CLI.

use std::{
    fs::File,
    io::{BufReader, Write},
    path::Path,
};

use crate::Error;

pub const HELP: &str = "safeyolo host-package gunzip ARCHIVE\nInstaller helper: decode an already verified host tar.gz to standard output. The caller runs tar and the complete package verifier before installation.";

pub fn gunzip(archive: &Path) -> Result<(), Error> {
    // Read every gzip member and its trailer, including checksum/length checks.
    // A large output buffer lets zlib-rs decode beyond small copy chunks.
    let decoder = flate2::read::MultiGzDecoder::new(File::open(archive)?);
    let mut decoder = BufReader::with_capacity(128 * 1024, decoder);
    let mut output = std::io::stdout().lock();
    std::io::copy(&mut decoder, &mut output)?;
    output.flush()?;
    Ok(())
}
