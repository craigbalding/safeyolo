//! Stream a host package through the gzip decoder already in the CLI.

use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
};

use crate::Error;
use ring::digest::{Context, SHA256};

pub const HELP: &str = "safeyolo host-package gunzip INPUT [--save ARCHIVE --sha256 SHA256]\nInstaller helper: decode a host tar.gz to standard output.\n--save writes compressed bytes to a new ARCHIVE and checks their release SHA-256 through EOF.\nThe caller must wait for successful decoding and release checksum verification, then validate the complete package before installation. Without --save, the caller verifies the compressed archive checksum separately.";

pub fn gunzip(archive: &Path) -> Result<(), Error> {
    decode(File::open(archive)?)
}

// Keep the cache write and digest on the decoder's compressed read. The public
// installer otherwise sends the whole archive through tee and a second FIFO,
// then reads the saved file again for its release checksum.
struct SavedHostArchive {
    input: File,
    archive: BufWriter<File>,
    digest: Context,
}

impl Read for SavedHostArchive {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.input.read(buffer)?;
        self.archive.write_all(&buffer[..read])?;
        self.digest.update(&buffer[..read]);
        Ok(read)
    }
}

pub fn save_gunzip(input: &Path, archive: &Path, expected: &str) -> Result<(), Error> {
    let mut input = SavedHostArchive {
        input: File::open(input)?,
        archive: BufWriter::with_capacity(
            128 * 1024,
            File::options().write(true).create_new(true).open(archive)?,
        ),
        digest: Context::new(&SHA256),
    };
    decode(&mut input)?;
    // A flush failure must prevent the installer from publishing this cache.
    input.archive.flush()?;
    let actual: String = input
        .digest
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if actual != expected {
        return Err("Host archive checksum failed. No package was installed.".into());
    }
    Ok(())
}

fn decode(input: impl Read) -> Result<(), Error> {
    // Read every gzip member and its trailer, including checksum/length checks.
    // A large output buffer lets zlib-rs decode beyond small copy chunks.
    let decoder = flate2::read::MultiGzDecoder::new(input);
    let mut decoder = BufReader::with_capacity(128 * 1024, decoder);
    let mut output = std::io::stdout().lock();
    std::io::copy(&mut decoder, &mut output)?;
    output.flush()?;
    Ok(())
}
