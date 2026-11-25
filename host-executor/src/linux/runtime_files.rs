//! Protect bubblewrap's loader inputs from workload writes. Qualification reads
//! ELF and the native loader cache; it does not execute the helper or ldd.
use super::{require, unavailable};
use crate::{Refusal, RefusalCode};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

fn bytes(data: &[u8], offset: u64, length: u64) -> Result<&[u8], Refusal> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| unavailable("ELF offset overflow"))?;
    data.get(
        usize::try_from(offset).map_err(unavailable)?..usize::try_from(end).map_err(unavailable)?,
    )
    .ok_or_else(|| unavailable("incomplete ELF runtime dependency data"))
}
fn elf_u64(data: &[u8], offset: u64) -> Result<u64, Refusal> {
    Ok(u64::from_le_bytes(
        bytes(data, offset, 8)?.try_into().unwrap(),
    ))
}
fn elf_u16(data: &[u8], offset: u64) -> Result<u16, Refusal> {
    Ok(u16::from_le_bytes(
        bytes(data, offset, 2)?.try_into().unwrap(),
    ))
}

fn elf(data: &[u8]) -> Result<(u16, Vec<PathBuf>), Refusal> {
    require(
        data.starts_with(b"\x7fELF\x02\x01"),
        RefusalCode::Unavailable,
        "writable jobs require a native 64-bit little-endian ELF bubblewrap and resolvable loader dependencies",
    )?;
    let machine = elf_u16(data, 18)?;
    let offset = elf_u64(data, 32)?;
    let stride = elf_u16(data, 54)? as u64;
    require(
        stride >= 56,
        RefusalCode::Unavailable,
        "invalid ELF program header size",
    )?;
    let mut loads = Vec::new();
    let mut dynamic = None;
    let mut required = Vec::new();
    for index in 0..elf_u16(data, 56)? as u64 {
        let header = bytes(
            data,
            offset
                .checked_add(index * stride)
                .ok_or_else(|| unavailable("ELF header offset overflow"))?,
            56,
        )?;
        let kind = u32::from_le_bytes(header[..4].try_into().unwrap());
        let file = elf_u64(header, 8)?;
        let length = elf_u64(header, 32)?;
        match kind {
            1 => loads.push((elf_u64(header, 16)?, file, length)),
            2 => dynamic = Some(bytes(data, file, length)?),
            3 => {
                let value = bytes(data, file, length)?
                    .strip_suffix(&[0])
                    .ok_or_else(|| unavailable("unterminated ELF interpreter"))?;
                required.push(Path::new(std::ffi::OsStr::from_bytes(value)).to_owned());
            }
            _ => (),
        }
    }
    let Some(dynamic) = dynamic else {
        return Ok((machine, required));
    };
    let mut strings = None;
    let mut string_bytes = None;
    let mut names = Vec::new();
    for item in dynamic.chunks_exact(16) {
        let tag = elf_u64(item, 0)?;
        let value = elf_u64(item, 8)?;
        match tag {
            0 => break,
            1 => names.push(value),
            5 => strings = Some(value),
            10 => string_bytes = Some(value),
            15 | 29 => {
                return Err(unavailable(
                    "writable jobs cannot yet qualify bubblewrap libraries with ELF RPATH/RUNPATH; use a native system-library helper or retain the read-only profile",
                ));
            }
            _ => (),
        }
    }
    if names.is_empty() {
        return Ok((machine, required));
    }
    let address = strings.ok_or_else(|| unavailable("missing ELF string table"))?;
    let (start, file, _) = loads
        .iter()
        .find(|(start, _, size)| address >= *start && address - *start < *size)
        .ok_or_else(|| unavailable("ELF string table is outside file-backed loads"))?;
    let strings = bytes(
        data,
        file.checked_add(address - start)
            .ok_or_else(|| unavailable("ELF string offset overflow"))?,
        string_bytes.ok_or_else(|| unavailable("missing ELF string bounds"))?,
    )?;
    for name in names {
        let value = strings
            .get(usize::try_from(name).map_err(unavailable)?..)
            .ok_or_else(|| unavailable("invalid ELF dependency offset"))?;
        let end = value
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| unavailable("unterminated ELF dependency"))?;
        require(
            end > 0,
            RefusalCode::Unavailable,
            "empty ELF dependency name",
        )?;
        required.push(Path::new(std::ffi::OsStr::from_bytes(&value[..end])).to_owned());
    }
    Ok((machine, required))
}

fn native_library(data: &[u8], machine: u16) -> Result<bool, Refusal> {
    let header = bytes(data, 0, 20)?;
    require(
        header.starts_with(b"\x7fELF") && matches!(header[4], 1 | 2) && matches!(header[5], 1 | 2),
        RefusalCode::Unavailable,
        "invalid ELF runtime dependency header",
    )?;
    // A multilib loader cache may contain the same soname for several ABIs.
    // Only a matching candidate can supply this helper's dependencies.
    if header[4] != 2 || header[5] != 1 || elf_u16(header, 18)? != machine {
        return Ok(false);
    }
    elf(data)?;
    Ok(true)
}

pub(super) fn dependencies(helper: &Path) -> Result<Vec<PathBuf>, Refusal> {
    let mut protected = Vec::new();
    for path in [
        Path::new("/etc/ld.so.cache"),
        Path::new("/etc/ld.so.preload"),
    ] {
        let real = match path.canonicalize() {
            Ok(real) => real,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && fs::symlink_metadata(path).is_err() =>
            {
                path.parent()
                    .unwrap()
                    .canonicalize()
                    .map_err(unavailable)?
                    .join(path.file_name().unwrap())
            }
            Err(error) => return Err(unavailable(error)),
        };
        protected.push(real);
    }
    // glibc cache values are absolute NUL-terminated paths. Include every
    // matching native candidate, including hardware-capability variants.
    let cache = match fs::read("/etc/ld.so.cache") {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(unavailable(error)),
    };
    let cached: Vec<_> = cache
        .split(|b| *b == 0)
        .filter(|name| name.starts_with(b"/"))
        .map(|name| PathBuf::from(std::ffi::OsStr::from_bytes(name)))
        .collect();
    let (machine, _) = elf(&fs::read(helper).map_err(unavailable)?)?;
    let preload = match fs::read("/etc/ld.so.preload") {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(unavailable(error)),
    };
    let mut preload: Vec<_> = preload
        .split(|b| *b == b'\n')
        .flat_map(|line| {
            line.split(|b| *b == b'#')
                .next()
                .unwrap()
                .split(|b| b.is_ascii_whitespace() || *b == b':')
        })
        .filter(|name| !name.is_empty())
        .map(|name| PathBuf::from(std::ffi::OsStr::from_bytes(name)))
        .collect();
    let mut pending = vec![helper.to_owned()];
    let mut visited = BTreeSet::new();
    while let Some(path) = pending.pop() {
        let path = path.canonicalize().map_err(unavailable)?;
        if !visited.insert(path.clone()) {
            continue;
        }
        let (_, mut names) = elf(&fs::read(&path).map_err(unavailable)?)
            .map_err(|error| unavailable(format!("{}: {}", path.display(), error.message)))?;
        names.append(&mut preload);
        protected.push(path);
        for name in names {
            if name.is_absolute() {
                pending.push(name);
                continue;
            }
            require(
                name.components().count() == 1,
                RefusalCode::Unavailable,
                "relative ELF dependency paths cannot yet qualify a writable helper",
            )?;
            let mut found = false;
            let defaults = [
                "/lib",
                "/lib64",
                "/usr/lib",
                "/usr/lib64",
                "/lib/x86_64-linux-gnu",
                "/lib/aarch64-linux-gnu",
                "/usr/lib/x86_64-linux-gnu",
                "/usr/lib/aarch64-linux-gnu",
            ];
            for candidate in cached
                .iter()
                .filter(|path| path.file_name() == Some(name.as_os_str()))
                .cloned()
                .chain(defaults.iter().map(|path| Path::new(path).join(&name)))
            {
                let data = match fs::read(&candidate) {
                    Ok(data) => data,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(unavailable(error)),
                };
                if native_library(&data, machine).map_err(|error| {
                    unavailable(format!("{}: {}", candidate.display(), error.message))
                })? {
                    pending.push(candidate);
                    found = true;
                }
            }
            require(
                found,
                RefusalCode::Unavailable,
                "bubblewrap runtime dependency could not be resolved without executing it",
            )?;
        }
    }
    Ok(protected)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_elf_does_not_establish_runtime_trust() {
        assert!(elf(b"not ELF").is_err());
        assert!(elf(b"\x7fELF\x02\x01").is_err());
    }
    #[test]
    fn foreign_library_candidates_do_not_block_native_dependencies() {
        let data = fs::read(std::env::current_exe().unwrap()).unwrap();
        let (machine, _) = elf(&data).unwrap();
        assert!(native_library(&data, machine).unwrap());
        for (class, endian, architecture) in [(1, 1, machine), (2, 2, machine), (2, 1, machine ^ 1)]
        {
            let mut foreign = data[..20].to_vec();
            foreign[4] = class;
            foreign[5] = endian;
            foreign[18..20].copy_from_slice(&architecture.to_le_bytes());
            assert!(!native_library(&foreign, machine).unwrap());
            assert!(elf(&foreign).is_err());
        }
        // A matching candidate must still qualify in full.
        assert!(native_library(&data[..20], machine).is_err());
        assert!(native_library(b"this is not an ELF library", machine).is_err());
        let mut invalid = data;
        invalid[4] = 0;
        assert!(native_library(&invalid, machine).is_err());
    }
    #[test]
    fn native_loader_dependencies_include_the_executable_and_controls() {
        let executable = std::env::current_exe().unwrap();
        let files = dependencies(&executable).unwrap();
        assert!(files.contains(&executable.canonicalize().unwrap()));
        assert!(files.contains(&PathBuf::from("/etc/ld.so.preload")));
        assert!(files.len() > 3);
    }
}
