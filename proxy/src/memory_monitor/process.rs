//! The serving process's current and peak resident memory, in source KB units.
//! This reads no guest, cgroup or host-wide memory state.

use std::{fs::File, io::Read};

use num_bigint::BigInt;
use serde_json::Value;

use super::{MemorySample, SampleError};
use crate::{circuits::CircuitValue, policy::python_whitespace};

/// Read the source procfs fields on the calling process. Callers that run on an
/// async executor must place this blocking read with their other report work.
pub fn sample() -> Result<MemorySample, SampleError> {
    match File::open("/proc/self/status") {
        Ok(mut file) => read_sample(&mut file),
        Err(_) => Ok(Parsed::default().finish()),
    }
}

#[derive(Default)]
struct Parsed {
    rss: BigInt,
    peak: BigInt,
}

impl Parsed {
    fn line(&mut self, line: &[u8]) -> Result<bool, SampleError> {
        let line = std::str::from_utf8(line).expect("validated procfs text");
        let destination = if line.starts_with("VmRSS:") {
            &mut self.rss
        } else if line.starts_with("VmHWM:") {
            &mut self.peak
        } else {
            return Ok(true);
        };
        let token = line
            .split(python_whitespace)
            .filter(|part| !part.is_empty())
            .nth(1)
            .ok_or(SampleError::Index)?;
        let Some(value) =
            crate::flow_store::integer(&CircuitValue::Other(Value::String(token.into())))
        else {
            // Source catches ValueError around the whole scan. Keep the
            // earlier fields, then stop without visiting later lines.
            return Ok(false);
        };
        *destination = value;
        Ok(true)
    }

    fn finish(self) -> MemorySample {
        MemorySample {
            peak_kb: self.rss.clone().max(self.peak),
            rss_kb: self.rss,
        }
    }
}

fn read_sample(input: &mut impl Read) -> Result<MemorySample, SampleError> {
    let mut parsed = Parsed::default();
    let mut line = Vec::new();
    let mut pending_cr = false;
    // Python's text reader decodes a chunk before yielding its lines. An
    // invalid byte later in that chunk prevents earlier lines in the same
    // chunk from reaching the field assignments. Up to three bytes can form
    // an unfinished UTF-8 character at the next read boundary.
    let mut buffer = [0_u8; 8195];
    let mut prefix = 0;
    loop {
        let count = match input.read(&mut buffer[prefix..prefix + 8192]) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Ok(parsed.finish()),
        };
        if count == 0 {
            if prefix == 0 && (pending_cr || !line.is_empty()) {
                parsed.line(&line)?;
            }
            return Ok(parsed.finish());
        }
        let end = prefix + count;
        let valid = match std::str::from_utf8(&buffer[..end]) {
            Ok(_) => end,
            Err(error) if error.error_len().is_none() => error.valid_up_to(),
            Err(_) => return Ok(parsed.finish()),
        };
        for byte in &buffer[..valid] {
            // The source newline decoder waits for another decoded character
            // before publishing a trailing CR, unless clean EOF flushes it.
            if pending_cr {
                if !parsed.line(&line)? {
                    return Ok(parsed.finish());
                }
                line.clear();
                pending_cr = false;
                if *byte == b'\n' {
                    continue;
                }
            }
            if *byte == b'\r' {
                pending_cr = true;
            } else if *byte == b'\n' {
                if !parsed.line(&line)? {
                    return Ok(parsed.finish());
                }
                line.clear();
            } else {
                line.push(*byte);
            }
        }
        prefix = end - valid;
        buffer.copy_within(valid..end, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(input: &[u8]) -> (BigInt, BigInt) {
        let sample = read_sample(&mut std::io::Cursor::new(input)).unwrap();
        (sample.rss_kb, sample.peak_kb)
    }

    #[test]
    fn fields_keep_source_order_partial_values_and_peak_lower_bound() {
        for (input, rss, peak) in [
            ("", 0, 0),
            ("Name: owned\nVmRSS: 2048 kB\nVmHWM: 4096 kB\n", 2048, 4096),
            ("VmRSS: 2048 ignored-unit\n", 2048, 2048),
            ("VmHWM: 2 kB\nVmRSS: 8 kB\n", 8, 8),
            ("VmRSS: -2 kB\nVmHWM: -3 kB\n", -2, -2),
            (" VmRSS: 99 kB\nVmRSS: 1 kB\nVmRSS: 4 kB\n", 4, 4),
            ("VmRSS: 8 kB\nVmHWM: invalid\nVmRSS: 99 kB\n", 8, 8),
            ("VmRSS:\u{2003}+٢_٤ kB\r\nVmHWM: 30 kB\r", 24, 30),
        ] {
            assert_eq!(
                fields(input.as_bytes()),
                (rss.into(), peak.into()),
                "{input:?}"
            );
        }
        assert!(matches!(
            read_sample(&mut &b"VmRSS:\n"[..]),
            Err(SampleError::Index)
        ));
    }

    #[test]
    fn text_decode_and_read_failures_keep_only_reached_field_assignments() {
        assert_eq!(fields(b"VmRSS: 8 kB\n\xff"), (0.into(), 0.into()));
        let mut later = b"VmRSS: 8 kB\n".to_vec();
        later.resize(8191, b' ');
        later.push(b'\n');
        later.push(0xff);
        assert_eq!(fields(&later), (8.into(), 8.into()));

        struct Fault {
            call: usize,
            data: &'static [u8],
        }
        impl Read for Fault {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                self.call += 1;
                match self.call {
                    1 => Err(std::io::ErrorKind::Interrupted.into()),
                    2 => {
                        let input = self.data;
                        output[..input.len()].copy_from_slice(input);
                        Ok(input.len())
                    }
                    _ => Err(std::io::Error::other("owned read failure")),
                }
            }
        }
        for (data, expected) in [(b"VmRSS: 8 kB\n".as_slice(), 8), (b"VmRSS: 8 kB\r", 0)] {
            let sample = read_sample(&mut Fault { call: 0, data }).unwrap();
            assert_eq!(
                (sample.rss_kb, sample.peak_kb),
                (expected.into(), expected.into())
            );
        }
    }
}
