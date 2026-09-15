//! The pinned Pydantic model JSON used by PDPCore.policy_hash.
//!
//! Borrow the already compiled canonical model and parser-owned temporal types.
//! This is distinct from ordinary Python JSON response encoding. No model JSON
//! buffer, token copy, new model or request-time compilation is needed to hash.

use std::io::{self, Write};

use ring::digest::{Context, SHA256};
use serde_json::{Value, ser::Formatter};

use super::{Baseline, Policy, TimestampPaths};

impl Policy {
    /// Source-compatible cache identity of baseline then task model JSON.
    /// This retains the source's simple-host summary counts, not the extracted
    /// host names. It is not an authorization signature over every native rule.
    pub fn policy_hash(&self) -> String {
        let mut sink = DigestSink(Context::new(&SHA256));
        self.write_model_json(&mut sink)
            .expect("canonical model JSON and digest sink are infallible");
        let digest = sink.0.finish();
        let mut result = String::with_capacity(23);
        result.push_str("sha256:");
        for byte in &digest.as_ref()[..8] {
            use std::fmt::Write;
            write!(&mut result, "{byte:02x}").expect("writing to a String is infallible");
        }
        result
    }

    fn write_model_json(&self, writer: &mut impl Write) -> io::Result<()> {
        if let Some(baseline) = &self.baseline {
            write_baseline(baseline, writer)?;
        }
        if let Some(task) = &self.task {
            write_baseline(&task.baseline, writer)?;
        }
        Ok(())
    }
}

struct DigestSink(Context);

impl Write for DigestSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_baseline(baseline: &Baseline, writer: &mut impl Write) -> io::Result<()> {
    write_value(&baseline.value, &baseline.timestamps, &[], writer)
}

fn write_value(
    value: &Value,
    timestamps: &TimestampPaths,
    path: &[&str],
    writer: &mut impl Write,
) -> io::Result<()> {
    if let Some(temporal) = timestamps.value_at(path) {
        return temporal.write_model_json(writer);
    }
    match value {
        Value::Null => writer.write_all(b"null"),
        Value::Bool(true) => writer.write_all(b"true"),
        Value::Bool(false) => writer.write_all(b"false"),
        Value::String(value) => write_string(value, writer),
        Value::Number(value) => {
            let raw = value.as_str();
            if raw.contains(['.', 'e', 'E']) {
                // A valid JSON number always parses to f64 (possibly infinity
                // or signed zero); the source uses that same binary64 value.
                write_float(raw.parse().expect("canonical JSON float"), writer)
            } else {
                writer.write_all(if raw == "-0" { b"0" } else { raw.as_bytes() })
            }
        }
        Value::Array(values) => {
            writer.write_all(b"[")?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    writer.write_all(b",")?;
                }
                let index = index.to_string();
                let mut child = path.to_vec();
                child.push(&index);
                write_value(value, timestamps, &child, writer)?;
            }
            writer.write_all(b"]")
        }
        Value::Object(values) => {
            writer.write_all(b"{")?;
            for (index, (key, value)) in values.iter().enumerate() {
                if index != 0 {
                    writer.write_all(b",")?;
                }
                // Path entries borrow the model, including token-map keys.
                // A temporal key and a quoted lookalike remain separate
                // entries even when their serialized JSON spellings coincide.
                let mut child = path.to_vec();
                child.push(key);
                if let Some(temporal) = timestamps.key_at(&child) {
                    temporal.write_model_json(writer)?;
                } else {
                    write_string(key, writer)?;
                }
                writer.write_all(b":")?;
                write_value(value, timestamps, &child, writer)?;
            }
            writer.write_all(b"}")
        }
    }
}

fn write_string(value: &str, writer: &mut impl Write) -> io::Result<()> {
    // serde_json's string serializer emits literal UTF-8 and the same compact
    // escapes as the pinned pydantic-core model serializer.
    serde_json::to_writer(writer, value).map_err(|error| {
        io::Error::new(
            error.io_error_kind().unwrap_or(io::ErrorKind::Other),
            "model JSON string sink failed",
        )
    })
}

fn write_float(value: f64, writer: &mut impl Write) -> io::Result<()> {
    if !value.is_finite() {
        return writer.write_all(b"null");
    }
    // The existing shortest-f64 formatter matches the pinned model serializer
    // after removing the plus sign in positive exponents. Keep its digits,
    // thresholds and signed zero, independently of the input token spelling.
    serde_json::ser::CompactFormatter.write_f64(
        &mut ExponentWriter {
            inner: writer,
            exponent: false,
        },
        value,
    )
}

struct ExponentWriter<'a, W> {
    inner: &'a mut W,
    exponent: bool,
}

impl<W: Write> Write for ExponentWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for byte in bytes {
            if !self.exponent || *byte != b'+' {
                self.inner.write_all(std::slice::from_ref(byte))?;
            }
            self.exponent = *byte == b'e';
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests;
