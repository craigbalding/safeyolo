//! HTTP content buffering and decoding shared by local JSON and provenance capture.
//!
//! Prefix capture discards later output while still executing the entire source
//! decode operation. In particular, source gzip and Zstandard accept incomplete
//! final streams; gzip ignores later members, while Zstandard crosses frames.
//! Buffering preserves source-streamed content absence independently of decoding.

use std::fmt;

use base64::{
    Engine,
    engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig},
};
use flate2::{Decompress, FlushDecompress, Status};
use zeroize::{Zeroize, Zeroizing};
use zstd::stream::raw::Operation;

/// Production `stream_large_bodies=10m` selects whether raw content is retained.
/// This encoded-body threshold is not an admission or decoded-content limit.
pub const BUFFERED_BODY_THRESHOLD: usize = 10 * 1024 * 1024;

/// Retain source-buffered encoded bytes until streaming makes raw content absent.
///
/// The caller owns body completion and transport errors. Only use the returned
/// content for completed bodies; this owner does not parse or decode body frames.
/// Dropping the owner or switching to streamed content wipes its retained bytes.
pub struct BufferedContent {
    content: Option<Zeroizing<Vec<u8>>>,
}

impl BufferedContent {
    pub fn new(content_length: Option<u64>, streamed: bool) -> Self {
        let streamed = streamed
            || content_length.is_some_and(|length| length > BUFFERED_BODY_THRESHOLD as u64);
        Self {
            content: (!streamed).then(|| Zeroizing::new(Vec::new())),
        }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.try_push(data).expect("HTTP content allocation failed");
    }

    /// Capture callbacks cannot propagate a transport error. Their owner can
    /// retain this categorical failure and discard the incomplete capture.
    pub fn try_push(&mut self, data: &[u8]) -> Result<(), ContentError> {
        let Some(content) = self.content.as_mut() else {
            return Ok(());
        };
        if data.len() > BUFFERED_BODY_THRESHOLD - content.len() {
            // Dropping Zeroizing wipes and releases the buffered allocation.
            self.content = None;
        } else {
            content
                .try_reserve(data.len())
                .map_err(|_| ContentError::Allocation)?;
            content.extend_from_slice(data);
        }
        Ok(())
    }

    pub fn is_streamed(&self) -> bool {
        self.content.is_none()
    }

    /// Return encoded content, or `None` when source raw content is absent.
    pub fn into_content(self) -> Option<Zeroizing<Vec<u8>>> {
        self.content
    }
}

/// Payload-free decoding failures. No encoding name or content is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentError {
    /// The source decoder rejects the encoding or encoded bytes with ValueError.
    Value,
    /// A source bytes-to-text transformation rejects its input with TypeError.
    Type,
    /// Growing the caller-owned decoded output failed.
    Allocation,
}

impl fmt::Display for ContentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Value => "invalid HTTP content encoding",
            Self::Type => "invalid HTTP content decoder input type",
            Self::Allocation => "HTTP content allocation failed",
        })
    }
}

impl std::error::Error for ContentError {}

/// Decode the complete buffered body, retaining every decoded byte.
pub fn decode(content: &[u8], content_encoding: &[u8]) -> Result<Zeroizing<Vec<u8>>, ContentError> {
    decode_into(content, content_encoding, None).map(|decoded| decoded.content)
}

/// Decode the complete buffered body, retaining at most `prefix_len` bytes.
///
/// This length only selects returned evidence; it never stops decoding or hides a
/// later source decoding error. The encoded input is borrowed and unchanged.
pub fn decode_prefix(
    content: &[u8],
    content_encoding: &[u8],
    prefix_len: usize,
) -> Result<Zeroizing<Vec<u8>>, ContentError> {
    decode_prefix_with_size(content, content_encoding, prefix_len).map(|decoded| decoded.content)
}

/// Retained decoded bytes and the complete successful decoded size. No encoded
/// transfer bytes or abandoned decoder attempts contribute to `total_bytes`.
pub struct DecodedContent {
    pub content: Zeroizing<Vec<u8>>,
    pub total_bytes: usize,
}

/// Decode to completion while retaining only a prefix and counting all output.
/// Evidence storage uses the count to distinguish original size from retained
/// size. A later decoding failure returns no successful size or partial result.
pub fn decode_prefix_with_size(
    content: &[u8],
    content_encoding: &[u8],
    prefix_len: usize,
) -> Result<DecodedContent, ContentError> {
    decode_into(content, content_encoding, Some(prefix_len))
}

struct Output {
    bytes: Zeroizing<Vec<u8>>,
    prefix_len: Option<usize>,
    total_bytes: usize,
}

impl Output {
    fn new(prefix_len: Option<usize>) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
            prefix_len,
            total_bytes: 0,
        }
    }

    fn append(&mut self, decoded: &[u8]) -> Result<(), ContentError> {
        self.total_bytes = self
            .total_bytes
            .checked_add(decoded.len())
            .ok_or(ContentError::Allocation)?;
        let retained = self.prefix_len.map_or(decoded.len(), |limit| {
            decoded.len().min(limit.saturating_sub(self.bytes.len()))
        });
        self.bytes
            .try_reserve(retained)
            .map_err(|_| ContentError::Allocation)?;
        self.bytes.extend_from_slice(&decoded[..retained]);
        Ok(())
    }

    fn clear(&mut self) {
        self.bytes.zeroize();
        self.total_bytes = 0;
    }
}

fn decode_into(
    content: &[u8],
    content_encoding: &[u8],
    prefix_len: Option<usize>,
) -> Result<DecodedContent, ContentError> {
    let mut output = Output::new(prefix_len);
    let name = content_encoding.to_ascii_lowercase();
    match name.as_slice() {
        b"" | b"identity" | b"none" => output.append(content)?,
        b"gzip" => {
            // The installed source uses zlib's automatic gzip/zlib detection.
            // Both header formats are delegated to the existing inflater.
            let decoder = if content.first() == Some(&0x1f) {
                Decompress::new_gzip(15)
            } else {
                Decompress::new(true)
            };
            inflate(content, decoder, false, &mut output)?;
        }
        b"deflate" | b"deflateraw" => {
            if !content.is_empty() {
                match inflate(content, Decompress::new(true), true, &mut output) {
                    Err(ContentError::Value) => {
                        output.clear();
                        inflate(content, Decompress::new(false), true, &mut output)?;
                    }
                    other => other?,
                }
            }
        }
        b"br" => brotli(content, &mut output)?,
        b"zstd" => zstandard(content, &mut output)?,
        _ => byte_codec(content, &name, &mut output)?,
    }
    Ok(DecodedContent {
        content: output.bytes,
        total_bytes: output.total_bytes,
    })
}

fn inflate(
    content: &[u8],
    mut decoder: Decompress,
    require_end: bool,
    output: &mut Output,
) -> Result<(), ContentError> {
    let mut buffer = Zeroizing::new([0u8; 16384]);
    let mut offset = 0;
    loop {
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let status = decoder
            .decompress(&content[offset..], &mut buffer[..], FlushDecompress::None)
            .map_err(|_| ContentError::Value)?;
        let consumed = (decoder.total_in() - before_in) as usize;
        let written = (decoder.total_out() - before_out) as usize;
        offset += consumed;
        output.append(&buffer[..written])?;
        if status == Status::StreamEnd {
            return Ok(());
        }
        if consumed == 0 && written == 0 {
            return if !require_end && offset == content.len() {
                Ok(())
            } else {
                Err(ContentError::Value)
            };
        }
    }
}

fn brotli(content: &[u8], output: &mut Output) -> Result<(), ContentError> {
    use brotli_decompressor::{BrotliDecompressStream, BrotliResult, BrotliState, StandardAlloc};

    if content.is_empty() {
        return Ok(());
    }
    let mut state = BrotliState::new(
        StandardAlloc::default(),
        StandardAlloc::default(),
        StandardAlloc::default(),
    );
    let mut buffer = Zeroizing::new([0u8; 16384]);
    let mut consumed: usize = 0;
    let mut total_out = 0;
    loop {
        // Incremental input avoids the library's internal u32 input indices
        // imposing a size boundary on the caller's complete encoded slice.
        let chunk = &content[consumed..content.len().min(consumed.saturating_add(16384))];
        let mut available_in = chunk.len();
        let mut input_offset = 0;
        let mut available_out = buffer.len();
        let mut output_offset = 0;
        let result = BrotliDecompressStream(
            &mut available_in,
            &mut input_offset,
            chunk,
            &mut available_out,
            &mut output_offset,
            &mut buffer[..],
            &mut total_out,
            &mut state,
        );
        consumed += input_offset;
        output.append(&buffer[..output_offset])?;
        match result {
            BrotliResult::ResultSuccess if consumed == content.len() => return Ok(()),
            BrotliResult::NeedsMoreOutput => {}
            BrotliResult::NeedsMoreInput if consumed < content.len() && input_offset != 0 => {}
            _ => return Err(ContentError::Value),
        }
    }
}

fn zstandard(content: &[u8], output: &mut Output) -> Result<(), ContentError> {
    if content.is_empty() {
        return Ok(());
    }
    let mut decoder = zstd::stream::raw::Decoder::new().map_err(|_| ContentError::Value)?;
    let mut buffer = Zeroizing::new([0u8; 16384]);
    let mut offset = 0;
    loop {
        let status = decoder
            .run_on_buffers(&content[offset..], &mut buffer[..])
            .map_err(|_| ContentError::Value)?;
        offset += status.bytes_read;
        output.append(&buffer[..status.bytes_written])?;
        if offset == content.len() && status.bytes_written < buffer.len() {
            // Python stream_reader.read accepts an incomplete final frame.
            return Ok(());
        }
        if status.bytes_read == 0 && status.bytes_written == 0 {
            return Err(ContentError::Value);
        }
    }
}

fn byte_codec(content: &[u8], name: &[u8], output: &mut Output) -> Result<(), ContentError> {
    let name = normalize_codec(name)?;
    match name.as_str() {
        "zlib" | "zip" | "zlib_codec" => inflate(content, Decompress::new(true), true, output),
        "hex" | "hex_codec" => {
            if !content.len().is_multiple_of(2) {
                return Err(ContentError::Value);
            }
            for pair in content.chunks_exact(2) {
                let high = (pair[0] as char).to_digit(16).ok_or(ContentError::Value)?;
                let low = (pair[1] as char).to_digit(16).ok_or(ContentError::Value)?;
                output.append(&[(high * 16 + low) as u8])?;
            }
            Ok(())
        }
        "base64" | "base_64" | "base64_codec" => base64_content(content, output),
        "bz2" | "bz2_codec" => bzip(content, output),
        "quopri" | "quopri_codec" | "quoted_printable" | "quotedprintable" => {
            quoted_printable(content, output)
        }
        "uu" | "uu_codec" => uu(content, output),
        "rot13" | "rot_13" => Err(ContentError::Type),
        _ => Err(ContentError::Value),
    }
}

fn base64_content(content: &[u8], output: &mut Output) -> Result<(), ContentError> {
    // Python's non-strict binascii adapter ignores junk and incomplete padding
    // until a complete padded quartet terminates the operation. The existing
    // base64 engine performs the actual quartet decoding.
    let engine = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    let mut quartet = Zeroizing::new([0u8; 4]);
    let mut decoded = Zeroizing::new([0u8; 3]);
    let mut position = 0;
    let mut pads = 0;
    for &byte in content {
        if byte == b'=' {
            if position >= 2 {
                pads += 1;
                if position + pads >= 4 {
                    quartet[position..].fill(b'=');
                    let count = engine
                        .decode_slice(&quartet[..], &mut decoded[..])
                        .map_err(|_| ContentError::Value)?;
                    return output.append(&decoded[..count]);
                }
            }
        } else if byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/') {
            pads = 0;
            quartet[position] = byte;
            position += 1;
            if position == 4 {
                let count = engine
                    .decode_slice(&quartet[..], &mut decoded[..])
                    .map_err(|_| ContentError::Value)?;
                output.append(&decoded[..count])?;
                position = 0;
            }
        }
    }
    if position == 0 {
        Ok(())
    } else {
        Err(ContentError::Value)
    }
}

fn bzip(content: &[u8], output: &mut Output) -> Result<(), ContentError> {
    let mut offset = 0;
    let mut complete_frames = 0;
    let mut buffer = Zeroizing::new([0u8; 16384]);
    while offset < content.len() {
        let mut decoder = bzip2::Decompress::new(false);
        let retained_before_frame = output.bytes.len();
        let total_before_frame = output.total_bytes;
        loop {
            let before_in = decoder.total_in();
            let before_out = decoder.total_out();
            let status = decoder.decompress(&content[offset..], &mut buffer[..]);
            let consumed = (decoder.total_in() - before_in) as usize;
            let written = (decoder.total_out() - before_out) as usize;
            offset += consumed;
            match status {
                Err(bzip2::Error::Data | bzip2::Error::DataMagic) if complete_frames != 0 => {
                    // bz2.decompress ignores a later corrupt/non-bzip member,
                    // including output produced before that member's error.
                    output.bytes[retained_before_frame..].zeroize();
                    output.bytes.truncate(retained_before_frame);
                    output.total_bytes = total_before_frame;
                    return Ok(());
                }
                Err(_) => return Err(ContentError::Value),
                Ok(status) => {
                    output.append(&buffer[..written])?;
                    if status == bzip2::Status::StreamEnd {
                        complete_frames += 1;
                        break;
                    }
                }
            }
            if consumed == 0 && written == 0 {
                return Err(ContentError::Value);
            }
        }
    }
    Ok(())
}

fn quoted_printable(content: &[u8], output: &mut Output) -> Result<(), ContentError> {
    // Exact bytes-only quopri.decode/binascii.a2b_qp behavior: malformed escapes
    // remain literal, doubled '=' is one byte, and CR soft breaks skip to LF.
    let mut offset = 0;
    while offset < content.len() {
        let byte = content[offset];
        offset += 1;
        if byte != b'=' {
            output.append(&[byte])?;
            continue;
        }
        let Some(&next) = content.get(offset) else {
            break;
        };
        match next {
            b'\n' => offset += 1,
            b'\r' => {
                while offset < content.len() && content[offset] != b'\n' {
                    offset += 1;
                }
                if offset < content.len() {
                    offset += 1;
                }
            }
            b'=' => {
                output.append(b"=")?;
                offset += 1;
            }
            _ => {
                let pair = content.get(offset..offset.saturating_add(2));
                if let Some(pair) = pair
                    && let (Some(high), Some(low)) = (
                        (pair[0] as char).to_digit(16),
                        (pair[1] as char).to_digit(16),
                    )
                {
                    output.append(&[(high * 16 + low) as u8])?;
                    offset += 2;
                } else {
                    output.append(b"=")?;
                }
            }
        }
    }
    Ok(())
}

fn uu(content: &[u8], output: &mut Output) -> Result<(), ContentError> {
    // Match encodings.uu_codec's small envelope, including its retry with a
    // length-derived line prefix for broken encoders. There is no file access.
    let mut lines = content.split_inclusive(|&byte| byte == b'\n');
    if !lines.by_ref().any(|line| line.starts_with(b"begin")) {
        return Err(ContentError::Value);
    }
    for line in lines {
        if line == b"end\n" {
            return Ok(());
        }
        let (decoded, count) = uu_line(line).or_else(|_| {
            let length = ((line[0].wrapping_sub(32) & 63) as usize * 4 + 5) / 3;
            uu_line(&line[..line.len().min(length)])
        })?;
        output.append(&decoded[..count])?;
    }
    Err(ContentError::Value)
}

fn uu_line(line: &[u8]) -> Result<(Zeroizing<[u8; 63]>, usize), ContentError> {
    let count = (line.first().copied().unwrap_or(0).wrapping_sub(32) & 63) as usize;
    let mut decoded = Zeroizing::new([0u8; 63]);
    let mut offset = 1;
    let mut written = 0;
    let mut bits = 0;
    let mut accumulator = 0u16;
    while written < count {
        let value = match line.get(offset) {
            None | Some(b'\r' | b'\n') => 0,
            Some(&byte) if (b' '..=b'`').contains(&byte) => (byte - b' ') & 63,
            _ => return Err(ContentError::Value),
        };
        offset += 1;
        accumulator = (accumulator << 6) | u16::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded[written] = (accumulator >> bits) as u8;
            written += 1;
            accumulator &= (1 << bits) - 1;
        }
    }
    if line.get(offset..).is_some_and(|tail| {
        tail.iter()
            .any(|byte| !matches!(byte, b' ' | b'`' | b'\r' | b'\n'))
    }) {
        return Err(ContentError::Value);
    }
    Ok((decoded, count))
}

fn normalize_codec(name: &[u8]) -> Result<String, ContentError> {
    // Header decoding leaves invalid UTF-8 as surrogates, which codec lookup
    // rejects. Valid UTF-8 reaches CPython's ASCII codec-name normalization.
    if std::str::from_utf8(name).is_err() || name.contains(&0) {
        return Err(ContentError::Value);
    }
    let mut result = String::new();
    let mut punctuation = false;
    for &byte in name {
        if byte.is_ascii_alphanumeric() || byte == b'.' {
            if punctuation && !result.is_empty() {
                result.push('_');
            }
            result.push(byte as char);
            punctuation = false;
        } else {
            punctuation = true;
        }
    }
    Ok(result)
}
