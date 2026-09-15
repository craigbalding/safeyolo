//! Python 3.12 gzip.decompress framing for retained database bodies.
//!
//! HTTP Content-Encoding uses a different source decoder. This adapter keeps
//! storage's strict trailers, multiple members, ignored header CRC and trailing
//! zero padding, while flate2 owns the DEFLATE decoder and CRC calculation.

use flate2::{Crc, Decompress, FlushDecompress, Status};
use zeroize::Zeroizing;

use super::{Error, ErrorKind, Result};

pub(super) fn decode(mut input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(Vec::new());
    while !input.is_empty() {
        if input.get(..2) != Some(&[0x1f, 0x8b]) {
            return Err(Error(ErrorKind::BadGzip));
        }
        input = &input[2..];
        let header = take(&mut input, 8)?;
        if header[0] != 8 {
            return Err(Error(ErrorKind::BadGzip));
        }
        let flags = header[1];
        if flags & 4 != 0 {
            let length = take(&mut input, 2)?;
            let length = u16::from_le_bytes([length[0], length[1]]);
            take(&mut input, usize::from(length))?;
        }
        // Python consumes through NUL or EOF, then lets the inflater/trailer
        // check report an incomplete member. It does not reject reserved flags.
        for flag in [8, 16] {
            if flags & flag != 0 {
                let consumed = input
                    .iter()
                    .position(|byte| *byte == 0)
                    .map_or(input.len(), |index| index + 1);
                input = &input[consumed..];
            }
        }
        if flags & 2 != 0 {
            take(&mut input, 2)?;
        }
        let mut decoder = Decompress::new(false);
        let mut crc = Crc::new();
        let mut buffer = Zeroizing::new([0_u8; 8192]);
        loop {
            let before_in = decoder.total_in();
            let before_out = decoder.total_out();
            let status = decoder
                .decompress(input, buffer.as_mut(), FlushDecompress::None)
                .map_err(|_| Error(ErrorKind::Deflate))?;
            let consumed = usize::try_from(decoder.total_in() - before_in)
                .map_err(|_| Error(ErrorKind::Overflow))?;
            let produced = usize::try_from(decoder.total_out() - before_out)
                .map_err(|_| Error(ErrorKind::Overflow))?;
            input = &input[consumed..];
            crc.update(&buffer[..produced]);
            output.extend_from_slice(&buffer[..produced]);
            if status == Status::StreamEnd {
                break;
            }
            if consumed == 0 && produced == 0 {
                return Err(Error(ErrorKind::UnexpectedEof));
            }
        }
        let trailer = take(&mut input, 8)?;
        let expected_crc = u32::from_le_bytes(trailer[..4].try_into().expect("four CRC bytes"));
        let expected_length = u32::from_le_bytes(trailer[4..].try_into().expect("four size bytes"));
        if crc.sum() != expected_crc || crc.amount() != expected_length {
            return Err(Error(ErrorKind::BadGzip));
        }
        input = &input[input.iter().take_while(|byte| **byte == 0).count()..];
    }
    Ok(output)
}

fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8]> {
    let prefix = input.get(..count).ok_or(Error(ErrorKind::UnexpectedEof))?;
    *input = &input[count..];
    Ok(prefix)
}
