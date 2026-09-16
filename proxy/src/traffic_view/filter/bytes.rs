//! Python bytes-pattern spelling for operator display filters only. Subjects
//! remain bytes throughout; this is not an HTTP credential or text adapter.
//!
//! Locale flags and arbitrary Python/engine grammar equivalence remain native
//! compatibility gaps. No payload, backtracking or compiled-size cap is added.

use fancy_regex::{BytesMode, Regex, RegexBuilder};
use zeroize::Zeroizing;

use super::{FilterError, Result};

pub(super) enum ByteRegex {
    Regular(regex::bytes::Regex),
    Fancy(Regex),
}
impl ByteRegex {
    pub(super) fn is_match(&self, value: &[u8]) -> Result<bool> {
        match self {
            Self::Regular(regex) => Ok(regex.is_match(value)),
            Self::Fancy(regex) => regex.is_match(value).map_err(super::match_error),
        }
    }
}

pub(super) fn compile(
    pattern: &str,
    insensitive: bool,
    multiline: bool,
    dotall: bool,
) -> Result<ByteRegex> {
    let adapted = adapt(pattern, insensitive)?;
    if let Ok(regex) = regex::bytes::RegexBuilder::new(&adapted)
        .unicode(false)
        .case_insensitive(insensitive)
        .multi_line(multiline)
        .dot_matches_new_line(dotall)
        .size_limit(usize::MAX)
        .nest_limit(u32::MAX)
        .build()
    {
        return Ok(ByteRegex::Regular(regex));
    }
    // The vendored fancy parser turns high-byte hex literals into Unicode
    // scalars. Never accept its resulting false negatives for byte patterns.
    // Regular byte patterns above retain the complete byte alphabet.
    if contains_high_byte(&adapted) {
        return Err(FilterError::Compatibility);
    }
    RegexBuilder::new(&adapted)
        .bytes_mode(BytesMode::Ascii)
        .case_insensitive(insensitive)
        .multi_line(multiline)
        .dot_matches_new_line(dotall)
        .backtrack_limit(usize::MAX)
        .stack_limit(None)
        .delegate_size_limit(usize::MAX)
        .build()
        .map(ByteRegex::Fancy)
        .map_err(|error| match error {
            fancy_regex::Error::ParseError(
                _,
                fancy_regex::ParseError::UnclosedOpenParen
                | fancy_regex::ParseError::TrailingBackslash
                | fancy_regex::ParseError::InvalidClass
                | fancy_regex::ParseError::InvalidHex
                | fancy_regex::ParseError::InvalidRepeat
                | fancy_regex::ParseError::InvalidBackref
                | fancy_regex::ParseError::InvalidGroupName
                | fancy_regex::ParseError::InvalidGroupNameBackref(_),
            ) => FilterError::Invalid,
            _ => FilterError::Compatibility,
        })
}

fn contains_high_byte(pattern: &str) -> bool {
    pattern.as_bytes().windows(4).any(|part| {
        part.starts_with(b"\\x")
            && std::str::from_utf8(&part[2..])
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
                .is_some_and(|byte| byte >= 128)
    })
}

fn literal_byte(output: &mut String, byte: u8, in_class: bool) {
    use std::fmt::Write;
    if !in_class {
        output.push('[');
    }
    write!(output, "\\x{byte:02x}").expect("String sink");
    if !in_class {
        output.push(']');
    }
}

fn adapt(pattern: &str, insensitive: bool) -> Result<Zeroizing<String>> {
    let input = pattern.as_bytes();
    let mut output = Zeroizing::new(String::new());
    let mut index = 0;
    let mut class = false;
    let mut class_start = false;
    let mut groups = Vec::new();
    let mut verbose = false;
    let mut case_insensitive = insensitive;
    let mut class_negated = false;
    let mut at_start = true;
    while index < input.len() {
        let byte = input[index];
        if !class && verbose {
            if matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
                index += 1;
                continue;
            }
            if byte == b'#' {
                while index < input.len() && input[index] != b'\n' {
                    index += 1;
                }
                continue;
            }
        }
        if byte >= 128 {
            // Python compiles expr.encode(), including individual UTF-8 bytes
            // inside a character class, rather than a Unicode scalar.
            literal_byte(&mut output, byte, class);
            index += 1;
            at_start = false;
            class_start = false;
            continue;
        }
        if byte == b'\\' {
            let escaped = *input.get(index + 1).ok_or(FilterError::Invalid)?;
            if !class
                && matches!(escaped, b'A' | b'Z' | b'b' | b'B')
                && repeated(input, index + 2, verbose)
            {
                return Err(FilterError::Invalid);
            }
            if escaped == b'x' {
                let hex = input
                    .get(index + 2..index + 4)
                    .ok_or(FilterError::Invalid)?;
                if !hex.iter().all(u8::is_ascii_hexdigit) {
                    return Err(FilterError::Invalid);
                }
                literal_byte(
                    &mut output,
                    u8::from_str_radix(&pattern[index + 2..index + 4], 16).expect("hex byte"),
                    class,
                );
                index += 4;
            } else if escaped.is_ascii_digit() {
                let octal = escaped <= b'7'
                    && (class
                        || escaped == b'0'
                        || input
                            .get(index + 1..index + 4)
                            .is_some_and(|bytes| bytes.iter().all(|b| matches!(b, b'0'..=b'7'))));
                if octal {
                    let mut end = index + 1;
                    let mut value = 0u16;
                    while end < input.len() && end < index + 4 && matches!(input[end], b'0'..=b'7')
                    {
                        value = value * 8 + u16::from(input[end] - b'0');
                        end += 1;
                    }
                    literal_byte(
                        &mut output,
                        u8::try_from(value).map_err(|_| FilterError::Invalid)?,
                        class,
                    );
                    index = end;
                } else if class {
                    return Err(FilterError::Invalid);
                } else {
                    if case_insensitive {
                        return Err(FilterError::Compatibility);
                    }
                    let end = if input.get(index + 2).is_some_and(u8::is_ascii_digit) {
                        index + 3
                    } else {
                        index + 2
                    };
                    output.push_str(&pattern[index..end]);
                    index = end;
                }
            } else {
                match escaped {
                    b'Z' if !class => output.push_str(r"\z"),
                    b'B' if !class => output.push_str(r"(?:(?<=[A-Za-z0-9_])(?=[A-Za-z0-9_])|(?<![A-Za-z0-9_])(?![A-Za-z0-9_])(?:(?=[\s\S])|(?<=[\s\S])))"),
                    b'b' if class => output.push_str(r"\x08"),
                    b'b' if !class => output.push_str(r"(?:(?<![A-Za-z0-9_])(?=[A-Za-z0-9_])|(?<=[A-Za-z0-9_])(?![A-Za-z0-9_]))"),
                    b'A' if !class => { output.push('\\'); output.push('A'); }
                    b'a' | b'f' | b'n' | b'r' | b't' | b'v' | b'd' | b'D' | b's' | b'S' | b'w' | b'W' => { output.push('\\'); output.push(escaped as char); }
                    other if other.is_ascii_alphabetic() => return Err(FilterError::Invalid),
                    other => literal_byte(&mut output, other, class),
                }
                index += 2;
            }
            at_start = false;
            class_start = false;
            continue;
        }
        if class {
            // Python and Rust interpret double-hyphen class syntax differently.
            // Keep the native limitation visible instead of accepting a set
            // subtraction that changes the source expression.
            if input.get(index..index + 2) == Some(b"--") {
                return Err(FilterError::Compatibility);
            }
            match byte {
                b']' if !class_start => {
                    class = false;
                    output.push(']');
                }
                b']' | b'[' | b'&' | b'~' | b'|' | b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c
                | b'#' => literal_byte(&mut output, byte, class),
                _ => output.push(byte as char),
            }
            if byte == b'^' && class_start && !class_negated {
                class_negated = true;
            } else {
                class_start = false;
            }
            index += 1;
            continue;
        }
        if byte == b'[' {
            class = true;
            class_start = true;
            class_negated = false;
            output.push('[');
            index += 1;
            at_start = false;
            continue;
        }
        if input.get(index..index + 3) == Some(b"(?#") {
            let mut end = index + 3;
            while end < input.len() && input[end] != b')' {
                if input[end] == b'\\' {
                    end += 1;
                }
                end += 1;
            }
            if end >= input.len() {
                return Err(FilterError::Invalid);
            }
            index = end + 1;
            continue;
        }
        if byte == b'(' {
            if input.get(index + 1) == Some(&b'?') {
                let mut end = index + 2;
                while input.get(end).is_some_and(|ch| b"aiLmsux-".contains(ch)) {
                    end += 1;
                }
                if end > index + 2 && input.get(end).is_some_and(|ch| matches!(ch, b':' | b')')) {
                    let flags = &pattern[index + 2..end];
                    if flags.contains('u') {
                        return Err(FilterError::Invalid);
                    }
                    if flags.contains('L') {
                        return Err(FilterError::Compatibility);
                    }
                    let scoped = input[end] == b':';
                    if !scoped && (!at_start || !groups.is_empty() || flags.contains('-')) {
                        return Err(FilterError::Invalid);
                    }
                    if flags
                        .split_once('-')
                        .is_some_and(|(_, negative)| negative.is_empty() || negative.contains('a'))
                    {
                        return Err(FilterError::Invalid);
                    }
                    let (positive, negative) = flags.split_once('-').unwrap_or((flags, ""));
                    if positive.chars().any(|flag| negative.contains(flag)) {
                        return Err(FilterError::Invalid);
                    }
                    if scoped {
                        groups.push((verbose, case_insensitive));
                    }
                    if positive.contains('x') {
                        verbose = true;
                    }
                    if negative.contains('x') {
                        verbose = false;
                    }
                    if positive.contains('i') {
                        case_insensitive = true;
                    }
                    if negative.contains('i') {
                        case_insensitive = false;
                    }
                    let flags: String = flags.chars().filter(|ch| *ch != 'a').collect();
                    if scoped || !flags.is_empty() {
                        output.push_str("(?");
                        output.push_str(&flags);
                        output.push(if scoped { ':' } else { ')' });
                    }
                    index = end + 1;
                    continue;
                }
                // Python supports these group forms; other engine extensions
                // must not quietly become accepted operator syntax.
                let rest = &input[index + 2..];
                if rest.starts_with(b"P=") && case_insensitive {
                    return Err(FilterError::Compatibility);
                }
                if !(rest.starts_with(b":")
                    || rest.starts_with(b"=")
                    || rest.starts_with(b"!")
                    || rest.starts_with(b"<=")
                    || rest.starts_with(b"<!")
                    || rest.starts_with(b"P<")
                    || rest.starts_with(b"P=")
                    || rest.starts_with(b">")
                    || rest.starts_with(b"("))
                {
                    return Err(FilterError::Invalid);
                }
            }
            groups.push((verbose, case_insensitive));
        } else if byte == b')' {
            (verbose, case_insensitive) = groups.pop().ok_or(FilterError::Invalid)?;
        }
        if matches!(byte, b'$' | b'^') && repeated(input, index + 1, verbose) {
            return Err(FilterError::Invalid);
        }
        if byte == b'$' {
            output.push_str(r"(?:(?=\n\z)|$)");
        } else {
            output.push(byte as char);
        }
        index += 1;
        at_start = false;
    }
    if class || !groups.is_empty() {
        return Err(FilterError::Invalid);
    }
    Ok(output)
}

fn repeated(input: &[u8], mut position: usize, verbose: bool) -> bool {
    loop {
        if verbose {
            while input
                .get(position)
                .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c))
            {
                position += 1;
            }
            if input.get(position) == Some(&b'#') {
                while input.get(position).is_some_and(|b| *b != b'\n') {
                    position += 1;
                }
                continue;
            }
        }
        if input.get(position..position + 3) == Some(b"(?#") {
            position += 3;
            while input.get(position).is_some_and(|b| *b != b')') {
                if input[position] == b'\\' {
                    position += 1;
                }
                position += 1;
            }
            if input.get(position) != Some(&b')') {
                return false;
            }
            position += 1;
            continue;
        }
        break;
    }
    match input.get(position) {
        Some(b'*' | b'+' | b'?') => true,
        Some(b'{') => {
            position += 1;
            let first = position;
            while input.get(position).is_some_and(u8::is_ascii_digit) {
                position += 1;
            }
            if input.get(position) == Some(&b',') {
                position += 1;
                while input.get(position).is_some_and(u8::is_ascii_digit) {
                    position += 1;
                }
            }
            position > first && input.get(position) == Some(&b'}')
        }
        _ => false,
    }
}
