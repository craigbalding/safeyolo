//! Pinned Python IDNA2003 primitives for host presentation, separate from routing.
//!
//! These functions do not parse authorities, resolve hosts, apply policy, or
//! choose inspection canonicalization. In particular the source decoder's ACE
//! prefix is case-sensitive. The transport owns any intentional repair of that
//! behavior and must retain its separate original wire authority.

use serde::Deserialize;
use std::sync::OnceLock;

// Preserve the licensed upstream codec, including its other public entry points.
#[allow(dead_code)]
mod punycode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NonAsciiInput,
    LabelLength,
    Prohibited,
    Bidirectional,
    AcePrefix,
    Punycode,
    Roundtrip,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NonAsciiInput => "invalid IDNA input encoding",
            Self::LabelLength => "invalid IDNA label length",
            Self::Prohibited => "prohibited IDNA character",
            Self::Bidirectional => "invalid IDNA bidirectional label",
            Self::AcePrefix => "invalid IDNA ACE prefix",
            Self::Punycode => "invalid IDNA Punycode",
            Self::Roundtrip => "invalid IDNA roundtrip",
        })
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

/// Decode only the Punycode payload after an ACE prefix, without Nameprep or
/// roundtrip validation. The caller owns prior hostname validity and its choice
/// of inspection presentation. This is never a replacement for strict IDNA.
pub fn decode_punycode_label(payload: &str) -> Result<String> {
    // Python consumes the last delimiter even at offset zero. The vendored
    // codec retains a leading delimiter in its input; adapt that one framing
    // case without changing its arithmetic or case-preserving decoder.
    let payload = if payload.rfind('-') == Some(0) {
        &payload[1..]
    } else {
        payload
    };
    punycode::decode_to_string(payload).ok_or(Error::Punycode)
}

#[derive(Deserialize)]
struct Data {
    mapping: Vec<(u32, String)>,
    decomposition: Vec<(u32, String)>,
    combining: Vec<(u32, u8)>,
    composition: Vec<(u32, u32, u32)>,
    prohibited: Vec<(u32, u32)>,
    bidi_ral: Vec<(u32, u32)>,
    bidi_l: Vec<(u32, u32)>,
}
fn data() -> &'static Data {
    static DATA: OnceLock<Data> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("../data/host_names/nameprep.json"))
            .expect("validated pinned IDNA data")
    })
}
fn contains(ranges: &[(u32, u32)], c: char) -> bool {
    let point = u32::from(c);
    let index = ranges.partition_point(|&(low, _)| low <= point);
    index > 0 && point <= ranges[index - 1].1
}
fn mapping(table: &[(u32, String)], c: char) -> Option<&str> {
    table
        .binary_search_by_key(&u32::from(c), |&(point, _)| point)
        .ok()
        .map(|index| table[index].1.as_str())
}
fn combining(c: char) -> u8 {
    data()
        .combining
        .binary_search_by_key(&u32::from(c), |&(point, _)| point)
        .map_or(0, |index| data().combining[index].1)
}

const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const L_COUNT: u32 = 19;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = V_COUNT * T_COUNT;
const S_COUNT: u32 = L_COUNT * N_COUNT;

fn compose(left: char, right: char) -> Option<char> {
    let left = u32::from(left);
    let right = u32::from(right);
    if (L_BASE..L_BASE + L_COUNT).contains(&left) && (V_BASE..V_BASE + V_COUNT).contains(&right) {
        return char::from_u32(S_BASE + (left - L_BASE) * N_COUNT + (right - V_BASE) * T_COUNT);
    }
    if (S_BASE..S_BASE + S_COUNT).contains(&left)
        && (left - S_BASE).is_multiple_of(T_COUNT)
        && (T_BASE + 1..T_BASE + T_COUNT).contains(&right)
    {
        return char::from_u32(left + right - T_BASE);
    }
    data()
        .composition
        .binary_search_by_key(&(left, right), |&(a, b, _)| (a, b))
        .ok()
        .and_then(|index| char::from_u32(data().composition[index].2))
}

fn nfkc32(input: impl Iterator<Item = char>) -> String {
    let mut decomposed = Vec::new();
    for c in input {
        let point = u32::from(c);
        if (S_BASE..S_BASE + S_COUNT).contains(&point) {
            let index = point - S_BASE;
            decomposed.push((char::from_u32(L_BASE + index / N_COUNT).unwrap(), 0));
            decomposed.push((
                char::from_u32(V_BASE + (index % N_COUNT) / T_COUNT).unwrap(),
                0,
            ));
            if !index.is_multiple_of(T_COUNT) {
                decomposed.push((char::from_u32(T_BASE + index % T_COUNT).unwrap(), 0));
            }
        } else if let Some(value) = mapping(&data().decomposition, c) {
            decomposed.extend(value.chars().map(|c| (c, combining(c))));
        } else {
            decomposed.push((c, combining(c)));
        }
    }
    // Stable order within each non-starter run, including a leading run. Avoid
    // quadratic insertion for arbitrarily long caller-supplied nameprep input.
    let mut start = 0;
    for end in 0..=decomposed.len() {
        if end == decomposed.len() || decomposed[end].1 == 0 {
            decomposed[start..end].sort_by_key(|&(_, class)| class);
            start = end + 1;
        }
    }
    let mut output: Vec<char> = Vec::with_capacity(decomposed.len());
    let mut starter: Option<usize> = None;
    let mut last_class = 0;
    for (c, class) in decomposed {
        if let Some(index) = starter
            && (last_class == 0 || last_class < class)
            && let Some(composed) = compose(output[index], c)
        {
            output[index] = composed;
            continue;
        }
        if class == 0 {
            starter = Some(output.len());
        }
        output.push(c);
        last_class = class;
    }
    output.into_iter().collect()
}

/// Exact pinned Python Nameprep: B.1/B.2 mapping, NFKC3.2, prohibited and bidi
/// checks. Python permits Unicode3.2-unassigned code points in this profile.
pub fn nameprep(input: &str) -> Result<String> {
    let mut mapped = String::new();
    for c in input.chars() {
        if let Some(value) = mapping(&data().mapping, c) {
            mapped.push_str(value);
        } else {
            mapped.push(c);
        }
    }
    let result = nfkc32(mapped.chars());
    if result.chars().any(|c| contains(&data().prohibited, c)) {
        return Err(Error::Prohibited);
    }
    if result.chars().any(|c| contains(&data().bidi_ral, c))
        && (result.chars().any(|c| contains(&data().bidi_l, c))
            || !contains(&data().bidi_ral, result.chars().next().unwrap())
            || !contains(&data().bidi_ral, result.chars().next_back().unwrap()))
    {
        return Err(Error::Bidirectional);
    }
    Ok(result)
}

fn ascii_label(label: &str) -> Result<String> {
    if label.is_ascii() {
        return if (1..64).contains(&label.len()) {
            Ok(label.to_owned())
        } else {
            Err(Error::LabelLength)
        };
    }
    let prepared = nameprep(label)?;
    if prepared.is_ascii() {
        return ascii_label(&prepared);
    }
    if prepared.starts_with("xn--") {
        return Err(Error::AcePrefix);
    }
    let encoded = format!(
        "xn--{}",
        punycode::encode_str(&prepared).ok_or(Error::Punycode)?
    );
    if encoded.len() >= 64 {
        return Err(Error::LabelLength);
    }
    Ok(encoded)
}

/// Python `str.encode("idna")` for Unicode scalar strings. This is a codec,
/// not hostname validation: ASCII underscores, spaces and IP colons are retained.
pub fn encode_idna2003(input: &str) -> Result<String> {
    if input.is_empty() {
        return Ok(String::new());
    }
    if input.is_ascii() {
        let mut labels = input.split('.').peekable();
        while let Some(label) = labels.next() {
            if label.len() >= 64 || (label.is_empty() && labels.peek().is_some()) {
                return Err(Error::LabelLength);
            }
        }
        return Ok(input.to_owned());
    }
    let mut labels: Vec<_> = input
        .split(['.', '\u{3002}', '\u{FF0E}', '\u{FF61}'])
        .collect();
    let trailing_dot = labels.last() == Some(&"");
    if trailing_dot {
        labels.pop();
    }
    let mut output = labels
        .into_iter()
        .map(ascii_label)
        .collect::<Result<Vec<_>>>()?
        .join(".");
    if trailing_dot {
        output.push('.');
    }
    Ok(output)
}

fn unicode_label(label: &[u8]) -> Result<String> {
    if label.len() > 1024 {
        return Err(Error::LabelLength);
    }
    if !label.is_ascii() {
        return Err(Error::NonAsciiInput);
    }
    let label = std::str::from_utf8(label).map_err(|_| Error::NonAsciiInput)?;
    let Some(payload) = label.strip_prefix("xn--") else {
        return Ok(label.to_owned());
    };
    let decoded = decode_punycode_label(payload)?;
    let encoded = ascii_label(&decoded)?;
    if label.to_ascii_lowercase() != encoded {
        return Err(Error::Roundtrip);
    }
    Ok(decoded)
}

/// Python `bytes.decode("idna")`, including its case-sensitive lowercase ACE
/// prefix and ASCII fast path. Complete authority validity is the caller's task.
pub fn decode_idna2003(input: &[u8]) -> Result<String> {
    if !input.windows(4).any(|part| part == b"xn--") && input.is_ascii() {
        return Ok(std::str::from_utf8(input).unwrap().to_owned());
    }
    let mut labels: Vec<_> = input.split(|&byte| byte == b'.').collect();
    let trailing_dot = labels.last() == Some(&b"".as_slice());
    if trailing_dot {
        labels.pop();
    }
    let mut output = labels
        .into_iter()
        .map(unicode_label)
        .collect::<Result<Vec<_>>>()?
        .join(".");
    if trailing_dot {
        output.push('.');
    }
    Ok(output)
}
