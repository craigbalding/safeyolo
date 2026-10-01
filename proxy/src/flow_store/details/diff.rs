//! Specialized port of Python 3.12.14 difflib defaults used by FlowStore.
//!
//! Source difflib.py SHA256:
//! 3eb2d371b4a171b063921de6bbf115108bc39de8bf72866315868ce2599213b7
//! Python Software Foundation copyright/license: PYTHON-LICENSE.txt beside
//! this file. Adaptation: borrowed UTF-8 lines, no custom junk callback or
//! reusable matcher/cache, fixed context=3 and source output cap=5000.

use std::collections::HashMap;

use serde_json::Value;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Kind {
    Equal,
    Replace,
    Delete,
    Insert,
}
#[derive(Clone, Copy)]
struct Op {
    kind: Kind,
    a: usize,
    end_a: usize,
    b: usize,
    end_b: usize,
}
#[derive(Clone, Copy, Default, Eq, Ord, PartialEq, PartialOrd)]
struct Match {
    a: usize,
    b: usize,
    size: usize,
}

pub(super) fn unified(a: &str, b: &str, id_a: i64, id_b: i64) -> (Vec<Value>, bool) {
    let a = splitlines(a);
    let b = splitlines(b);
    let mut opcodes = opcodes(&a, &b);
    if opcodes.is_empty() {
        return (Vec::new(), false);
    }
    if let Some(first) = opcodes.first_mut().filter(|op| op.kind == Kind::Equal) {
        first.a = first.a.max(first.end_a.saturating_sub(3));
        first.b = first.b.max(first.end_b.saturating_sub(3));
    }
    if let Some(last) = opcodes.last_mut().filter(|op| op.kind == Kind::Equal) {
        last.end_a = last.end_a.min(last.a + 3);
        last.end_b = last.end_b.min(last.b + 3);
    }
    let mut output = Output {
        lines: Vec::new(),
        truncated: false,
    };
    let mut group = Vec::new();
    for mut op in opcodes {
        if op.kind == Kind::Equal && op.end_a - op.a > 6 {
            group.push(Op {
                end_a: op.end_a.min(op.a + 3),
                end_b: op.end_b.min(op.b + 3),
                ..op
            });
            emit(&mut output, &group, &a, &b, id_a, id_b);
            group.clear();
            op.a = op.a.max(op.end_a.saturating_sub(3));
            op.b = op.b.max(op.end_b.saturating_sub(3));
        }
        group.push(op);
    }
    if !(group.is_empty() || group.len() == 1 && group[0].kind == Kind::Equal) {
        emit(&mut output, &group, &a, &b, id_a, id_b);
    }
    (output.lines, output.truncated)
}

struct Output {
    lines: Vec<Value>,
    truncated: bool,
}
impl Output {
    fn push(&mut self, line: impl FnOnce() -> String) {
        if self.lines.len() == 5000 {
            self.truncated = true;
        } else {
            self.lines.push(Value::String(line()));
        }
    }
}
fn emit(output: &mut Output, group: &[Op], a: &[&str], b: &[&str], id_a: i64, id_b: i64) {
    if output.lines.is_empty() {
        output.push(|| format!("--- flow/{id_a}\n"));
        output.push(|| format!("+++ flow/{id_b}\n"));
    }
    let first = group.first().expect("nonempty diff group");
    let last = group.last().expect("nonempty diff group");
    output.push(|| {
        format!(
            "@@ -{} +{} @@\n",
            range(first.a, last.end_a),
            range(first.b, last.end_b)
        )
    });
    for op in group {
        match op.kind {
            Kind::Equal => {
                for line in &a[op.a..op.end_a] {
                    output.push(|| format!(" {line}"));
                }
            }
            Kind::Replace | Kind::Delete => {
                for line in &a[op.a..op.end_a] {
                    output.push(|| format!("-{line}"));
                }
            }
            Kind::Insert => {}
        }
        if matches!(op.kind, Kind::Replace | Kind::Insert) {
            for line in &b[op.b..op.end_b] {
                output.push(|| format!("+{line}"));
            }
        }
    }
}
fn range(start: usize, end: usize) -> String {
    let length = end - start;
    match length {
        0 => format!("{start},0"),
        1 => (start + 1).to_string(),
        _ => format!("{},{length}", start + 1),
    }
}

fn opcodes(a: &[&str], b: &[&str]) -> Vec<Op> {
    let mut b2j: HashMap<&str, Vec<usize>> = HashMap::new();
    for (j, line) in b.iter().enumerate() {
        b2j.entry(line).or_default().push(j);
    }
    // SequenceMatcher(None, a, b) uses autojunk=True. Popular values are
    // excluded from the lookup but may extend a selected match at its edges.
    if b.len() >= 200 {
        b2j.retain(|_, indices| indices.len() <= b.len() / 100 + 1);
    }
    let mut queue = vec![(0, a.len(), 0, b.len())];
    let mut matches = Vec::new();
    while let Some((alo, ahi, blo, bhi)) = queue.pop() {
        let found = longest(a, b, &b2j, alo, ahi, blo, bhi);
        if found.size != 0 {
            matches.push(found);
            if alo < found.a && blo < found.b {
                queue.push((alo, found.a, blo, found.b));
            }
            if found.a + found.size < ahi && found.b + found.size < bhi {
                queue.push((found.a + found.size, ahi, found.b + found.size, bhi));
            }
        }
    }
    matches.sort_unstable();
    let mut combined = Vec::new();
    let mut prior = Match::default();
    for found in matches {
        if prior.a + prior.size == found.a && prior.b + prior.size == found.b {
            prior.size += found.size;
        } else {
            if prior.size != 0 {
                combined.push(prior);
            }
            prior = found;
        }
    }
    if prior.size != 0 {
        combined.push(prior);
    }
    combined.push(Match {
        a: a.len(),
        b: b.len(),
        size: 0,
    });
    let (mut i, mut j) = (0, 0);
    let mut result = Vec::new();
    for found in combined {
        let kind = if i < found.a && j < found.b {
            Some(Kind::Replace)
        } else if i < found.a {
            Some(Kind::Delete)
        } else if j < found.b {
            Some(Kind::Insert)
        } else {
            None
        };
        if let Some(kind) = kind {
            result.push(Op {
                kind,
                a: i,
                end_a: found.a,
                b: j,
                end_b: found.b,
            });
        }
        i = found.a + found.size;
        j = found.b + found.size;
        if found.size != 0 {
            result.push(Op {
                kind: Kind::Equal,
                a: found.a,
                end_a: i,
                b: found.b,
                end_b: j,
            });
        }
    }
    result
}

fn longest(
    a: &[&str],
    b: &[&str],
    b2j: &HashMap<&str, Vec<usize>>,
    alo: usize,
    ahi: usize,
    blo: usize,
    bhi: usize,
) -> Match {
    let mut best = Match {
        a: alo,
        b: blo,
        size: 0,
    };
    let mut lengths = HashMap::new();
    for (i, line) in a.iter().enumerate().take(ahi).skip(alo) {
        let mut next = HashMap::new();
        if let Some(indices) = b2j.get(line) {
            for &j in indices {
                if j < blo {
                    continue;
                }
                if j >= bhi {
                    break;
                }
                let size = j
                    .checked_sub(1)
                    .and_then(|j| lengths.get(&j).copied())
                    .unwrap_or(0)
                    + 1;
                next.insert(j, size);
                // Strictly greater preserves the source earliest-a/earliest-b tie.
                if size > best.size {
                    best = Match {
                        a: i + 1 - size,
                        b: j + 1 - size,
                        size,
                    };
                }
            }
        }
        lengths = next;
    }
    while best.a > alo && best.b > blo && a[best.a - 1] == b[best.b - 1] {
        best.a -= 1;
        best.b -= 1;
        best.size += 1;
    }
    while best.a + best.size < ahi
        && best.b + best.size < bhi
        && a[best.a + best.size] == b[best.b + best.size]
    {
        best.size += 1;
    }
    best
}

fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut characters = text.char_indices().peekable();
    while let Some((index, character)) = characters.next() {
        if matches!(
            character,
            '\n' | '\r'
                | '\u{b}'
                | '\u{c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        ) {
            let mut end = index + character.len_utf8();
            if character == '\r' && characters.peek().is_some_and(|(_, next)| *next == '\n') {
                end = characters.next().unwrap().0 + 1;
            }
            lines.push(&text[start..end]);
            start = end;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}
