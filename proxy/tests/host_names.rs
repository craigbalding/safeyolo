use safeyolo_proxy::host_names::{
    decode_idna2003, decode_punycode_label, encode_idna2003, nameprep,
};
use serde_json::{Value, json};
use std::{io::Write, process::Command};

#[test]
fn source_ace_case_and_ascii_fast_paths_remain_explicit() {
    assert_eq!(
        decode_idna2003(b"xn--pi-6kc.invalid").unwrap(),
        "аpi.invalid"
    );
    assert_eq!(
        decode_idna2003(b"XN--pi-6kc.invalid").unwrap(),
        "XN--pi-6kc.invalid"
    );
    assert_eq!(
        decode_idna2003(b"Xn--pi-6kc.invalid").unwrap(),
        "Xn--pi-6kc.invalid"
    );
    assert_eq!(
        decode_idna2003(b"xn--PI-6KC.INVALID.").unwrap(),
        "аPI.INVALID."
    );
    assert_eq!(decode_idna2003(b"xn--BCHER-KVA").unwrap(), "BüCHER");
    assert_eq!(encode_idna2003("MiXeD.Example").unwrap(), "MiXeD.Example");
    assert_eq!(encode_idna2003("MiXeD.ü").unwrap(), "MiXeD.xn--tda");
    for input in ["_svc.invalid", "bad host", "2001:DB8::1", "\0"] {
        assert_eq!(encode_idna2003(input).unwrap(), input);
        assert_eq!(decode_idna2003(input.as_bytes()).unwrap(), input);
    }
    // Codec decoding has no global hostname/label restriction on its ASCII path.
    assert_eq!(decode_idna2003(&vec![b'A'; 2048]).unwrap().len(), 2048);
    let label = format!("{}.xn--pi-6kc", "A".repeat(1025));
    assert!(decode_idna2003(label.as_bytes()).is_err());
}

#[test]
fn nameprep_uses_pinned_mapping_normalization_composition_and_bidi() {
    for (input, expected) in [
        ("faß", "fass"),
        ("\u{1E9E}", "ss"),
        ("\u{1D2C}", "\u{1D2C}"),
        ("\u{2F868}", "\u{2136A}"),
        ("\u{1F600}", "\u{1F600}"),
        ("A\u{30A}", "å"),
        ("\u{1100}\u{1161}\u{11A8}", "각"),
        ("\u{AC00}\u{11A8}", "각"),
        ("a\u{301}\u{327}", "á\u{327}"),
        ("\u{AD}\u{200D}", ""),
        ("\0", "\0"),
    ] {
        assert_eq!(nameprep(input).unwrap(), expected);
    }
    for input in ["\u{E000}", "\u{FFFE}", "aא", "אa", "א1"] {
        assert!(nameprep(input).is_err());
    }
    assert_eq!(nameprep("א1א").unwrap(), "א1א");
}

#[test]
fn codec_lengths_dots_invalid_ace_and_idna2003_acceptance_are_not_uts46() {
    assert!(decode_idna2003(b"xn--fa-hia.invalid").is_err());
    assert_eq!(decode_idna2003(b"xn--e28h.invalid").unwrap(), "😀.invalid");
    assert_eq!(encode_idna2003("faß.invalid").unwrap(), "fass.invalid");
    assert_eq!(
        encode_idna2003("ü。MiXeD．example｡").unwrap(),
        "xn--tda.MiXeD.example."
    );
    assert_eq!(decode_idna2003(b"xn--tda..invalid").unwrap(), "ü..invalid");
    for input in [
        b"xn--".as_slice(),
        b"xn--abc-",
        b"xn--a",
        b"xn---a",
        b"\xff",
    ] {
        assert!(decode_idna2003(input).is_err());
    }
    assert!(decode_idna2003("ü.invalid".as_bytes()).is_err());
    assert!(encode_idna2003(&"a".repeat(64)).is_err());
    assert_eq!(encode_idna2003(&"a".repeat(63)).unwrap().len(), 63);
    assert!(encode_idna2003("a..invalid").is_err());
    // Total DNS length belongs to authority validation, not this codec.
    let long_domain = vec!["a".repeat(63); 5].join(".");
    assert_eq!(encode_idna2003(&long_domain).unwrap(), long_domain);
}

#[test]
fn raw_punycode_inspection_primitive_does_not_add_nameprep_restrictions() {
    assert_eq!(decode_punycode_label("-a").unwrap(), "\u{80}");
    assert_eq!(decode_punycode_label("-").unwrap(), "");
    for (payload, expected) in [
        ("fa-hia", "faß"),
        ("pi-fia905a", "аßpi"),
        ("pi-6kc646z", "а\u{200D}pi"),
    ] {
        assert_eq!(decode_punycode_label(payload).unwrap(), expected);
        assert!(decode_idna2003(format!("xn--{payload}").as_bytes()).is_err());
        assert_eq!(
            decode_idna2003(format!("XN--{payload}").as_bytes()).unwrap(),
            format!("XN--{payload}")
        );
    }
    assert!(safeyolo_proxy::network_guard::dangerous_domain(
        &decode_punycode_label("pi-fia905a").unwrap()
    ));
    assert!(safeyolo_proxy::network_guard::dangerous_domain(
        &decode_punycode_label("pi-6kc646z").unwrap()
    ));
    // Python's raw codec can emit lone surrogates; Rust strings cannot. Keep a
    // visible error for the caller, never a silently uninspected ASCII fallback.
    assert!(decode_punycode_label("a-qc4g").is_err());
    assert!(decode_punycode_label("ib9b").is_err());
}

fn from_hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn portable_source_form_rows_preserve_separate_policy_presentation() {
    let cases: Value = serde_json::from_str(include_str!(
        "../data/host_names/source-host-witnesses.json"
    ))
    .unwrap();
    let mut accepted = 0;
    for row in cases["rows"].as_array().unwrap() {
        if row["source_validation_passed"] != true {
            continue;
        }
        let bytes = from_hex(row["input_host_hex"].as_str().unwrap());
        let host = if row["authority_input_kind"] == "bytes" {
            decode_idna2003(&bytes).unwrap()
        } else {
            String::from_utf8(bytes).unwrap()
        };
        let host = host
            .strip_prefix('[')
            .and_then(|v| v.strip_suffix(']'))
            .unwrap_or(&host);
        assert_eq!(
            host,
            row["policy_host"].as_str().unwrap(),
            "{} / {}",
            row["case"],
            row["form"]
        );
        accepted += 1;
    }
    assert_eq!(json!(accepted), cases["counts"]["accepted"]);
    assert_eq!(
        json!(cases["rows"].as_array().unwrap().len()),
        cases["counts"]["rows"]
    );
}

#[test]
#[ignore = "requires historical Python and mitmproxy environment"]
fn portable_forms_match_actual_python_parsers_and_sensor() {
    let cases: Value = serde_json::from_str(include_str!(
        "../data/host_names/source-host-witnesses.json"
    ))
    .unwrap();
    let expected = python(
        r#"
import json,sys
from mitmproxy import http
from mitmproxy.net.http.http1 import read_request_head
from mitmproxy.options import Options
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layers.http import HTTPMode,HttpStream
from mitmproxy.proxy.layers.http._events import RequestHeaders
from mitmproxy.proxy.layers.http._http2 import parse_h2_request_headers
from mitmproxy.test.tflow import tclient_conn
from safeyolo.core.sensor_utils import build_http_event_from_flow
from safeyolo.mitm_addons.network_guard import detect_homoglyph_attack
rows=json.load(open(sys.argv[1]))['rows'];output=[]
for row in rows:
 form=row['form'];auth=bytes.fromhex(row['input_authority_hex']);value={'source_validation_passed':False}
 try:
  if form.startswith('h2'):
   fields=[(b':method',b'GET'),(b':scheme',b'http'),(b':path',b'/p?Q=%2F'),(b'host' if form=='h2_host_fallback' else b':authority',auth)]
   host,port,method,scheme,authority,path,headers=parse_h2_request_headers(fields)
   req=http.Request(host,port,method,scheme,authority,path,b'HTTP/2.0',headers,None,None,0,None)
  else:
   target=b'http://'+auth+b'/p?Q=%2F' if form=='absolute' else auth if form=='connect' else b'/p?Q=%2F'
   req=read_request_head([(b'CONNECT ' if form=='connect' else b'GET ')+target+b' HTTP/1.1',b'Host: '+auth])
  options=Options();options.add_option('validate_inbound_headers',bool,True,'')
  stream=HttpStream(Context(tclient_conn(),options),1);stream.mode=HTTPMode.upstream
  for cmd in stream.state_wait_for_request_headers(RequestHeaders(1,req,True)):
   if type(cmd).__name__ in ('HttpRequestHeadersHook','HttpConnectHook'):
    event=build_http_event_from_flow(stream.flow,'source-witness',agent='alice')
    value.update(source_validation_passed=True,policy_host=event.http.host,event_path=event.http.path,event_scheme=event.http.scheme,port=event.http.port,homoglyph=bool(detect_homoglyph_attack(req.host)))
    break
 except (ValueError,UnicodeError):pass
 output.append(value)
print(json.dumps(output))
"#,
        &cases,
    );
    for (index, row) in cases["rows"].as_array().unwrap().iter().enumerate() {
        for key in [
            "source_validation_passed",
            "policy_host",
            "event_path",
            "event_scheme",
            "port",
            "homoglyph",
        ] {
            assert_eq!(
                row[key], expected[index][key],
                "source fixture row {index}: {key}"
            );
        }
    }
    eprintln!(
        "Verified {} portable source parser/sensor rows",
        cases["rows"].as_array().unwrap().len()
    );
}

#[test]
#[ignore = "requires historical Python environment"]
fn raw_punycode_matches_python_with_explicit_non_scalar_errors() {
    let mut inputs: Vec<String> = [
        "",
        "fa-hia",
        "pi-fia905a",
        "pi-6kc646z",
        "a-qc4g",
        "ib9b",
        "BCHER-KVA",
        "abc-",
        "-a",
        "a-",
        "----",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-";
    let mut seed = 0x3492u64;
    for index in 0..5000 {
        let mut input = String::new();
        for _ in 0..index % 60 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            input.push(alphabet[(seed >> 32) as usize % alphabet.len()] as char);
        }
        inputs.push(input);
    }
    let expected = python(
        r#"
import json,sys
output=[]
for payload in json.load(open(sys.argv[1])):
 try:output.append([ord(c) for c in payload.encode('ascii').decode('punycode')])
 except UnicodeError:output.append(None)
print(json.dumps(output))
"#,
        &json!(inputs),
    );
    let mut non_scalar = 0;
    for (index, input) in inputs.iter().enumerate() {
        let expected = &expected[index];
        let Some(points) = expected.as_array() else {
            assert!(decode_punycode_label(input).is_err(), "raw payload {index}");
            continue;
        };
        if points
            .iter()
            .any(|point| char::from_u32(point.as_u64().unwrap() as u32).is_none())
        {
            non_scalar += 1;
            assert!(
                decode_punycode_label(input).is_err(),
                "non-scalar payload {index}"
            );
            continue;
        }
        let decoded =
            decode_punycode_label(input).unwrap_or_else(|_| panic!("valid raw payload {index}"));
        assert_eq!(
            json!(decoded.chars().map(u32::from).collect::<Vec<_>>()),
            *expected,
            "raw payload {index}"
        );
    }
    eprintln!(
        "Compared {} Python raw Punycode outcomes; {non_scalar} explicit non-scalar errors",
        inputs.len()
    );
}

fn python(script: &str, input: &Value) -> Value {
    let executable = std::env::var("SAFEYOLO_POLICY_PYTHON")
        .expect("set SAFEYOLO_POLICY_PYTHON to the historical Python environment");
    let mut file = tempfile::NamedTempFile::new().unwrap();
    serde_json::to_writer(file.as_file_mut(), input).unwrap();
    file.flush().unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let result = Command::new(executable)
        .arg("-c")
        .arg(script)
        .arg(file.path())
        .current_dir(root)
        .env(
            "PYTHONPATH",
            format!("{}:{}", root.join("cli/src").display(), root.display()),
        )
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}
fn observed(result: safeyolo_proxy::host_names::Result<String>) -> Value {
    match result {
        Ok(value) => json!({"ok":value}),
        Err(_) => json!({"error":true}),
    }
}

#[test]
#[ignore = "requires historical Python environment"]
fn differential_codecs_and_combining_sequences_match_actual_python() {
    let mut encode = vec![String::new()];
    let pool = [
        'a',
        'A',
        '_',
        '-',
        '.',
        'ü',
        'ß',
        '\u{1E9E}',
        '\u{300}',
        '\u{301}',
        '\u{327}',
        '\u{34F}',
        '\u{1100}',
        '\u{1161}',
        '\u{11A8}',
        '\u{2F868}',
        '\u{1D2C}',
        '\u{1F600}',
        'א',
        'ا',
        '1',
        '\u{AD}',
        '\u{200D}',
        '\u{3002}',
        '\u{FF61}',
        '\0',
        '\u{E000}',
    ];
    let mut seed = 0x49D_A2003u64;
    for index in 0..4000 {
        let mut input = String::new();
        for _ in 0..index % 12 + 1 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            input.push(pool[(seed >> 32) as usize % pool.len()]);
        }
        encode.push(input);
    }
    for length in [0, 1, 2, 58, 59, 60, 62, 63, 64, 65, 1023, 1024, 1025] {
        for (prefix, suffix) in [
            ("a", ""),
            ("ü", ""),
            ("a", "ü"),
            ("a", ".example."),
            ("a", "\u{300}"),
            ("\u{AD}", "A"),
        ] {
            encode.push(format!("{}{suffix}", prefix.repeat(length)));
        }
    }
    for point in (0..=0x10FFFF).step_by(997) {
        if let Some(c) = char::from_u32(point) {
            encode.push(format!("a{c}Z"));
        }
    }
    let expected = python(
        r#"
import encodings.idna,json,sys
x=json.load(open(sys.argv[1]))
def observe(fn):
 try:
  value=fn()
  return {'ok':value.decode('ascii') if isinstance(value,bytes) else value}
 except UnicodeError:return {'error':True}
raw=[b'',b'xn--',b'XN--',b'xn--abc-',b'xn---a',b'xn--a',b'xn--fa-hia',b'xn--e28h',b'xn--BCHER-KVA',b'xn--tda..invalid']
raw += [bytes([v]) for v in range(256)]
for size in (0,1,59,60,63,64,1024,1025,2048):
 raw += [b'a'*size,b'xn--'+b'a'*size,b'a'*size+b'.xn--tda']
for text in x:
 encoded=observe(lambda:text.encode('idna'))
 if 'ok' in encoded:
  value=encoded['ok'].encode('ascii')
  raw += [value,value.upper(),value+b'.']
 if len(text)<64:raw.append(b'xn--'+text.encode('punycode'))
json.dump({'encode':[observe(lambda s=s:s.encode('idna')) for s in x], 'nameprep':[observe(lambda s=s:encodings.idna.nameprep(s)) for s in x], 'decode':[{'input':list(s),'result':observe(lambda s=s:s.decode('idna'))} for s in raw]},sys.stdout)
"#,
        &json!(encode),
    );
    for (index, input) in encode.iter().enumerate() {
        assert_eq!(
            observed(encode_idna2003(input)),
            expected["encode"][index],
            "encode case {index}"
        );
        assert_eq!(
            observed(nameprep(input)),
            expected["nameprep"][index],
            "nameprep case {index}"
        );
    }
    for (index, case) in expected["decode"].as_array().unwrap().iter().enumerate() {
        let input: Vec<u8> = serde_json::from_value(case["input"].clone()).unwrap();
        assert_eq!(
            observed(decode_idna2003(&input)),
            case["result"],
            "decode case {index}"
        );
    }
    eprintln!(
        "Compared {} encode, {} nameprep and {} decode cases with pinned Python",
        encode.len(),
        encode.len(),
        expected["decode"].as_array().unwrap().len()
    );
}

#[test]
#[ignore = "requires historical Python environment; exhaustive scalar witness"]
fn nameprep_matches_python_for_every_unicode_scalar() {
    let expected = python(
        r#"
import encodings.idna,hashlib,json
h=hashlib.sha256();count=0
for point in range(0x110000):
 if 0xD800<=point<=0xDFFF:continue
 count+=1;h.update(point.to_bytes(4,'big'))
 try:value=encodings.idna.nameprep(chr(point)).encode('utf8')
 except UnicodeError:h.update(b'\x00')
 else:h.update(b'\x01'+len(value).to_bytes(4,'big')+value)
print(json.dumps({'count':count,'sha256':list(h.digest())}))
"#,
        &Value::Null,
    );
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    let mut count = 0;
    for point in 0..=0x10FFFFu32 {
        let Some(c) = char::from_u32(point) else {
            continue;
        };
        count += 1;
        digest.update(&point.to_be_bytes());
        match nameprep(&c.to_string()) {
            Ok(value) => {
                digest.update(&[1]);
                digest.update(&(value.len() as u32).to_be_bytes());
                digest.update(value.as_bytes());
            }
            Err(_) => digest.update(&[0]),
        }
    }
    assert_eq!(json!(count), expected["count"]);
    assert_eq!(json!(digest.finish().as_ref()), expected["sha256"]);
    eprintln!("Compared all {count} Unicode scalar Nameprep outcomes with Python");
}
