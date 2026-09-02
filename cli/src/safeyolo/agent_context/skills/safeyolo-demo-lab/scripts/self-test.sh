#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
lesson_helper="$script_dir/lesson-helper.sh"
request_story="$script_dir/request-story.sh"
boundary_orientation="$script_dir/boundary-orientation.sh"
trace_explainer="$script_dir/explain-trace.jq"
renderer_installer="$script_dir/install-presenterm.sh"
test_root=$(mktemp -d)

cleanup() {
    rm -rf -- "$test_root"
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

for script in "$lesson_helper" "$request_story" "$boundary_orientation" \
    "$renderer_installer" "$0"; do
    bash -n "$script" || fail "shell syntax: $script"
done
command -v jq >/dev/null 2>&1 || fail 'jq is required for the demo helper self-test'

renderer_asset=$("$renderer_installer" --print-asset)
grep -Eq '^archive=presenterm-0\.16\.1-(aarch64|x86_64)-unknown-linux-(gnu|musl)\.tar\.gz$' \
    <<< "$renderer_asset" || fail 'pinned renderer archive selection'
grep -Eq '^sha256=[0-9a-f]{64}$' <<< "$renderer_asset" || \
    fail 'pinned renderer checksum selection'

platform_bin="$test_root/platform-bin"
mkdir -p "$platform_bin"
cat > "$platform_bin/uname" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  -s) printf 'Linux\n' ;;
  -m) printf '%s\n' "$TEST_ARCH" ;;
  *) printf 'Linux\n' ;;
esac
EOF
cat > "$platform_bin/ldd" <<'EOF'
#!/usr/bin/env bash
if [ "$TEST_LIBC" = musl ]; then
  printf 'musl libc\n'
else
  printf 'ldd (GNU libc)\n'
fi
EOF
chmod +x "$platform_bin/uname" "$platform_bin/ldd"

while IFS='|' read -r test_arch test_libc expected_checksum; do
  asset=$(
    PATH="$platform_bin:$PATH" TEST_ARCH="$test_arch" TEST_LIBC="$test_libc" \
      "$renderer_installer" --print-asset
  )
  grep -Fqx "archive=presenterm-0.16.1-${test_arch}-unknown-linux-${test_libc}.tar.gz" \
    <<< "$asset" || fail "renderer asset for $test_arch/$test_libc"
  grep -Fqx "sha256=$expected_checksum" <<< "$asset" || \
    fail "renderer checksum for $test_arch/$test_libc"
done <<'EOF'
aarch64|gnu|d08cac84c26f2c683ae34458e8be497575ef92af9bca5bfbe8e01a97742eadd9
aarch64|musl|c03c3744609d61587aac9dda4f431912748bd70d88d4fa6c0440b079001c64c3
x86_64|gnu|01fbe92c16d76e84ad9baa10c32ae6ed020a514bf72bd3980a1218250a292b14
x86_64|musl|87512d7c88c3d961c7687aca3519f83c2b7611a550cf769c67c6f7948e8b8f54
EOF

trace_fixture="$test_root/trace.json"
cat > "$trace_fixture" <<'EOF'
{
  "request_id": "req-demo-1",
  "truncated": false,
  "steps": [
    {
      "addon": "network-guard",
      "hook": "request",
      "state": "evaluated",
      "outcome": "allowed"
    },
    {
      "addon": "service-gateway",
      "hook": "requestheaders",
      "state": "evaluated",
      "outcome": "not_a_gateway_request"
    },
    {
      "addon": "circuit-breaker",
      "hook": "response",
      "state": "evaluated",
      "outcome": "success_recorded"
    }
  ],
  "not_loaded": []
}
EOF

explanation=$(jq -r -f "$trace_explainer" "$trace_fixture")
grep -Fq 'state=evaluated means the named hook ran' <<< "$explanation" || \
    fail 'evaluated-state explanation is absent'
grep -Fq 'This was not a service-gateway call' <<< "$explanation" || \
    fail 'service-gateway non-applicable explanation is absent'
grep -Fq 'Existing circuit state was updated when present' <<< "$explanation" || \
    fail 'conditional circuit update explanation is absent'
grep -Fq 'does not prove a stored mutation' <<< "$explanation" || \
    fail 'circuit mutation limit is absent'

lesson="$test_root/LESSON.md"
"$lesson_helper" new "$lesson" 'Test lesson' 'Small self-test lesson' >/dev/null
[ -s "$lesson" ] || fail 'lesson source was not created'
[ -s "$lesson.questions.tsv" ] || fail 'question registry was not created'
grep -Fq 'Press `q` to choose a question.' "$lesson" || \
    fail 'lesson question control is absent'
if grep -Fq 'Not started' "$lesson" || grep -Fq '+exec' "$lesson"; then
    fail 'default lesson exposes renderer execution state'
fi
set +e
"$lesson_helper" new "$lesson" 'Duplicate' >/dev/null 2>&1
duplicate_rc=$?
set -e
[ "$duplicate_rc" -eq 1 ] || fail "lesson overwrite refusal returned $duplicate_rc"

fake_bin="$test_root/bin"
mkdir -p "$fake_bin"
cat > "$fake_bin/cat" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = /app/agent_token ]; then
    printf 'fake-agent-token-for-demo-self-test\n'
    exit 0
fi
exec /usr/bin/cat "$@"
EOF
chmod +x "$fake_bin/cat"

cat > "$fake_bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
headers_file=
body_file=
url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --dump-header)
            headers_file=$2
            shift 2
            ;;
        --output)
            body_file=$2
            shift 2
            ;;
        --max-time|--header|--write-out)
            shift 2
            ;;
        -sS)
            shift
            ;;
        http://*|https://*)
            url=$1
            shift
            ;;
        *)
            shift
            ;;
    esac
done

case "$url" in
    *'/lookup?'*)
        printf '{"host":"example.com","decision":"allow"}\n'
        ;;
    *'/trace?'*)
        /usr/bin/cat "$SAFEYOLO_DEMO_TRACE_FIXTURE"
        ;;
    https://example.com/)
        printf '%s\r\n' \
            'HTTP/2 200' \
            'Content-Type: text/plain' \
            'X-SafeYolo-Request-ID: req-demo-1' \
            '' > "$headers_file"
        printf 'Example response body\n' > "$body_file"
        printf 'http_status=200 total_seconds=0.010000\n'
        ;;
    *)
        printf 'Unexpected self-test URL: %s\n' "$url" >&2
        exit 22
        ;;
esac
EOF
chmod +x "$fake_bin/curl"

story_output="$test_root/request-story.txt"
PATH="$fake_bin:$PATH" \
SAFEYOLO_DEMO_TRACE_FIXTURE="$trace_fixture" \
    "$request_story" --brief example.com > "$story_output"
grep -Fq 'Example response body' "$story_output" || \
    fail 'ordinary response body is absent'
grep -Fq 'outcome=not_a_gateway_request' "$story_output" || \
    fail 'raw service-gateway outcome is absent'
grep -Fq 'This was not a service-gateway call' "$story_output" || \
    fail 'nearby outcome explanation is absent'
grep -Fq '__SAFEYOLO_REQUEST_DEMO_DONE__ rc=0' "$story_output" || \
    fail 'request story did not report success'

printf 'PASS: safeyolo-demo-lab helper self-test\n'
