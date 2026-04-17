#!/bin/bash
# sudoers_integration_test.sh �� outcome-based positive/negative testing
#
# Creates a restricted test user with ONLY SafeYolo's sudoers rules,
# then verifies that every needed operation succeeds and every
# escalation attempt is denied.
#
# Requires: root access on a Linux host with nft, ip, runsc installed.
# Usage: sudo bash sudoers_integration_test.sh
#
# Exit code: 0 if all tests pass, 1 if any fail.

set -u

TEST_USER="testsy"
SUDOERS_FILE="/etc/sudoers.d/safeyolo-test-${TEST_USER}"
PASS=0
FAIL=0
TESTS=()

# --- helpers ---

pass_test() { PASS=$((PASS + 1)); TESTS+=("PASS: $1"); echo "  PASS: $1"; }
fail_test() { FAIL=$((FAIL + 1)); TESTS+=("FAIL: $1"); echo "  FAIL: $1"; }

# Run a command as the test user. Returns the exit code.
as_testsy() { sudo -u "$TEST_USER" sudo -n "$@" 2>/dev/null; }

# Expect success (rc=0)
expect_allow() {
    local desc="$1"; shift
    if as_testsy "$@"; then
        pass_test "$desc"
    else
        fail_test "$desc (expected ALLOW, got DENIED)"
    fi
}

# Expect failure (rc!=0, specifically sudo denial)
expect_deny() {
    local desc="$1"; shift
    if as_testsy "$@" 2>/dev/null; then
        fail_test "$desc (expected DENY, got ALLOWED)"
    else
        pass_test "$desc"
    fi
}

# --- setup ---

setup() {
    echo "=== SETUP ==="
    # Create test user (no sudo group, no extra privileges)
    useradd -m -s /bin/bash "$TEST_USER" 2>/dev/null || true

    # Resolve paths as the test user would have them
    local home
    home=$(eval echo "~${TEST_USER}")
    local share_dir="${home}/.safeyolo/share"
    local base_ext4="${share_dir}/rootfs-base.ext4"
    local base_dest="${share_dir}/rootfs-base"
    local uid gid
    uid=$(id -u "$TEST_USER")
    gid=$(id -g "$TEST_USER")

    # Render the sudoers template with substitutions. Mirrors the
    # production template at cli/src/safeyolo/templates/safeyolo-linux.sudoers.
    cat > "$SUDOERS_FILE" << SUDEOF
# Network namespace lifecycle
${TEST_USER} ALL=(root) NOPASSWD: /usr/sbin/ip netns add safeyolo-*, \\
                                   /usr/sbin/ip netns del safeyolo-*, \\
                                   /sbin/ip netns add safeyolo-*, \\
                                   /sbin/ip netns del safeyolo-*

# Loopback bring-up inside the netns
${TEST_USER} ALL=(root) NOPASSWD: /usr/sbin/ip -n safeyolo-* link set lo up, \\
                                   /sbin/ip -n safeyolo-* link set lo up

# One-time extraction mount (pinned paths)
${TEST_USER} ALL=(root) NOPASSWD: /usr/bin/mount -o loop\,ro ${base_ext4} /tmp/safeyolo-rootfs-mnt, \\
                                   /bin/mount -o loop\,ro ${base_ext4} /tmp/safeyolo-rootfs-mnt, \\
                                   /usr/bin/umount /tmp/safeyolo-rootfs-mnt, \\
                                   /bin/umount /tmp/safeyolo-rootfs-mnt

# runsc with --host-uds=open
${TEST_USER} ALL=(root) NOPASSWD: /usr/local/bin/runsc --root /run/safeyolo --host-uds=open --platform=kvm create *, \\
                                   /usr/local/bin/runsc --root /run/safeyolo --host-uds=open --platform=systrap create *, \\
                                   /usr/local/bin/runsc --root /run/safeyolo start *, \\
                                   /usr/local/bin/runsc --root /run/safeyolo state *, \\
                                   /usr/local/bin/runsc --root /run/safeyolo kill *, \\
                                   /usr/local/bin/runsc --root /run/safeyolo delete *, \\
                                   /usr/local/bin/runsc --root /run/safeyolo exec *, \\
                                   /usr/bin/runsc --root /run/safeyolo --host-uds=open --platform=kvm create *, \\
                                   /usr/bin/runsc --root /run/safeyolo --host-uds=open --platform=systrap create *, \\
                                   /usr/bin/runsc --root /run/safeyolo start *, \\
                                   /usr/bin/runsc --root /run/safeyolo state *, \\
                                   /usr/bin/runsc --root /run/safeyolo kill *, \\
                                   /usr/bin/runsc --root /run/safeyolo delete *, \\
                                   /usr/bin/runsc --root /run/safeyolo exec *

# State directory
${TEST_USER} ALL=(root) NOPASSWD: /usr/bin/mkdir -p /run/safeyolo, \\
                                   /bin/mkdir -p /run/safeyolo

# Base rootfs copy
${TEST_USER} ALL=(root) NOPASSWD: /usr/bin/cp -a /tmp/safeyolo-rootfs-mnt/. ${base_dest}

# chown base rootfs (colon escaped as \: for sudoers parser)
${TEST_USER} ALL=(root) NOPASSWD: /usr/bin/chown -R ${uid}\:${gid} ${base_dest}, \\
                                   /bin/chown -R ${uid}\:${gid} ${base_dest}
SUDEOF

    chmod 0440 "$SUDOERS_FILE"
    if ! visudo -c -f "$SUDOERS_FILE" 2>&1; then
        echo "FATAL: sudoers file failed validation (see error above)"
        exit 2
    fi
    echo "  sudoers installed and validated for $TEST_USER"
}

# --- cleanup ---

cleanup() {
    echo "=== CLEANUP ==="
    # Remove any state created during tests
    ip netns del safeyolo-test99 2>/dev/null || true
    ip link del veth-sy99 2>/dev/null || true
    nft delete table ip safeyolo 2>/dev/null || true
    umount /tmp/safeyolo-rootfs-mnt 2>/dev/null || true
    rm -f "$SUDOERS_FILE"
    userdel -r "$TEST_USER" 2>/dev/null || true
    echo "  cleaned up"
}

trap cleanup EXIT

# --- tests ---

run_positive_tests() {
    echo ""
    echo "=== POSITIVE TESTS (must succeed) ==="

    # -- loopback-only netns lifecycle --
    expect_allow "ip netns add safeyolo-test99" \
        /usr/sbin/ip netns add safeyolo-test99
    expect_allow "ip -n safeyolo-test99 link set lo up" \
        /usr/sbin/ip -n safeyolo-test99 link set lo up
    expect_allow "ip netns del safeyolo-test99" \
        /usr/sbin/ip netns del safeyolo-test99

    # -- mkdir --
    expect_allow "mkdir -p /run/safeyolo" \
        /usr/bin/mkdir -p /run/safeyolo

    # -- runsc (state query returns non-zero for missing container, but
    # sudo must allow the command. Check for sudo denial, not runsc error.) --
    local runsc_out
    runsc_out=$(sudo -u "$TEST_USER" sudo -n /usr/bin/runsc --root /run/safeyolo state nonexistent 2>&1)
    if echo "$runsc_out" | grep -q "password is required"; then
        fail_test "runsc --root /run/safeyolo state (sudo denied)"
    else
        pass_test "runsc --root /run/safeyolo state (sudo allowed)"
    fi
}

run_negative_tests() {
    echo ""
    echo "=== NEGATIVE TESTS (must be denied) ==="

    # -- ip netns exec (root shell) --
    expect_deny "ip netns exec (root shell attempt)" \
        /usr/sbin/ip netns exec safeyolo-test99 /bin/id

    # -- ip netns on non-safeyolo name --
    expect_deny "ip netns add evil-ns" \
        /usr/sbin/ip netns add evil-ns

    # -- ip -n: only loopback-up is allowed --
    expect_deny "ip -n addr add (not in new arch)" \
        /usr/sbin/ip -n safeyolo-test99 addr add 1.2.3.4/32 dev lo
    expect_deny "ip -n route add (not in new arch)" \
        /usr/sbin/ip -n safeyolo-test99 route add default via 1.2.3.4

    # -- ip link / ip addr entirely removed from the template --
    expect_deny "ip link add veth" \
        /usr/sbin/ip link add veth-sy99 type veth peer name eth0
    expect_deny "ip link set eth0 down" \
        /usr/sbin/ip link set eth0 down
    expect_deny "ip addr add on veth-sy" \
        /usr/sbin/ip addr add 192.168.99.1/24 dev veth-sy99

    # -- nft: no firewall rules allowed anymore --
    expect_deny "nft add table ip safeyolo (removed)" \
        /usr/sbin/nft add table ip safeyolo
    expect_deny "nft add table ip evil" \
        /usr/sbin/nft add table ip evil
    expect_deny "nft flush ruleset" \
        /usr/sbin/nft flush ruleset

    # -- sysctl removed entirely --
    expect_deny "sysctl ip_forward (removed)" \
        /usr/sbin/sysctl -w net.ipv4.ip_forward=1
    expect_deny "sysctl kernel.hostname" \
        /usr/sbin/sysctl -w kernel.hostname=pwned

    # -- mount (wrong source path) --
    expect_deny "mount with wrong ext4 path" \
        /usr/bin/mount -o loop,ro /dev/sda1 /tmp/safeyolo-rootfs-mnt
    expect_deny "mount overlay (not in sudoers)" \
        /usr/bin/mount -t overlay overlay -o lowerdir=/etc /tmp/evil

    # -- umount (wrong path) --
    expect_deny "umount /proc" \
        /usr/bin/umount /proc
    expect_deny "umount arbitrary path" \
        /usr/bin/umount /home

    # -- runsc with wrong --root or without --host-uds=open --
    expect_deny "runsc --root /tmp/evil" \
        /usr/bin/runsc --root /tmp/evil state foo
    expect_deny "runsc without --root" \
        /usr/bin/runsc state foo

    # -- generic escalation --
    expect_deny "bash as root" \
        /bin/bash -c "id"
    expect_deny "cat /etc/shadow" \
        /usr/bin/cat /etc/shadow
    expect_deny "iptables (removed)" \
        /usr/sbin/iptables -L
    expect_deny "rm -rf" \
        /usr/bin/rm -rf /tmp
}

# --- main ---

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root (need to create test user + install sudoers)"
    exit 2
fi

setup
run_positive_tests
run_negative_tests

echo ""
echo "=== RESULTS ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "  Total:  $((PASS + FAIL))"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "FAILURES:"
    for t in "${TESTS[@]}"; do
        if [[ "$t" == FAIL* ]]; then
            echo "  $t"
        fi
    done
    exit 1
fi

echo ""
echo "ALL TESTS PASSED"
exit 0
