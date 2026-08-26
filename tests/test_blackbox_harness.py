"""Static regression tests for blackbox harness instance isolation."""

from pathlib import Path


def test_harness_assigns_distinct_proxy_admin_and_web_ports():
    harness = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()

    assert "TEST_PROXY_PORT=8180" in harness
    assert "TEST_ADMIN_PORT=9190" in harness
    assert "TEST_WEB_PORT=8181" in harness
    assert "config['proxy']['port'] = $TEST_PROXY_PORT" in harness
    assert "config['proxy']['admin_port'] = $TEST_ADMIN_PORT" in harness
    assert "config['proxy']['web_port'] = $TEST_WEB_PORT" in harness


def test_kvm_lane_prepares_operator_access_before_product_bootstrap():
    lane = (Path(__file__).parent / "blackbox" / "run-lane.sh").read_text()

    operator_acl = 'sudo -n setfacl -m "u:${OPERATOR_UID}:rw" /dev/kvm'
    assert 'if [ "$LANE" = "kvm" ]; then' in lane
    assert 'OPERATOR_UID="$(id -u)"' in lane
    assert operator_acl in lane
    assert lane.index(operator_acl) < lane.index("    safeyolo bootstrap\n")
    # The harness supplies only its operator prerequisite. Product setup owns
    # the separate persistent uid 100000 ACL and udev rule.
    assert 'setfacl -m "u:100000:rw"' not in lane
