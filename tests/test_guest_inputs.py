"""Challenge the shared resolver with official release formats and failed inputs."""
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from guest import resolve_inputs as inputs


def test_both_architectures_share_stable_release_and_verified_checksums(monkeypatch):
    version = "9.8.7"
    assets = []
    rows = []
    for arch in inputs.ARCHITECTURES:
        name = inputs.asset_name("mise", version, arch)
        checksum = hashlib.sha256(arch.encode()).hexdigest()
        assets.append({"name": name, "browser_download_url": f"https://official.invalid/{name}", "digest": "sha256:" + checksum})
        rows.append(f"{checksum}  ./{name}")
    assets.append({"name": "SHASUMS256.txt", "browser_download_url": "https://official.invalid/checksums"})
    release = {"tag_name": "v" + version, "draft": False, "prerelease": False, "html_url": "https://official.invalid/release", "assets": assets}
    responses = {"https://api.github.com/repos/jdx/mise/releases/latest": json.dumps(release).encode(),
                 "https://official.invalid/checksums": ("\n".join(rows) + "\n").encode()}
    monkeypatch.setattr(inputs, "fetch", responses.__getitem__)
    monkeypatch.setattr(inputs, "signed_checksums", lambda *args: {"signer": "verified fixture"})
    resolved = inputs.resolve(["mise"], False)
    for arch in inputs.ARCHITECTURES:
        env = inputs.environment(resolved, arch)
        assert env["MISE_VERSION"] == version
        assert env["MISE_SHA256"] == hashlib.sha256(arch.encode()).hexdigest()
    release["prerelease"] = True
    responses["https://api.github.com/repos/jdx/mise/releases/latest"] = json.dumps(release).encode()
    with pytest.raises(ValueError, match="stable"):
        inputs.resolve(["mise"], False)


@pytest.mark.parametrize("fault", ["missing-architecture", "wrong-checksum", "signature", "network"])
def test_resolver_never_falls_back(monkeypatch, fault):
    names = [inputs.asset_name("oras", "1.2.3", arch) for arch in inputs.ARCHITECTURES]
    assets = [{"name": name, "browser_download_url": "https://official.invalid/" + name, "digest": "sha256:" + "a" * 64} for name in names]
    assets.append({"name": "oras_1.2.3_checksums.txt", "browser_download_url": "https://official.invalid/sums"})
    if fault == "missing-architecture":
        assets.pop(1)
    release = {"tag_name": "v1.2.3", "draft": False, "prerelease": False, "html_url": "https://official.invalid/release", "assets": assets}
    def fetch(url):
        if fault == "network":
            raise OSError("offline")
        return json.dumps(release).encode() if "/releases/" in url else "\n".join(
            f"{'b' if fault == 'wrong-checksum' else 'a' * 1}" * 64 + f"  {name}" for name in names).encode()
    def signature(*args):
        if fault == "signature":
            raise subprocess.CalledProcessError(1, "gpg")
        return {"signer": "fixture"}
    monkeypatch.setattr(inputs, "fetch", fetch)
    monkeypatch.setattr(inputs, "signed_checksums", signature)
    with pytest.raises((ValueError, OSError, KeyError, subprocess.SubprocessError)):
        inputs.resolve(["oras"], False)


def test_official_trixie_index_and_both_manifests_are_frozen(monkeypatch):
    raw = {arch: json.dumps({"schemaVersion": 2, "architecture": arch}).encode() for arch in inputs.ARCHITECTURES}
    manifests = [{"digest": "sha256:" + inputs.sha256(value), "size": len(value), "mediaType": "manifest",
                  "platform": {"os": "linux", "architecture": arch}} for arch, value in raw.items()]
    index = json.dumps({"manifests": manifests}).encode()
    def capture(args, **kwargs):
        if args[-1].endswith(":trixie"):
            return index
        arch = next(arch for arch, value in raw.items() if args[-1].endswith(inputs.sha256(value)))
        return json.dumps({"os": "linux", "architecture": arch}).encode() if "--config" in args else raw[arch]
    monkeypatch.setattr(subprocess, "check_output", capture)
    result = inputs.debian()
    assert result["index"].endswith(inputs.sha256(index))
    assert set(result["manifests"]) == set(inputs.ARCHITECTURES)
    manifests.pop()
    index = json.dumps({"manifests": manifests}).encode()
    with pytest.raises(ValueError, match="arm64"):
        inputs.debian()


def test_download_cache_is_identity_checked_and_bad_download_fails(tmp_path, monkeypatch):
    target = tmp_path / "cached"
    target.write_bytes(b"yesterday")
    record = {"url": "https://official.invalid/tool", "sha256": inputs.sha256(b"today")}
    monkeypatch.setattr(inputs, "fetch", lambda url: b"today")
    inputs.download(record, target)
    assert target.read_bytes() == b"today"
    monkeypatch.setattr(inputs, "fetch", lambda url: pytest.fail("matching cache was downloaded again"))
    inputs.download(record, target)
    target.write_bytes(b"corrupted")
    monkeypatch.setattr(inputs, "fetch", lambda url: b"unverified")
    with pytest.raises(ValueError, match="checksum"):
        inputs.download(record, target)
    assert target.read_bytes() == b"corrupted"


def test_kernel_uses_upstream_stable_not_rc_and_no_existing_image_shortcut(monkeypatch):
    monkeypatch.setattr(inputs, "fetch", lambda url: json.dumps({"latest_stable": {"version": "9.8.7"}}).encode()
                        if url.endswith("json") else ("a" * 64 + "  linux-9.8.7.tar.xz\n").encode())
    assert inputs.kernel()["version"] == "9.8.7"
    monkeypatch.setenv("KERNEL_VERSION", "9.9-rc1")
    with pytest.raises(ValueError, match="stable"):
        inputs.kernel()
    root = Path(__file__).resolve().parents[1]
    for script in ("build-rootfs.sh", "build-kernel.sh", "build-initramfs.sh", "install-guest-common.sh"):
        source = (root / "guest" / script).read_text()
        assert "already present" not in source and "already exists at" not in source and "mise already installed" not in source
    for script in ("publish_guest_oci.sh", "publish_guest_by_digest.sh", "install_oras.sh"):
        assert "1.3.4" not in (root / "scripts" / script).read_text()


def test_existing_kernel_image_is_rebuilt_in_fresh_source_tree(tmp_path):
    import io
    import os
    import shutil
    import sys
    import tarfile

    root = Path(__file__).resolve().parents[1]
    builder = tmp_path / "guest"
    builder.mkdir()
    shutil.copyfile(root / "guest/build-kernel.sh", builder / "build-kernel.sh")
    shutil.copyfile(root / "guest/defconfig", builder / "defconfig")
    (builder / "input-functions.sh").write_text('''guest_inputs() { export KERNEL_VERSION=1.2.3 GUEST_INPUTS="$TEST_INPUTS"; }
guest_download() { printf '%s' '{"signer":"controlled fixture"}' > "$3.verification.json"; }
''')
    output = tmp_path / "out"
    cache = output / ".download-cache"
    cache.mkdir(parents=True)
    (output / "Image").write_bytes(b"yesterday")
    with tarfile.open(cache / "linux-1.2.3.tar.xz", "w:xz") as bundle:
        entry = tarfile.TarInfo("linux-1.2.3/Makefile")
        entry.size = 1
        bundle.addfile(entry, io.BytesIO(b"x"))
    tools = tmp_path / "tools"
    tools.mkdir()
    tool = '''#!/usr/bin/env python3
import pathlib, sys
if '-C' in sys.argv:
    output=pathlib.Path(sys.argv[sys.argv.index('-C')+1])/'arch/arm64/boot/Image'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(b'fresh controlled kernel')
print('controlled build tool')
'''
    for name in ("make", "bc", "flex", "bison", "aarch64-linux-gnu-gcc", "pkg-config"):
        path = tools / name
        path.write_text(tool)
        path.chmod(0o755)
    inputs_path = tmp_path / "inputs.json"
    inputs_path.write_text('{}')
    result = subprocess.run(["bash", str(builder / "build-kernel.sh")], capture_output=True, text=True, timeout=30,
                            env={**os.environ, "PATH": f"{tools}:{Path(sys.executable).parent}:{os.environ['PATH']}",
                                 "OUTPUT_DIR": str(output), "TMPDIR": str(tmp_path), "TEST_INPUTS": str(inputs_path)})
    assert result.returncode == 0, result.stderr
    assert (output / "Image").read_bytes() == b"fresh controlled kernel"
    assert (output / "provenance/kernel.config").read_bytes() == (builder / "defconfig").read_bytes()


def test_frozen_input_keys_cannot_inject_shell_assignments():
    with pytest.raises(ValueError, match="unknown"):
        inputs.environment({"schema": "safeyolo.guest-inputs/v1", "tools": {"mise;touch /unsafe": {}}}, "arm64")
