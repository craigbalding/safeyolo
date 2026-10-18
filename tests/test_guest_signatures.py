"""Exercise real GPG verification with complete publisher keys and bad inputs.

The mise fixtures are its public gpg-key.pub and the official v2026.10.12
SHASUMS256.txt/.asc release assets. Their identities match the frozen inputs
from guest build 39052091734. Kernel controls use disposable signing keys.
"""
import json
import lzma
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.error import URLError

import pytest

from guest import resolve_inputs as inputs

FIXTURES = Path(__file__).parent / "fixtures/guest-signatures"


@pytest.fixture(scope="module")
def signing_keys():
    if not shutil.which("gpg") or not shutil.which("xz"):
        pytest.skip("signature controls require GPG and xz")
    # GPG also binds S.gpg-agent.extra, which exceeds Darwin socket limits
    # under pytest's default /var/folders temporary parent.
    with tempfile.TemporaryDirectory(prefix="sy-gpg-", dir="/tmp") as directory:
        home = Path(directory).resolve()
        home.chmod(0o700)
        common = ["gpg", "--homedir", str(home), "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
        keys = {}
        try:
            for name in ("signer", "other"):
                uid = f"{name} <{name}@signature.test>"
                generated = subprocess.run([*common, "--quick-generate-key", uid, "ed25519", "sign", "0"],
                                           capture_output=True, text=True, timeout=30)
                assert generated.returncode == 0, generated.stderr[-4000:]
                listing = subprocess.check_output([*common, "--with-colons", "--list-keys", uid], timeout=30).decode()
                fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
                keys[name] = {"fingerprint": fingerprint,
                              "binary": subprocess.check_output([*common, "--export", fingerprint], timeout=30),
                              "armor": subprocess.check_output([*common, "--armor", "--export", fingerprint], timeout=30)}
            keys["signer"]["no-user-ids"] = subprocess.check_output([
                *common, "--export-options", "export-minimal", "--export-filter",
                "keep-uid=mbox = absent@signature.test", "--export", keys["signer"]["fingerprint"]], timeout=30)
            yield common, keys
        finally:
            subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"], check=True, timeout=30)


def sign(common, fingerprint, raw):
    return subprocess.check_output([*common, "--local-user", fingerprint, "--detach-sign"], input=raw, timeout=30)


@pytest.mark.parametrize("key_format", ["binary", "armor"])
def test_kernel_complete_key_and_provenance(tmp_path, monkeypatch, signing_keys, key_format):
    common, keys = signing_keys
    signer = keys["signer"]
    raw = b"controlled kernel tar bytes"
    archive = lzma.compress(raw)
    signature = sign(common, signer["fingerprint"], raw)
    key_url = "https://publisher.invalid/complete-key"
    record = {"url": "https://publisher.invalid/kernel.tar.xz", "sha256": inputs.sha256(archive),
              "signature_url": "https://publisher.invalid/kernel.tar.sign"}
    responses = {record["url"]: archive, record["signature_url"]: signature, key_url: signer[key_format]}
    monkeypatch.setattr(inputs, "KERNEL_KEYS", {signer["fingerprint"]: key_url})
    monkeypatch.setattr(inputs, "fetch", responses.__getitem__)
    target = tmp_path / "kernel.tar.xz"
    inputs.download(record, target, kernel_signature=True)
    provenance = json.loads(target.with_suffix(".xz.verification.json").read_bytes())
    assert provenance["signers"] == [signer["fingerprint"]]
    assert provenance["key_url"] == key_url
    assert provenance["key_sha256"] == inputs.sha256(signer[key_format])
    assert provenance["signature_url"] == record["signature_url"]
    assert provenance["signature_sha256"] == inputs.sha256(signature)
    del responses[record["url"]]
    inputs.download(record, target, kernel_signature=True)


@pytest.mark.parametrize("fault", ["altered-content", "corrupt-signature", "wrong-key", "unknown-signer",
                                  "missing-user-ids", "malformed-key", "unavailable-key", "checksum-mismatch"])
def test_kernel_refuses_failed_verification(tmp_path, monkeypatch, signing_keys, fault):
    common, keys = signing_keys
    signer = keys["signer"]
    raw = b"controlled signed tar bytes"
    archive = lzma.compress(raw if fault != "altered-content" else raw + b"changed")
    signature = sign(common, keys["other"]["fingerprint"] if fault == "unknown-signer" else signer["fingerprint"], raw)
    record = {"url": "https://publisher.invalid/kernel", "sha256": inputs.sha256(archive),
              "signature_url": "https://publisher.invalid/signature"}
    key_url = "https://publisher.invalid/key"
    responses = {record["url"]: archive, record["signature_url"]: signature, key_url: signer["binary"]}
    if fault == "wrong-key":
        responses[key_url] = keys["other"]["binary"]
    elif fault == "missing-user-ids":
        responses[key_url] = signer["no-user-ids"]
    elif fault == "malformed-key":
        responses[key_url] = b"invalid key"
    elif fault == "corrupt-signature":
        responses[record["signature_url"]] = b"invalid signature"
    elif fault == "checksum-mismatch":
        record["sha256"] = "0" * 64
    def fetch(url):
        if fault == "unavailable-key" and url == key_url:
            raise URLError("key unavailable")
        return responses[url]
    monkeypatch.setattr(inputs, "KERNEL_KEYS", {signer["fingerprint"]: key_url})
    monkeypatch.setattr(inputs, "fetch", fetch)
    target = tmp_path / "kernel.tar.xz"
    with pytest.raises((subprocess.CalledProcessError, ValueError, URLError)):
        inputs.download(record, target, kernel_signature=True)
    assert not target.with_suffix(".xz.verification.json").exists()


@pytest.fixture(scope="module")
def mise_without_user_ids():
    with tempfile.TemporaryDirectory(prefix="sy-mise-", dir="/tmp") as directory:
        home = Path(directory).resolve()
        home.chmod(0o700)
        common = ["gpg", "--homedir", str(home), "--batch", "--no-autostart"]
        imported = subprocess.run([*common, "--import", str(FIXTURES / "mise-key.pub")],
                                  capture_output=True, text=True, timeout=30)
        assert imported.returncode == 0, imported.stderr[-4000:]
        raw = subprocess.check_output([*common, "--export-options", "export-minimal", "--export-filter",
                                       "keep-uid=mbox = absent@signature.test", "--export"], timeout=30)
        packets = subprocess.check_output([*common, "--list-packets"], input=raw, timeout=30)
        assert b":public key packet:" in packets and b":user ID packet:" not in packets
        return raw


@pytest.mark.parametrize("fault", [None, "unsigned-content", "wrong-key", "untrusted-signature", "missing-user-ids",
                                  "malformed-key", "unavailable-key"])
def test_mise_uses_complete_publisher_key(monkeypatch, signing_keys, mise_without_user_ids, fault):
    common, keys = signing_keys
    key = (FIXTURES / "mise-key.pub").read_bytes()
    signature = (FIXTURES / "mise-2026.10.12-SHASUMS256.asc").read_bytes()
    checksums = (FIXTURES / "mise-2026.10.12-SHASUMS256.txt").read_bytes()
    assert inputs.sha256(checksums) == "42aaa07a3afccfe46c44cfba2113a4deb09d76c4f87a67cbea9fe402a6f00085"
    signature_url = "https://github.com/jdx/mise/releases/download/v2026.10.12/SHASUMS256.asc"
    key_url = "https://mise.jdx.dev/gpg-key.pub"
    key = {"wrong-key": keys["other"]["armor"], "missing-user-ids": mise_without_user_ids,
           "malformed-key": b"invalid key"}.get(fault, key)
    if fault == "untrusted-signature":
        key = keys["other"]["armor"]
        signature = subprocess.check_output([*common, "--local-user", keys["other"]["fingerprint"], "--clearsign"],
                                            input=checksums, timeout=30)
    responses = {signature_url: signature, key_url: key,
                 "https://keys.openpgp.org/vks/v1/by-fingerprint/24853EC9F655CE80B48E6C3A8B81C9D17413A06D": mise_without_user_ids}
    def fetch(url):
        if fault == "unavailable-key" and url == key_url:
            raise URLError("key unavailable")
        return responses[url]
    monkeypatch.setattr(inputs, "fetch", fetch)
    if fault == "unsigned-content":
        checksums += b"0" * 64 + b"  unsigned-file\n"
    names = {"SHASUMS256.asc": {"browser_download_url": signature_url}}
    if fault is None:
        provenance = inputs.signed_checksums("mise", "2026.10.12", names, checksums)
        assert provenance == {"signature_url": signature_url, "signature_sha256": inputs.sha256(signature),
                              "key_url": key_url, "key_sha256": inputs.sha256(key),
                              "signer": "24853EC9F655CE80B48E6C3A8B81C9D17413A06D"}
    elif fault == "untrusted-signature":
        with pytest.raises(ValueError, match="trusted release signature"):
            inputs.signed_checksums("mise", "2026.10.12", names, checksums)
    else:
        with pytest.raises((subprocess.CalledProcessError, ValueError, URLError)):
            inputs.signed_checksums("mise", "2026.10.12", names, checksums)


def test_download_requires_https_and_refuses_http_redirect(monkeypatch):
    with pytest.raises(ValueError, match="HTTPS"):
        inputs.fetch("http://publisher.invalid/key")
    class Response:
        url = "http://publisher.invalid/key"
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self):
            pytest.fail("read the key after an insecure redirect")
    monkeypatch.setattr(inputs.urllib.request, "urlopen", lambda *args, **kwargs: Response())
    with pytest.raises(ValueError, match="HTTPS"):
        inputs.fetch("https://publisher.invalid/key")
