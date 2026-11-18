"""The shipped Python image must carry its own native SSL dependencies."""

import hashlib
import importlib.util
import io
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("builder", REPO / "scripts/build_hyperlight_jobs.py")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def entries(image):
    """Read the complete newc record stream independently of the writer."""
    result = {}
    with image.open("rb") as stream:
        while True:
            header = stream.read(110)
            assert header[:6] == b"070701" and len(header) == 110
            fields = [int(header[index:index + 8], 16) for index in range(6, 110, 8)]
            name = stream.read(fields[11]).removesuffix(b"\0").decode()
            stream.read(-stream.tell() % 4)
            value = stream.read(fields[6])
            assert len(value) == fields[6]
            stream.read(-stream.tell() % 4)
            if name == "TRAILER!!!":
                assert stream.read() == b""
                return result
            assert name not in result
            result[name] = (fields[1], value)


def image_at(path):
    with path.open("wb") as stream:
        builder.cpio_entry(stream, "usr", b"", 0o40755)
        builder.cpio_entry(stream, "usr/bin/python3", b"retained interpreter", 0o100755)
        builder.cpio_entry(stream, "usr/local/lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem",
                           b"retained public roots", 0o100644)
        builder.cpio_entry(stream, "TRAILER!!!", b"", 0)
        stream.write(b"\0" * 512)
    return path


def test_rootfs_addition_preserves_existing_files_and_creates_library_parents(tmp_path):
    image = image_at(tmp_path / "python.cpio")
    added = {"usr/lib/aarch64-linux-gnu/libssl.so.3": b"SSL library",
             "usr/lib/aarch64-linux-gnu/libcrypto.so.3": b"crypto library",
             "usr/share/doc/libssl3/copyright": b"required license"}
    builder.add_ssl_to_rootfs(image, added)
    records = entries(image)
    assert records.pop("usr/bin/python3") == (0o100755, b"retained interpreter")
    assert records.pop("usr/local/lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem") == (
        0o100644, b"retained public roots")
    assert records.pop("usr/lib/ssl/cert.pem") == (0o100644, b"retained public roots")
    for name, value in added.items():
        assert records.pop(name) == (0o100644, value)
    assert all(mode == 0o40755 and value == b"" for mode, value in records.values())
    before = image.read_bytes()
    with pytest.raises(ValueError, match="already contains"):
        builder.add_ssl_to_rootfs(image, added)
    assert image.read_bytes() == before


@pytest.mark.parametrize("malformed", [False, True])
def test_incomplete_guest_image_fails_before_adding_ssl(tmp_path, malformed):
    image = tmp_path / "python.cpio"
    with image.open("wb") as stream:
        builder.cpio_entry(stream, "TRAILER!!!", b"", 0)
    if malformed:
        image.write_bytes(b"not a CPIO image")
    before = image.read_bytes()
    with pytest.raises(ValueError, match="invalid newc|missing its bundled public CA roots"):
        builder.add_ssl_to_rootfs(image, {})
    assert image.read_bytes() == before


@pytest.mark.parametrize("architecture", ["aarch64", "x86_64"])
@pytest.mark.parametrize("defect", [None, "hash", "size", "symlink"])
def test_pinned_package_is_verified_before_only_required_regular_members_are_added(
        tmp_path, monkeypatch, architecture, defect):
    package = b"verified package bytes"
    debian_arch, library_arch, _, _ = builder.OPENSSL_PACKAGES[architecture]
    expected = {f"usr/lib/{library_arch}/libssl.so.3": b"ssl",
                f"usr/lib/{library_arch}/libcrypto.so.3": b"crypto",
                "usr/share/doc/libssl3/copyright": b"license"}
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:xz") as archive:
        for name, value in {**expected, "unrelated-file": b"not installed"}.items():
            member = tarfile.TarInfo("./" + name)
            member.size = len(value)
            if defect == "symlink" and name.endswith("libssl.so.3"):
                member.type, member.linkname, member.size = tarfile.SYMTYPE, "/outside", 0
            archive.addfile(member, io.BytesIO(value))
    digest = hashlib.sha256(package).hexdigest() if defect != "hash" else "0" * 64
    monkeypatch.setitem(builder.OPENSSL_PACKAGES, architecture,
                        (debian_arch, library_arch, len(package) + (defect == "size"), digest))
    urls, commands, added = [], [], []

    def download(url, timeout):
        urls.append(url)
        assert timeout == 30
        return io.BytesIO(package)

    def ar(arguments, **kwargs):
        commands.append(arguments)
        assert kwargs["check"] is True
        return SimpleNamespace(stdout=data.getvalue())

    monkeypatch.setattr(builder.urllib.request, "urlopen", download)
    monkeypatch.setattr(builder.subprocess, "run", ar)
    monkeypatch.setattr(builder, "add_ssl_to_rootfs", lambda image, files: added.append((image, files)))
    image = tmp_path / "python.cpio"
    if defect:
        with pytest.raises(ValueError):
            builder.add_openssl(image, tmp_path, architecture)
        assert added == []
        if defect in {"hash", "size"}:
            assert commands == [] and not (tmp_path / "openssl.deb").exists()
    else:
        builder.add_openssl(image, tmp_path, architecture)
        expected["usr/share/common-licenses/Apache-2.0"] = (REPO / "jobs/licenses/hyperlight-LICENSE.txt").read_bytes()
        assert added == [(image, expected)]
        assert commands == [["ar", "p", str(tmp_path / "openssl.deb"), "data.tar.xz"]]
    assert urls[0].endswith(f"libssl3_{builder.OPENSSL_VERSION}_{debian_arch}.deb")
