"""Supply the installed Mac proxy's private tmux without changing host tools.

Linux bootstrap supplies the supported system tmux prerequisite. On macOS,
reuse a private runtime from the selected installation if present; otherwise
build pinned sources on Tart. Link third-party libraries statically so offline
Bristol needs only macOS libraries and the system terminfo database. This is
an acceptance input producer, not the self-contained release artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

# GitHub release-asset SHA-256 values, checked through the authenticated API.
# Keep sources and their licenses together when changing these pins.
TMUX_VERSION = "3.7c"
SOURCES = {
    "tmux": (f"https://github.com/tmux/tmux/releases/download/{TMUX_VERSION}/tmux-{TMUX_VERSION}.tar.gz",
             "7c60cae9a0e25288e2e24750aafc9e8800fc7fd4555e447e1b29ee4201cfb3bf"),
    "libevent": ("https://github.com/libevent/libevent/releases/download/release-2.1.13-stable/libevent-2.1.13-stable.tar.gz",
                 "f7e9383b8c0baa81b687e5b5eecc01beefaf1b19b64151d95ed61647fe7a315c"),
    "utf8proc": ("https://github.com/JuliaStrings/utf8proc/releases/download/v2.12.0/utf8proc-2.12.0.tar.gz",
                 "a393fbef160835fb315bc3e91ba8d86f7a73a7cec9e6198b6c60b848b498bfeb"),
}


def source_archive(name: str, directory: Path) -> Path:
    """Verify the release before parsing it; extract within owned scratch."""
    url, expected = SOURCES[name]
    archive = directory / f"{name}.tar.gz"
    with urllib.request.urlopen(url, timeout=60) as response, archive.open("xb") as output:
        shutil.copyfileobj(response, output)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise ValueError(f"{name} release archive differs from its selected SHA-256")
    extracted = directory / name
    extracted.mkdir()
    with tarfile.open(archive) as bundle:
        bundle.extractall(extracted, filter="data")
    roots = list(extracted.iterdir())
    if len(roots) != 1 or not roots[0].is_dir():
        raise ValueError(f"{name} release needs one source directory")
    return roots[0]


def verify_mac_tmux(binary: Path, *, env: dict | None = None) -> str:
    """Reject a build-host library dependency before offline transfer."""
    subprocess.run(["codesign", "--verify", "--strict", str(binary)], env=env, check=True, timeout=30)
    libraries = subprocess.check_output(["otool", "-L", str(binary)], env=env, text=True, timeout=30)
    lines = libraries.splitlines()
    if len(lines) < 2 or lines[0] != f"{binary}:":
        raise ValueError("private tmux has no complete Mac library observation")
    for line in lines[1:]:
        library = line.strip().split(" (", 1)[0]
        if not library.startswith(("/usr/lib/", "/System/Library/")):
            raise ValueError(f"private tmux depends on a non-system Mac library: {library}")
    version = subprocess.check_output([str(binary), "-V"], env=env, text=True, timeout=30).strip()
    if re.fullmatch(r"tmux [0-9]+(?:\.[0-9]+)*[a-z]?", version) is None:
        raise ValueError("private tmux has no observed release version")
    return version


def build_mac_tmux(root: Path) -> Path:
    """Build one relocatable signed tmux; retain third-party license notices."""
    if platform.system() != "Darwin":
        raise ValueError("private Mac tmux needs a macOS build host")
    binary = root / "bin/safeyolo-tmux"
    if binary.exists():
        raise FileExistsError(binary)
    binary.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="safeyolo-tmux-", dir=Path.home()) as temporary:
        scratch = Path(temporary)
        sources = {name: source_archive(name, scratch) for name in SOURCES}
        prefix = scratch / "prefix"
        env = os.environ.copy()
        for name in ("CFLAGS", "CPPFLAGS", "LDFLAGS", "LIBS", "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR",
                     "DYLD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES"):
            env.pop(name, None)
        env.update(CFLAGS="-O2", PKG_CONFIG="/usr/bin/false")

        def run(command, source, *, build_env=env):
            subprocess.run(command, cwd=source, env=build_env, check=True, timeout=600)

        run(["./configure", f"--prefix={prefix}", "--disable-shared", "--enable-static",
             "--disable-openssl", "--disable-libevent-regress", "--disable-samples"], sources["libevent"])
        run(["make", "-j1", "install"], sources["libevent"])
        run(["make", "-j1", "libutf8proc.a"], sources["utf8proc"])
        tmux_env = {**env,
                    "LIBEVENT_CORE_CFLAGS": f"-I{prefix / 'include'}",
                    "LIBEVENT_CORE_LIBS": str(prefix / "lib/libevent_core.a"),
                    "LIBNCURSES_CFLAGS": " ", "LIBNCURSES_LIBS": "-lncurses",
                    "LIBUTF8PROC_CFLAGS": f"-I{sources['utf8proc']}",
                    "LIBUTF8PROC_LIBS": str(sources["utf8proc"] / "libutf8proc.a")}
        run(["./configure", "--enable-utf8proc", "--disable-utempter", "--disable-systemd"],
            sources["tmux"], build_env=tmux_env)
        run(["make", "-j1"], sources["tmux"], build_env=tmux_env)
        built = sources["tmux"] / "tmux"
        run(["codesign", "--force", "--sign", "-", "--timestamp=none", str(built)], sources["tmux"])
        if verify_mac_tmux(built, env=env) != f"tmux {TMUX_VERSION}":
            raise ValueError("private tmux build does not report its selected version")
        licenses = root / "share/tmux-licenses"
        licenses.mkdir(parents=True, exist_ok=False)
        for name, filename in (("tmux", "COPYING"), ("libevent", "LICENSE"), ("utf8proc", "LICENSE.md")):
            shutil.copy2(sources[name] / filename, licenses / f"{name}.txt")
        shutil.copy2(built, binary)
        binary.chmod(0o755)
    return binary


def prepare_tmux(cli: Path, root: Path) -> dict:
    """Resolve through the selected installed CLI, excluding Mac system fallback."""
    python = Path(cli.read_text().splitlines()[0][2:])
    env = os.environ.copy()
    env.pop("SAFEYOLO_TMUX_BIN", None)
    env["SAFEYOLO_CONFIG_DIR"] = str(root)
    code = """
import json, platform
from safeyolo.traffic_session import find_private_tmux
try:
    path = str(find_private_tmux(allow_system=platform.system() == 'Linux'))
except RuntimeError:
    path = None
print(json.dumps(path))
"""
    selected = json.loads(subprocess.check_output([str(python), "-I", "-c", code],
                                                  env=env, text=True, timeout=30))
    if selected is None:
        if platform.system() == "Linux":
            raise RuntimeError("installed Linux preparation needs bootstrap's tmux prerequisite")
        selected = str(build_mac_tmux(root))
    binary = Path(selected)
    version = (verify_mac_tmux(binary) if platform.system() == "Darwin" else
               subprocess.check_output([str(binary), "-V"], text=True, timeout=30).strip())
    return {"path": str(binary), "version": version,
            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--config-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare_tmux(args.cli.resolve(), args.config_dir.resolve())))


if __name__ == "__main__":
    main()
