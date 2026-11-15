#!/usr/bin/env python3
"""Create small #1553 metadata specimens, never a bootable guest.

Run on the selected Linux host with zstd and a guest-compatible /bin/cat.
The output must be a new disk-backed directory.
No host ownership, capability, ACL or device-node changes occur. Special
metadata and the GNU1.0 sparse map exist only in archive headers and data.
"""

import argparse
import hashlib
import io
import json
import struct
import subprocess
import tarfile
from pathlib import Path

BASE = 100000


def member(name, data=b"", *, uid=BASE, gid=BASE, mode=0o644, kind=tarfile.REGTYPE,
           link="", pax=None, device=(0, 0)):
    info = tarfile.TarInfo("rootfs-tree" + ("/" + name if name else ""))
    info.uid, info.gid, info.mode, info.type = uid, gid, mode, kind
    info.linkname, info.devmajor, info.devminor = link, *device
    info.pax_headers = pax or {}
    info.size = len(data)
    return info, data


def capability(revision):
    raw = struct.pack("<5I", (revision << 24) | 1, 1 << 10, 0, 0, 0)
    if revision == 3:
        raw += struct.pack("<I", BASE)
    return raw.decode("utf-8", "surrogateescape")


def create(output):
    output.mkdir(mode=0o700)
    external = output / "external-target"
    external.mkdir(mode=0o700)
    (external / "marker").write_bytes(b"external target must survive")
    cat = Path("/bin/cat").read_bytes()
    acl = "user::rwx,user:101000:r--,group::r-x,group:100033:--x,mask::r-x,other::---"
    ordinary = [
        member("regular", b"published-coordinate specimen\n"),
        member("private", mode=0o700, uid=101000, gid=101000, kind=tarfile.DIRTYPE),
        member("private/agent", b"private\n", uid=101000, gid=101000, mode=0o600),
        member("daemon", b"another guest identity\n", uid=100033, gid=100033),
        member("boundary", b"last delegated guest ID\n", uid=165535, gid=165535),
        member("executable", b"#!/bin/sh\nprintf 'fixture executed\\n'\n", mode=0o755),
        member("setid", cat, mode=0o6751),
        member("symlink", kind=tarfile.SYMTYPE, link="regular", mode=0o777),
        member("hardlink", kind=tarfile.LNKTYPE, link="rootfs-tree/regular"),
        member("fifo", kind=tarfile.FIFOTYPE, mode=0o600),
        member("acl-dir", kind=tarfile.DIRTYPE, mode=0o750,
               pax={"SCHILY.acl.access": acl, "SCHILY.acl.default": acl}),
        member("user-xattr", b"xattr\n", pax={"SCHILY.xattr.user.safeyolo.fixture": "preserved"}),
        member("cap-v3", cat, mode=0o755,
               pax={"SCHILY.xattr.security.capability": capability(3)}),
        member("sparse", b"2\n0\n4096\n67104768\n4096\n".ljust(512, b"\0")
               + b"start".ljust(4096, b"\0") + b"end".rjust(4096, b"\0"),
               pax={"GNU.sparse.major": "1", "GNU.sparse.minor": "0",
                    "GNU.sparse.name": "rootfs-tree/sparse", "GNU.sparse.realsize": "67108864"}),
    ]
    cases = {
        "canonical": ordinary,
        "devices": [member("character", kind=tarfile.CHRTYPE, device=(1, 3)),
                    member("block", kind=tarfile.BLKTYPE, device=(7, 0))],
        "v2-capability": [member("cap-v2", cat, mode=0o755,
                                 pax={"SCHILY.xattr.security.capability": capability(2)})],
        "raw-acl42": [member("acl42", mode=0o750, kind=tarfile.DIRTYPE,
                             pax={"SCHILY.acl.access": "user::rwx,user:42:r--,group::r-x,mask::r-x,other::---"})],
        "escaping-link": [member("escape", kind=tarfile.SYMTYPE, link=str(external)),
                          member("escape/marker", b"must not replace external target\n")],
    }
    result = {}
    for name, records in cases.items():
        path = output / (name + ".tar")
        with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
            cache = tarfile.TarInfo("cache-paths.txt")
            cache.uid = cache.gid = BASE
            for info, data in [member("", kind=tarfile.DIRTYPE, mode=0o755), (cache, b""), *records]:
                archive.addfile(info, io.BytesIO(data))
        compressed = path.with_suffix(".tar.zst")
        subprocess.run(["zstd", "-q", "-o", str(compressed), "--", str(path)], check=True)
        path.unlink()
        result[name] = {"path": str(compressed), "sha256": hashlib.sha256(compressed.read_bytes()).hexdigest(),
                        "scope": "supplementary metadata specimen; not a published or bootable guest"}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(create(args.output.absolute()), indent=2))


if __name__ == "__main__":
    main()
