"""Distribution fixture shared by OCI publication and nested Docker proof.

Run the standalone server inside the owned provider guest with a new disk-backed
directory, ready-file and events-file. It listens only on guest loopback. Docker
seeds it from the retained application image; it never fetches external images.
"""

import argparse
import hashlib
import json
import os
import shutil
import signal
import threading
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


@contextmanager
def distribution_registry(directory=None, events_file=None):
    """Keep publisher controls in memory, or stream Docker blobs to disk."""
    blobs, manifests, tags, uploads, events = {}, {}, {}, {}, []
    faults = {"blob": False, "index": False, "upload": False, "promotion": False}
    if directory is not None:
        directory.mkdir(parents=True)

    class Registry(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            return

        def handle(self):
            try:
                super().handle()
            except (ConnectionResetError, BrokenPipeError):
                # Digest-failure controls and Docker's HTTPS-to-HTTP loopback
                # fallback can close a connection before reading its response.
                return

        def body_blocks(self):
            # Docker 26's blob_writer.ReadFrom sends chunked PATCH bodies and
            # consumes the returned Range. ORAS uses Content-Length here.
            chunked = self.headers.get("Transfer-Encoding", "").lower() == "chunked"
            remaining = int(self.rfile.readline().split(b";", 1)[0], 16) if chunked else int(self.headers.get("Content-Length", 0))
            while remaining:
                block = self.rfile.read(min(remaining, 64 * 1024))
                if not block:
                    raise EOFError("incomplete registry upload")
                remaining -= len(block)
                yield block
                if chunked and not remaining:
                    assert self.rfile.read(2) == b"\r\n"
                    remaining = int(self.rfile.readline().split(b";", 1)[0], 16)
            if chunked:
                while self.rfile.readline() not in (b"\r\n", b""):
                    pass

        def reply(self, status, data=b"", **headers):
            size = data.stat().st_size if isinstance(data, Path) else len(data)
            if events_file is not None:
                with events_file.open("a") as log:
                    log.write(json.dumps({"method": self.command, "path": self.path, "status": status,
                                          "bytes": size, "digest": headers.get("Docker_Content_Digest")}) + "\n")
            self.send_response(status)
            self.send_header("Content-Length", str(size))
            self.send_header("Docker-Distribution-Api-Version", "registry/2.0")
            for key, value in headers.items():
                self.send_header(key.replace("_", "-"), value)
            self.end_headers()
            if self.command != "HEAD":
                if isinstance(data, Path):
                    with data.open("rb") as blob:
                        shutil.copyfileobj(blob, self.wfile, 64 * 1024)
                else:
                    self.wfile.write(data)

        def upload(self, request):
            path = request.path
            if self.command == "POST":
                token = uuid.uuid4().hex
                uploads[token] = directory / token if directory is not None else b""
            else:
                token = path.rsplit("/", 1)[1]
            data = uploads[token]
            if isinstance(data, Path):
                with data.open("ab") as upload:
                    for block in self.body_blocks():
                        upload.write(block)
                size = data.stat().st_size
            else:
                uploads[token] += b"".join(self.body_blocks())
                data = uploads[token]
                size = len(data)
            location = f"/v2/guest/blobs/uploads/{token}"
            if self.command in {"POST", "PATCH"}:
                return self.reply(202, Location=location, Docker_Upload_UUID=token, Range=f"0-{max(0, size - 1)}")
            digest = parse_qs(request.query)["digest"][0]
            if isinstance(data, Path):
                with data.open("rb") as blob:
                    actual = "sha256:" + hashlib.file_digest(blob, "sha256").hexdigest()
            else:
                actual = "sha256:" + hashlib.sha256(data).hexdigest()
            if digest != actual:
                return self.reply(400)
            blobs[digest] = data
            return self.reply(201, Location=f"/v2/guest/blobs/{digest}", Docker_Content_Digest=digest)

        def dispatch(self):
            request = urlsplit(self.path)
            path = request.path
            events.append((self.command, path))
            if "/blobs/uploads" in path:
                return self.upload(request)
            body = b"".join(self.body_blocks())
            if path in ("/v2/", "/v2"):
                return self.reply(200, b"{}")
            if path.endswith("/tags/list"):
                return self.reply(200, json.dumps({"name": "guest", "tags": list(tags)}).encode(),
                                  Content_Type="application/json")
            if "/blobs/" in path:
                digest = path.rsplit("/", 1)[1]
                if digest not in blobs:
                    return self.reply(404)
                data = blobs[digest]
                if (faults["blob"] is True or faults["blob"] == digest) and self.command == "GET":
                    if isinstance(data, Path):
                        data = data.read_bytes()
                    data = b"!" + data[1:]
                return self.reply(200, data, Content_Type="application/octet-stream", Docker_Content_Digest=digest)
            if "/manifests/" in path:
                reference = path.rsplit("/", 1)[1]
                if self.command == "PUT":
                    if faults["upload"] or (faults["promotion"] and reference == "compat-v1"):
                        return self.reply(400)
                    digest = "sha256:" + hashlib.sha256(body).hexdigest()
                    manifests[digest] = body
                    if not reference.startswith("sha256:"):
                        tags[reference] = digest
                    return self.reply(201, Location=path, Docker_Content_Digest=digest)
                digest = tags.get(reference, reference)
                if digest not in manifests:
                    return self.reply(404)
                data = manifests[digest]
                if faults["index"] and self.command == "GET" and "manifests" in json.loads(data):
                    data = b" " + data
                return self.reply(200, data, Content_Type=json.loads(data)["mediaType"], Docker_Content_Digest=digest)
            return self.reply(404)

        do_GET = do_HEAD = do_POST = do_PATCH = do_PUT = dispatch

    server = ThreadingHTTPServer(("127.0.0.1", 0), Registry)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"127.0.0.1:{server.server_port}/guest", blobs, manifests, tags, events, faults
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--ready-file", required=True, type=Path)
    parser.add_argument("--events-file", required=True, type=Path)
    args = parser.parse_args()
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    with distribution_registry(args.directory, args.events_file) as registry:
        pending = args.ready_file.with_suffix(".pending")
        pending.write_text(json.dumps({"repository": registry[0], "pid": os.getpid()}))
        pending.replace(args.ready_file)
        stopped.wait()


if __name__ == "__main__":
    main()
