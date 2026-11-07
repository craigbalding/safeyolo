"""Two-process notes application for the nested Docker qualification.

ROLE=store writes SQLite data under /data and listens on guest loopback:8090.
ROLE=api listens on loopback:8088 and forwards notes requests to the store.
Each process runs in its own inner container with guest host networking.
"""

import http.client
import json
import os
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROLE = os.environ["ROLE"]
assert ROLE in {"api", "store"}, ROLE
DATABASE = Path(os.environ.get("NOTES_DATA", "/data")) / "notes.sqlite"
if ROLE == "store":
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DATABASE) as database:
        database.execute("CREATE TABLE IF NOT EXISTS notes (text TEXT NOT NULL)")


class NotesRequest(BaseHTTPRequestHandler):
    def do_GET(self):
        self.notes()

    def do_POST(self):
        self.notes()

    def notes(self):
        if self.path != "/api/v1/notes":
            self.send_error(404)
            return
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if ROLE == "api":
            connection = http.client.HTTPConnection("127.0.0.1", 8090, timeout=10)
            try:
                connection.request(self.command, self.path, body,
                                   {"Content-Type": "application/json"})
                response = connection.getresponse()
                status, result = response.status, response.read()
            finally:
                connection.close()
        else:
            with sqlite3.connect(DATABASE) as database:
                if self.command == "POST":
                    database.execute("INSERT INTO notes VALUES (?)", (json.loads(body)["text"],))
                result = json.dumps([row[0] for row in database.execute("SELECT text FROM notes ORDER BY rowid")]).encode()
            status = 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(result)))
        self.end_headers()
        self.wfile.write(result)

    def log_message(self, *_args):
        # Keep the provider identity observation without logging credentials.
        print(json.dumps({"role": ROLE, "method": self.command, "path": self.path,
                          "caller_ids": self.headers.get_all("X-SafeYolo-Agent-ID", []),
                          "caller_names": self.headers.get_all("X-SafeYolo-Agent-Name", []),
                          "authorization_count": len(self.headers.get_all("Authorization", [])),
                          "legacy_identity_count": len(self.headers.get_all("X-SafeYolo-Agent", []))}), flush=True)


ThreadingHTTPServer(("127.0.0.1", 8090 if ROLE == "store" else 8088), NotesRequest).serve_forever()
