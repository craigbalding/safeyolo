#!/usr/bin/env python3
"""Called by native acceptance inside its disposable account/entry fixture."""

import os
import pwd
import select
import shlex
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=20, **kwargs)


def main():
    lab = Path(sys.argv[1])
    account = sys.argv[2]
    source = Path(__file__).resolve().parent
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        ssh_port = reservation.getsockname()[1]
    host_key = lab / "server-key"
    run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key))
    config = lab / "live-sshd_config"
    config.write_text(f"ListenAddress 127.0.0.1\nPort {ssh_port}\nHostKey {host_key}\nUsePAM no\nAllowUsers {account}\n")
    run("/bin/sh", str(source / "configure-ssh"), "--user", account, "--config", str(config))

    class ConnectProxy(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(10)
            assert self.rfile.readline() == f"CONNECT 127.0.0.1:{ssh_port} HTTP/1.1\r\n".encode()
            while self.rfile.readline() != b"\r\n":
                pass
            with socket.create_connection(("127.0.0.1", ssh_port), timeout=10) as upstream:
                self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                self.wfile.flush()
                while ready := select.select([self.connection, upstream], [], [], 10)[0]:
                    for stream in ready:
                        chunk = stream.recv(65536)
                        if not chunk:
                            return
                        (upstream if stream is self.connection else self.connection).sendall(chunk)

    # This local fixture tests OpenSSH/stdio integration. Real SafeYolo policy
    # admission and denial are separately covered by test_seatbelt_client.py.
    proxy = socketserver.ThreadingTCPServer(("127.0.0.1", 0), ConnectProxy)
    proxy.daemon_threads = True
    proxy_thread = threading.Thread(target=proxy.serve_forever)
    with (lab / "live-sshd.log").open("w") as log:
        daemon = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while True:
                assert daemon.poll() is None, (lab / "live-sshd.log").read_text()
                try:
                    with socket.create_connection(("127.0.0.1", ssh_port), timeout=0.1):
                        break
                except OSError:
                    assert time.monotonic() < deadline, "sshd readiness deadline expired"
                    time.sleep(0.05)
            proxy_thread.start()
            client = lab / "client"
            (client / ".ssh").mkdir(parents=True)
            for suffix in ("", ".pub"):
                shutil.copyfile(lab / ("client-key" + suffix), client / ".ssh" / ("id_ed25519_sy_agent" + suffix))
            (client / ".ssh/id_ed25519_sy_agent").chmod(0o600)
            env = {**os.environ, "HOME": str(client), "HTTPS_PROXY": f"http://127.0.0.1:{proxy.server_address[1]}"}
            handoff = f"127.0.0.1\n{ssh_port}\n{host_key.with_suffix('.pub').read_text()}"
            run(sys.executable, str(source / "configure-client"), "--user", account, input=handoff, text=True, env=env)
            ssh = ["/usr/bin/ssh", "-F", str(client / ".ssh/seatbelt-agent/config"), "seatbelt-mac"]
            identity = run(*ssh, "id", env=env).stdout
            assert identity.startswith(f"uid={pwd.getpwnam(account).pw_uid}".encode()), identity
            payload = bytes(range(256)) * 1024
            assert run(*ssh, "/bin/cat", env=env, input=payload).stdout == payload
            canary = lab / "outside-canary"
            canary.write_text("outside the allowed entry tree\n")
            run("sudo", "-n", "-u", account, "/bin/cat", str(canary))
            denied = subprocess.run([*ssh, f"/bin/cat {shlex.quote(str(canary))}"], env=env, capture_output=True, timeout=20)
            assert denied.returncode != 0 and not denied.stdout
            run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(lab / "wrong-key"))
            wrong = f"127.0.0.1\n{ssh_port}\n{(lab / 'wrong-key.pub').read_text()}"
            run(sys.executable, str(source / "configure-client"), "--user", account, input=wrong, text=True, env=env)
            rejected = subprocess.run([*ssh, "id"], env=env, capture_output=True, timeout=20)
            assert rejected.returncode == 255 and b"Host key verification failed" in rejected.stderr
            print("PASS: generated client config, fresh confined SSH login, binary stdin/stdout and host-key mismatch rejection")
        finally:
            if proxy_thread.is_alive():
                proxy.shutdown()
                proxy_thread.join(timeout=5)
            proxy.server_close()
            daemon.terminate()
            try:
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=5)


if __name__ == "__main__":
    main()
