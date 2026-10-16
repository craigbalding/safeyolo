"""Authenticate to the guest's SSH server on every selected backend."""

import os
import stat
import subprocess
import tempfile
from pathlib import Path


class TestGuestSSH:
    """The default guest retains working key-only SSH access.

    Why: Linux agent shell uses runsc, so a shell or SSH banner alone does
    not prove that the shipped SSH server can authenticate an agent.
    """

    def test_guest_server_accepts_owned_key_and_refuses_unknown_key(self):
        """Guest SSH executes a command only with an authorized key.

        What: Add a disposable public key to the owned agent's authorized
        keys, pin the guest's existing public host key, and connect on loopback.
        Check the reached UID and an unknown-key refusal, then restore the keys.
        Why: Both SSH packages and the existing authentication controls must
        work on gVisor and VZ after the image package reduction.
        """
        assert os.getuid() == 1000, "run the SSH witness as the ordinary agent"
        authorized = Path('/home/agent/.ssh/authorized_keys')
        authorized.parent.mkdir(mode=0o700, exist_ok=True)
        original = authorized.read_bytes() if authorized.exists() else None
        original_mode = stat.S_IMODE(authorized.stat().st_mode) if original is not None else None
        host_key = Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()
        assert host_key[0] == 'ssh-ed25519'
        with tempfile.TemporaryDirectory(prefix='safeyolo-ssh-') as scratch:
            directory = Path(scratch)
            known = directory / 'known_hosts'
            known.write_text(f'127.0.0.1 {host_key[0]} {host_key[1]}\n')
            for name in ('accepted', 'unknown'):
                subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(directory / name)],
                               check=True, capture_output=True, timeout=10)
            command = ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
                       '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
                       '-o', 'PreferredAuthentications=publickey', '-o', 'StrictHostKeyChecking=yes',
                       '-o', 'GlobalKnownHostsFile=/dev/null', '-o', f'UserKnownHostsFile={known}',
                       '-o', 'HostKeyAlgorithms=ssh-ed25519']
            try:
                authorized.write_bytes((original or b'') + b'\n' + (directory / 'accepted.pub').read_bytes())
                authorized.chmod(0o600)
                accepted = subprocess.run([*command, '-i', str(directory / 'accepted'), 'agent@127.0.0.1',
                                           'id -u; printf "safeyolo-ssh-ok\\n"'],
                                          capture_output=True, text=True, timeout=15)
                assert accepted.returncode == 0, accepted.stderr
                assert accepted.stdout.splitlines() == ['1000', 'safeyolo-ssh-ok']
                unknown = subprocess.run([*command, '-i', str(directory / 'unknown'), 'agent@127.0.0.1', 'true'],
                                         capture_output=True, text=True, timeout=15)
                assert unknown.returncode == 255 and 'Permission denied' in unknown.stderr, unknown.stderr
            finally:
                if original is None:
                    authorized.unlink(missing_ok=True)
                else:
                    authorized.write_bytes(original)
                    authorized.chmod(original_mode)
