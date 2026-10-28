"""Enter a private job root, then directly exec the broker's fixed argv.

The short-lived mapper exits before the command starts. This process keeps
its PID through exec so sshd observes the command's own wait status and pipes.
"""

import ctypes
import json
import os
import resource
import subprocess
from pathlib import Path


def enter_job_namespaces() -> None:
    """Map job IDs away from sshd, including its privilege-separated account."""
    os.setgroups([])
    job_pid = os.getpid()
    reader, writer = os.pipe()
    mapper = os.fork()
    if mapper == 0:
        os.close(writer)
        try:
            if os.read(reader, 1) != b"m":
                os._exit(1)
            # The mapper retains initial-namespace authority only for setup.
            # No command runs until the mapper has exited and been reaped.
            Path(f"/proc/{job_pid}/uid_map").write_text("0 65536 65536\n")
            Path(f"/proc/{job_pid}/gid_map").write_text("0 65536 65536\n")
        except OSError as error:
            os.write(2, f"job identity mapping failed: {error}\n".encode())
            os._exit(1)
        os._exit(0)

    os.close(reader)
    error = None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        # CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET. No PID namespace or
        # fork/wait wrapper can change the command's signal semantics.
        if libc.unshare(0x10000000 | 0x00020000 | 0x40000000) != 0:
            error = OSError(ctypes.get_errno(), "could not enter job namespaces")
        else:
            os.write(writer, b"m")
    finally:
        os.close(writer)
        _, status = os.waitpid(mapper, 0)
    if error is not None:
        raise error
    if status != 0:
        raise RuntimeError("job identity mapper failed")
    os.setresgid(0, 0, 0)
    os.setresuid(0, 0, 0)


def mount(*arguments: str) -> None:
    subprocess.run(["/usr/bin/mount", *arguments], check=True, stdin=subprocess.DEVNULL)


def enter_job_root() -> None:
    """Expose the shared lower with a private writable upper and minimal mounts."""
    mount("--make-rprivate", "/")
    private = Path("/run/job-private")
    mount("-t", "tmpfs", "-o", "mode=700", "tmpfs", str(private))
    for name in ("upper", "work", "root"):
        (private / name).mkdir()
    root = private / "root"
    mount(
        "-t",
        "overlay",
        "-o",
        f"lowerdir=/run/job-lower,upperdir={private}/upper,workdir={private}/work,userxattr",
        "overlay",
        str(root),
    )
    for name in ("input", "work", "proc", "sys", "dev", "tmp", "run", "home/agent"):
        (root / name).mkdir(parents=True, exist_ok=True)
    mount("--bind", "/input", str(root / "input"))
    # Existing proc shows PIDs, but their credentials and descriptors remain
    # outside this user namespace. A chroot or hidden PIDs alone is insufficient.
    mount("--bind", "/proc", str(root / "proc"))
    mount("--bind", "/sys", str(root / "sys"))
    mount("-o", "remount,bind,ro", str(root / "sys"))
    mount("-t", "tmpfs", "-o", "nosuid,mode=755", "tmpfs", str(root / "dev"))
    for device in ("null", "zero", "random", "urandom", "tty"):
        target = root / "dev" / device
        target.touch()
        mount("--bind", f"/dev/{device}", str(target))
    (root / "dev/pts").mkdir()
    mount("-t", "devpts", "-o", "newinstance,ptmxmode=0666,mode=0620,gid=5", "devpts", str(root / "dev/pts"))
    (root / "dev/ptmx").symlink_to("pts/ptmx")
    (root / "dev/fd").symlink_to("/proc/self/fd")
    for name, options in (("tmp", "mode=1777"), ("run", "mode=755"), ("home/agent", "mode=700,uid=1000,gid=1000")):
        mount("-t", "tmpfs", "-o", f"nosuid,nodev,{options}", "tmpfs", str(root / name))
    os.chown(root / "work", 1000, 1000)
    subprocess.run(["/usr/sbin/ip", "link", "set", "lo", "up"], check=True, stdin=subprocess.DEVNULL)
    # Remove the inherited observer tree before the fixed command can run.
    (root / ".observer-root").mkdir()
    os.chdir(root)
    subprocess.run(["/usr/sbin/pivot_root", ".", ".observer-root"], check=True, stdin=subprocess.DEVNULL)
    subprocess.run(["/usr/bin/umount", "-l", "/.observer-root"], check=True, stdin=subprocess.DEVNULL)
    Path("/.observer-root").rmdir()
    os.chdir("/work")


def main() -> None:
    with open("/safeyolo/job.json") as source:
        spec = json.load(source)
    enter_job_namespaces()
    enter_job_root()
    argv = spec["argv"]
    if spec["privilege"] == "unprivileged":
        argv = [
            "/usr/bin/setpriv",
            "--reuid=1000",
            "--regid=1000",
            "--clear-groups",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
            "--",
            *argv,
        ]
    # No old-root, namespace or observer descriptor is donated to the command.
    limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    os.closerange(3, limit)
    os.execvpe(
        argv[0],
        argv,
        {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/home/agent",
            "USER": "agent",
            "LOGNAME": "agent",
            "LANG": "C.UTF-8",
        },
    )


if __name__ == "__main__":
    main()
