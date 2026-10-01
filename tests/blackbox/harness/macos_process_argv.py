"""Read a macOS process's exact argument vector when the seatbelt denies ps."""

import ctypes
import os
import sys


def process_argv(pid: int) -> list[bytes]:
    """Return kernel-reported argv without including the process environment."""
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    sysctl = libc.sysctl
    sysctl.argtypes = [
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_uint,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    sysctl.restype = ctypes.c_int
    mib = (ctypes.c_int * 3)(1, 49, pid)  # CTL_KERN, KERN_PROCARGS2, PID
    size = ctypes.c_size_t()
    if sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    data = ctypes.create_string_buffer(size.value)
    if sysctl(mib, 3, data, ctypes.byref(size), None, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))

    raw = data.raw[: size.value]
    if len(raw) < ctypes.sizeof(ctypes.c_int):
        raise ValueError("macOS process arguments are truncated")
    argc = ctypes.c_int.from_buffer_copy(raw).value
    if argc < 1:
        raise ValueError("macOS process has no arguments")

    # KERN_PROCARGS2 begins with argc, the executable path, zero padding,
    # then argc NUL-terminated arguments. Bytes after argv are environment.
    offset = raw.find(b"\0", ctypes.sizeof(ctypes.c_int))
    if offset < 0:
        raise ValueError("macOS process executable path is unterminated")
    offset += 1
    while offset < len(raw) and raw[offset] == 0:
        offset += 1
    argv = []
    for _ in range(argc):
        end = raw.find(b"\0", offset)
        if end < 0:
            raise ValueError("macOS process argument is unterminated")
        argv.append(raw[offset:end])
        offset = end + 1
    return argv


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: macos_process_argv.py PID")
    arguments = process_argv(int(sys.argv[1]))
    sys.stdout.buffer.write(b"\0".join(arguments) + b"\0")
