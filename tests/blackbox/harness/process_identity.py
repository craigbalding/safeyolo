"""Standalone black-box observer for native Linux/macOS process birth receipts.

Adapted from the retired runtime_identity reader. Product execution does not
import this test instrument; it needs only the standard library.
"""

import ctypes
import errno
import os
import sys
from pathlib import Path


class _DarwinBSDInfo(ctypes.Structure):
    """The proc_bsdinfo layout in macOS sys/proc_info.h."""

    _fields_ = [
        (name, ctypes.c_uint32) for name in (
            "pbi_flags", "pbi_status", "pbi_xstatus", "pbi_pid", "pbi_ppid",
            "pbi_uid", "pbi_gid", "pbi_ruid", "pbi_rgid", "pbi_svuid",
            "pbi_svgid", "rfu_1",
        )
    ] + [
        ("pbi_comm", ctypes.c_char * 16),
        ("pbi_name", ctypes.c_char * 32),
    ] + [
        (name, ctypes.c_uint32) for name in (
            "pbi_nfiles", "pbi_pgid", "pbi_pjobc", "e_tdev", "e_tpgid",
        )
    ] + [
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]


def _darwin_process_info(process_id: int) -> _DarwinBSDInfo | None:
    """Read kernel process data without invoking ps, which may be seatbelt-denied."""
    info = _DarwinBSDInfo()
    if ctypes.sizeof(info) != 136:
        raise RuntimeError("Unexpected macOS process information layout")
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    pidinfo = libproc.proc_pidinfo
    pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    pidinfo.restype = ctypes.c_int
    ctypes.set_errno(0)
    size = pidinfo(process_id, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
    if size == 0 and ctypes.get_errno() == errno.ESRCH:
        return None
    if size != ctypes.sizeof(info):
        error = ctypes.get_errno() or errno.EIO
        raise OSError(error, os.strerror(error))
    if info.pbi_pid != process_id or not info.pbi_start_tvsec or info.pbi_start_tvusec >= 1_000_000:
        raise RuntimeError("Invalid macOS process information")
    return info


def _macos_process_start_token(process_id: int) -> str | None:
    """Read a PID's kernel start time without requiring process-list access."""
    try:
        info = _darwin_process_info(process_id)
    except (AttributeError, OSError, RuntimeError):
        return None
    if info is None:
        return None
    return f"darwin:{process_id}:{info.pbi_start_tvsec}:{info.pbi_start_tvusec}"


def process_start_token(process_id: int) -> str | None:
    """Return an OS-backed token that changes when a PID is reused."""
    if sys.platform.startswith("linux"):
        try:
            stat_text = Path(f"/proc/{process_id}/stat").read_text()
            # The command field can contain spaces or parentheses. Fields after
            # its final ')' begin at stat field 3; starttime is field 22.
            fields_after_command = stat_text.rsplit(")", 1)[1].split()
            start_ticks = fields_after_command[19]
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        except (IndexError, OSError):
            return None
        return f"linux:{boot_id}:{process_id}:{start_ticks}"

    if sys.platform == "darwin":
        token = _macos_process_start_token(process_id)
        if token is not None:
            return token

    return None
