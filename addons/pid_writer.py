"""
pid_writer.py - Write mitmproxy pid file atomically on ready, clean up on exit.

Loaded by the SafeYolo CLI (proxy.py::start_proxy) so the CLI's start routine
can wait for actual listener-ready without sleeps: the pid file appears only
after mitmproxy's `running` lifecycle event fires, which is AFTER all addons
have loaded and the listener is bound. Mitmdump's own early failures (addon
import errors, port collisions) never reach `running`, so the pid file never
appears -- the CLI observes the subprocess exit instead and surfaces the log.

Contract with the CLI:
  * Path is passed via env var SAFEYOLO_PROXY_PID_FILE (absolute path).
  * If the var is unset, this addon no-ops (lets mitmdump run standalone).
  * Writes os.getpid() + "\\n" on `running`.
  * Unlinks on `done` (graceful shutdown). Crashes/kills leave the stale
    file for the CLI to reconcile on next start.
"""

import os


class PidWriter:
    def __init__(self) -> None:
        self.path = os.environ.get("SAFEYOLO_PROXY_PID_FILE")

    def running(self) -> None:
        """mitmproxy lifecycle: fires after all addons loaded and the
        listener is bound. File appearance = proxy ready for traffic."""
        if not self.path:
            return
        with open(self.path, "w") as f:
            f.write(f"{os.getpid()}\n")

    def done(self) -> None:
        """Graceful shutdown -- remove our pid marker."""
        if not self.path:
            return
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            # Pid file already gone (e.g. CLI beat us to it on restart,
            # or `running` never fired so we never wrote it). Both are
            # fine -- nothing to clean up.
            pass


addons = [PidWriter()]
