"""SafeYolo CLI - Security proxy for AI coding agents."""

import time

# Captured before the CLI imports its command tree. Lifecycle profiling uses
# this to include import and argument-parsing time rather than starting the
# clock only after Typer has dispatched the selected command.
PROCESS_STARTED_AT_NS = time.monotonic_ns()

__version__ = "0.1.1"
