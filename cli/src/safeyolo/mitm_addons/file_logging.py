"""
file_logging.py - Configure file logging at mitmproxy startup

Loaded first in addon chain to ensure logging is configured before other addons run.
"""

from safeyolo.core.utils import FileLoggingAddon

addons = [FileLoggingAddon()]
