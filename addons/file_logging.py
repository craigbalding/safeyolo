"""
file_logging.py - Configure file logging at mitmproxy startup

Loaded first in addon chain to ensure logging is configured before other addons run.
"""

from utils import FileLoggingAddon

addons = [FileLoggingAddon()]
