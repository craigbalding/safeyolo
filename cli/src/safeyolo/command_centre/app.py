"""Application entry point for SafeYolo Command Centre."""

from __future__ import annotations

import argparse
import sys

from PySide6.QtWidgets import QApplication, QMessageBox, QSystemTrayIcon

from safeyolo.config import get_admin_token, load_config
from safeyolo.coord.identity import get_or_create_instance_id

from .client import SafeYoloClient, default_event_url
from .credentials import CredentialStoreError, load_token, store_token
from .ui import CommandCentre


def _arguments(argv: list[str] | None = None) -> argparse.Namespace:
    config = load_config()
    admin_port = int(config.get("proxy", {}).get("admin_port", 9090))
    events_port = int(config.get("command_centre", {}).get("events_port", 9091))
    parser = argparse.ArgumentParser(description="SafeYolo Command Centre")
    parser.add_argument("--admin-url", default=f"http://127.0.0.1:{admin_port}")
    parser.add_argument("--events-url")
    parser.add_argument("--events-port", type=int, default=events_port)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _arguments(argv)
    application = QApplication(sys.argv[:1])
    application.setApplicationName("SafeYolo Command Centre")
    application.setQuitOnLastWindowClosed(False)

    if not QSystemTrayIcon.isSystemTrayAvailable():
        QMessageBox.critical(None, "SafeYolo", "The system tray is unavailable.")
        return 1

    instance_id = get_or_create_instance_id()
    token = None
    keychain_error = None
    try:
        token = load_token(instance_id)
    except CredentialStoreError as exc:
        keychain_error = str(exc)

    if token is None:
        token = get_admin_token()
        if token:
            try:
                store_token(instance_id, token)
            except CredentialStoreError as exc:
                keychain_error = str(exc)

    if not token:
        QMessageBox.critical(
            None,
            "SafeYolo",
            "No local Admin API credential is available. Run safeyolo init first.",
        )
        return 1

    events_url = args.events_url or default_event_url(args.admin_url, args.events_port)
    client = SafeYoloClient(
        admin_url=args.admin_url,
        events_url=events_url,
        token=token,
    )
    command_centre = CommandCentre(client)
    command_centre.start(application.quit)
    if keychain_error:
        command_centre.tray.showMessage(
            "SafeYolo Keychain",
            keychain_error,
            QSystemTrayIcon.MessageIcon.Warning,
        )
    result = application.exec()
    client.stop()
    return result


if __name__ == "__main__":
    raise SystemExit(main())
