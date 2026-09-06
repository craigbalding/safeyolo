"""PySide6 menu-bar UI for SafeYolo Command Centre."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import (
    QAction,
    QColor,
    QDesktopServices,
    QFont,
    QIcon,
    QPainter,
    QPixmap,
)
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QInputDialog,
    QLabel,
    QMenu,
    QSystemTrayIcon,
    QVBoxLayout,
)

from .client import SafeYoloClient
from .model import ApprovalItem, approval_items


def command_centre_icon() -> QIcon:
    """Create a small, high-contrast status-bar icon without external assets."""
    pixmap = QPixmap(44, 44)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QColor("#ff2f92"))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(2, 2, 40, 40)
    painter.setPen(QColor("white"))
    font = QFont("Helvetica", 23, QFont.Weight.Bold)
    painter.setFont(font)
    painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "S")
    painter.end()
    return QIcon(pixmap)


class ApprovalDialog(QDialog):
    """Focused Allow / Deny decision for one trusted audit event."""

    def __init__(
        self,
        item: ApprovalItem,
        resolve: Callable[[ApprovalItem, bool, str | None], None],
    ) -> None:
        super().__init__()
        self.item = item
        self._resolve = resolve
        self.setWindowTitle("SafeYolo approval")
        self.setMinimumWidth(460)

        layout = QVBoxLayout(self)
        heading = QLabel(item.summary)
        heading.setWordWrap(True)
        heading_font = heading.font()
        heading_font.setBold(True)
        heading.setFont(heading_font)
        layout.addWidget(heading)

        fields = QFormLayout()
        for label, value in item.detail_rows:
            value_label = QLabel(value)
            value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            value_label.setWordWrap(True)
            fields.addRow(f"{label}:", value_label)
        layout.addLayout(fields)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        self.buttons = QDialogButtonBox()
        self.allow_button = self.buttons.addButton("Allow", QDialogButtonBox.ButtonRole.AcceptRole)
        self.deny_button = self.buttons.addButton("Deny", QDialogButtonBox.ButtonRole.DestructiveRole)
        self.buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        self.allow_button.clicked.connect(lambda: self._choose(True))
        self.deny_button.clicked.connect(lambda: self._choose(False))
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    def _choose(self, allow: bool) -> None:
        credential = None
        if allow and self.item.approval_type == "service":
            credential, accepted = QInputDialog.getText(
                self,
                "Service credential",
                "Existing SafeYolo vault credential name:",
            )
            if not accepted or not credential.strip():
                return
            credential = credential.strip()
        self.set_busy("Allowing…" if allow else "Denying…")
        self._resolve(self.item, allow, credential)

    def set_busy(self, message: str) -> None:
        self.status.setText(message)
        self.buttons.setEnabled(False)

    def set_error(self, message: str) -> None:
        self.status.setText(message)
        self.buttons.setEnabled(True)


class CommandCentre:
    """Own the menu-bar item and approval windows for one instance."""

    def __init__(self, client: SafeYoloClient) -> None:
        self.client = client
        self.icon = command_centre_icon()
        self.tray = QSystemTrayIcon(self.icon)
        self.tray.setToolTip("SafeYolo Command Centre")
        self.menu = QMenu()
        self.status_action = QAction("Connecting…")
        self.status_action.setEnabled(False)
        self.menu.addAction(self.status_action)
        self.menu.addSeparator()
        self._approval_actions: list[QAction] = []
        self._items: dict[str, ApprovalItem] = {}
        self._dialogs: dict[str, ApprovalDialog] = {}
        self._announced: set[str] = set()
        self._quit_action = QAction("Quit Command Centre")
        self.menu.addAction(self._quit_action)
        self.tray.setContextMenu(self.menu)

        client.connection_changed.connect(self._connection_changed)
        client.approvals_loaded.connect(self._approvals_loaded)
        client.action_finished.connect(self._action_finished)
        client.error.connect(self._error)

    def start(self, quit_callback: Callable[[], None]) -> None:
        self._quit_action.triggered.connect(quit_callback)
        self.tray.show()
        self.client.start()

    def _connection_changed(self, connected: bool) -> None:
        self.status_action.setText("Connected" if connected else "Reconnecting…")

    def _approvals_loaded(self, events: list[dict]) -> None:
        items = approval_items(events)
        current_keys = {item.key for item in items}
        self._items = {item.key: item for item in items}

        for action in self._approval_actions:
            self.menu.removeAction(action)
            action.deleteLater()
        self._approval_actions.clear()

        insert_before = self._quit_action
        if not items:
            action = QAction("No pending approvals")
            action.setEnabled(False)
            self.menu.insertAction(insert_before, action)
            self._approval_actions.append(action)
        else:
            count = QAction(f"{len(items)} pending approval(s)")
            count.setEnabled(False)
            self.menu.insertAction(insert_before, count)
            self._approval_actions.append(count)
            for item in items:
                action = QAction(item.title)
                action.triggered.connect(lambda _checked=False, key=item.key: self.show_approval(key))
                self.menu.insertAction(insert_before, action)
                self._approval_actions.append(action)

        for key in list(self._dialogs):
            if key not in current_keys:
                self._dialogs.pop(key).accept()
        self._announced.intersection_update(current_keys)

        new_items = [item for item in items if item.key not in self._announced]
        if new_items:
            self._announced.update(item.key for item in new_items)
            self.tray.showMessage(
                "SafeYolo approval needed",
                new_items[0].title,
                QSystemTrayIcon.MessageIcon.Warning,
            )
            self.show_approval(new_items[0].key)

    def show_approval(self, key: str) -> None:
        item = self._items.get(key)
        if item is None:
            return
        dialog = self._dialogs.get(key)
        if dialog is None:
            dialog = ApprovalDialog(item, self._resolve)
            dialog.finished.connect(lambda _result, key=key: self._dialogs.pop(key, None))
            self._dialogs[key] = dialog
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    def _resolve(
        self,
        item: ApprovalItem,
        allow: bool,
        credential: str | None,
    ) -> None:
        self.client.resolve(
            item.event,
            allow=allow,
            service_credential=credential,
        )

    def _action_finished(self, approval_key: str, success: bool, result: object) -> None:
        matching = [dialog for dialog in self._dialogs.values() if dialog.item.key == approval_key]
        if success:
            for dialog in matching:
                dialog.accept()
            if isinstance(result, dict) and result.get("url") and result.get("unlock_code"):
                QApplication.clipboard().setText(str(result["unlock_code"]))
                QDesktopServices.openUrl(QUrl(str(result["url"])))
                message = "Unlock code copied; desktop opened in your browser."
            else:
                message = str(result)
            self.tray.showMessage("SafeYolo", message)
        else:
            message = str(result)
            for dialog in matching:
                dialog.set_error(message)
            self.tray.showMessage(
                "SafeYolo action failed",
                message,
                QSystemTrayIcon.MessageIcon.Critical,
            )

    def _error(self, message: str) -> None:
        self.status_action.setText(f"Error: {message}")
