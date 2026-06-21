from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget


class EmptyStateWidget(QWidget):
    """Muted placeholder shown when a table or panel has no rows yet."""

    def __init__(self, message: str, *, hint: str = "") -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.message = QLabel(message)
        self.message.setObjectName("Muted")
        self.message.setWordWrap(True)
        self.message.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.message)
        self.hint = QLabel(hint)
        self.hint.setObjectName("Muted")
        self.hint.setWordWrap(True)
        self.hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        if hint:
            layout.addWidget(self.hint)
        self.setVisible(False)

    def set_message(self, message: str, *, hint: str = "") -> None:
        self.message.setText(message)
        self.hint.setText(hint)
        self.hint.setVisible(bool(hint))
