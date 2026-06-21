from __future__ import annotations

from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget


class PlaceholderTab(QWidget):
    def __init__(self, title: str, message: str) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        heading = QLabel(title)
        heading.setObjectName("PageTitle")
        body = QLabel(message)
        body.setObjectName("Muted")
        body.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(body)
        layout.addStretch(1)
