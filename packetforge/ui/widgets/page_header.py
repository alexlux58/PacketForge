from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from packetforge.ui.widgets.help_dialog import HelpDialog


class PageHeader(QWidget):
    """Page title row with optional subtitle and help (i) button."""

    def __init__(
        self,
        title: str,
        help_key: str,
        *,
        subtitle: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._help_key = help_key

        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("PageTitle")
        text_col.addWidget(self.title_label)

        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setObjectName("Muted")
        self.subtitle_label.setWordWrap(True)
        self.subtitle_label.setVisible(bool(subtitle))
        text_col.addWidget(self.subtitle_label)
        row.addLayout(text_col, 1)

        self.help_button = QPushButton("i")
        self.help_button.setObjectName("HelpButton")
        self.help_button.setFixedSize(28, 28)
        self.help_button.setToolTip("How to use and interpret this tool")
        self.help_button.setAccessibleName("Help")
        self.help_button.clicked.connect(self._open_help)
        row.addWidget(self.help_button, 0, Qt.AlignmentFlag.AlignTop)

    def set_subtitle(self, text: str) -> None:
        self.subtitle_label.setText(text)
        self.subtitle_label.setVisible(bool(text))

    def _open_help(self) -> None:
        HelpDialog.show_for(self._help_key, self)
