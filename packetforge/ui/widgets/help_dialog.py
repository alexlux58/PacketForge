from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from packetforge.ui.help.topics import HelpTopic, help_topic


class HelpDialog(QDialog):
    """Scrollable help dialog for a tab or global topic."""

    def __init__(self, topic_key: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        topic = help_topic(topic_key)
        self.setWindowTitle(f"Help — {topic.title}")
        self.resize(560, 480)

        root = QVBoxLayout(self)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(14)
        self._fill(layout, topic)
        layout.addStretch(1)
        scroll.setWidget(body)
        root.addWidget(scroll, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    @staticmethod
    def _fill(layout: QVBoxLayout, topic: HelpTopic) -> None:
        intro = QLabel(topic.intro)
        intro.setWordWrap(True)
        intro.setObjectName("Muted")
        layout.addWidget(intro)

        for section in topic.sections:
            heading = QLabel(section.heading)
            font = heading.font()
            font.setPointSize(13)
            font.setBold(True)
            heading.setFont(font)
            layout.addWidget(heading)

            body = QLabel(section.body)
            body.setWordWrap(True)
            body.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
            layout.addWidget(body)

    @classmethod
    def show_for(cls, topic_key: str, parent: QWidget | None = None) -> None:
        dialog = cls(topic_key, parent)
        dialog.exec()
