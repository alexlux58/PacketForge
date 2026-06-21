from __future__ import annotations

from collections.abc import Callable

from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from packetforge.errors import ErrorEvent

_SEVERITY_STYLE: dict[str, str] = {
    "info": "background:#1d3a5f; color:#dbeafe; border:1px solid #3b6ea5;",
    "warning": "background:#5a4a16; color:#fff3cd; border:1px solid #e0b400;",
    "error": "background:#5a1f1a; color:#ffd9d2; border:1px solid #c4453a;",
    "critical": "background:#6e1410; color:#ffe0db; border:1px solid #ff5a4d;",
}


class ErrorBanner(QWidget):
    """A dismissible, non-modal banner that shows a safe error summary.

    It never shows the traceback and never raises out of its own callbacks, so a
    failed network operation can surface here without crashing the GUI thread.
    """

    def __init__(self) -> None:
        super().__init__()
        self._on_retry: Callable[[], None] | None = None
        self._detail_text = ""

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        self._frame = QWidget()
        self._frame.setObjectName("ErrorBannerFrame")
        layout = QVBoxLayout(self._frame)
        layout.setContentsMargins(10, 8, 10, 8)

        top = QHBoxLayout()
        self._message = QLabel()
        self._message.setWordWrap(True)
        top.addWidget(self._message, 1)

        self.retry_button = QPushButton("Retry")
        self.retry_button.clicked.connect(self._retry)
        top.addWidget(self.retry_button)

        self.details_button = QPushButton("Details")
        self.details_button.setCheckable(True)
        self.details_button.toggled.connect(self._toggle_details)
        top.addWidget(self.details_button)

        self.dismiss_button = QPushButton("Dismiss")
        self.dismiss_button.clicked.connect(self.clear)
        top.addWidget(self.dismiss_button)
        layout.addLayout(top)

        self._detail_label = QLabel()
        self._detail_label.setWordWrap(True)
        self._detail_label.setVisible(False)
        layout.addWidget(self._detail_label)

        outer.addWidget(self._frame)
        self.setVisible(False)

    def show_event(self, event: ErrorEvent, *, on_retry: Callable[[], None] | None = None) -> None:
        self._on_retry = on_retry
        self._detail_text = event.detail
        self._frame.setStyleSheet(
            f"#ErrorBannerFrame {{ border-radius:6px; "
            f"{_SEVERITY_STYLE.get(event.severity, _SEVERITY_STYLE['error'])} }}"
        )
        self._message.setText(f"{event.source}: {event.gui_summary}")
        self.retry_button.setVisible(on_retry is not None)
        self.details_button.setChecked(False)
        self.details_button.setVisible(bool(event.detail))
        self._detail_label.setVisible(False)
        self._detail_label.setText(event.detail)
        self.setVisible(True)

    def clear(self) -> None:
        self._on_retry = None
        self.setVisible(False)

    def _retry(self) -> None:
        callback = self._on_retry
        self.clear()
        if callback is not None:
            callback()

    def _toggle_details(self, checked: bool) -> None:
        self._detail_label.setVisible(checked and bool(self._detail_text))
