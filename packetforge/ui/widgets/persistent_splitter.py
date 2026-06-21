from __future__ import annotations

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QSplitter, QWidget


class PersistentSplitter(QSplitter):
    """QSplitter that restores and saves pane sizes via QSettings."""

    def __init__(
        self,
        orientation: Qt.Orientation,
        settings_key: str,
        *,
        default_sizes: list[int] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(orientation, parent)
        self._settings_key = settings_key
        self._default_sizes = default_sizes or [400, 400]
        self.splitterMoved.connect(self._save_sizes)

    def restore(self, settings: QSettings | None = None) -> None:
        settings = settings or QSettings()
        raw = settings.value(self._settings_key)
        if isinstance(raw, list) and raw:
            sizes = [int(value) for value in raw]
            if len(sizes) == self.count():
                self.setSizes(sizes)
                return
        self.setSizes(self._default_sizes)

    def _save_sizes(self, *_pos: int) -> None:
        settings = QSettings()
        settings.setValue(self._settings_key, self.sizes())
