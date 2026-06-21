from __future__ import annotations

from PySide6.QtCore import QSettings


class AppPreferences:
    """Typed accessors for user preferences stored in QSettings."""

    def __init__(self, settings: QSettings | None = None) -> None:
        self._settings = settings or QSettings()

    @property
    def theme(self) -> str:
        return str(self._settings.value("theme", "dark"))

    @theme.setter
    def theme(self, value: str) -> None:
        self._settings.setValue("theme", value)

    @property
    def last_tab_index(self) -> int:
        value = self._settings.value("last_tab_index", 0)
        return int(str(value)) if value is not None else 0

    @last_tab_index.setter
    def last_tab_index(self, value: int) -> None:
        self._settings.setValue("last_tab_index", value)

    @property
    def remember_last_tab(self) -> bool:
        return str(self._settings.value("remember_last_tab", "true")).lower() != "false"

    @remember_last_tab.setter
    def remember_last_tab(self, value: bool) -> None:
        self._settings.setValue("remember_last_tab", value)

    @property
    def default_scan_profile(self) -> str:
        return str(self._settings.value("default_scan_profile", "Balanced"))

    @default_scan_profile.setter
    def default_scan_profile(self, value: str) -> None:
        self._settings.setValue("default_scan_profile", value)

    @property
    def default_interface(self) -> str:
        return str(self._settings.value("default_interface", ""))

    @default_interface.setter
    def default_interface(self, value: str) -> None:
        self._settings.setValue("default_interface", value)

    @property
    def status_message_ms(self) -> int:
        value = self._settings.value("status_message_ms", 6000)
        return int(str(value)) if value is not None else 6000

    @status_message_ms.setter
    def status_message_ms(self, value: int) -> None:
        self._settings.setValue("status_message_ms", value)
