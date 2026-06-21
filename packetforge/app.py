from __future__ import annotations

import sys

from PySide6.QtCore import QCoreApplication
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from packetforge.assets import icon_path
from packetforge.ui.main_window import MainWindow


def run() -> int:
    QCoreApplication.setOrganizationName("PacketForge")
    QCoreApplication.setApplicationName("PacketForge")
    app = QApplication(sys.argv)
    icon_file = icon_path()
    if icon_file.exists():
        app.setWindowIcon(QIcon(str(icon_file)))
    window = MainWindow()
    window.show()
    return app.exec()
