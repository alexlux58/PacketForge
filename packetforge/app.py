from __future__ import annotations

import sys

from packetforge.assets import icon_path
from packetforge.qt_bootstrap import configure_qt_plugins
from packetforge.ui.main_window import MainWindow


def run() -> int:
    configure_qt_plugins()

    from PySide6.QtCore import QCoreApplication
    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication

    QCoreApplication.setOrganizationName("PacketForge")
    QCoreApplication.setApplicationName("PacketForge")
    app = QApplication(sys.argv)
    icon_file = icon_path()
    if icon_file.exists():
        app.setWindowIcon(QIcon(str(icon_file)))
    window = MainWindow()
    window.show()
    return app.exec()
