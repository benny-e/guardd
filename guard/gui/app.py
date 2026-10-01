from __future__ import annotations

from pathlib import Path

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from guard.gui.main_window import MainWindow
from guard.gui.theme import STYLESHEET


def run_gui(*, db_path: str | Path, model_path: str | Path, limit: int = 200) -> int:
    app = QApplication([])
    app.setApplicationName("Guardd")
    app.setOrganizationName("guardd")
    app.setDesktopFileName("guardd")
    app.setWindowIcon(QIcon(str(Path(__file__).parent / "assets" / "guardd.png")))
    app.setStyle("Fusion")
    app.setStyleSheet(STYLESHEET)
    window = MainWindow(db_path, model_path, limit=limit)
    window.show()
    return app.exec()
