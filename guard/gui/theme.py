SEVERITY_COLORS = {"high": "#ef8b91", "medium": "#e4b96a", "low": "#8fbbec"}

STYLESHEET = """
QWidget { background: #111318; color: #f2f3f5; font-size: 14px; }
QWidget#sidebar { background: #171a20; border-right: 1px solid #292e38; }
QLabel { background: transparent; }
QLabel#brand { font-size: 25px; font-weight: 700; letter-spacing: 3px; }
QLabel#title { font-size: 27px; font-weight: 600; }
QLabel#muted, QLabel#eyebrow { color: #9299a5; }
QLabel#eyebrow { font-size: 12px; }
QLabel#metric { font-size: 29px; font-weight: 600; }
QLabel#section { font-size: 17px; font-weight: 600; }
QLabel#notice { background: #29251c; color: #e4c88e; border: 1px solid #52452e; border-radius: 6px; padding: 10px; }
QFrame#card, QWidget#detail { background: #1b1f26; border: 1px solid #292e38; border-radius: 8px; }
QPushButton { background: #222731; border: 1px solid #303743; border-radius: 6px; padding: 9px 14px; }
QPushButton:hover { background: #2b323e; }
QPushButton:focus { border: 1px solid #8fbbec; }
QPushButton#nav { background: transparent; border: 1px solid transparent; text-align: left; padding: 12px 16px; }
QPushButton#nav:hover { background: #222731; }
QPushButton#nav:checked { background: #292f3a; color: #bdd6f4; border-color: #343e4d; }
QLineEdit, QComboBox { background: #1b1f26; border: 1px solid #303743; border-radius: 6px; padding: 9px; }
QLineEdit:focus, QComboBox:focus { border-color: #8fbbec; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView { background: #1b1f26; selection-background-color: #303c4d; }
QTableWidget { background: #171a20; alternate-background-color: #1b1f26; border: 1px solid #292e38; border-radius: 6px; gridline-color: #292e38; selection-background-color: #2b3a4d; selection-color: #f2f3f5; }
QTableWidget::item { padding: 7px; border: none; }
QHeaderView::section { background: #20242c; color: #9299a5; border: none; border-bottom: 1px solid #303743; padding: 11px 7px; font-size: 12px; }
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical { background: #171a20; width: 10px; }
QScrollBar::handle:vertical { background: #3c4452; border-radius: 4px; min-height: 30px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QSplitter::handle { background: #111318; width: 12px; }
QStatusBar { color: #9299a5; border-top: 1px solid #292e38; }
"""
