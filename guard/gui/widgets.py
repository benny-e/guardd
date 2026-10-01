from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QGridLayout,
    QHeaderView,
    QLabel,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from guard.gui.theme import SEVERITY_COLORS

FIELD_LABELS = {
    "exec_count": "Process executions",
    "net_count": "Outbound connections",
    "unique_uid_count": "Unique users",
    "unique_comm_count": "Unique process names",
    "unique_file_count": "Unique executable paths",
    "unique_parent_child_count": "Parent–child patterns",
    "unique_dst_ip_count": "Destination IPs",
    "unique_dst_port_count": "Destination ports",
    "exec_to_net_ratio": "Executions per connection",
    "ringbuf_drop_total": "Dropped telemetry events",
    "new_comm_count": "New process names",
    "new_file_count": "New executable paths",
    "new_parent_child_counts": "New parent–child patterns",
    "new_parent_child_ratio": "New parent–child ratio",
    "new_comms": "New process names",
    "new_files": "New executable paths",
    "new_parent_child": "New parent–child patterns",
    "unique_comms": "Process names",
    "unique_files": "Executable paths",
    "unique_dst_ips": "Destination IPs",
    "unique_dst_ports": "Destination ports",
    "unique_parent_child": "Parent–child patterns",
}


def label(text: str, name: str = "", *, wrap: bool = False) -> QLabel:
    widget = QLabel(text)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    widget.setObjectName(name)
    widget.setWordWrap(wrap or name == "section")
    widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return widget


def timestamp(ts_ms: int | None) -> str:
    return (
        datetime.fromtimestamp(ts_ms / 1000, UTC)
        .astimezone()
        .strftime("%b %d, %Y · %H:%M:%S")
        if ts_ms is not None
        else "No data yet"
    )


class MetricCard(QFrame):
    def __init__(self, title: str) -> None:
        super().__init__()
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)
        layout.addWidget(label(title.upper(), "eyebrow"))
        self.value = label("—", "metric")
        self.note = label("", "muted", wrap=True)
        layout.addWidget(self.value)
        layout.addWidget(self.note)
        layout.addStretch()

    def update_value(self, value: str, note: str) -> None:
        self.value.setText(value)
        self.note.setText(note)


class InfoCard(QFrame):
    def __init__(self, title: str, fields: list[str]) -> None:
        super().__init__()
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.addWidget(label(title, "section"))
        grid = QGridLayout()
        grid.setContentsMargins(0, 8, 0, 0)
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(8)
        self.values = {}
        for row, field_name in enumerate(fields):
            grid.addWidget(label(field_name, "muted"), row, 0)
            self.values[field_name] = label("—", wrap=True)
            grid.addWidget(self.values[field_name], row, 1)
        grid.setColumnStretch(1, 1)
        layout.addLayout(grid)

    def update_values(self, values: dict[str, str]) -> None:
        for key, value in values.items():
            self.values[key].setText(value)


class AlertTable(QTableWidget):
    alert_selected = Signal(object)

    def __init__(self) -> None:
        super().__init__(0, 4)
        self.records: list[dict[str, Any]] = []
        self.setHorizontalHeaderLabels(["TIME", "SEVERITY", "SCORE", "REASON"])
        self.verticalHeader().hide()
        self.verticalHeader().setDefaultSectionSize(45)
        self.setShowGrid(False)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setWordWrap(False)
        self.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        for index, width in enumerate((190, 96, 82)):
            self.setColumnWidth(index, width)
        self.itemSelectionChanged.connect(self._selected)

    def _selected(self) -> None:
        row = self.currentRow()
        if self.selectedItems() and 0 <= row < len(self.records):
            self.alert_selected.emit(self.records[row])

    def set_records(
        self, records: list[dict[str, Any]], *, select: bool = True
    ) -> None:
        previous_id = None
        if self.selectedItems() and 0 <= self.currentRow() < len(self.records):
            previous_id = self.records[self.currentRow()]["id"]
        scroll = self.verticalScrollBar().value()
        self.blockSignals(True)
        self.records = records
        self.setRowCount(len(records))
        for row, record in enumerate(records):
            reason = (
                str(record["reasons"][0])
                if record["reasons"]
                else "No explanation available"
            )
            texts = [
                timestamp(record["ts_ms"]),
                str(record["severity"]).upper(),
                f"{record['score']:.3f}",
                reason,
            ]
            for column, text in enumerate(texts):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                if column == 1:
                    item.setForeground(
                        QColor(
                            SEVERITY_COLORS.get(
                                str(record["severity"]).lower(), "#9299a5"
                            )
                        )
                    )
                self.setItem(row, column, item)
        if records and select:
            row = next(
                (i for i, record in enumerate(records) if record["id"] == previous_id),
                0,
            )
            self.selectRow(row)
        else:
            self.clearSelection()
        self.verticalScrollBar().setValue(scroll)
        self.blockSignals(False)
        if records and select:
            self._selected()


class AlertDetail(QScrollArea):
    def __init__(self) -> None:
        super().__init__()
        self.setWidgetResizable(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setMinimumWidth(270)
        self.content = QWidget()
        self.content.setObjectName("detail")
        self.layout = QVBoxLayout(self.content)
        self.layout.setContentsMargins(22, 22, 22, 22)
        self.layout.setSpacing(13)
        self.setWidget(self.content)
        self.show_record(None)

    def show_record(self, record: dict[str, Any] | None) -> None:
        if hasattr(self, "_record") and self._record == record:
            return
        self._record = record
        self.verticalScrollBar().setValue(0)
        while self.layout.count():
            item = self.layout.takeAt(0)
            if item.widget():
                item.widget().hide()
                item.widget().deleteLater()
        if record is None:
            self.layout.addWidget(label("Alert details", "section"))
            self.layout.addWidget(
                label(
                    "Select an alert to inspect its reasons and activity.",
                    "muted",
                    wrap=True,
                )
            )
        else:
            badge = label(str(record["severity"]).upper(), "eyebrow")
            badge.setStyleSheet(
                f"color: {SEVERITY_COLORS.get(str(record['severity']).lower(), '#9299a5')}; font-weight: 600;"
            )
            self.layout.addWidget(badge)
            self.layout.addWidget(label(f"Alert #{record['id']}", "section"))
            self.layout.addWidget(label(timestamp(record["ts_ms"]), "muted", wrap=True))
            self.layout.addWidget(
                label(
                    f"Window: {timestamp(record['window_start_ms'])}",
                    "muted",
                    wrap=True,
                )
            )
            self.layout.addWidget(label("ANOMALY SCORE / THRESHOLD", "eyebrow"))
            self.layout.addWidget(
                label(
                    f"{record['score']:.6f}  /  {record['threshold_score']:.6f}",
                    "section",
                    wrap=True,
                )
            )
            self.layout.addWidget(
                label(
                    "Lower scores indicate more unusual behavior.", "muted", wrap=True
                )
            )
            self.layout.addWidget(label("Why Guardd flagged this", "section"))
            for reason in record["reasons"] or ["No explanation stored."]:
                self.layout.addWidget(label(f"• {reason}", wrap=True))
            self.layout.addWidget(label("Activity during window", "section"))
            for key, value in record["summary"].items():
                rendered = f"{value:g}" if isinstance(value, float) else str(value)
                self.layout.addWidget(
                    label(
                        f"{FIELD_LABELS.get(key, key.replace('_', ' ').capitalize())}: {rendered}",
                        wrap=True,
                    )
                )
            self.layout.addWidget(label("Context", "section"))
            for key, value in record["metadata"].items():
                if value == [] or value is None:
                    continue
                if isinstance(value, list):
                    rendered = "\n".join(
                        f"Parent PID {item['ppid']} → {item['comm']}"
                        if isinstance(item, dict) and "ppid" in item and "comm" in item
                        else str(item)
                        for item in value
                    )
                elif isinstance(value, dict):
                    rendered = json.dumps(value, ensure_ascii=False, indent=2)
                else:
                    rendered = str(value)
                self.layout.addWidget(
                    label(
                        FIELD_LABELS.get(key, key.replace("_", " ").capitalize()),
                        "muted",
                        wrap=True,
                    )
                )
                self.layout.addWidget(label(rendered, wrap=True))
            self.layout.addWidget(
                label(f"Feature version {record['feature_version']}", "muted")
            )
        self.layout.addStretch()
