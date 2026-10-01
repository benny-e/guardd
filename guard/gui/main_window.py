from __future__ import annotations

import platform
import socket
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QThread, QTimer, Signal, Slot
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QHBoxLayout,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from guard.gui.data import AlertQuery, ServiceUsage, Snapshot, load_snapshot
from guard.gui.widgets import (
    AlertDetail,
    AlertTable,
    InfoCard,
    MetricCard,
    label,
    timestamp,
)
from guard.pipeline.aggregator import DEFAULT_WINDOW_MS
from guard.pipeline.features import FEATURE_VERSION


class RefreshWorker(QThread):
    loaded = Signal(object, object)
    failed = Signal(str)

    def __init__(
        self, db_path: Path, model_path: Path, query: AlertQuery, parent: QWidget
    ) -> None:
        super().__init__(parent)
        self.db_path, self.model_path, self.query = db_path, model_path, query

    def run(self) -> None:
        try:
            self.loaded.emit(
                self.query, load_snapshot(self.db_path, self.model_path, self.query)
            )
        except Exception as exc:  # noqa: BLE001 - report errors at the worker boundary
            self.failed.emit(f"Refresh failed: {exc}")


class MainWindow(QMainWindow):
    def __init__(
        self, db_path: str | Path, model_path: str | Path, *, limit: int = 200
    ) -> None:
        super().__init__()
        self.db_path, self.model_path = Path(db_path), Path(model_path)
        self.limit = limit
        self._worker: RefreshWorker | None = None
        self._pending = False
        self._closing = False
        self.service_usage = ServiceUsage()
        self.setWindowTitle("Guardd · Behavioral detection")
        self.resize(1280, 820)
        self.setMinimumSize(1000, 660)

        root = QWidget()
        self.setCentralWidget(root)
        shell = QHBoxLayout(root)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(180)
        nav = QVBoxLayout(sidebar)
        nav.setContentsMargins(18, 28, 18, 22)
        nav.setSpacing(12)
        nav.addWidget(label("Guardd", "brand"))
        nav.addWidget(label("Behavioral detection", "muted"))
        nav.addSpacing(28)
        self.nav_group = QButtonGroup(self)
        self.nav_buttons = []
        for index, title in enumerate(("Overview", "Alerts")):
            button = QPushButton(title)
            button.setObjectName("nav")
            button.setCheckable(True)
            self.nav_group.addButton(button, index)
            nav.addWidget(button)
            self.nav_buttons.append(button)
        nav.addStretch()
        nav.addWidget(label("Linux endpoint\nsecurity", "muted"))
        shell.addWidget(sidebar)

        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(28, 26, 28, 18)
        layout.setSpacing(18)
        header = QHBoxLayout()
        self.heading = label("Overview", "title")
        self.service_badge = label("● Checking service", "muted")
        header.addWidget(self.heading)
        header.addStretch()
        header.addWidget(self.service_badge)
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.request_refresh)
        header.addWidget(self.refresh_button)
        layout.addLayout(header)
        self.notice = label("", "notice", wrap=True)
        self.notice.hide()
        layout.addWidget(self.notice)
        self.pages = QStackedWidget()
        self.pages.addWidget(self._overview())
        self.pages.addWidget(self._alerts())
        layout.addWidget(self.pages, 1)
        shell.addWidget(body, 1)
        self.nav_group.idClicked.connect(self.navigate)
        self.nav_buttons[0].setChecked(True)
        self.statusBar().showMessage("Connecting to local Guardd data…")

        self.debounce = QTimer(self)
        self.debounce.setSingleShot(True)
        self.debounce.setInterval(300)
        self.debounce.timeout.connect(self.request_refresh)
        self.search.textChanged.connect(lambda: self.debounce.start())
        self.severity.currentIndexChanged.connect(self.request_refresh)
        self.period.currentIndexChanged.connect(self.request_refresh)
        self.timer = QTimer(self)
        self.timer.setInterval(5000)
        self.timer.timeout.connect(self.request_refresh)
        self.timer.start()
        QTimer.singleShot(0, self.request_refresh)

    def _overview(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(22)
        layout.addWidget(
            label(
                "A view of your host’s behavioral alerts and telemetry.",
                "muted",
                wrap=True,
            )
        )
        cards = QHBoxLayout()
        cards.setSpacing(14)
        self.service_card = MetricCard("Service")
        self.alerts_card = MetricCard("Alerts today")
        self.model_card = MetricCard("Model")
        for card in (self.service_card, self.alerts_card, self.model_card):
            cards.addWidget(card, 1)
        layout.addLayout(cards)
        information = QHBoxLayout()
        information.setSpacing(14)
        self.resources = InfoCard(
            "Guardd resource utilization", ["CPU", "Memory", "Process ID", "Uptime"]
        )
        self.resources.setToolTip(
            "CPU and memory cover guardd.service, including its eBPF collector. CPU is sampled between refreshes; one logical core equals 100%. Unavailable accounting is shown explicitly."
        )
        self.system_info = InfoCard(
            "Host & telemetry", ["Host", "Kernel", "Window size", "Feature schema"]
        )
        self.system_info.update_values(
            {
                "Host": socket.gethostname(),
                "Kernel": f"{platform.system()} {platform.release()}",
                "Window size": f"{DEFAULT_WINDOW_MS / 1000:g} seconds",
                "Feature schema": f"{FEATURE_VERSION} (client)",
            }
        )
        information.addWidget(self.resources, 1)
        information.addWidget(self.system_info, 1)
        layout.addLayout(information)
        recent_header = QHBoxLayout()
        recent_header.addWidget(label("Recent alerts", "section"))
        recent_header.addStretch()
        view = QPushButton("View all alerts")
        view.clicked.connect(self.view_all_alerts)
        recent_header.addWidget(view)
        layout.addLayout(recent_header)
        self.recent_table = AlertTable()
        self.recent_table.alert_selected.connect(self.open_alert)
        layout.addWidget(self.recent_table, 1)
        self.recent_empty = label("No alerts recorded yet.", "muted")
        layout.addWidget(self.recent_empty)
        self.telemetry = label("Waiting for telemetry…", "muted", wrap=True)
        layout.addWidget(self.telemetry)
        return page

    def _alerts(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)
        filters = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText(
            "Search reasons, processes, paths, or destinations…"
        )
        self.search.setClearButtonEnabled(True)
        self.search.setAccessibleName("Search alerts")
        self.severity = QComboBox()
        self.severity.setAccessibleName("Filter by severity")
        for title, value in (
            ("All severities", None),
            ("High", "high"),
            ("Medium", "medium"),
            ("Low", "low"),
        ):
            self.severity.addItem(title, value)
        self.period = QComboBox()
        self.period.setAccessibleName("Filter by time range")
        for title, hours in (
            ("Last 24 hours", 24),
            ("Last 7 days", 168),
            ("Last 30 days", 720),
            ("All time", None),
        ):
            self.period.addItem(title, hours)
        filters.addWidget(self.search, 1)
        filters.addWidget(self.severity)
        filters.addWidget(self.period)
        layout.addLayout(filters)
        self.result_count = label("Loading alerts…", "muted")
        layout.addWidget(self.result_count)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.setHandleWidth(12)
        self.alert_table = AlertTable()
        self.detail = AlertDetail()
        self.alert_table.alert_selected.connect(self.select_alert)
        split.addWidget(self.alert_table)
        split.addWidget(self.detail)
        split.setChildrenCollapsible(False)
        split.setSizes([640, 340])
        layout.addWidget(split, 1)
        return page

    @Slot(int)
    def navigate(self, index: int) -> None:
        self.pages.setCurrentIndex(index)
        self.nav_buttons[index].setChecked(True)
        self.heading.setText(("Overview", "Alerts")[index])

    @Slot()
    def view_all_alerts(self) -> None:
        self.search.clear()
        self.severity.setCurrentIndex(0)
        self.period.setCurrentIndex(3)
        self.navigate(1)
        self.request_refresh()

    @Slot(object)
    def open_alert(self, record: dict) -> None:
        # A recent alert may be outside the active filters or row limit.
        # Show its stored details immediately while switching to all alerts.
        self.view_all_alerts()
        self._external_record = record
        self._external_query = self.query()
        self.detail.show_record(record)

    @Slot(object)
    def select_alert(self, record: dict) -> None:
        self._external_record = None
        self.detail.show_record(record)

    def query(self) -> AlertQuery:
        return AlertQuery(
            self.search.text(),
            self.severity.currentData(),
            self.period.currentData(),
            self.limit,
        )

    @Slot()
    def request_refresh(self) -> None:
        if self._closing:
            return
        if self._worker is not None:
            self._pending = True
            return
        self._pending = False
        self._worker = RefreshWorker(self.db_path, self.model_path, self.query(), self)
        self._worker.loaded.connect(self.apply_snapshot)
        self._worker.failed.connect(self.show_error)
        self._worker.finished.connect(self._refresh_finished)
        self._worker.start()

    @Slot()
    def _refresh_finished(self) -> None:
        worker, self._worker = self._worker, None
        if worker is not None:
            worker.deleteLater()
        if self._closing:
            self.close()
        elif self._pending:
            self.request_refresh()

    @Slot(str)
    def show_error(self, message: str) -> None:
        self.notice.setText(message)
        self.notice.show()
        self.statusBar().showMessage(
            "Refresh failed. Displayed data may be out of date."
        )

    @Slot(object, object)
    def apply_snapshot(self, query: AlertQuery, snapshot: Snapshot) -> None:
        if self._closing:
            return
        if query != self.query():
            self._pending = True
            return
        self.notice.setText("\n".join(snapshot.notices))
        self.notice.setVisible(bool(snapshot.notices))
        self.service_badge.setText(f"● Service {snapshot.service.lower()}")
        self.service_badge.setStyleSheet(
            "color: #8fc9ab;" if snapshot.service == "Running" else "color: #9299a5;"
        )
        self.service_card.update_value(snapshot.service, snapshot.service_note)
        sample = snapshot.service_sample
        cpu = self.service_usage.update(sample)
        cpu_text = (
            f"{cpu:.1f}%"
            if cpu is not None
            else ("Sampling…" if sample.cpu_time_ns is not None else "Unavailable")
        )
        uptime = "—"
        if sample.uptime_seconds is not None:
            seconds = int(sample.uptime_seconds)
            hours, minutes = divmod(seconds // 60, 60)
            uptime = (
                f"{hours // 24}d {hours % 24}h {minutes}m"
                if hours >= 24
                else f"{hours}h {minutes}m"
            )
        self.resources.update_values(
            {
                "CPU": cpu_text,
                "Memory": f"{sample.memory_bytes / 1024**2:.1f} MiB"
                if sample.memory_bytes is not None
                else "Unavailable",
                "Process ID": str(sample.pid) if sample.pid is not None else "—",
                "Uptime": uptime,
            }
        )
        version = snapshot.latest_feature_version
        self.system_info.update_values(
            {
                "Feature schema": str(version)
                if version is not None
                else f"{FEATURE_VERSION} (client)"
            }
        )
        self.alerts_card.update_value(
            "—" if snapshot.today is None else str(snapshot.today),
            f"{snapshot.high_today} high severity · local calendar day"
            if snapshot.today is not None
            else "Database unavailable",
        )
        note = (
            f"File updated {timestamp(snapshot.model_modified_ms)}"
            if snapshot.model_modified_ms is not None
            else "Waiting for a trained model file"
        )
        self.model_card.update_value(snapshot.model, note)
        self.model_card.setToolTip(
            "Model file presence does not confirm detection mode or model validity."
        )
        self.recent_table.set_records(snapshot.recent, select=False)
        self.recent_empty.setVisible(not snapshot.recent)
        self.recent_empty.setText(
            "Alert data unavailable."
            if snapshot.today is None
            else "No alerts recorded yet."
        )
        external = getattr(self, "_external_record", None)
        if (
            external
            and getattr(self, "_external_query", None) == query
            and snapshot.today is not None
        ):
            self.alert_table.set_records(snapshot.alerts, select=False)
            self.detail.show_record(external)
            for index, record in enumerate(snapshot.alerts):
                if record["id"] == external["id"]:
                    self.alert_table.selectRow(index)
                    break
        else:
            self._external_record = None
            self.alert_table.set_records(snapshot.alerts)
            if not snapshot.alerts:
                self.detail.show_record(None)
        self.result_count.setText(
            f"Showing {len(snapshot.alerts):,} of {snapshot.matching:,} matching alerts · newest first"
            if snapshot.alerts
            else (
                "Alert data unavailable."
                if snapshot.today is None
                else "No alerts match these filters."
            )
        )
        if snapshot.matching > self.limit:
            self.result_count.setText(
                self.result_count.text()
                + f" · narrow filters or increase --limit (currently {self.limit})"
            )
        if snapshot.windows is None:
            telemetry = "No feature windows available."
        else:
            telemetry = f"{snapshot.windows:,} stored windows · latest: {timestamp(snapshot.latest_window_ms)}"
            if snapshot.latest_window_ms is not None:
                age_seconds = max(
                    0,
                    int(
                        datetime.now().astimezone().timestamp()
                        - snapshot.latest_window_ms / 1000
                    ),
                )
                if age_seconds > 180:
                    telemetry += (
                        f" · no recent telemetry ({age_seconds // 60} minutes old)"
                    )
        self.telemetry.setText(telemetry)
        self.statusBar().showMessage(
            f"Updated {datetime.now().astimezone():%H:%M:%S} · auto-refresh every 5s · {self.db_path}"
        )

    def closeEvent(self, event: QCloseEvent) -> None:
        self.timer.stop()
        self.debounce.stop()
        self._closing = True
        # Let the bounded read finish before deleting the QThread. No daemon
        # control is performed and the GUI event loop stays responsive.
        if self._worker is not None:
            event.ignore()
            self.hide()
        else:
            event.accept()
