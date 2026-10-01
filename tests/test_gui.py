import os
import time
from datetime import datetime, timedelta

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel
from test_gui_data import alert

from guard.gui import data
from guard.gui.main_window import MainWindow
from guard.gui.theme import STYLESHEET
from guard.storage.anomaly_store import AnomalyStore


@pytest.fixture(scope="module")
def app():
    instance = QApplication.instance() or QApplication([])
    instance.setStyle("Fusion")
    instance.setStyleSheet(STYLESHEET)
    return instance


def wait_until(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "GUI refresh timed out"
        QTest.qWait(10)


@pytest.fixture
def window(app, tmp_path, monkeypatch):
    monkeypatch.setattr(
        data,
        "service_state",
        lambda: data.ServiceSample(state="Running", note="guardd.service"),
    )
    db = tmp_path / "features.db"
    store = AnomalyStore(db)
    store.init_db()
    now = datetime.now().astimezone()
    store.insert_anomaly(alert(now - timedelta(minutes=1), severity="high"))
    store.insert_anomaly(
        alert(now - timedelta(minutes=2), "connection spike", "medium")
    )
    store.insert_anomaly(alert(now - timedelta(days=3), "old process", "low"))
    view = MainWindow(db, tmp_path / "model.bundle")
    view.show()
    wait_until(lambda: view._worker is None and view.alert_table.rowCount() == 2)
    yield view, store
    view.close()
    wait_until(lambda: view._worker is None)
    app.processEvents()


def test_navigation_filters_details_and_refresh_preserve_selection(window):
    view, store = window
    assert view.pages.currentIndex() == 0
    assert view.recent_table.rowCount() == 3
    QTest.mouseClick(view.nav_buttons[1], Qt.MouseButton.LeftButton)
    assert view.pages.currentIndex() == 1
    view.alert_table.selectRow(1)
    selected = view.detail._record["id"]
    assert view.detail._record["severity"] == "medium"
    store.insert_anomaly(alert(datetime.now().astimezone(), "newer alert"))
    view.request_refresh()
    wait_until(lambda: view._worker is None and view.alert_table.rowCount() == 3)
    assert view.detail._record["id"] == selected
    view.severity.setCurrentIndex(1)
    wait_until(lambda: view._worker is None and view.alert_table.rowCount() == 2)
    assert all(record["severity"] == "high" for record in view.alert_table.records)
    view.search.setText("nonexistent")
    wait_until(lambda: view._worker is None and view.alert_table.rowCount() == 0)
    assert view.detail._record is None
    assert view.result_count.text() == "No alerts match these filters."


def test_overview_resource_and_window_information(window):
    view, _ = window
    query = view.query()
    snapshot = data.load_snapshot(view.db_path, view.model_path, query)
    snapshot.service_sample = data.ServiceSample(
        state="Running",
        pid=42,
        cpu_time_ns=0,
        memory_bytes=1024**2 * 64,
        uptime_seconds=3660,
        sampled_at=1,
    )
    view.apply_snapshot(query, snapshot)
    assert view.resources.values["CPU"].text() == "Sampling…"
    snapshot.service_sample = data.ServiceSample(
        state="Running",
        pid=42,
        cpu_time_ns=500000000,
        memory_bytes=1024**2 * 64,
        uptime_seconds=3661,
        sampled_at=2,
    )
    view.apply_snapshot(query, snapshot)
    assert view.resources.values["CPU"].text() == "50.0%"
    assert view.resources.values["Memory"].text() == "64.0 MiB"
    assert view.resources.values["Process ID"].text() == "42"
    assert view.resources.values["Uptime"].text() == "1h 1m"
    assert view.system_info.values["Window size"].text() == "60 seconds"


def test_recent_alert_opens_outside_time_filter(window):
    view, _ = window
    old = view.recent_table.records[2]
    view.open_alert(old)
    wait_until(lambda: view._worker is None and view.alert_table.rowCount() == 3)
    assert view.period.currentData() is None
    assert view.detail._record["id"] == old["id"]


def test_record_text_is_plain_text(window):
    view, _ = window
    record = dict(view.alert_table.records[0], reasons=["<b>process</b> & metadata"])
    view.detail.show_record(record)
    labels = view.detail.findChildren(QLabel)
    assert any("<b>process</b>" in widget.text() for widget in labels)
    assert all(widget.textFormat() == Qt.TextFormat.PlainText for widget in labels)


def test_changing_alert_hides_previous_details_before_deferred_deletion(window):
    view, _ = window
    view.navigate(1)
    old_record = view.detail._record
    view.alert_table.selectRow(1)
    QApplication.processEvents()
    visible = [
        widget.text()
        for widget in view.detail.findChildren(QLabel)
        if widget.isVisible()
    ]
    assert "HIGH" not in visible
    assert f"Alert #{old_record['id']}" not in visible
    assert visible.count("MEDIUM") == 1


def test_recent_alert_remains_open_when_outside_row_limit(window):
    view, _ = window
    view.limit = 1
    old = view.recent_table.records[2]
    view.open_alert(old)
    wait_until(lambda: view._worker is None and view.alert_table.rowCount() == 1)
    assert view.detail._record["id"] == old["id"]
    view.request_refresh()
    wait_until(lambda: view._worker is None)
    assert view.detail._record["id"] == old["id"]
    view.alert_table.selectRow(0)
    assert view.detail._record["id"] != old["id"]


def test_filter_change_during_slow_refresh_uses_latest_query(window, monkeypatch):
    view, _ = window
    real = data.load_snapshot

    def slow(*args, **kwargs):
        time.sleep(0.1)
        return real(*args, **kwargs)

    monkeypatch.setattr("guard.gui.main_window.load_snapshot", slow)
    view.request_refresh()
    view.severity.setCurrentIndex(2)
    wait_until(lambda: view._worker is None and view.alert_table.rowCount() == 1)
    assert view.alert_table.records[0]["severity"] == "medium"


def test_close_during_refresh_does_not_destroy_running_thread(window, monkeypatch):
    view, _ = window
    real = data.load_snapshot

    def slow(*args, **kwargs):
        time.sleep(0.15)
        return real(*args, **kwargs)

    monkeypatch.setattr("guard.gui.main_window.load_snapshot", slow)
    view.request_refresh()
    assert view._worker is not None
    view.close()
    assert not view.isVisible()
    wait_until(lambda: view._worker is None)


def test_missing_database_recovers_on_refresh(app, tmp_path, monkeypatch):
    monkeypatch.setattr(data, "service_state", lambda: data.ServiceSample())
    path = tmp_path / "later.db"
    view = MainWindow(path, tmp_path / "model")
    view.show()
    try:
        wait_until(lambda: view._worker is None and not view.notice.isHidden())
        assert "Cannot read" in view.notice.text()
        store = AnomalyStore(path)
        store.init_db()
        store.insert_anomaly(alert(datetime.now().astimezone()))
        view.request_refresh()
        wait_until(lambda: view._worker is None and view.alert_table.rowCount() == 1)
        assert view.notice.isHidden()
    finally:
        view.close()
        wait_until(lambda: view._worker is None)
