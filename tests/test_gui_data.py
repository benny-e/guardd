import sqlite3
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from guard.gui import data
from guard.gui.data import AlertQuery, load_snapshot
from guard.pipeline.features import FEATURE_VERSION, FeatureVector
from guard.storage.anomaly_store import AnomalyStore
from guard.storage.feature_store import FeatureStore

NOW = datetime(2026, 9, 30, 16, 0, tzinfo=timezone(timedelta(hours=-5)))


def alert(ts, reason="new executable: /tmp/update", severity="high"):
    ms = int(ts.timestamp() * 1000)
    return {
        "ts_ms": ms,
        "window_start_ms": ms - 60_000,
        "feature_version": FEATURE_VERSION,
        "score": -0.537,
        "threshold_score": -0.421,
        "severity": severity,
        "reasons": [reason],
        "summary": {"exec_count": 42, "net_count": 13},
        "metadata": {"new_files": ["/tmp/update"], "unique_dst_ports": [443]},
    }


@pytest.fixture
def stores(tmp_path, monkeypatch):
    monkeypatch.setattr(
        data,
        "service_state",
        lambda: data.ServiceSample(state="Running", note="guardd.service"),
    )
    path = tmp_path / "features.db"
    anomalies = AnomalyStore(path)
    anomalies.init_db()
    features = FeatureStore(path)
    features.init_db()
    model = tmp_path / "model.bundle"
    model.write_bytes(b"file presence only; never unpickle this")
    return path, model, anomalies, features


def test_filters_counts_and_latest_windows_are_independent(stores):
    path, model, anomalies, features = stores
    anomalies.insert_anomaly(alert(NOW - timedelta(minutes=1)))
    anomalies.insert_anomaly(alert(NOW - timedelta(hours=1), severity="medium"))
    anomalies.insert_anomaly(
        alert(NOW - timedelta(hours=17))
    )  # yesterday, still within 24h
    anomalies.insert_anomaly(alert(NOW - timedelta(days=2), severity="low"))
    features.insert_feature_vector(FeatureVector(FEATURE_VERSION, 100, [1.0] * 14, {}))
    features.insert_feature_vector(FeatureVector(FEATURE_VERSION, 200, [2.0] * 14, {}))

    snapshot = load_snapshot(path, model, AlertQuery(severity="high", limit=1), now=NOW)
    assert snapshot.matching == 2
    assert len(snapshot.alerts) == 1
    assert snapshot.today == 2 and snapshot.high_today == 1
    assert len(snapshot.recent) == 4
    assert snapshot.windows == 2 and snapshot.latest_window_ms == 200
    assert snapshot.model == "Available" and snapshot.service == "Running"

    old = load_snapshot(
        path, model, AlertQuery(search="443", severity="low", hours=None), now=NOW
    )
    assert old.matching == 1 and old.alerts[0]["severity"] == "low"


def test_search_is_literal_and_parameterized(stores):
    path, model, anomalies, _ = stores
    anomalies.insert_anomaly(alert(NOW, "name contains 100%_done\\file"))
    anomalies.insert_anomaly(alert(NOW, "ordinary name"))
    for text in ("100%_", "\\file", "%", "_done"):
        snapshot = load_snapshot(path, model, AlertQuery(search=text), now=NOW)
        assert snapshot.matching == 1
    snapshot = load_snapshot(path, model, AlertQuery(search="' OR 1=1 --"), now=NOW)
    assert snapshot.matching == 0


def test_reads_committed_wal_updates_without_writing_database(stores):
    path, model, anomalies, _ = stores
    with sqlite3.connect(path) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        anomalies.insert_anomaly(alert(NOW))
        before = path.read_bytes()
        snapshot = load_snapshot(path, model, AlertQuery(), now=NOW)
        assert len(snapshot.alerts) == 1
        assert path.read_bytes() == before
        anomalies.insert_anomaly(alert(NOW + timedelta(seconds=1)))
        assert load_snapshot(path, model, AlertQuery(), now=NOW).matching == 2


def test_missing_database_is_not_created(tmp_path, monkeypatch):
    monkeypatch.setattr(data, "service_state", lambda: data.ServiceSample())
    path = tmp_path / "absent" / "features.db"
    snapshot = load_snapshot(path, tmp_path / "no-model", AlertQuery(), now=NOW)
    assert not path.parent.exists()
    assert snapshot.today is None and snapshot.alerts == []
    assert "Cannot read" in snapshot.notices[0]
    assert snapshot.model == "Missing"


def test_collection_database_without_anomaly_table(tmp_path, monkeypatch):
    monkeypatch.setattr(
        data,
        "service_state",
        lambda: data.ServiceSample(state="Stopped", note="guardd.service"),
    )
    path = tmp_path / "features.db"
    FeatureStore(path).init_db()
    snapshot = load_snapshot(path, tmp_path / "model", AlertQuery(), now=NOW)
    assert snapshot.today == 0 and snapshot.windows == 0
    assert any("No alerts table yet" in notice for notice in snapshot.notices)


def test_corrupt_database_and_invalid_alert_are_visible(stores, tmp_path):
    path, model, anomalies, _ = stores
    anomalies.insert_anomaly(alert(NOW))
    anomalies.insert_anomaly(alert(NOW, "valid row"))
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE anomalies SET reasons_json = 'invalid json' WHERE id = 1")
    snapshot = load_snapshot(path, model, AlertQuery(), now=NOW)
    assert len(snapshot.alerts) == 1 and snapshot.matching == 2
    assert any("Alert #1" in notice for notice in snapshot.notices)
    bad_path = tmp_path / "broken.db"
    bad_path.write_bytes(b"not a SQLite database")
    broken = load_snapshot(bad_path, model, AlertQuery(), now=NOW)
    assert broken.today is None and broken.notices


def test_sqlite_uri_handles_special_characters(tmp_path, monkeypatch):
    monkeypatch.setattr(data, "service_state", lambda: data.ServiceSample())
    path = tmp_path / "a?# file.db"
    anomalies = AnomalyStore(path)
    anomalies.init_db()
    anomalies.insert_anomaly(alert(NOW))
    assert load_snapshot(path, tmp_path / "model", AlertQuery(), now=NOW).matching == 1


@pytest.mark.parametrize(
    "stdout,code,expected",
    [
        ("LoadState=loaded\nActiveState=active\n", 0, "Running"),
        ("LoadState=loaded\nActiveState=inactive\n", 0, "Stopped"),
        ("LoadState=loaded\nActiveState=failed\n", 0, "Failed"),
        ("LoadState=not-found\nActiveState=inactive\n", 0, "Not installed"),
        ("", 1, "Unknown"),
    ],
)
def test_service_status(monkeypatch, stdout, code, expected):
    monkeypatch.setattr(
        data.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, code, stdout),
    )
    assert data.service_state().state == expected


def test_service_timeout_is_unknown(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("systemctl", 2)

    monkeypatch.setattr(data.subprocess, "run", timeout)
    assert data.service_state().state == "Unknown"


def test_service_resource_counters_and_uptime(monkeypatch):
    stdout = "LoadState=loaded\nActiveState=active\nMainPID=42\nCPUUsageNSec=500000000\nMemoryCurrent=10485760\nActiveEnterTimestampMonotonic=1000000\nInvocationID=run1\n"
    monkeypatch.setattr(
        data.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout),
    )
    monkeypatch.setattr(data.time, "monotonic", lambda: 61.0)
    sample = data.service_state()
    assert sample.pid == 42 and sample.cpu_time_ns == 500000000
    assert sample.memory_bytes == 10485760 and sample.invocation_id == "run1"
    # The dataclass captures its own monotonic clock when instantiated.
    assert sample.uptime_seconds == sample.sampled_at - 1.0


def test_cpu_percentage_handles_restarts_and_missing_accounting():
    usage = data.ServiceUsage()

    def sample(cpu, at, pid=42, invocation="run1", state="Running"):
        return data.ServiceSample(
            state=state,
            pid=pid,
            invocation_id=invocation,
            cpu_time_ns=cpu,
            sampled_at=at,
        )

    assert usage.update(sample(0, 1)) is None
    assert usage.update(sample(500000000, 2)) == 50.0
    assert usage.update(sample(2500000000, 3)) == 200.0
    assert usage.update(sample(0, 4, pid=43, invocation="run2")) is None
    assert usage.update(sample(100000000, 5, pid=43, invocation="run2")) == 10.0
    assert usage.update(sample(None, 6)) is None
    assert usage.update(sample(10, 7)) is None
    assert usage.update(sample(0, 8)) is None
    assert usage.update(sample(0, 9, state="Stopped")) is None


def test_unavailable_service_counters_do_not_look_like_zero_usage(monkeypatch):
    stdout = "LoadState=loaded\nActiveState=active\nMainPID=0\nCPUUsageNSec=[not set]\nMemoryCurrent=18446744073709551615\n"
    monkeypatch.setattr(
        data.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout),
    )
    sample = data.service_state()
    assert sample.pid is sample.cpu_time_ns is sample.memory_bytes is None
