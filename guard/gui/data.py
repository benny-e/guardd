"""Read-only desktop queries; never initialize stores or unpickle a model."""

from __future__ import annotations

import sqlite3
import subprocess
import time
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from guard.storage.anomaly_store import AnomalyStore


@dataclass(frozen=True)
class AlertQuery:
    search: str = ""
    severity: str | None = None
    hours: int | None = 24
    limit: int = 200


@dataclass
class ServiceSample:
    state: str = "Unknown"
    note: str = "Service status unavailable. Guardd may be running manually."
    pid: int | None = None
    cpu_time_ns: int | None = None
    memory_bytes: int | None = None
    uptime_seconds: float | None = None
    invocation_id: str = ""
    sampled_at: float = field(default_factory=time.monotonic)


class ServiceUsage:
    """CPU rate between samples, with one logical core equal to 100%."""

    def __init__(self) -> None:
        self.previous: ServiceSample | None = None

    def update(self, current: ServiceSample) -> float | None:
        previous, self.previous = self.previous, current
        if current.state != "Running" or current.cpu_time_ns is None:
            self.previous = None
            return None
        if previous is None or previous.cpu_time_ns is None:
            return None
        if (current.pid, current.invocation_id) != (
            previous.pid,
            previous.invocation_id,
        ):
            return None
        elapsed = current.sampled_at - previous.sampled_at
        cpu_delta = current.cpu_time_ns - previous.cpu_time_ns
        if elapsed <= 0 or cpu_delta < 0:
            return None
        return cpu_delta / (elapsed * 1_000_000_000) * 100


@dataclass
class Snapshot:
    alerts: list[dict[str, Any]] = field(default_factory=list)
    recent: list[dict[str, Any]] = field(default_factory=list)
    matching: int = 0
    today: int | None = None
    high_today: int = 0
    windows: int | None = None
    latest_window_ms: int | None = None
    latest_feature_version: int | None = None
    service: str = "Unknown"
    service_note: str = ""
    service_sample: ServiceSample = field(default_factory=ServiceSample)
    model: str = "Missing"
    model_modified_ms: int | None = None
    notices: list[str] = field(default_factory=list)


def _counter(text: str | None) -> int | None:
    try:
        value = int(text) if text is not None else -1
        return value if 0 <= value < 2**64 - 1 else None
    except ValueError:
        return None


def service_state() -> ServiceSample:
    try:
        result = subprocess.run(
            [
                "systemctl",
                "show",
                "guardd.service",
                "--property=LoadState,ActiveState,MainPID,CPUUsageNSec,MemoryCurrent,ActiveEnterTimestampMonotonic,InvocationID",
            ],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ServiceSample()
    if result.returncode:
        return ServiceSample()
    properties = dict(
        line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
    )
    if properties.get("LoadState") == "not-found":
        return ServiceSample(
            state="Not installed", note="guardd.service was not found."
        )
    state = properties.get("ActiveState", "unknown")
    sample = ServiceSample(
        state={"active": "Running", "inactive": "Stopped"}.get(
            state, state.capitalize()
        ),
        note="guardd.service",
    )
    if state == "active":
        sample.pid = _counter(properties.get("MainPID")) or None
        sample.cpu_time_ns = _counter(properties.get("CPUUsageNSec"))
        sample.memory_bytes = _counter(properties.get("MemoryCurrent"))
        sample.invocation_id = properties.get("InvocationID", "")
        started_usec = _counter(properties.get("ActiveEnterTimestampMonotonic"))
        if started_usec:
            sample.uptime_seconds = max(
                0.0, sample.sampled_at - started_usec / 1_000_000
            )
    return sample


def _where(query: AlertQuery, now_ms: int) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if query.severity:
        clauses.append("severity = ?")
        params.append(query.severity)
    if query.hours is not None:
        clauses.append("ts_ms >= ?")
        params.append(now_ms - query.hours * 3_600_000)
    if query.search.strip():
        # Search is literal text, including SQL wildcard characters.
        escaped = (
            query.search.strip()
            .replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        clauses.append(
            "("
            + " OR ".join(
                f"{column} LIKE ? ESCAPE '\\'"
                for column in (
                    "severity",
                    "reasons_json",
                    "summary_json",
                    "metadata_json",
                )
            )
            + ")"
        )
        params.extend([f"%{escaped}%"] * 4)
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), params


def _records(rows: list[sqlite3.Row], snapshot: Snapshot) -> list[dict[str, Any]]:
    records = []
    for row in rows:
        try:
            record = AnomalyStore.row_to_dict(row)
            if not isinstance(record["reasons"], list) or not all(
                isinstance(record[key], dict) for key in ("summary", "metadata")
            ):
                raise ValueError("invalid alert payload")
            records.append(record)
        except (ValueError, TypeError, KeyError, IndexError):
            notice = f"Alert #{row['id']} has invalid stored data and could not be displayed."
            if notice not in snapshot.notices:
                snapshot.notices.append(notice)
    return records


def load_snapshot(
    db_path: Path, model_path: Path, query: AlertQuery, *, now: datetime | None = None
) -> Snapshot:
    if query.limit < 1:
        raise ValueError("alert limit must be positive")
    snapshot = Snapshot()
    snapshot.service_sample = service_state()
    snapshot.service = snapshot.service_sample.state
    snapshot.service_note = snapshot.service_sample.note
    if now is None:
        now = datetime.now().astimezone()
        # Resolve midnight in the local zone separately: its UTC offset can
        # differ from the current offset on a daylight-saving transition day.
        midnight = datetime.combine(now.date(), datetime.min.time()).astimezone()
    else:
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    now_ms = int(now.timestamp() * 1000)
    midnight_ms = int(midnight.timestamp() * 1000)
    try:
        if model_path.is_file():
            snapshot.model_modified_ms = int(model_path.stat().st_mtime * 1000)
            snapshot.model = "Available"
    except OSError:
        snapshot.model = "Unavailable"
        snapshot.notices.append(f"Cannot inspect model: {model_path}")

    try:
        # mode=ro prevents accidentally creating a database at a wrong path.
        with closing(
            sqlite3.connect(
                db_path.resolve().as_uri() + "?mode=ro", uri=True, timeout=1
            )
        ) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            conn.execute("BEGIN")
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if "anomalies" in tables:
                where, params = _where(query, now_ms)
                snapshot.matching = conn.execute(
                    "SELECT COUNT(*) FROM anomalies" + where, params
                ).fetchone()[0]
                rows = conn.execute(
                    "SELECT * FROM anomalies"
                    + where
                    + " ORDER BY ts_ms DESC, id DESC LIMIT ?",
                    [*params, query.limit],
                ).fetchall()
                snapshot.alerts = _records(rows, snapshot)
                snapshot.recent = _records(
                    conn.execute(
                        "SELECT * FROM anomalies ORDER BY ts_ms DESC, id DESC LIMIT 6"
                    ).fetchall(),
                    snapshot,
                )
                counts = conn.execute(
                    "SELECT COUNT(*), COALESCE(SUM(severity = 'high'), 0) FROM anomalies WHERE ts_ms >= ? AND ts_ms <= ?",
                    (midnight_ms, now_ms),
                ).fetchone()
                snapshot.today, snapshot.high_today = counts
            else:
                snapshot.today = 0
                snapshot.notices.append(
                    "No alerts table yet. It will appear when Guardd starts detection."
                )
            if "feature_windows" in tables:
                snapshot.windows, snapshot.latest_window_ms = conn.execute(
                    "SELECT COUNT(*), MAX(window_start_ms) FROM feature_windows"
                ).fetchone()
                latest = conn.execute(
                    "SELECT feature_version FROM feature_windows ORDER BY window_start_ms DESC LIMIT 1"
                ).fetchone()
                snapshot.latest_feature_version = (
                    latest[0] if latest is not None else None
                )
    except (sqlite3.Error, OSError) as exc:
        # Avoid presenting partial results as current after a failed refresh.
        snapshot.alerts = []
        snapshot.recent = []
        snapshot.matching = 0
        snapshot.today = snapshot.windows = snapshot.latest_window_ms = None
        snapshot.notices.append(
            f"Cannot read {db_path}: {exc}. Check the path and read permissions."
        )
    return snapshot
