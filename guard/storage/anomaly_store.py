from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any


class AnomalyStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def init_db(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts_ms INTEGER NOT NULL,
                    window_start_ms INTEGER NOT NULL,
                    feature_version INTEGER NOT NULL,
                    score REAL NOT NULL,
                    threshold_score REAL NOT NULL,
                    severity TEXT NOT NULL,
                    reasons_json TEXT NOT NULL,
                    summary_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_anomalies_ts_ms
                ON anomalies(ts_ms DESC);

                CREATE INDEX IF NOT EXISTS idx_anomalies_window_start_ms
                ON anomalies(window_start_ms DESC);

                CREATE INDEX IF NOT EXISTS idx_anomalies_severity
                ON anomalies(severity);
                """
            )

    def insert_anomaly(self, record: dict[str, Any]) -> None:
        now_ms = int(time.time() * 1000)

        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO anomalies (
                    ts_ms,
                    window_start_ms,
                    feature_version,
                    score,
                    threshold_score,
                    severity,
                    reasons_json,
                    summary_json,
                    metadata_json,
                    created_at_ms
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(record["ts_ms"]),
                    int(record["window_start_ms"]),
                    int(record["feature_version"]),
                    float(record["score"]),
                    float(record["threshold_score"]),
                    str(record["severity"]),
                    json.dumps(record["reasons"], separators=(",", ":")),
                    json.dumps(record["summary"], sort_keys=True, separators=(",", ":")),
                    json.dumps(record["metadata"], sort_keys=True, separators=(",", ":")),
                    now_ms,
                ),
            )

    def list_anomalies(
        self,
        *,
        search: str | None = None,
        severity: str | None = None,
        limit: int = 200,
    ) -> list[sqlite3.Row]:
        query = """
            SELECT
                id,
                ts_ms,
                window_start_ms,
                feature_version,
                score,
                threshold_score,
                severity,
                reasons_json,
                summary_json,
                metadata_json,
                created_at_ms
            FROM anomalies
            WHERE 1 = 1
        """
        params: list[Any] = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if search:
            like = f"%{search}%"
            query += """
                AND (
                    severity LIKE ?
                    OR reasons_json LIKE ?
                    OR summary_json LIKE ?
                    OR metadata_json LIKE ?
                )
            """
            params.extend([like, like, like, like])

        query += " ORDER BY ts_ms DESC LIMIT ?"
        params.append(limit)

        with self.connect() as conn:
            return conn.execute(query, params).fetchall()

    @staticmethod
    def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "ts_ms": row["ts_ms"],
            "window_start_ms": row["window_start_ms"],
            "feature_version": row["feature_version"],
            "score": row["score"],
            "threshold_score": row["threshold_score"],
            "severity": row["severity"],
            "reasons": json.loads(row["reasons_json"]),
            "summary": json.loads(row["summary_json"]),
            "metadata": json.loads(row["metadata_json"]),
            "created_at_ms": row["created_at_ms"],
        }
