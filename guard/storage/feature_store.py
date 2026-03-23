from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from guard.pipeline.features import FeatureVector


class FeatureStore:
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
                CREATE TABLE IF NOT EXISTS feature_windows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    window_start_ms INTEGER NOT NULL,
                    feature_version INTEGER NOT NULL,
                    vector_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_feature_windows_unique
                ON feature_windows(window_start_ms, feature_version);

                CREATE INDEX IF NOT EXISTS idx_feature_windows_window_start
                ON feature_windows(window_start_ms);
                """
            )

    def insert_feature_vector(self, feature: FeatureVector) -> None:
        now_ms = int(time.time() * 1000)

        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO feature_windows (
                    window_start_ms,
                    feature_version,
                    vector_json,
                    metadata_json,
                    created_at_ms
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    feature.window_start_ms,
                    feature.feature_version,
                    json.dumps(feature.values, separators=(",", ":")),
                    json.dumps(feature.metadata, sort_keys=True, separators=(",", ":")),
                    now_ms,
                ),
            )

    def list_feature_rows(
        self,
        *,
        feature_version: int | None = None,
        start_ms: int | None = None,
        end_ms: int | None = None,
        limit: int | None = None,
    ) -> list[sqlite3.Row]:
        query = """
            SELECT
                id,
                window_start_ms,
                feature_version,
                vector_json,
                metadata_json,
                created_at_ms
            FROM feature_windows
            WHERE 1 = 1
        """
        params: list[Any] = []

        if feature_version is not None:
            query += " AND feature_version = ?"
            params.append(feature_version)

        if start_ms is not None:
            query += " AND window_start_ms >= ?"
            params.append(start_ms)

        if end_ms is not None:
            query += " AND window_start_ms < ?"
            params.append(end_ms)

        query += " ORDER BY window_start_ms ASC"

        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        with self.connect() as conn:
            return conn.execute(query, params).fetchall()

    def load_feature_examples(
        self,
        *,
        feature_version: int | None = None,
        start_ms: int | None = None,
        end_ms: int | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        rows = self.list_feature_rows(
            feature_version=feature_version,
            start_ms=start_ms,
            end_ms=end_ms,
            limit=limit,
        )

        return [self.row_to_example(row) for row in rows]

    @staticmethod
    def row_to_example(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "window_start_ms": row["window_start_ms"],
            "feature_version": row["feature_version"],
            "values": json.loads(row["vector_json"]),
            "metadata": json.loads(row["metadata_json"]),
            "created_at_ms": row["created_at_ms"],
        }
