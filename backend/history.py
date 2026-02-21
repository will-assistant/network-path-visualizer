"""SQLite-backed historical trace storage."""

from __future__ import annotations

import logging
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

MAX_HISTORY_ROWS = 1000


@dataclass
class TraceRecord:
    id: str
    timestamp: str
    query_type: str
    source: Optional[str]
    destination: Optional[str]
    prefix: Optional[str]
    result_json: str
    query_time_ms: Optional[float]


class HistoryDB:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS trace_history (
                        id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        query_type TEXT NOT NULL,
                        source TEXT,
                        destination TEXT,
                        prefix TEXT,
                        result_json TEXT NOT NULL,
                        query_time_ms REAL
                    )
                    """
                )
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.commit()

    def save(self, record: TraceRecord) -> None:
        try:
            with self._lock:
                with self._connect() as conn:
                    conn.execute(
                        """
                        INSERT INTO trace_history (
                            id, timestamp, query_type, source, destination, prefix, result_json, query_time_ms
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            record.id,
                            record.timestamp,
                            record.query_type,
                            record.source,
                            record.destination,
                            record.prefix,
                            record.result_json,
                            record.query_time_ms,
                        ),
                    )
                    conn.execute(
                        """
                        DELETE FROM trace_history
                        WHERE id IN (
                            SELECT id FROM trace_history
                            ORDER BY timestamp ASC
                            LIMIT (
                                SELECT MAX(0, COUNT(*) - ?)
                                FROM trace_history
                            )
                        )
                        """,
                        (MAX_HISTORY_ROWS,),
                    )
                    conn.commit()
        except Exception as exc:
            logger.warning("Failed to save history record: %s", exc)

    def list(self, limit: int = 50, query_type: Optional[str] = None) -> list[dict]:
        try:
            safe_limit = max(1, min(limit, 500))
            with self._lock:
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    if query_type:
                        rows = conn.execute(
                            """
                            SELECT id, timestamp, query_type, source, destination, prefix, query_time_ms
                            FROM trace_history
                            WHERE query_type = ?
                            ORDER BY timestamp DESC
                            LIMIT ?
                            """,
                            (query_type, safe_limit),
                        ).fetchall()
                    else:
                        rows = conn.execute(
                            """
                            SELECT id, timestamp, query_type, source, destination, prefix, query_time_ms
                            FROM trace_history
                            ORDER BY timestamp DESC
                            LIMIT ?
                            """,
                            (safe_limit,),
                        ).fetchall()
                    return [dict(row) for row in rows]
        except Exception as exc:
            logger.warning("Failed to list history: %s", exc)
            return []

    def get(self, record_id: str) -> Optional[dict]:
        try:
            with self._lock:
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    row = conn.execute(
                        """
                        SELECT id, timestamp, query_type, source, destination, prefix, result_json, query_time_ms
                        FROM trace_history
                        WHERE id = ?
                        """,
                        (record_id,),
                    ).fetchone()
                    return dict(row) if row else None
        except Exception as exc:
            logger.warning("Failed to get history record: %s", exc)
            return None

    def delete(self, record_id: str) -> bool:
        try:
            with self._lock:
                with self._connect() as conn:
                    cursor = conn.execute("DELETE FROM trace_history WHERE id = ?", (record_id,))
                    conn.commit()
                    return cursor.rowcount > 0
        except Exception as exc:
            logger.warning("Failed to delete history record: %s", exc)
            return False

    def clear(self) -> int:
        try:
            with self._lock:
                with self._connect() as conn:
                    cursor = conn.execute("DELETE FROM trace_history")
                    conn.commit()
                    return cursor.rowcount
        except Exception as exc:
            logger.warning("Failed to clear history: %s", exc)
            return 0
