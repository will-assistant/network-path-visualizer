from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
from history import HistoryDB, TraceRecord, MAX_HISTORY_ROWS


def make_record(idx: int = 0, query_type: str = "trace", ts: str | None = None) -> TraceRecord:
    return TraceRecord(
        id=str(uuid.uuid4()),
        timestamp=ts or (datetime.now(timezone.utc) + timedelta(seconds=idx)).isoformat(),
        query_type=query_type,
        source=f"src-{idx}",
        destination=f"dst-{idx}",
        prefix=f"10.0.{idx}.0/24",
        result_json=json.dumps({"idx": idx, "type": query_type}),
        query_time_ms=idx + 0.5,
    )


def test_init_creates_table(tmp_path: Path):
    db = HistoryDB(tmp_path / "history.db")
    with sqlite3.connect(db.db_path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM trace_history").fetchone()[0]
    assert count == 0


def test_save_and_list(tmp_path: Path):
    db = HistoryDB(tmp_path / "history.db")
    rec = make_record(1)
    db.save(rec)
    rows = db.list()
    assert len(rows) == 1
    assert rows[0]["id"] == rec.id


def test_list_excludes_result_json(tmp_path: Path):
    db = HistoryDB(tmp_path / "history.db")
    db.save(make_record(1))
    row = db.list()[0]
    assert "result_json" not in row


def test_get_includes_result_json(tmp_path: Path):
    db = HistoryDB(tmp_path / "history.db")
    rec = make_record(2)
    db.save(rec)
    fetched = db.get(rec.id)
    assert fetched is not None
    assert fetched["result_json"] == rec.result_json


def test_list_limit(tmp_path: Path):
    db = HistoryDB(tmp_path / "history.db")
    for i in range(5):
        db.save(make_record(i))
    rows = db.list(limit=2)
    assert len(rows) == 2
    assert rows[0]["timestamp"] >= rows[1]["timestamp"]


def test_list_filter_by_type(tmp_path: Path):
    db = HistoryDB(tmp_path / "history.db")
    db.save(make_record(1, query_type="trace"))
    db.save(make_record(2, query_type="blast_radius"))
    filtered = db.list(query_type="blast_radius")
    assert len(filtered) == 1
    assert filtered[0]["query_type"] == "blast_radius"


def test_get_not_found(tmp_path: Path):
    db = HistoryDB(tmp_path / "history.db")
    assert db.get("nonexistent") is None


def test_delete_found(tmp_path: Path):
    db = HistoryDB(tmp_path / "history.db")
    rec = make_record(1)
    db.save(rec)
    assert db.delete(rec.id) is True


def test_delete_not_found(tmp_path: Path):
    db = HistoryDB(tmp_path / "history.db")
    assert db.delete("missing") is False


def test_clear(tmp_path: Path):
    db = HistoryDB(tmp_path / "history.db")
    for i in range(3):
        db.save(make_record(i))
    assert db.clear() == 3
    assert db.list() == []


def test_thread_safety(tmp_path: Path):
    db = HistoryDB(tmp_path / "history.db")

    def writer(thread_idx: int):
        for i in range(5):
            db.save(make_record(thread_idx * 10 + i))

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(db.list(limit=100)) == 50


def test_save_bad_path_doesnt_raise(tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch):
    db = HistoryDB(tmp_path / "history.db")

    def bad_connect():
        raise sqlite3.OperationalError("unable to open database file")

    monkeypatch.setattr(db, "_connect", bad_connect)
    db.save(make_record(1))
    assert "Failed to save history record" in caplog.text


def test_list_returns_empty_on_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db = HistoryDB(tmp_path / "history.db")

    def bad_connect():
        raise sqlite3.OperationalError("corrupt")

    monkeypatch.setattr(db, "_connect", bad_connect)
    assert db.list() == []


def test_get_returns_none_on_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db = HistoryDB(tmp_path / "history.db")

    def bad_connect():
        raise sqlite3.OperationalError("corrupt")

    monkeypatch.setattr(db, "_connect", bad_connect)
    assert db.get("any-id") is None


def test_max_rows_pruned(tmp_path: Path):
    db = HistoryDB(tmp_path / "history.db")
    for i in range(MAX_HISTORY_ROWS + 5):
        db.save(make_record(i))

    rows = db.list(limit=MAX_HISTORY_ROWS + 10)
    assert len(rows) <= MAX_HISTORY_ROWS
