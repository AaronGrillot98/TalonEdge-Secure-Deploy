"""Offline queue persistence tests."""

import json

from talonedge.offline_queue import OfflineQueue


def test_enqueue_and_flush_returns_events_in_order(tmp_path):
    q = OfflineQueue(tmp_path / "queue.jsonl")
    q.enqueue({"event": "first"})
    q.enqueue({"event": "second"})
    q.enqueue({"event": "third"})

    flushed = q.flush()
    assert [e["event"] for e in flushed] == ["first", "second", "third"]


def test_flush_clears_queue(tmp_path):
    q = OfflineQueue(tmp_path / "queue.jsonl")
    q.enqueue({"event": "x"})
    q.flush()
    assert q.flush() == []


def test_flush_empty_queue_returns_empty_list(tmp_path):
    q = OfflineQueue(tmp_path / "queue.jsonl")
    assert q.flush() == []


def test_enqueue_adds_iso_timestamp(tmp_path):
    q = OfflineQueue(tmp_path / "queue.jsonl")
    q.enqueue({"event": "x"})
    line = (tmp_path / "queue.jsonl").read_text(encoding="utf-8").strip()
    parsed = json.loads(line)
    assert "queued_at" in parsed
    # ISO 8601 with timezone suffix.
    assert "T" in parsed["queued_at"]
    assert parsed["queued_at"].endswith("+00:00")


def test_enqueue_does_not_mutate_caller_dict(tmp_path):
    q = OfflineQueue(tmp_path / "queue.jsonl")
    payload = {"event": "x"}
    q.enqueue(payload)
    assert "queued_at" not in payload


def test_creates_parent_directory(tmp_path):
    q = OfflineQueue(tmp_path / "deep" / "nested" / "queue.jsonl")
    q.enqueue({"event": "x"})
    assert (tmp_path / "deep" / "nested" / "queue.jsonl").exists()
