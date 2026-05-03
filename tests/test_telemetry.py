"""Telemetry loader tests."""

import json

from talonedge.telemetry import create_sample_telemetry, load_telemetry


def test_load_telemetry_returns_existing_file_unchanged(tmp_path):
    path = tmp_path / "t.json"
    payload = {"node_id": "edge-99", "marker": "real-data"}
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = load_telemetry(path)
    assert result["marker"] == "real-data"
    assert result["node_id"] == "edge-99"


def test_load_telemetry_creates_sample_when_missing(tmp_path):
    # Documents the deliberate "demo helper" behavior: load_telemetry materializes
    # a sample if the file is missing. In production this should be replaced
    # with a hard error — the demo path is ergonomic, not safe by default.
    path = tmp_path / "missing.json"
    result = load_telemetry(path)
    assert path.exists()
    assert result["node_id"] == "edge-node-01"


def test_create_sample_telemetry_writes_expected_shape(tmp_path):
    path = tmp_path / "deep" / "t.json"
    create_sample_telemetry(path)
    parsed = json.loads(path.read_text(encoding="utf-8"))
    for key in (
        "node_id",
        "environment",
        "network_status",
        "disk_encrypted",
        "last_patch_days",
        "failed_login_count",
        "telemetry_backlog",
        "critical_services",
    ):
        assert key in parsed
    assert isinstance(parsed["critical_services"], dict)
