import json
from pathlib import Path


def create_sample_telemetry(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sample = {
        "node_id": "edge-node-01",
        "environment": "forward-deployed-training-range",
        "network_status": "degraded",
        "disk_encrypted": True,
        "last_patch_days": 18,
        "failed_login_count": 4,
        "telemetry_backlog": 12,
        "critical_services": {
            "artifact_verifier": "running",
            "telemetry_forwarder": "running",
            "policy_agent": "running"
        }
    }
    path.write_text(json.dumps(sample, indent=2), encoding="utf-8")


def load_telemetry(path: Path) -> dict:
    if not path.exists():
        create_sample_telemetry(path)
    return json.loads(path.read_text(encoding="utf-8"))
