import json
from pathlib import Path
from datetime import datetime, timezone


class OfflineQueue:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def enqueue(self, event: dict) -> None:
        event = dict(event)
        event["queued_at"] = datetime.now(timezone.utc).isoformat()
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

    def flush(self) -> list[dict]:
        if not self.path.exists():
            return []
        events = [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.path.write_text("", encoding="utf-8")
        return events
