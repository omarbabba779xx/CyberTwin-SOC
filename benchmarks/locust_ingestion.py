"""CyberTwin SOC - Locust ingestion stress test.

Run:
    locust -f benchmarks/locust_ingestion.py \
           --host=http://localhost:8000 \
           --users 100 --spawn-rate 10 --run-time 1m --headless
"""

from __future__ import annotations

import os
import random
import uuid
from datetime import datetime, timezone

from locust import HttpUser, between, task


TOKEN = os.getenv("CYBERTWIN_TOKEN", "")
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"} if TOKEN else {}


def _windows_event() -> dict:
    return {
        "System": {
            "EventID":     random.choice([4624, 4625, 4688]),
            "Computer":    f"WS-{random.randint(1, 50):03d}",
            "TimeCreated": datetime.now(timezone.utc).isoformat(),
        },
        "EventData": {
            "TargetUserName": random.choice(["alice", "bob", "charlie"]),
            "IpAddress":      f"10.0.0.{random.randint(1, 254)}",
            "NewProcessName": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine":    "powershell -enc " + uuid.uuid4().hex[:20],
        },
        "event_id": f"k6-{uuid.uuid4().hex[:8]}",
    }


class IngestionUser(HttpUser):
    wait_time = between(0.05, 0.2)

    @task(10)
    def post_event(self):
        self.client.post(
            "/api/ingest/event",
            json={"event": _windows_event(), "source_type": "windows_event"},
            headers=HEADERS,
            name="POST /api/ingest/event",
        )

    @task(2)
    def post_batch(self):
        events = [_windows_event() for _ in range(20)]
        self.client.post(
            "/api/ingest/batch",
            json={"events": events, "source_type": "windows_event"},
            headers=HEADERS,
            name="POST /api/ingest/batch",
        )

    @task(1)
    def get_stats(self):
        self.client.get(
            "/api/ingest/stats", headers=HEADERS, name="GET /api/ingest/stats",
        )

    @task(1)
    def get_health(self):
        self.client.get("/api/health", name="GET /api/health")
