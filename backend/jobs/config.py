"""Arq worker / Redis broker configuration.

Keeps the broker URL aligned with the rest of the platform (REDIS_URL env)
so a single Redis instance handles cache, rate-limit, jti denylist AND the
job queue. In production a separate Redis can be used by setting
JOBS_REDIS_URL explicitly.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class RedisSettings:
    host: str = "localhost"
    port: int = 6379
    database: int = 0
    password: str | None = None

    @classmethod
    def from_url(cls, url: str) -> "RedisSettings":
        # Minimal parser — Arq has a richer one, but we want zero hard import
        # in the API process so it stays cheap when no jobs are enqueued.
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return cls(
            host=parsed.hostname or "localhost",
            port=parsed.port or 6379,
            database=int(parsed.path.lstrip("/") or "0"),
            password=parsed.password,
        )


def queue_settings() -> RedisSettings:
    url = os.environ.get("JOBS_REDIS_URL") or os.environ.get(
        "REDIS_URL", "redis://localhost:6379/0"
    )
    return RedisSettings.from_url(url)


# Job queue name — keep separate from any future cybertwin pubsub channels.
QUEUE_NAME = "cybertwin:jobs"

# Maximum job duration before the worker kills it (seconds).
DEFAULT_TIMEOUT = 600

# Number of retries on retriable failures.
DEFAULT_RETRIES = 2
