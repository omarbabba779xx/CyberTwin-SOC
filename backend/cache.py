"""
CyberTwin SOC — Cache Layer
=============================
Provides a unified cache interface backed by Redis when available,
falling back to a thread-safe in-memory dict when Redis is not
configured or reachable.

Usage::

    from backend.cache import cache
    cache.set("key", value, ttl=3600)
    value = cache.get("key")
    cache.delete("key")
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, Optional

logger = logging.getLogger("cybertwin.cache")


# ---------------------------------------------------------------------------
# In-memory fallback
# ---------------------------------------------------------------------------

class _MemoryCache:
    """Thread-safe in-memory cache with TTL support."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[Any, float]] = {}
        self._lock = threading.Lock()

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        expires_at = time.time() + ttl if ttl else float("inf")
        with self._lock:
            self._store[key] = (value, expires_at)

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if time.time() > expires_at:
                del self._store[key]
                return None
            return value

    def delete(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def keys(self) -> list[str]:
        now = time.time()
        with self._lock:
            return [k for k, (_, exp) in self._store.items() if now <= exp]

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    @property
    def backend(self) -> str:
        return "memory"


# ---------------------------------------------------------------------------
# Redis-backed cache
# ---------------------------------------------------------------------------

class _RedisCache:
    def __init__(self, client) -> None:
        self._r = client

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        data = json.dumps(value, default=str)
        if ttl:
            self._r.setex(key, ttl, data)
        else:
            self._r.set(key, data)

    def get(self, key: str) -> Optional[Any]:
        data = self._r.get(key)
        if data is None:
            return None
        return json.loads(data)

    def delete(self, key: str) -> None:
        self._r.delete(key)

    def keys(self) -> list[str]:
        return [k.decode() if isinstance(k, bytes) else k for k in self._r.keys("*")]

    def clear(self) -> None:
        self._r.flushdb()

    @property
    def backend(self) -> str:
        return "redis"


# ---------------------------------------------------------------------------
# Factory — pick Redis if available
# ---------------------------------------------------------------------------

def _build_cache():
    redis_url = os.getenv("REDIS_URL", "")
    if redis_url:
        try:
            import redis as _redis
            client = _redis.from_url(redis_url, socket_connect_timeout=2)
            client.ping()
            logger.info("Cache backend: Redis (%s)", redis_url)
            return _RedisCache(client)
        except Exception as exc:
            logger.warning("Redis unavailable (%s) — falling back to in-memory cache", exc)
    else:
        logger.info("Cache backend: in-memory (set REDIS_URL to enable Redis)")
    return _MemoryCache()


cache = _build_cache()
