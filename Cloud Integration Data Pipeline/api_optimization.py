"""
GovernX Week 4 - API Optimization & Performance Layer (Person 1: Backend Lead)

Delivers low-latency query optimization, thread-safe TTL caching,
in-memory rate limiting, and structured pagination for high-volume cloud datasets.
"""

import time
import logging
import threading
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TTLCache:
    """Thread-safe In-Memory Time-To-Live (TTL) Cache for API endpoints"""

    def __init__(self, default_ttl_seconds: int = 300):
        self.default_ttl = default_ttl_seconds
        self._store: Dict[str, Tuple[Any, float]] = {}
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key not in self._store:
                self.misses += 1
                return None

            val, expiry = self._store[key]
            if time.time() > expiry:
                del self._store[key]
                self.misses += 1
                return None

            self.hits += 1
            return val

    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None):
        with self._lock:
            ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
            self._store[key] = (value, time.time() + ttl)

    def invalidate(self, key: str):
        with self._lock:
            self._store.pop(key, None)

    def clear(self):
        with self._lock:
            self._store.clear()

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self.hits + self.misses
            ratio = round((self.hits / total * 100), 2) if total > 0 else 0.0
            return {
                "active_entries": len(self._store),
                "cache_hits": self.hits,
                "cache_misses": self.misses,
                "hit_ratio_percentage": ratio
            }


class InMemoryRateLimiter:
    """Sliding window token-bucket rate limiter per IP / API client"""

    def __init__(self, requests_per_minute: int = 60):
        self.rate_limit = requests_per_minute
        self.window_seconds = 60.0
        self._clients: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, client_id: str) -> Tuple[bool, int]:
        """Returns (is_allowed, remaining_requests)"""
        now = time.time()
        with self._lock:
            timestamps = self._clients.setdefault(client_id, [])
            # Prune timestamps outside the rolling window
            cutoff = now - self.window_seconds
            self._clients[client_id] = [t for t in timestamps if t > cutoff]

            if len(self._clients[client_id]) >= self.rate_limit:
                return False, 0

            self._clients[client_id].append(now)
            remaining = self.rate_limit - len(self._clients[client_id])
            return True, remaining


def paginate_items(items: List[Any], skip: int = 0, limit: int = 50) -> Dict[str, Any]:
    """Uniform pagination wrapper for API responses"""
    safe_skip = max(0, skip)
    safe_limit = max(1, min(limit, 500))  # Capped at 500 records max

    total = len(items)
    paginated = items[safe_skip : safe_skip + safe_limit]
    page = (safe_skip // safe_limit) + 1
    total_pages = (total + safe_limit - 1) // safe_limit if total > 0 else 1

    return {
        "total_records": total,
        "returned_records": len(paginated),
        "page": page,
        "total_pages": total_pages,
        "has_next": (safe_skip + safe_limit) < total,
        "data": paginated
    }


if __name__ == "__main__":
    cache = TTLCache(default_ttl_seconds=2)
    cache.set("key1", {"status": "ok"})
    print("Initial cache hit:", cache.get("key1"))

    limiter = InMemoryRateLimiter(requests_per_minute=3)
    for i in range(5):
        allowed, rem = limiter.is_allowed("test-client")
        print(f"Req {i+1}: Allowed={allowed}, Remaining={rem}")

    data = list(range(105))
    page_res = paginate_items(data, skip=20, limit=10)
    print("Pagination test:", {k: v for k, v in page_res.items() if k != 'data'})
