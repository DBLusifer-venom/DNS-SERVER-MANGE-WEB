"""In-process sliding-window login rate limiter.

Per-IP and per-username limits with a sliding window. For multi-worker /
HA deployments this should be replaced with a Redis-backed store (P1-02).

The store is intentionally a plain dict — single-process uvicorn only.
"""

import threading
import time
from collections import deque

from ..config import get_settings

_lock = threading.Lock()
_hits: dict[str, deque[float]] = {}


def _allowed(key: str, now: float, limit: int, window: float) -> bool:
    q = _hits.get(key)
    if q is None:
        return True
    while q and now - q[0] > window:
        q.popleft()
    return len(q) < limit


def check_and_record(key: str) -> bool:
    """Record an attempt and return False if the key is over the limit."""
    settings = get_settings()
    now = time.monotonic()
    with _lock:
        allowed = _allowed(key, now, settings.rate_limit_attempts, settings.rate_limit_window_seconds)
        q = _hits.setdefault(key, deque())
        while q and now - q[0] > settings.rate_limit_window_seconds:
            q.popleft()
        q.append(now)
        return allowed


def clear(key: str) -> None:
    with _lock:
        _hits.pop(key, None)


def reset() -> None:
    """Clear all state (used by tests and on settings reload)."""
    with _lock:
        _hits.clear()