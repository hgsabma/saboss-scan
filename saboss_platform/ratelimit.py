"""Simple in-memory rate limiting (sliding window).

Good for a single server process. When Saboss runs on several servers, this
must move to a shared store such as Redis (documented in docs/DEPLOYMENT.md).
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window_seconds: int, now: float | None = None) -> bool:
        """Record one event. Returns False if the limit is exceeded (event not recorded)."""
        now = time.monotonic() if now is None else now
        with self._lock:
            events = self._events[key]
            while events and events[0] <= now - window_seconds:
                events.popleft()
            if len(events) >= limit:
                return False
            events.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._events.clear()
