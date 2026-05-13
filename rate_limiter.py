
# rate_limiter.py
"""
Simple in-memory rate limiter to protect the API from abuse.
Limits requests per IP per minute.
"""
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, Tuple


class RateLimiter:
    """
    Token-bucket rate limiter.
    Default: 30 requests per minute per IP for analysis endpoints,
             60 per minute for lightweight endpoints.
    """

    def __init__(self):
        self._buckets: Dict[str, list] = defaultdict(list)
        self._lock = Lock()

    def is_allowed(self, ip: str, endpoint: str = "default", limit: int = 30, window: int = 60) -> Tuple[bool, Dict]:
        now = time.time()
        key = ip + ":" + endpoint
        with self._lock:
            timestamps = self._buckets[key]
            # Remove expired timestamps
            self._buckets[key] = [t for t in timestamps if now - t < window]
            count = len(self._buckets[key])
            remaining = limit - count
            if count >= limit:
                oldest = self._buckets[key][0]
                retry_after = int(window - (now - oldest)) + 1
                return False, {
                    "error": "Rate limit exceeded",
                    "limit": limit,
                    "remaining": 0,
                    "retry_after_seconds": retry_after
                }
            self._buckets[key].append(now)
            return True, {
                "limit": limit,
                "remaining": remaining - 1,
                "window_seconds": window
            }

    def get_limits(self, endpoint: str) -> Tuple[int, int]:
        """Returns (limit, window) for an endpoint."""
        limits = {
            "analyze": (10, 60),       # 10 email analyses per minute
            "check-domain": (30, 60),  # 30 domain checks per minute
            "check-url": (30, 60),     # 30 URL checks per minute
            "extract-iocs": (20, 60),  # 20 IOC extractions per minute
            "default": (60, 60),       # 60 general requests per minute
        }
        return limits.get(endpoint, limits["default"])
