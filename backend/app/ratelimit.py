"""Fixed-window rate limiting. In-memory by default; Redis when REDIS_URL is configured.

Redis here only holds disposable counters. If Redis is unreachable the limiter falls back to the
in-process counters rather than blocking requests.
"""
import logging
import threading
import time
from collections import defaultdict

from app.config import get_settings
from app.errors import AppError

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_buckets: dict[str, tuple[int, int]] = defaultdict(lambda: (0, 0))  # key -> (window_start, count)
_redis = None
_redis_failed = False


def _get_redis():
    global _redis, _redis_failed
    url = get_settings().redis_url
    if not url or _redis_failed:
        return None
    if _redis is None:
        try:
            import redis

            _redis = redis.Redis.from_url(url, socket_timeout=1, socket_connect_timeout=1)
        except Exception as exc:  # pragma: no cover - depends on a Redis server
            logger.warning("Redis unavailable for rate limiting (%s); using in-process counters", type(exc).__name__)
            _redis_failed = True
            return None
    return _redis


def hit(key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
    """Count a request. Returns (allowed, retry_after_seconds)."""
    now = int(time.time())
    window = now // window_seconds
    retry_after = window_seconds - (now % window_seconds)

    client = _get_redis()
    if client is not None:
        try:  # pragma: no cover - requires a Redis server
            redis_key = f"tiq:rl:{key}:{window}"
            count = client.incr(redis_key)
            if count == 1:
                client.expire(redis_key, window_seconds + 1)
            return count <= limit, retry_after
        except Exception as exc:
            logger.warning("Redis rate-limit call failed (%s); using in-process counters", type(exc).__name__)

    with _lock:
        start, count = _buckets[key]
        if start != window:
            start, count = window, 0
        count += 1
        _buckets[key] = (start, count)
        if len(_buckets) > 50_000:  # bound memory under key-spraying
            for stale in [k for k, (w, _) in _buckets.items() if w != window][:10_000]:
                _buckets.pop(stale, None)
    return count <= limit, retry_after


def enforce(key: str, limit: int, window_seconds: int = 60) -> None:
    allowed, retry_after = hit(key, limit, window_seconds)
    if not allowed:
        raise AppError("RATE_LIMITED", "Too many requests. Please slow down and retry shortly.", 429, headers={"Retry-After": str(retry_after)})


def reset_for_tests() -> None:  # kept so operators can clear counters in a REPL
    with _lock:
        _buckets.clear()
