"""Organization-scoped live event bus feeding Server-Sent Events.

In-process by default. When REDIS_URL is set, events are published through Redis pub/sub so that
API instances and Celery workers all reach every connected browser. Redis only carries transient
notifications; the database remains the source of truth, so a missed event is recoverable by a
page refresh.
"""
import asyncio
import json
import logging
import threading

from app.config import get_settings

logger = logging.getLogger(__name__)

CHANNEL = "tiq:events"


class EventBus:
    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._subscribers: dict[int, tuple[str, asyncio.Queue]] = {}
        self._next_id = 0
        self._lock = threading.Lock()
        self._redis = None
        self._listener: threading.Thread | None = None
        self._stop = threading.Event()

    # ------------------------------------------------------------------ lifecycle
    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        url = get_settings().redis_url
        if url:
            try:  # pragma: no cover - requires a Redis server
                import redis

                self._redis = redis.Redis.from_url(url, socket_timeout=5, socket_connect_timeout=2)
                self._redis.ping()
                self._listener = threading.Thread(target=self._listen, name="event-bus-redis", daemon=True)
                self._listener.start()
            except Exception as exc:
                logger.warning("Redis pub/sub unavailable (%s); live events are in-process only", type(exc).__name__)
                self._redis = None

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------ subscribe / publish
    def subscribe(self, organization_id: str) -> tuple[int, asyncio.Queue]:
        queue: asyncio.Queue = asyncio.Queue(maxsize=200)
        with self._lock:
            self._next_id += 1
            sub_id = self._next_id
            self._subscribers[sub_id] = (organization_id, queue)
        return sub_id, queue

    def unsubscribe(self, sub_id: int) -> None:
        with self._lock:
            self._subscribers.pop(sub_id, None)

    def publish(self, organization_id: str, event_type: str, data: dict) -> None:
        """Thread-safe; callable from request handlers and background jobs."""
        message = {"organization_id": organization_id, "type": event_type, "data": data}
        if self._redis is not None:
            try:  # pragma: no cover - requires a Redis server
                self._redis.publish(CHANNEL, json.dumps(message, default=str))
                return
            except Exception as exc:
                logger.warning("Redis publish failed (%s); delivering locally", type(exc).__name__)
        self._deliver(message)

    def _deliver(self, message: dict) -> None:
        if self._loop is None or self._loop.is_closed():
            return
        with self._lock:
            targets = [q for org, q in self._subscribers.values() if org == message["organization_id"]]
        for queue in targets:
            self._loop.call_soon_threadsafe(self._offer, queue, message)

    @staticmethod
    def _offer(queue: asyncio.Queue, message: dict) -> None:
        try:
            queue.put_nowait(message)
        except asyncio.QueueFull:
            pass  # a slow client misses an event; it can refetch from the API

    def _listen(self) -> None:  # pragma: no cover - requires a Redis server
        while not self._stop.is_set():
            try:
                pubsub = self._redis.pubsub(ignore_subscribe_messages=True)
                pubsub.subscribe(CHANNEL)
                for item in pubsub.listen():
                    if self._stop.is_set():
                        return
                    self._deliver(json.loads(item["data"]))
            except Exception as exc:
                logger.warning("Redis listener error (%s); retrying", type(exc).__name__)
                self._stop.wait(2)


bus = EventBus()
