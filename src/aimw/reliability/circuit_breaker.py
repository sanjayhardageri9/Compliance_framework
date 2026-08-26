"""Circuit breaker + failure scoring (Section 13's "Reliability" row).

L1 relies on token caps and static timeouts alone. L2 adds a circuit
breaker that tracks a rolling failure score per key (e.g. "agent:tool")
and trips open - denying further calls - once that key's recent failure
rate crosses a threshold, instead of letting a misbehaving tool keep
failing (and keep costing sandbox time) indefinitely. The backend is
pluggable: InMemoryCircuitBreakerBackend is the hermetic default (no
external service), RedisCircuitBreakerBackend is the real L2 backend for
when a shared, cross-process view is needed - matching the doc's "Redis
circuit breaker + scoring" - and is only exercised by opt-in tests.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections import deque


class BaseCircuitBreakerBackend(ABC):
    """Tracks per-key outcomes and reports whether a key's circuit is open."""

    @abstractmethod
    async def record_success(self, key: str) -> None: ...

    @abstractmethod
    async def record_failure(self, key: str) -> None: ...

    @abstractmethod
    async def is_open(self, key: str) -> bool: ...

    @abstractmethod
    async def score(self, key: str) -> float:
        """Recent failure rate for `key`, in [0.0, 1.0]. 0.0 = no data."""
        ...


class InMemoryCircuitBreakerBackend(BaseCircuitBreakerBackend):
    """Hermetic default: sliding time-window of outcomes, kept in memory."""

    def __init__(
        self,
        window_seconds: float = 60.0,
        failure_threshold: float = 0.5,
        min_samples: int = 5,
        cooldown_seconds: float = 30.0,
    ) -> None:
        self._window_seconds = window_seconds
        self._failure_threshold = failure_threshold
        self._min_samples = min_samples
        self._cooldown_seconds = cooldown_seconds
        # key -> deque[(timestamp, success: bool)]
        self._events: dict[str, deque[tuple[float, bool]]] = {}
        # key -> timestamp the circuit tripped open, or None if closed
        self._tripped_at: dict[str, float] = {}

    def _prune(self, key: str, now: float) -> deque[tuple[float, bool]]:
        events = self._events.setdefault(key, deque())
        cutoff = now - self._window_seconds
        while events and events[0][0] < cutoff:
            events.popleft()
        return events

    async def record_success(self, key: str) -> None:
        now = time.monotonic()
        self._prune(key, now).append((now, True))

    async def record_failure(self, key: str) -> None:
        now = time.monotonic()
        self._prune(key, now).append((now, False))

    async def score(self, key: str) -> float:
        events = self._prune(key, time.monotonic())
        if not events:
            return 0.0
        failures = sum(1 for _, success in events if not success)
        return failures / len(events)

    async def is_open(self, key: str) -> bool:
        now = time.monotonic()
        tripped_at = self._tripped_at.get(key)
        if tripped_at is not None:
            if now - tripped_at < self._cooldown_seconds:
                return True
            # Cooldown elapsed: close the circuit and clear history for a
            # fresh read (a simplified half-open -> closed transition).
            del self._tripped_at[key]
            self._events[key] = deque()
            return False

        events = self._prune(key, now)
        if len(events) < self._min_samples:
            return False
        failures = sum(1 for _, success in events if not success)
        if failures / len(events) >= self._failure_threshold:
            self._tripped_at[key] = now
            return True
        return False


class RedisCircuitBreakerBackend(BaseCircuitBreakerBackend):
    """L2 backend: a real Redis-shared circuit breaker for multi-process deployments.

    Requires the optional `redis` extra (`pip install ai-governance-middleware[redis]`)
    and a running Redis instance. Not exercised by the default test suite -
    see tests marked `@pytest.mark.redis`.
    """

    def __init__(
        self,
        redis_client: object,
        window_seconds: int = 60,
        failure_threshold: float = 0.5,
        min_samples: int = 5,
        cooldown_seconds: int = 30,
        key_prefix: str = "aimw:cb",
    ) -> None:
        self._redis = redis_client
        self._window_seconds = window_seconds
        self._failure_threshold = failure_threshold
        self._min_samples = min_samples
        self._cooldown_seconds = cooldown_seconds
        self._key_prefix = key_prefix

    def _events_key(self, key: str) -> str:
        return f"{self._key_prefix}:events:{key}"

    def _tripped_key(self, key: str) -> str:
        return f"{self._key_prefix}:tripped:{key}"

    async def _record(self, key: str, success: bool) -> None:
        member = f"{time.time_ns()}:{int(success)}"
        events_key = self._events_key(key)
        await self._redis.zadd(events_key, {member: time.time()})  # type: ignore[attr-defined]
        cutoff = time.time() - self._window_seconds
        await self._redis.zremrangebyscore(events_key, 0, cutoff)  # type: ignore[attr-defined]
        await self._redis.expire(events_key, self._window_seconds * 2)  # type: ignore[attr-defined]

    async def record_success(self, key: str) -> None:
        await self._record(key, True)

    async def record_failure(self, key: str) -> None:
        await self._record(key, False)

    async def _recent_events(self, key: str) -> list[str]:
        events_key = self._events_key(key)
        cutoff = time.time() - self._window_seconds
        await self._redis.zremrangebyscore(events_key, 0, cutoff)  # type: ignore[attr-defined]
        members: list[bytes] = await self._redis.zrange(events_key, 0, -1)  # type: ignore[attr-defined]
        return [m.decode() if isinstance(m, bytes) else m for m in members]

    async def score(self, key: str) -> float:
        events = await self._recent_events(key)
        if not events:
            return 0.0
        failures = sum(1 for e in events if e.endswith(":0"))
        return failures / len(events)

    async def is_open(self, key: str) -> bool:
        tripped_key = self._tripped_key(key)
        ttl: int = await self._redis.ttl(tripped_key)  # type: ignore[attr-defined]
        if ttl and ttl > 0:
            return True

        events = await self._recent_events(key)
        if len(events) < self._min_samples:
            return False
        failures = sum(1 for e in events if e.endswith(":0"))
        if failures / len(events) >= self._failure_threshold:
            await self._redis.setex(tripped_key, self._cooldown_seconds, "1")  # type: ignore[attr-defined]
            return True
        return False


class CircuitBreaker:
    """Facade: derives a key from (agent_id, tool_name) and delegates to a backend."""

    def __init__(self, backend: BaseCircuitBreakerBackend) -> None:
        self._backend = backend

    @staticmethod
    def key_for(agent_id: str, tool_name: str) -> str:
        return f"{agent_id}:{tool_name}"

    async def check(self, agent_id: str, tool_name: str) -> bool:
        """Returns True if calls are currently allowed (circuit closed)."""
        return not await self._backend.is_open(self.key_for(agent_id, tool_name))

    async def record_result(self, agent_id: str, tool_name: str, success: bool) -> None:
        key = self.key_for(agent_id, tool_name)
        if success:
            await self._backend.record_success(key)
        else:
            await self._backend.record_failure(key)

    async def score(self, agent_id: str, tool_name: str) -> float:
        return await self._backend.score(self.key_for(agent_id, tool_name))
