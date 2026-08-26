"""Exercises RedisCircuitBreakerBackend's logic against an in-memory fake
Redis client (sorted-set + string ops only), so the algorithm is covered
without requiring a real Redis server. A real end-to-end check against an
actual Redis instance is a separate, opt-in concern (not included here -
this build has no dependency on a live Redis).
"""

from __future__ import annotations

import time

from aimw.reliability.circuit_breaker import CircuitBreaker, RedisCircuitBreakerBackend


class FakeAsyncRedis:
    """Minimal in-memory stand-in for the handful of redis-py async methods used."""

    def __init__(self) -> None:
        self._zsets: dict[str, dict[str, float]] = {}
        self._strings: dict[str, tuple[str, float | None]] = {}  # key -> (value, expiry_epoch)

    async def zadd(self, key: str, mapping: dict[str, float]) -> None:
        self._zsets.setdefault(key, {}).update(mapping)

    async def zremrangebyscore(self, key: str, min_score: float, max_score: float) -> None:
        zset = self._zsets.get(key, {})
        self._zsets[key] = {m: s for m, s in zset.items() if not (min_score <= s <= max_score)}

    async def zrange(self, key: str, start: int, stop: int) -> list[bytes]:
        members = sorted(self._zsets.get(key, {}).items(), key=lambda kv: kv[1])
        members_only = [m.encode() for m, _ in members]
        if stop == -1:
            return members_only[start:]
        return members_only[start : stop + 1]

    async def expire(self, key: str, seconds: int) -> None:
        pass  # not needed for these tests

    async def setex(self, key: str, seconds: int, value: str) -> None:
        self._strings[key] = (value, time.time() + seconds)

    async def ttl(self, key: str) -> int:
        entry = self._strings.get(key)
        if entry is None:
            return -2
        _, expiry = entry
        remaining = int(expiry - time.time())
        if remaining <= 0:
            del self._strings[key]
            return -2
        return remaining


async def test_closed_by_default():
    backend = RedisCircuitBreakerBackend(FakeAsyncRedis())
    breaker = CircuitBreaker(backend)
    assert await breaker.check("agent-1", "sql_tool") is True


async def test_trips_open_after_failure_threshold():
    backend = RedisCircuitBreakerBackend(
        FakeAsyncRedis(), failure_threshold=0.5, min_samples=4, cooldown_seconds=60
    )
    breaker = CircuitBreaker(backend)
    for _ in range(4):
        await breaker.record_result("agent-1", "sql_tool", success=False)
    assert await breaker.check("agent-1", "sql_tool") is False


async def test_stays_closed_below_min_samples():
    backend = RedisCircuitBreakerBackend(FakeAsyncRedis(), failure_threshold=0.5, min_samples=10)
    breaker = CircuitBreaker(backend)
    for _ in range(3):
        await breaker.record_result("agent-1", "sql_tool", success=False)
    assert await breaker.check("agent-1", "sql_tool") is True


async def test_score_reflects_failure_rate():
    backend = RedisCircuitBreakerBackend(FakeAsyncRedis())
    breaker = CircuitBreaker(backend)
    assert await breaker.score("agent-1", "sql_tool") == 0.0
    await breaker.record_result("agent-1", "sql_tool", success=True)
    await breaker.record_result("agent-1", "sql_tool", success=False)
    assert await breaker.score("agent-1", "sql_tool") == 0.5


async def test_once_tripped_stays_open_until_ttl_expires():
    backend = RedisCircuitBreakerBackend(
        FakeAsyncRedis(), failure_threshold=0.5, min_samples=2, cooldown_seconds=1
    )
    breaker = CircuitBreaker(backend)
    await breaker.record_result("agent-1", "sql_tool", success=False)
    await breaker.record_result("agent-1", "sql_tool", success=False)
    assert await breaker.check("agent-1", "sql_tool") is False
    # Still tripped immediately after (the "tripped" sentinel key has a TTL).
    assert await breaker.check("agent-1", "sql_tool") is False


async def test_keys_are_independent_per_agent_and_tool():
    backend = RedisCircuitBreakerBackend(FakeAsyncRedis(), failure_threshold=0.5, min_samples=2)
    breaker = CircuitBreaker(backend)
    await breaker.record_result("agent-1", "sql_tool", success=False)
    await breaker.record_result("agent-1", "sql_tool", success=False)
    assert await breaker.check("agent-1", "sql_tool") is False
    assert await breaker.check("agent-1", "other_tool") is True
    assert await breaker.check("agent-2", "sql_tool") is True
