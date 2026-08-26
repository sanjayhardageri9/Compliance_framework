from __future__ import annotations

import asyncio

from aimw.reliability.circuit_breaker import CircuitBreaker, InMemoryCircuitBreakerBackend


async def test_closed_by_default():
    breaker = CircuitBreaker(InMemoryCircuitBreakerBackend())
    assert await breaker.check("agent-1", "sql_tool") is True


async def test_trips_open_after_failure_threshold():
    backend = InMemoryCircuitBreakerBackend(
        failure_threshold=0.5, min_samples=4, cooldown_seconds=60
    )
    breaker = CircuitBreaker(backend)
    for _ in range(4):
        await breaker.record_result("agent-1", "sql_tool", success=False)
    assert await breaker.check("agent-1", "sql_tool") is False


async def test_stays_closed_below_min_samples():
    backend = InMemoryCircuitBreakerBackend(failure_threshold=0.5, min_samples=10)
    breaker = CircuitBreaker(backend)
    for _ in range(3):
        await breaker.record_result("agent-1", "sql_tool", success=False)
    assert await breaker.check("agent-1", "sql_tool") is True


async def test_stays_closed_when_mostly_succeeding():
    backend = InMemoryCircuitBreakerBackend(failure_threshold=0.5, min_samples=4)
    breaker = CircuitBreaker(backend)
    await breaker.record_result("agent-1", "sql_tool", success=True)
    await breaker.record_result("agent-1", "sql_tool", success=True)
    await breaker.record_result("agent-1", "sql_tool", success=True)
    await breaker.record_result("agent-1", "sql_tool", success=False)
    assert await breaker.check("agent-1", "sql_tool") is True


async def test_keys_are_independent_per_agent_and_tool():
    backend = InMemoryCircuitBreakerBackend(failure_threshold=0.5, min_samples=2)
    breaker = CircuitBreaker(backend)
    await breaker.record_result("agent-1", "sql_tool", success=False)
    await breaker.record_result("agent-1", "sql_tool", success=False)
    assert await breaker.check("agent-1", "sql_tool") is False
    assert await breaker.check("agent-1", "other_tool") is True
    assert await breaker.check("agent-2", "sql_tool") is True


async def test_reopens_for_evaluation_after_cooldown():
    backend = InMemoryCircuitBreakerBackend(
        failure_threshold=0.5, min_samples=2, cooldown_seconds=0.05
    )
    breaker = CircuitBreaker(backend)
    await breaker.record_result("agent-1", "sql_tool", success=False)
    await breaker.record_result("agent-1", "sql_tool", success=False)
    assert await breaker.check("agent-1", "sql_tool") is False

    await asyncio.sleep(0.1)
    assert await breaker.check("agent-1", "sql_tool") is True


async def test_score_reflects_failure_rate():
    backend = InMemoryCircuitBreakerBackend()
    breaker = CircuitBreaker(backend)
    assert await breaker.score("agent-1", "sql_tool") == 0.0
    await breaker.record_result("agent-1", "sql_tool", success=True)
    await breaker.record_result("agent-1", "sql_tool", success=False)
    assert await breaker.score("agent-1", "sql_tool") == 0.5
