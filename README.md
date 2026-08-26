# ai-governance-middleware (`aimw`)

Reference implementation of the runtime governance middleware described in
Part III of the *AI Governance & Runtime Protection Framework*, covering
the **L1 "Pragmatic Lite"** and **L2 "Growth Tier"** maturity levels
(Section 13). It intercepts an agent's proposed tool calls and enforces
policy, guardrails, sandboxing, and tamper-evident audit logging at
runtime, structured so L3 ("Enterprise Mesh": real OPA/Cedar, E2B microVM
sandboxing, full compound identity) can be added later as new
implementations of the same abstract interfaces — no rewrite required.

This build requires **no external services, accounts, or API keys**. Every
integration point (LLM calls, PII detection, the DB-backed policy store,
the circuit breaker) is a local/hermetic implementation, with an optional
real Docker backend for the sandbox and an optional real Redis backend for
the circuit breaker.

## Architecture

```
User / Context
  -> LiteLLM Gateway shim         (rate limits, identity check, PII pre-pass)
  -> Guardrail.inspect_input      (prompt-injection / control-token checks)
  -> LLM Reasoning Loop           (FakeLLMClient stub)
  -> ToolCallInterceptor          per proposed tool call:
       -> CircuitBreaker.check    (skip everything below if open)
       -> PolicyEngine.evaluate_tool_call
            allowed  -> Sandbox.execute -> CircuitBreaker.record_result
            denied / needs-approval -> HITL approval callback
  -> Guardrail.inspect_output
  -> WORM Audit Log               (hash-chained JSONL, + optional SIEM sinks)
```

## Maturity tiers

| Dimension     | L1 "Pragmatic Lite" (this repo)                            | L2 "Growth Tier" (this repo)                                  |
|---------------|-------------------------------------------------------------|-----------------------------------------------------------------|
| Gateway       | `LiteLLMGatewayShim` — in-process rate limit                | same shim, pluggable identity + `SemanticGuardrail` layer        |
| PII detection | `RegexPIIGuardrail` — regex masking, stand-in for Presidio  | + `DLPClassifier` — sensitivity tiering (LOW/MEDIUM/RESTRICTED) |
| Policy engine | `StaticPolicyEngine` — YAML-declared allow/deny rules       | `DbBackedPolicyEngine` — SQLite-backed, live-updatable RBAC     |
| Identity      | `StaticBearerTokenVerifier` — single deployment-wide token  | `SessionTokenIssuer` — HMAC-signed, session+agent-scoped, expiring |
| Reliability   | token caps & sandbox timeouts only                          | `CircuitBreaker` — trips per (agent, tool) after a failure-rate threshold |
| Sandboxing    | `SubprocessSandbox` (default stub) or `DockerSandbox`       | `RestrictedDockerSandbox` — non-root, read-only rootfs, all caps dropped |
| Audit         | `HashChainedJSONLLogger` — local hash-chained JSONL         | + `BaseAuditSink` forwarding (`LocalSiemForwarder` stand-in for Datadog/Elastic) |

Every concrete class implements one of the abstract interfaces in
`aimw.interfaces` (`BasePolicyEngine`, `BaseGuardrail`, `BaseRegistry`), or
the analogous `BaseSandbox` / `BaseIdentityVerifier` /
`BaseCircuitBreakerBackend` / `BaseAuditSink` hooks built the same way. An
L1 deployment upgrades to L2 by swapping which concrete class is passed
into `ToolCallInterceptor` / `LiteLLMGatewayShim` / `HashChainedJSONLLogger`
— the pipeline, interceptor, and callers never change. `DbBackedPolicyEngine`
and `DbBackedToolRegistry` share one `DbRuleStore` so their view of "what a
context can do" and "what a context can see" never drifts apart, and also
add a **Global RBAC** layer (Section 15.1) that L1 didn't have: a context
whose roles aren't recognized in the store at all is denied before any
per-tool check runs.

### A note on the audit log

`HashChainedJSONLLogger` detects tampering after the fact: each record's
hash is chained to the previous one, and `verify_chain()` can be run by a
completely separate process to confirm no record has been altered. It does
**not** prevent tampering the way real WORM storage does (OS-level
immutability, S3 Object Lock, Azure immutable blobs) — an attacker with
filesystem write access could rewrite the whole file with new, internally
consistent hashes. Real tamper-*prevention* is an explicit L3 upgrade. L2's
SIEM forwarding (`BaseAuditSink`) is best-effort and does not change this:
a sink failure is logged and swallowed, never allowed to break the local
write that already succeeded.

### A note on the circuit breaker

`InMemoryCircuitBreakerBackend` (the hermetic default) and
`RedisCircuitBreakerBackend` (opt-in, needs the `redis` extra and a running
Redis) implement the same `BaseCircuitBreakerBackend` contract — a key
(`agent_id:tool_name`) trips open once its recent sandbox-failure rate
crosses a threshold, and stays open for a cooldown window. `ToolCallInterceptor`
checks the breaker *before* the policy engine runs, so a misbehaving tool
stops costing sandbox time even while it's still "allowed" by policy.

## Install

```bash
python -m venv .venv
. .venv/Scripts/activate    # or: source .venv/bin/activate on Linux/macOS
pip install -e ".[dev]"
pip install -e ".[redis]"   # optional: only needed for RedisCircuitBreakerBackend
```

## Test

```bash
pytest -q                      # hermetic suite, no Docker/Redis/network/API keys required
pytest -q -m docker             # opt-in: also exercises DockerSandbox / RestrictedDockerSandbox (needs a local Docker daemon)
mypy src/aimw --strict
ruff check .
bandit -r src/aimw -c pyproject.toml
```

`RedisCircuitBreakerBackend`'s logic is covered by tests against an
in-memory fake Redis client (see `tests/unit/test_redis_circuit_breaker.py`)
— no real Redis server is required to run the suite.

## Run the demos

```bash
python examples/run_demo.py       # L1: allowed / denied / approval-required / tamper-evidence
python examples/run_demo_l2.py    # L2: session tokens, DB-backed RBAC, semantic guardrail,
                                   #     DLP classification, circuit breaker, SIEM forwarding
```

`run_demo.py` walks through an allowed tool call, a denied call (SQL
deny-pattern match), an approval-required call (shown both approved and
denied by a stub HITL queue), then prints the full audit trail, verifies
its hash chain (`valid=True`), tampers with one byte on disk, and
re-verifies (`valid=False`, with the exact broken record index).

`run_demo_l2.py` additionally shows: a session-scoped token rejected for
the wrong session/agent; a context with an unrecognized role denied at the
Global RBAC layer; a paraphrased prompt-injection attempt caught by the
semantic guardrail where an exact regex would miss it; DLP sensitivity
classification of masked PII; and a circuit breaker tripping after
repeated sandbox failures, denying the third call before policy even runs.

## Out of scope for this build

L3 concrete engines, real E2B/OPA/Cedar/Presidio/Datadog/Elastic
integration, a demo agent product, and the framework document's
governance-policy (Part I) and security-assessment-methodology (Part II)
content — this repository is the middleware SDK only.
