# ADR-002: L3 Backend Adapter Order

- **Status:** Proposed
- **Date:** 2026-09-21
- **Deciders:** Sanjay Hardageri / aimw maintainers
- **Related:** Phase 0 ABCs — `BaseIdentityVerifier`, `BasePolicyEngine`,
  `BaseSandbox`, `BaseAuditSink` / WORM upgrade, `BaseCircuitBreakerBackend`

## Context

Phase 0 ships hermetic L1/L2 implementations. L3 ("Enterprise Mesh") needs
real backends without rewriting `GovernancePipeline` / `ToolCallInterceptor`.
Adapters must land **one at a time** so each can be tested behind the same
ABC while hermetic fakes remain the default.

## Decision

Adopt adapters in this order (one-at-a-time):

1. **Identity — JWT/OIDC** (`OidcJwtVerifier` → `BaseIdentityVerifier`)
2. **Policy — OPA or Cedar** (`OpaEngine` / later Cedar → `BasePolicyEngine`)
3. **PII — Presidio** (replace/augment `RegexPIIGuardrail` / DLP path)
4. **Sandbox — E2B** (`E2BSandbox` → `BaseSandbox`)
5. **Audit — immutable / WORM store** (S3 Object Lock / Azure immutability;
   keep `HashChainedJSONLLogger` as local tamper-evident layer)
6. **Reliability — Redis circuit breaker** (promote existing
   `RedisCircuitBreakerBackend` to default enterprise profile)

Hermetic fakes (`StaticBearerTokenVerifier`, `StaticPolicyEngine` /
`DbBackedPolicyEngine`, `SubprocessSandbox`, local JSONL, in-memory CB)
**remain the default** for `pip install aimw` and CI.

Enterprise wiring: `aimw[enterprise]` + `configs/profiles/enterprise.example.yaml`.

## Consequences

**Positive**

- Incremental risk; each adapter has a clear ABC and rollback to hermetic
- CI stays offline-capable

**Negative**

- Dual code paths until enterprise profile is battle-tested
- OPA vs Cedar choice still open for step 2

## Alternatives considered

1. **Big-bang L3** — rejected; too much surface at once.
2. **Sidecar-only enterprise** — rejected as sole path; in-process agents
   still need ABC swaps without HTTP.

## NOT PRODUCTION

Stub modules under `phase2/src/aimw/**` are design alignment only. They
raise `NotImplementedError` / `Placeholder` and must not be imported in
production profiles until implemented and reviewed.
