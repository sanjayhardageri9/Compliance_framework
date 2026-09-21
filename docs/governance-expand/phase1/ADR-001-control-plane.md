# ADR-001: Control Plane as FastAPI Sidecar

- **Status:** Proposed
- **Date:** 2026-09-21
- **Deciders:** Sanjay Hardageri / aimw maintainers
- **Related:** Phase 0 SDK (`GovernancePipeline`, `ToolCallInterceptor`,
  `BaseIdentityVerifier`, `HashChainedJSONLLogger`, `Settings`)

## Context

The Phase 0 / M1–M4 SDK is an **in-process** library: callers construct
`GovernancePipeline` (and collaborators) and invoke it from Python. Operators
and non-Python agents need:

1. A stable HTTP surface to run governance decisions
2. Versioned policy CRUD + promote (beyond hermetic YAML/SQLite demos)
3. Decision explainability, audit query, HITL approval, and metrics

We must not force FastAPI onto every SDK consumer.

## Decision

Ship a **FastAPI sidecar** process that wraps an already-wired
`GovernancePipeline` instance.

- Package layout: `aimw_sidecar` (this expand tree) — later mergeable into
  the main repo under `src/aimw_sidecar/` or a sibling package.
- SDK remains importable **without** FastAPI.
- Optional extra: `aimw[sidecar]` installs FastAPI/uvicorn (and related deps).
- Auth on mutating / sensitive routes uses the existing
  `BaseIdentityVerifier.verify(credential, context)` contract (L1 static
  bearer, L2 session token, later L3 OIDC/JWT).

### Endpoint sketch

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/v1/govern` | Run pipeline for a proposed tool call / agent turn |
| `GET` | `/v1/policies` | List policy versions |
| `POST` | `/v1/policies` | Create a new policy version (draft) |
| `POST` | `/v1/policies/{id}/promote` | Promote version to active |
| `GET` | `/v1/decisions/{id}/explain` | Explain a stored decision |
| `GET` | `/v1/audit` | Query hash-chained audit records |
| `POST` | `/v1/approvals/{id}` | Resolve HITL approval |
| `GET` | `/metrics` | Prometheus-style counters |

### Auth

- Extract bearer / session credential from `Authorization`.
- Build `ExecutionContext` from request body / headers.
- Call configured `BaseIdentityVerifier`; fail closed on `False`.

### Packaging

```toml
[project.optional-dependencies]
sidecar = ["fastapi>=0.110", "uvicorn[standard]>=0.27", "prometheus-client>=0.20"]
```

Core `aimw` install must not pull these. Sidecar entrypoint (future):
`uvicorn aimw_sidecar.app:app`.

## Consequences

**Positive**

- Clear split: library vs control plane
- Same pipeline semantics over HTTP
- Metrics/audit suitable for ops without embedding HTTP in every agent

**Negative / risks**

- Dual deployment surface (in-process vs sidecar)
- Policy store durability not decided here (in-memory stub for Phase 1)
- Explain API needs a decision-id store keyed to audit records

## Alternatives considered

1. **Embed FastAPI inside `aimw` core** — rejected; breaks lightweight SDK use.
2. **gRPC-only control plane** — deferred; HTTP/JSON is enough for M5+ ops UX.
3. **Separate monorepo service** — possible later; skeleton stays adjacent for now.

## Open questions

See top-level README “Open design questions”.
