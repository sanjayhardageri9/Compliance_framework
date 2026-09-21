# Phase 1 — Sidecar Test Plan

Scope: FastAPI control plane wrapping `GovernancePipeline`. Hermetic only;
no real OPA/E2B/OIDC.

## Goals

1. Route contracts match ADR-001 (status codes + JSON shapes).
2. Auth fails closed via `BaseIdentityVerifier`.
3. Policy store versioning + promote is consistent.
4. Metrics counters exist and increment on govern / deny / approval paths.
5. SDK import without `fastapi` still succeeds (optional-extra gate).

## Unit

| ID | Case | Expect |
|----|------|--------|
| P1-U01 | Import `aimw` without fastapi installed | Success |
| P1-U02 | Import `aimw_sidecar.app` without fastapi | Clear ImportError / optional message |
| P1-U03 | `InMemoryPolicyStore.create` bumps version | Monotonic version, draft status |
| P1-U04 | `promote` sets active; previous active → superseded | Single active id |
| P1-U05 | Metrics registry exposes named counters | Names match `metrics.py` |

## API (TestClient / httpx ASGI)

| ID | Case | Expect |
|----|------|--------|
| P1-A01 | `POST /v1/govern` stub | 501 or stub JSON with `decision_id` |
| P1-A02 | Missing `Authorization` on `/v1/govern` | 401 |
| P1-A03 | Invalid credential | 403 |
| P1-A04 | `GET/POST /v1/policies` | list / create draft |
| P1-A05 | `POST /v1/policies/{id}/promote` | active flag flipped |
| P1-A06 | `GET /v1/decisions/{id}/explain` unknown id | 404 |
| P1-A07 | `GET /v1/audit` | empty list or stub page |
| P1-A08 | `POST /v1/approvals/{id}` | stub accept/deny body |
| P1-A09 | `GET /metrics` | text exposition with counter names |

## Integration (when wired to real pipeline)

| ID | Case | Expect |
|----|------|--------|
| P1-I01 | Govern allowed tool (StaticPolicyEngine) | allow + audit append |
| P1-I02 | Govern denied tool | deny + audit + deny counter |
| P1-I03 | HITL path → approval endpoint → resume | matches `InMemoryApprovalQueue` semantics |
| P1-I04 | Audit query after chain append | records readable; optional `verify_chain` |

## Non-goals (Phase 1)

- Durable policy DB, multi-tenant isolation, mTLS, real Prometheus scraping SLOs.

## Exit criteria

- All P1-U* and P1-A* green against skeletons (stubs OK).
- ADR-001 accepted or amended before production wiring.
