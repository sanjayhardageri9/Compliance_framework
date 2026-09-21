# AIMW roadmap (Phases 0–3 / milestones M1–M4)

Brief milestones for `sanjayhardageri9/Compliance_framework` (`aimw`).

## Phase 0 — Hardening baseline (M1)

Fail-closed defaults and supply-chain hygiene before feature growth.

- Identity: empty static bearer rejects; production constructor; constant-time compares; session token ID validation.
- Sandbox: Docker argv allowlist + shell-metacharacter rejection; hermetic policy tests; docker-marked daemon tests stay opt-in.
- Pipeline: catch input `GuardrailViolation`, audit, re-raise (no LLM/tools).
- WORM: corrupt/truncated line detection; optional strict `AuditTamperError`.
- Guardrail/DLP tests for card, phone, role-override.
- CI: `contents: read`, coverage gate ≥80%, `pip-audit`, Dependabot (pip + Actions).
- Docs: Security notes (Docker RCE footgun, identity migration).

**Exit:** hermetic `pytest` green; demos run; no unauthenticated “open” defaults in production paths.

## Phase 1 — Policy & observability (M2)

- Richer policy authoring (deny/allow clarity, requirement tokens documented).
- Structured metrics/tracing hooks around interceptor decisions.
- Stronger SIEM sink contracts (retry/backoff policy without breaking local WORM write).
- Expand e2e coverage for approval + circuit-breaker interactions.

**Exit:** operators can explain every deny with an audit record + metric label.

## Phase 2 — L2 completeness (M3)

- Semantic guardrail + DLP wired as default L2 demo path.
- DB-backed policy/registry operational runbooks; migration helpers.
- Redis circuit breaker integration tests against real Redis (still optional in CI).
- RestrictedDockerSandbox as the documented L2 production sandbox with policy-declared allowlists.

**Exit:** L2 stack documented as a supported deployment profile.

## Phase 3 — L3 foundations (M4)

- Interface-stable adapters toward OPA/Cedar, Presidio, E2B/gVisor, compound identity (JWT + agent key).
- Real WORM backends (object-lock / immutable storage) behind the same logger API.
- Threat-model refresh and residual-risk register for enterprise mesh.

**Exit:** L3 engines pluggable without rewriting `GovernancePipeline` / `ToolCallInterceptor`.
