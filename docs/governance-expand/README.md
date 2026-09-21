# aimw governance expand — Phases 1–3

Design + skeleton packages that extend the existing **aimw** SDK
(`sanjayhardageri9/Compliance_framework`, Phase 0 / M1–M4 L1+L2 hermetic build).

**Do not treat this tree as a installable release.** It is scaffolding for
control-plane, L3 adapters, and evidence export workstreams. No GitHub clone
or push is performed from this workspace.

## How this relates to Phase 0 and M1–M4

| Milestone | What shipped (Phase 0 SDK) | This expand tree |
|-----------|----------------------------|------------------|
| **M1** | Core contracts: `GovernancePipeline`, `ToolCallInterceptor`, `BasePolicyEngine`, `BaseSandbox`, `BaseIdentityVerifier`, models | Unchanged; Phase 1 sidecar *wraps* them |
| **M2** | L1 hermetic: `StaticPolicyEngine`, `StaticBearerTokenVerifier`, `SubprocessSandbox`/`DockerSandbox`, `HashChainedJSONLLogger`, gateway shim | Unchanged defaults |
| **M3** | L2 growth: session tokens, `DbBackedPolicyEngine`, semantic/DLP guardrails, circuit breaker, SIEM sinks | Unchanged; Phase 2 adapters swap in behind the same ABCs |
| **M4** | Settings/`factory`, demos, hermetic CI | Remains the installable SDK path |

```
Phase 0 SDK (importable without FastAPI)
    │
    ├─ Phase 1  aimw_sidecar     FastAPI control plane wrapping GovernancePipeline
    ├─ Phase 2  L3 stubs         OIDC/JWT, OPA/Cedar, Presidio, E2B, WORM, Redis CB
    └─ Phase 3  evidence         SOC2/NIST mappings + auditor zip exporter
```

Hermetic L1/L2 fakes remain the **default** wiring. Enterprise backends are
opt-in (`aimw[enterprise]` / `aimw[sidecar]`) and must not break SDK imports.

## Layout

```
aimw-governance-expand/
├── README.md                 # this file
├── phase1/                   # ADR-001 + FastAPI sidecar skeleton
├── phase2/                   # ADR-002 + L3 adapter stubs (NOT production)
└── phase3/                   # control mappings + evidence exporter skeleton
```

## Interface names referenced (from Phase 0 SDK)

- `GovernancePipeline`, `ToolCallInterceptor`
- `BasePolicyEngine`, `BaseSandbox`, `BaseIdentityVerifier`
- `HashChainedJSONLLogger`, `verify_chain`
- `Settings`, `ExecutionContext`, `ToolRequest`, `PolicyDecision`

## Status

Skeletons raise `NotImplementedError` or return stub JSON. Phase 2 modules
are marked **NOT PRODUCTION**. Wire real backends only after ADRs are accepted
and extras are installed.

## Open design questions (for Sanjay)

1. **Policy store durability for sidecar** — Keep Phase 1 in-memory + promote API, or immediately back with `DbRuleStore` / Postgres and treat memory as test-only?
2. **OPA vs Cedar** — ADR-002 picks OPA first; confirm Cedar is a follow-on adapter (same `BasePolicyEngine`) or a competing default for enterprise.
3. **Decision explain store** — Persist explain traces beside JSONL audit, or derive only from audit records + active policy snapshot?
4. **Sidecar packaging** — Merge `aimw_sidecar` into `Compliance_framework` as `aimw[sidecar]`, or keep a sibling package/repo?
5. **Presidio placement** — New `BaseGuardrail` impl only, or also a mandatory pre-pass inside the sidecar `/v1/govern` path?
6. **Immutable audit** — Dual-write (JSONL + Object Lock) vs replace local JSONL once WORM backend is configured?
7. **Approval resume semantics** — Should `POST /v1/approvals/{id}` re-enter `ToolCallInterceptor` automatically, or only record resolution for the caller to retry `/v1/govern`?
8. **Evidence retention** — Default retention window and whether exporter must redact roles/user_id further for external auditors.
