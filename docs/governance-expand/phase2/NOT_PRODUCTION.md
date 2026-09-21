# NOT PRODUCTION

Phase 2–3 modules under `src/aimw/identity/oidc_jwt.py`,
`src/aimw/policy/opa_engine.py`, `src/aimw/sandbox/e2b_sandbox.py`, and
`src/aimw/evidence/exporter.py` are **hermetic stepping stones**.

- They are **not** cloud OIDC JWKS, real OPA/Cedar, or E2B microVMs.
- Safe for offline CI, demos, and adapter contract tests.
- Do **not** enable them as “enterprise complete” in live profiles.
- Production L3 must swap to real backends per ADR-002 while keeping the
  same ABCs (`BaseIdentityVerifier`, `BasePolicyEngine`, `BaseSandbox`).
- Hermetic L1/L2 classes (`StaticBearerTokenVerifier`, `StaticPolicyEngine`,
  `SubprocessSandbox` / `DockerSandbox`, local JSONL) remain supported defaults.

See [`HERMETIC_ADAPTERS.md`](./HERMETIC_ADAPTERS.md) for the runnable adapter matrix.
