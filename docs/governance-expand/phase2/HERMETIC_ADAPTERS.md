# Hermetic Phase 2–3 Adapters

These adapters replace `NotImplementedError` stubs with **runnable offline**
implementations that exercise the same ABCs as production L3 backends.

They are **stepping stones**, not cloud OPA / E2B / OIDC. See also
[`NOT_PRODUCTION.md`](./NOT_PRODUCTION.md).

## Matrix

| Module | Hermetic class | ABC | Production swap (L3) |
|--------|----------------|-----|----------------------|
| `identity/oidc_jwt.py` | `HermeticJWTIdentityVerifier` | `BaseIdentityVerifier` | Real OIDC JWKS (RS256/ES256) |
| `policy/opa_engine.py` | `RegoLitePolicyEngine` / `OpaCompatiblePolicyEngine` | `BasePolicyEngine` | OPA HTTP `/v1/data/...` (or Cedar) |
| `sandbox/e2b_sandbox.py` | `HermeticIsolatedSandbox` | `BaseSandbox` | E2B microVM API |
| `evidence/exporter.py` | `export_evidence_pack` | n/a (Phase 3 packager) | Same API; stronger chain + SIEM IDs |

## Design rules

1. **No network** in hermetic paths (no JWKS fetch, no OPA HTTP, no E2B).
2. Constructor knobs that exist for L3 shape (`jwks_uri`, `opa_url`, `api_key`)
   are accepted and **ignored** offline.
3. Delegate to Phase 0 engines/sandboxes where possible
   (`StaticPolicyEngine`, `SubprocessSandbox`, `verify_chain`).
4. Keep `GovernancePipeline` / `ToolCallInterceptor` unchanged — swap instances only.

## Quick usage

```python
from aimw.identity.oidc_jwt import HermeticJWTIdentityVerifier
from aimw.policy.opa_engine import RegoLitePolicyEngine
from aimw.sandbox.e2b_sandbox import HermeticIsolatedSandbox
from aimw.evidence.exporter import export_evidence_pack
from aimw.policy.rules import PolicyRuleSet, ToolRule

verifier = HermeticJWTIdentityVerifier(b"dev-secret")
engine = RegoLitePolicyEngine(PolicyRuleSet(
    allowed_tools=["shell"],
    tools={"shell": ToolRule(tool_name="shell", allowed_functions=["run"])},
))
sandbox = HermeticIsolatedSandbox(
    timeout_s=1.0,
    allowed_commands=["shell.run"],
)
export_evidence_pack("audit/events.jsonl", "out/evidence.zip")
```

## Tests

```bash
cd /workspace/aimw-phase23-impl
pip install -e ".[dev]"
pytest tests/unit/test_hermetic_jwt_identity.py \
       tests/unit/test_opa_compatible_engine.py \
       tests/unit/test_hermetic_isolated_sandbox.py \
       tests/unit/test_evidence_exporter.py -q
```
