# Phase 1 Sidecar — How to Run

Working FastAPI control plane wrapping `GovernancePipeline` (not stubs).

## Install

From the repo root (after merging this tree):

```bash
pip install -e '.[sidecar,dev]'
```

Optional extra (see `pyproject-sidecar-extra.toml`):

```toml
[project.optional-dependencies]
sidecar = ["fastapi>=0.110", "uvicorn>=0.27", "httpx>=0.27"]
```

(`httpx` is used by hermetic ASGI tests; `uvicorn` runs the process.)

## Run

```bash
# Fail-closed by default: set tokens OR enable demo mode.
export AIMW_SIDECAR_BEARER_TOKENS='dev-token'
# OR for local demos only (allow_unconfigured=True):
# export AIMW_SIDECAR_DEMO_MODE=1

export AIMW_POLICY_PATH=configs/policy.example.yaml
uvicorn aimw_sidecar.app:app --host 0.0.0.0 --port 8080
```

Health: `GET /healthz` (no auth).

## Identity (fail-closed)

- Production / default: `StaticBearerTokenVerifier` with a non-empty token
  allow-set (`AIMW_SIDECAR_BEARER_TOKENS` or `create_app(valid_bearer_tokens=...)`).
- Empty allow-set **rejects all** credentials unless `demo_mode=True` /
  `AIMW_SIDECAR_DEMO_MODE=1`, which sets `allow_unconfigured=True` (demos only).

Mutating and sensitive routes require `Authorization: Bearer <token>` (or
`bearer_token` on `POST /v1/govern` body).

## HITL approvals

`POST /v1/approvals/{call_id}` records a decision on the shared
`InMemoryApprovalQueue`. Pre-set the decision **before** `POST /v1/govern`
with the same `call_id` in `scripted_tool_calls` for functions listed in
`requires_approval_functions`.

## Tests

```bash
# PYTHONPATH must include aimw (main package) + this sidecar src
pip install -e '.[sidecar,dev]'   # from main repo after merge
pytest tests/unit/test_sidecar_*.py tests/integration/test_sidecar_govern.py -q
```

Hermetic: httpx `ASGITransport` + FastAPI app; no Docker / network.
