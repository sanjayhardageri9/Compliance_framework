"""FastAPI sidecar app stub wrapping GovernancePipeline.

Install optional extra ``aimw[sidecar]`` before running. Route bodies are
stubs (NotImplementedError or stub JSON) pending wiring to a real pipeline.

Auth: intended to call ``BaseIdentityVerifier.verify(credential, context)``.
"""

from __future__ import annotations

from typing import Any

from aimw_sidecar.metrics import stub_metrics_text
from aimw_sidecar.policy_store import InMemoryPolicyStore

# Soft dependency: FastAPI is optional. Keep module importable for layout checks
# when fastapi is missing (tests may skip).
try:
    from fastapi import FastAPI, Header, HTTPException, Response
    from pydantic import BaseModel, Field
except ImportError as _exc:  # pragma: no cover - optional extra
    raise ImportError(
        "aimw_sidecar requires the 'sidecar' extra: pip install 'aimw[sidecar]'"
    ) from _exc


class GovernRequest(BaseModel):
    """Proposed tool call / turn to govern."""

    tool_name: str
    function_name: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    call_id: str | None = None
    user_id: str = "anonymous"
    agent_id: str = "default-agent"
    session_id: str = "default-session"
    roles: list[str] = Field(default_factory=list)


class PolicyCreateRequest(BaseModel):
    name: str
    body: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)


class ApprovalRequest(BaseModel):
    resolution: str  # "approve" | "deny"
    reason: str | None = None
    actor: str | None = None


def create_app(policy_store: InMemoryPolicyStore | None = None) -> FastAPI:
    """Build the FastAPI app. Pipeline wiring is TODO."""

    store = policy_store or InMemoryPolicyStore()
    app = FastAPI(
        title="aimw governance sidecar",
        version="0.0.0-skeleton",
        description="Phase 1 stub — wraps GovernancePipeline (not wired yet).",
    )
    app.state.policy_store = store
    # app.state.pipeline: GovernancePipeline | None = None  # TODO
    # app.state.identity: BaseIdentityVerifier | None = None  # TODO

    def _require_auth(authorization: str | None) -> str:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        token = authorization.split(" ", 1)[1].strip()
        if not token:
            raise HTTPException(status_code=401, detail="empty bearer token")
        # TODO: BaseIdentityVerifier.verify(token, context)
        return token

    @app.post("/v1/govern")
    async def govern(
        body: GovernRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        # TODO: build ToolRequest + ExecutionContext; call GovernancePipeline
        raise NotImplementedError("wire GovernancePipeline.run / interceptor")

    @app.get("/v1/policies")
    async def list_policies(
        name: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        policies = store.list_policies(name=name)
        return {
            "policies": [
                {
                    "id": p.id,
                    "name": p.name,
                    "version": p.version,
                    "status": p.status,
                    "created_at": p.created_at.isoformat(),
                    "promoted_at": p.promoted_at.isoformat() if p.promoted_at else None,
                }
                for p in policies
            ]
        }

    @app.post("/v1/policies")
    async def create_policy(
        body: PolicyCreateRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        pv = store.create(body.name, body.body, metadata=body.metadata)
        return {
            "id": pv.id,
            "name": pv.name,
            "version": pv.version,
            "status": pv.status,
        }

    @app.post("/v1/policies/{policy_id}/promote")
    async def promote_policy(
        policy_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        try:
            pv = store.promote(policy_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="policy not found") from None
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "id": pv.id,
            "name": pv.name,
            "version": pv.version,
            "status": pv.status,
            "promoted_at": pv.promoted_at.isoformat() if pv.promoted_at else None,
        }

    @app.get("/v1/decisions/{decision_id}/explain")
    async def explain_decision(
        decision_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        # TODO: look up decision + policy version + rule traces
        return {
            "decision_id": decision_id,
            "status": "stub",
            "explanation": "NOT IMPLEMENTED — decision store not wired",
            "rule_trace": [],
        }

    @app.get("/v1/audit")
    async def query_audit(
        limit: int = 100,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        # TODO: read HashChainedJSONLLogger path / query index
        return {"records": [], "limit": limit, "status": "stub"}

    @app.post("/v1/approvals/{approval_id}")
    async def resolve_approval(
        approval_id: str,
        body: ApprovalRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        if body.resolution not in {"approve", "deny"}:
            raise HTTPException(status_code=400, detail="resolution must be approve|deny")
        # TODO: InMemoryApprovalQueue / HITL callback
        return {
            "approval_id": approval_id,
            "resolution": body.resolution,
            "status": "stub",
        }

    @app.get("/metrics")
    async def metrics() -> Response:
        return Response(content=stub_metrics_text(), media_type="text/plain; version=0.0.4")

    return app


# Module-level app for ``uvicorn aimw_sidecar.app:app`` once wired
app = create_app()


def main() -> None:  # pragma: no cover
    raise NotImplementedError("use: uvicorn aimw_sidecar.app:app --reload")
