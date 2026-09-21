"""FastAPI sidecar wrapping GovernancePipeline (Phase 1 working control plane).

Auth uses ``BaseIdentityVerifier.verify`` (L1 ``StaticBearerTokenVerifier``).
Fail-closed unless demo mode opts into ``allow_unconfigured`` — see runtime.py.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from aimw.config import Settings
from aimw.gateway.shim import GatewayAuthError, ProposedToolCall
from aimw.guardrails.errors import GuardrailViolation
from aimw.hitl.approval import InMemoryApprovalQueue
from aimw.models import ExecutionContext

from aimw_sidecar.metrics import SidecarMetrics, render_prometheus
from aimw_sidecar.policy_store import InMemoryPolicyStore
from aimw_sidecar.runtime import SidecarRuntime, build_runtime, on_policy_promoted

try:
    from fastapi import FastAPI, Header, HTTPException, Response
    from pydantic import BaseModel, Field
except ImportError as _exc:  # pragma: no cover - optional extra
    raise ImportError(
        "aimw_sidecar requires the 'sidecar' extra: pip install 'aimw[sidecar]'"
    ) from _exc


class ScriptedToolCall(BaseModel):
    """Optional demo tool call for FakeLLMClient scripting."""

    tool_name: str
    function_name: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    call_id: str | None = None


class GovernRequest(BaseModel):
    """Agent turn to govern: prompt + context + optional scripted tool calls."""

    prompt: str
    user_id: str = "anonymous"
    agent_id: str = "default-agent"
    session_id: str = "default-session"
    roles: list[str] = Field(default_factory=list)
    delegated_scopes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    bearer_token: str | None = None
    scripted_tool_calls: list[ScriptedToolCall] = Field(default_factory=list)


class PolicyCreateRequest(BaseModel):
    """Create a draft policy version from JSON object or YAML text."""

    name: str = "default"
    body: dict[str, Any] | None = None
    yaml: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ApprovalRequest(BaseModel):
    resolution: str  # "approve" | "deny"
    reason: str | None = None
    actor: str | None = None


def _policy_summary(pv: Any) -> dict[str, Any]:
    return {
        "id": pv.id,
        "name": pv.name,
        "version": pv.version,
        "status": pv.status,
        "created_at": pv.created_at.isoformat(),
        "promoted_at": pv.promoted_at.isoformat() if pv.promoted_at else None,
        "metadata": pv.metadata,
    }


def create_app(
    *,
    settings: Settings | None = None,
    policy_store: InMemoryPolicyStore | None = None,
    approval_queue: InMemoryApprovalQueue | None = None,
    metrics: SidecarMetrics | None = None,
    runtime: SidecarRuntime | None = None,
    demo_mode: bool | None = None,
    valid_bearer_tokens: set[str] | None = None,
    audit_path: Path | str | None = None,
    seed_default_policy: bool = True,
) -> FastAPI:
    """Build the FastAPI app wired to a live GovernancePipeline."""

    rt = runtime or build_runtime(
        settings=settings,
        policy_store=policy_store,
        approval_queue=approval_queue,
        metrics=metrics,
        demo_mode=demo_mode,
        valid_bearer_tokens=valid_bearer_tokens,
        audit_path=audit_path,
        seed_default_policy=seed_default_policy,
    )

    app = FastAPI(
        title="aimw governance sidecar",
        version="0.1.0",
        description=(
            "Phase 1 control plane wrapping GovernancePipeline. "
            f"demo_mode={rt.demo_mode} (fail-closed identity unless demo)."
        ),
    )
    app.state.runtime = rt
    app.state.policy_store = rt.policy_store
    app.state.metrics = rt.metrics

    def _extract_bearer(
        authorization: str | None,
        body_token: str | None = None,
    ) -> str:
        token = ""
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1].strip()
        if not token and body_token:
            token = body_token.strip()
        if not token:
            raise HTTPException(status_code=401, detail="missing bearer token")
        return token

    def _verify(token: str, context: ExecutionContext) -> None:
        if not rt.identity.verify(token, context):
            raise HTTPException(status_code=403, detail="identity verification failed")

    def _anon_ctx() -> ExecutionContext:
        return ExecutionContext(
            user_id="sidecar",
            agent_id="sidecar",
            session_id="sidecar",
            roles=["sidecar"],
            delegated_scopes=[],
            metadata={},
        )

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        active = rt.policy_store.get_active()
        return {
            "status": "ok",
            "demo_mode": rt.demo_mode,
            "active_policy_id": active.id if active else None,
            "active_policy_version": active.version if active else None,
        }

    @app.post("/v1/govern")
    async def govern(
        body: GovernRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        rt.metrics.inc_govern()
        token = _extract_bearer(authorization, body.bearer_token)
        context = ExecutionContext(
            user_id=body.user_id,
            agent_id=body.agent_id,
            session_id=body.session_id,
            roles=list(body.roles),
            delegated_scopes=list(body.delegated_scopes),
            metadata=dict(body.metadata),
        )
        _verify(token, context)

        # Script optional demo tool calls onto the shared FakeLLMClient.
        rt.llm_client.clear_scripted_calls()
        for scripted in body.scripted_tool_calls:
            call_id = scripted.call_id or f"sidecar-{uuid.uuid4().hex[:12]}"
            rt.llm_client.script_tool_call(
                ProposedToolCall(
                    tool_name=scripted.tool_name,
                    function_name=scripted.function_name,
                    parameters=dict(scripted.parameters),
                    call_id=call_id,
                )
            )

        try:
            result = await rt.pipeline.run(body.prompt, context, bearer_token=token)
        except GatewayAuthError as exc:
            rt.metrics.inc_errors()
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except GuardrailViolation as exc:
            rt.metrics.inc_errors()
            raise HTTPException(
                status_code=400,
                detail={"error": "guardrail_violation", "message": str(exc)},
            ) from exc
        except Exception as exc:  # noqa: BLE001 - surface as 500 + metric
            rt.metrics.inc_errors()
            raise HTTPException(status_code=500, detail=f"govern failed: {exc}") from exc

        rt.record_interceptor_results(result.tool_call_results)

        tool_results = []
        for r in result.tool_call_results:
            tool_results.append(
                {
                    "call_id": r.audit_record.call_id,
                    "allowed": r.allowed,
                    "reason": r.decision.reason,
                    "action_requirements": list(r.decision.action_requirements),
                    "tool_name": r.audit_record.request.tool_name,
                    "function_name": r.audit_record.request.function_name,
                    "sandbox_stdout": (
                        r.sandbox_result.stdout if r.sandbox_result is not None else None
                    ),
                    "audit_record_id": r.audit_record.record_id,
                }
            )

        return {
            "final_response": result.final_response,
            "tool_results": tool_results,
            "audit_summary": {
                "records_appended": len(tool_results),
                "call_ids": [t["call_id"] for t in tool_results],
                "audit_path": str(rt.audit_path),
            },
        }

    @app.get("/v1/policies")
    async def list_policies(
        name: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        token = _extract_bearer(authorization)
        _verify(token, _anon_ctx())
        policies = rt.policy_store.list_policies(name=name)
        return {"policies": [_policy_summary(p) for p in policies]}

    @app.post("/v1/policies")
    async def create_policy(
        body: PolicyCreateRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        token = _extract_bearer(authorization)
        _verify(token, _anon_ctx())

        if body.yaml is not None:
            payload: dict[str, Any] | str = body.yaml
        elif body.body is not None:
            payload = body.body
        else:
            raise HTTPException(
                status_code=400,
                detail="provide body (JSON object) or yaml (string)",
            )

        try:
            pv = rt.policy_store.create(body.name, payload, metadata=body.metadata)
        except Exception as exc:  # noqa: BLE001 - validation errors
            raise HTTPException(status_code=400, detail=f"invalid policy: {exc}") from exc
        return _policy_summary(pv)

    @app.post("/v1/policies/{version_id}/promote")
    async def promote_policy(
        version_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        token = _extract_bearer(authorization)
        _verify(token, _anon_ctx())
        try:
            pv = rt.policy_store.promote(version_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="policy not found") from None
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        on_policy_promoted(rt, pv)
        return _policy_summary(pv)

    @app.get("/v1/policies/active")
    async def get_active_policy(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        token = _extract_bearer(authorization)
        _verify(token, _anon_ctx())
        pv = rt.policy_store.get_active()
        if pv is None:
            raise HTTPException(status_code=404, detail="no active policy")
        return {**_policy_summary(pv), "body": pv.body}

    @app.get("/v1/decisions/{call_id}/explain")
    async def explain_decision(
        call_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        token = _extract_bearer(authorization)
        _verify(token, _anon_ctx())
        entry = rt.decision_log.get(call_id)
        if entry is None:
            raise HTTPException(status_code=404, detail="decision not found")
        return {
            "call_id": entry.call_id,
            "allowed": entry.allowed,
            "reason": entry.reason,
            "tool_name": entry.tool_name,
            "function_name": entry.function_name,
            "action_requirements": entry.action_requirements,
            "sandbox_stdout": entry.sandbox_stdout,
            "audit_record_id": entry.audit_record_id,
            "explanation": entry.reason,
            "rule_trace": [
                {
                    "step": "policy_decision",
                    "allowed": entry.allowed,
                    "reason": entry.reason,
                }
            ],
            "raw": entry.raw,
        }

    @app.get("/v1/audit")
    async def query_audit(
        limit: int = 100,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        token = _extract_bearer(authorization)
        _verify(token, _anon_ctx())
        if limit < 1:
            raise HTTPException(status_code=400, detail="limit must be >= 1")
        records = rt.recent_audit(limit=min(limit, 1000))
        return {"records": records, "limit": limit, "count": len(records)}

    @app.post("/v1/approvals/{call_id}")
    async def resolve_approval(
        call_id: str,
        body: ApprovalRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        token = _extract_bearer(authorization)
        _verify(token, _anon_ctx())
        if body.resolution not in {"approve", "deny"}:
            raise HTTPException(status_code=400, detail="resolution must be approve|deny")
        approved = body.resolution == "approve"
        rt.approval_queue.set_decision(call_id, approved)
        return {
            "call_id": call_id,
            "resolution": body.resolution,
            "approved": approved,
            "reason": body.reason,
            "actor": body.actor,
            "status": "recorded",
            "note": (
                "Decision stored on InMemoryApprovalQueue; "
                "call POST /v1/govern with the same call_id in scripted_tool_calls "
                "for HITL-gated functions."
            ),
        }

    @app.get("/metrics")
    async def metrics_endpoint() -> Response:
        text = render_prometheus(rt.metrics)
        return Response(content=text, media_type="text/plain; version=0.0.4; charset=utf-8")

    return app


# Module-level app for ``uvicorn aimw_sidecar.app:app``.
# Demo mode / tokens come from AIMW_SIDECAR_DEMO_MODE / AIMW_SIDECAR_BEARER_TOKENS.
app = create_app()


def main() -> None:  # pragma: no cover
    import uvicorn

    uvicorn.run("aimw_sidecar.app:app", host="0.0.0.0", port=8080, reload=False)
