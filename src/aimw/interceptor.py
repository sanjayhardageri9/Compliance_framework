"""ToolCallInterceptor: the core governance orchestrator.

Implements Section 12.1 steps 1-4 of the framework document (tool call
interception, policy decision, sandboxed execution, audit) as a single
async pipeline stage. This is where "fail safe, not open" is structurally
enforced: any policy-engine exception or timeout becomes a synthetic deny,
and an audit record is written for every call - allowed, denied, errored,
or timed out - via a try/finally, so no tool call leaves this method
unaudited.

An optional CircuitBreaker (Section 13's L2 "Reliability" row) can gate
calls before policy evaluation even runs: a key (agent_id + tool_name)
with too high a recent sandbox-failure rate is denied outright, and every
sandbox outcome feeds back into the breaker's score.
"""

from __future__ import annotations

import asyncio
import logging
import time

from pydantic import BaseModel

from aimw.audit.models import AuditRecord
from aimw.audit.worm_log import HashChainedJSONLLogger
from aimw.hitl.approval import ApprovalCallback
from aimw.interfaces.policy_engine import BasePolicyEngine
from aimw.models import ExecutionContext, PolicyDecision, ToolRequest
from aimw.reliability.circuit_breaker import CircuitBreaker
from aimw.sandbox.base import BaseSandbox, SandboxResult

logger = logging.getLogger(__name__)

# The set of action_requirement tokens this interceptor knows how to honor.
# Any other token on an "allowed" PolicyDecision is treated as an
# unsupported requirement and denied - a future policy author cannot add a
# requirement type the pipeline silently ignores.
_SUPPORTED_REQUIREMENTS = {"human_approval"}


class InterceptorResult(BaseModel):
    """Everything a caller needs to know about how a tool call was handled."""

    allowed: bool
    decision: PolicyDecision
    sandbox_result: SandboxResult | None = None
    audit_record: AuditRecord


class ToolCallInterceptor:
    """Intercepts a tool call, enforces policy + HITL, executes, audits."""

    def __init__(
        self,
        policy_engine: BasePolicyEngine,
        sandbox: BaseSandbox,
        audit_log: HashChainedJSONLLogger,
        approval_callback: ApprovalCallback | None = None,
        decision_timeout_s: float = 2.0,
        circuit_breaker: CircuitBreaker | None = None,
    ) -> None:
        self._policy_engine = policy_engine
        self._sandbox = sandbox
        self._audit_log = audit_log
        self._approval_callback = approval_callback
        self._decision_timeout_s = decision_timeout_s
        self._circuit_breaker = circuit_breaker

    async def handle(self, context: ExecutionContext, request: ToolRequest) -> InterceptorResult:
        if self._circuit_breaker is not None and not await self._circuit_breaker.check(
            context.agent_id, request.tool_name
        ):
            decision = PolicyDecision(
                allowed=False,
                reason=(
                    f"circuit breaker open for agent '{context.agent_id}' "
                    f"tool '{request.tool_name}': too many recent failures"
                ),
            )
            return self._audit_and_wrap(context, request, decision, None)

        decision = PolicyDecision(allowed=False, reason="unresolved: interceptor did not complete")
        sandbox_result: SandboxResult | None = None

        try:
            decision = await self._evaluate_decision(context, request)

            if decision.allowed:
                decision = await self._safely_resolve_action_requirements(
                    context, request, decision
                )

            if decision.allowed:
                sandbox_result = await self._execute_sandboxed(context, request)
                await self._record_circuit_breaker_outcome(context, request, sandbox_result)
        finally:
            result = self._audit_and_wrap(context, request, decision, sandbox_result)

        return result

    async def _evaluate_decision(
        self, context: ExecutionContext, request: ToolRequest
    ) -> PolicyDecision:
        try:
            return await asyncio.wait_for(
                self._policy_engine.evaluate_tool_call(context, request),
                timeout=self._decision_timeout_s,
            )
        except TimeoutError:
            logger.warning("policy decision timed out for call %s: fail-closed", request.call_id)
            return PolicyDecision(allowed=False, reason="policy engine timeout: fail-closed")
        except Exception as exc:  # noqa: BLE001 - deliberate fail-closed catch-all
            logger.warning(
                "policy engine raised for call %s: fail-closed (%s)", request.call_id, exc
            )
            return PolicyDecision(
                allowed=False, reason=f"policy engine failure: fail-closed ({exc})"
            )

    async def _safely_resolve_action_requirements(
        self, context: ExecutionContext, request: ToolRequest, decision: PolicyDecision
    ) -> PolicyDecision:
        try:
            return await self._resolve_action_requirements(context, request, decision)
        except Exception as exc:  # noqa: BLE001 - fail-closed on approval-flow errors too
            logger.warning(
                "approval resolution raised for call %s: fail-closed (%s)", request.call_id, exc
            )
            return PolicyDecision(
                allowed=False, reason=f"approval resolution failure: fail-closed ({exc})"
            )

    async def _resolve_action_requirements(
        self, context: ExecutionContext, request: ToolRequest, decision: PolicyDecision
    ) -> PolicyDecision:
        unsupported = set(decision.action_requirements) - _SUPPORTED_REQUIREMENTS
        if unsupported:
            return PolicyDecision(
                allowed=False,
                reason=f"unsupported action requirement(s): {sorted(unsupported)}",
            )

        if "human_approval" in decision.action_requirements:
            if self._approval_callback is None:
                return PolicyDecision(
                    allowed=False,
                    reason="approval required but no approval_callback configured",
                )
            # The callback receives the raw, unredacted request and decision -
            # a human reviewer must see the actual payload, not a summary.
            approved = await self._approval_callback(context, request, decision)
            if not approved:
                return PolicyDecision(allowed=False, reason="approval required but not granted")
            return PolicyDecision(allowed=True, reason=f"{decision.reason}; human-approved")

        return decision

    async def _execute_sandboxed(
        self, context: ExecutionContext, request: ToolRequest
    ) -> SandboxResult:
        start = time.monotonic()
        try:
            return await self._sandbox.execute(request, context)
        except Exception as exc:  # noqa: BLE001 - sandbox failures must not crash the pipeline
            duration_ms = (time.monotonic() - start) * 1000
            logger.warning("sandbox execution raised for call %s: %s", request.call_id, exc)
            return SandboxResult(stdout="", stderr=str(exc), exit_code=1, duration_ms=duration_ms)

    async def _record_circuit_breaker_outcome(
        self, context: ExecutionContext, request: ToolRequest, sandbox_result: SandboxResult
    ) -> None:
        if self._circuit_breaker is None:
            return
        success = sandbox_result.exit_code == 0 and not sandbox_result.timed_out
        await self._circuit_breaker.record_result(context.agent_id, request.tool_name, success)

    def _audit_and_wrap(
        self,
        context: ExecutionContext,
        request: ToolRequest,
        decision: PolicyDecision,
        sandbox_result: SandboxResult | None,
    ) -> InterceptorResult:
        audit_record = self._audit_log.log_call(
            context=context,
            request=request,
            decision=decision,
            sandbox_result=sandbox_result.model_dump() if sandbox_result else None,
        )
        return InterceptorResult(
            allowed=decision.allowed,
            decision=decision,
            sandbox_result=sandbox_result,
            audit_record=audit_record,
        )
