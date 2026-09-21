"""GovernancePipeline: the full Section 12.2 request flow, wired end-to-end.

    User / Context
      -> LiteLLM Gateway shim (rate limits, bearer token, PII pre-pass)
      -> Guardrail.inspect_input (prompt-injection / control-token checks)
      -> LLM Reasoning Loop (stubbed)
      -> ToolCallInterceptor (policy -> HITL -> sandbox) per proposed tool call
      -> Guardrail.inspect_output
      -> WORM Audit Log (populated throughout by the interceptor)

This is the single top-level entrypoint a caller imports.
"""

from __future__ import annotations

import logging
import uuid

from pydantic import BaseModel

from aimw.gateway.shim import FakeLLMClient, LiteLLMGatewayShim
from aimw.guardrails.errors import GuardrailViolation
from aimw.interceptor import InterceptorResult, ToolCallInterceptor
from aimw.interfaces.guardrail import BaseGuardrail
from aimw.models import ExecutionContext, PolicyDecision, ToolRequest

logger = logging.getLogger(__name__)


class PipelineResult(BaseModel):
    final_response: str
    tool_call_results: list[InterceptorResult]


class GovernancePipeline:
    """Wires the gateway, guardrail, fake LLM loop, and interceptor together."""

    def __init__(
        self,
        gateway: LiteLLMGatewayShim,
        guardrail: BaseGuardrail,
        llm_client: FakeLLMClient,
        interceptor: ToolCallInterceptor,
    ) -> None:
        self._gateway = gateway
        self._guardrail = guardrail
        self._llm_client = llm_client
        self._interceptor = interceptor

    def _audit_input_guardrail_block(
        self, context: ExecutionContext, prompt: str, exc: GuardrailViolation
    ) -> None:
        """Best-effort WORM record when input injection is blocked (fail-closed)."""
        audit_log = getattr(self._interceptor, "_audit_log", None)
        if audit_log is None:
            return
        try:
            audit_log.log_call(
                context=context,
                request=ToolRequest(
                    tool_name="_guardrail",
                    function_name="inspect_input",
                    parameters={"prompt_preview": prompt[:200]},
                    call_id=f"guardrail-input-block-{uuid.uuid4().hex[:12]}",
                ),
                decision=PolicyDecision(
                    allowed=False,
                    reason=f"guardrail input block (fail-closed): {exc}",
                ),
            )
        except Exception:  # noqa: BLE001 - audit must never mask the GuardrailViolation
            logger.warning(
                "failed to write audit record for guardrail input block",
                exc_info=True,
            )

    async def run(
        self, prompt: str, context: ExecutionContext, bearer_token: str = ""
    ) -> PipelineResult:
        gateway_clean_prompt = self._gateway.handle_inbound(prompt, context, bearer_token)

        try:
            guardrail_clean_prompt = await self._guardrail.inspect_input(
                gateway_clean_prompt, context
            )
        except GuardrailViolation as exc:
            # Fail closed: do not invoke the LLM or any tool calls. Audit if
            # possible, then re-raise so callers see a clear, typed error.
            self._audit_input_guardrail_block(context, gateway_clean_prompt, exc)
            raise

        proposed_calls = await self._llm_client.propose_tool_calls(
            guardrail_clean_prompt, context
        )

        tool_call_results: list[InterceptorResult] = []
        for proposed in proposed_calls:
            result = await self._interceptor.handle(context, proposed.to_tool_request())
            tool_call_results.append(result)

        raw_response = await self._llm_client.complete(guardrail_clean_prompt, context)
        final_response = await self._guardrail.inspect_output(raw_response, context)

        return PipelineResult(final_response=final_response, tool_call_results=tool_call_results)
