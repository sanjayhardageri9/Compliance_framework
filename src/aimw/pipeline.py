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

from pydantic import BaseModel

from aimw.gateway.shim import FakeLLMClient, LiteLLMGatewayShim
from aimw.interceptor import InterceptorResult, ToolCallInterceptor
from aimw.interfaces.guardrail import BaseGuardrail
from aimw.models import ExecutionContext


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

    async def run(
        self, prompt: str, context: ExecutionContext, bearer_token: str = ""
    ) -> PipelineResult:
        gateway_clean_prompt = self._gateway.handle_inbound(prompt, context, bearer_token)
        guardrail_clean_prompt = await self._guardrail.inspect_input(
            gateway_clean_prompt, context
        )

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
