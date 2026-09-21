"""LiteLLM gateway stand-in (Section 12.2, first box in the request flow).

At L1 the real LiteLLM proxy is replaced by a minimal in-process shim doing
the same three jobs the doc assigns to that layer: rate limiting, bearer
token identity, and a PII pre-pass (belt-and-suspenders ahead of the
authoritative BaseGuardrail masking). FakeLLMClient stands in for the
"LLM Reasoning Loop" box so the pipeline can be exercised with zero
external provider calls.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from aimw.guardrails.patterns import mask
from aimw.identity.base import BaseIdentityVerifier
from aimw.identity.static_bearer import StaticBearerTokenVerifier
from aimw.models import ExecutionContext, ToolRequest


class GatewayAuthError(Exception):
    """Raised when the identity check or rate limit check fails at the gateway."""


@dataclass
class LiteLLMGatewayShim:
    """LiteLLM gateway stand-in: rate limits, identity verification, PII pre-pass.

    The identity check is delegated to a BaseIdentityVerifier so the
    "Identity" maturity dimension (Section 13) can move from L1's static
    bearer token to L2's session-scoped tokens, and eventually L3's
    compound identity, without this class changing.
    """

    # Explicit demo/test default: unconfigured static bearer remains permissive.
    # Production callers should pass StaticBearerTokenVerifier.for_production({...}).
    identity_verifier: BaseIdentityVerifier = field(
        default_factory=lambda: StaticBearerTokenVerifier(allow_unconfigured=True)
    )
    rate_limit_per_minute: int = 100
    _call_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def authenticate(self, credential: str, context: ExecutionContext) -> None:
        if not self.identity_verifier.verify(credential, context):
            raise GatewayAuthError("identity verification failed")

    def check_rate_limit(self, agent_id: str) -> None:
        self._call_counts[agent_id] += 1
        if self._call_counts[agent_id] > self.rate_limit_per_minute:
            raise GatewayAuthError(f"rate limit exceeded for agent '{agent_id}'")

    def call_count(self, agent_id: str) -> int:
        return self._call_counts[agent_id]

    def handle_inbound(self, prompt: str, context: ExecutionContext, bearer_token: str) -> str:
        self.authenticate(bearer_token, context)
        self.check_rate_limit(context.agent_id)
        # Fast pre-filter pass; RegexPIIGuardrail.inspect_input remains authoritative.
        return mask(prompt)


@dataclass
class ProposedToolCall:
    """A tool call the fake LLM reasoning loop wants to make."""

    tool_name: str
    function_name: str
    parameters: dict[str, object]
    call_id: str

    def to_tool_request(self) -> ToolRequest:
        return ToolRequest(
            tool_name=self.tool_name,
            function_name=self.function_name,
            parameters=self.parameters,
            call_id=self.call_id,
        )


class FakeLLMClient:
    """Stand-in for the 'LLM Reasoning Loop' box: no real model call."""

    def __init__(self) -> None:
        self._scripted_tool_calls: list[ProposedToolCall] = []
        self._final_response: str = "acknowledged"

    def script_tool_call(self, call: ProposedToolCall) -> None:
        self._scripted_tool_calls.append(call)

    def clear_scripted_calls(self) -> None:
        self._scripted_tool_calls.clear()

    def set_final_response(self, response: str) -> None:
        self._final_response = response

    async def propose_tool_calls(
        self, prompt: str, context: ExecutionContext
    ) -> list[ProposedToolCall]:
        return list(self._scripted_tool_calls)

    async def complete(self, prompt: str, context: ExecutionContext) -> str:
        return self._final_response
