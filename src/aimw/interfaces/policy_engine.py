"""Abstract policy-decision contract.

Scales from L1 static allow/deny lists to L3 declarative Policy-as-Code
engines (OPA Rego, AWS Cedar) without any change to callers. The
ToolCallInterceptor depends only on this interface, never on a concrete
engine, so upgrading maturity tiers is a matter of instantiating a
different BasePolicyEngine subclass.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from aimw.models import ExecutionContext, PolicyDecision, ToolRequest


class BasePolicyEngine(ABC):
    """Scales from L1 static lists to L3 OPA/Cedar rules."""

    @abstractmethod
    async def evaluate_tool_call(
        self, context: ExecutionContext, request: ToolRequest
    ) -> PolicyDecision: ...
