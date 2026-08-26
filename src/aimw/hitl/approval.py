"""Human-in-the-loop approval seam.

Per the framework document: irreversible or high-impact actions require
out-of-band human approval that shows the raw action payload, not a
persuasive agent summary. ApprovalCallback is deliberately just a function
signature - a real deployment plugs in a Slack/webhook-backed
implementation without any change to ToolCallInterceptor.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from aimw.models import ExecutionContext, PolicyDecision, ToolRequest

ApprovalCallback = Callable[
    [ExecutionContext, ToolRequest, PolicyDecision], Awaitable[bool]
]


class InMemoryApprovalQueue:
    """Test/demo stub: pre-program approve/deny decisions by call_id."""

    def __init__(self, default: bool = False) -> None:
        self._decisions: dict[str, bool] = {}
        self._default = default
        self.received: list[tuple[ExecutionContext, ToolRequest, PolicyDecision]] = []

    def set_decision(self, call_id: str, approved: bool) -> None:
        self._decisions[call_id] = approved

    async def __call__(
        self, context: ExecutionContext, request: ToolRequest, decision: PolicyDecision
    ) -> bool:
        # The raw, unredacted request is what a human reviewer sees here -
        # never a summary. This stub just records it for callers/tests to
        # inspect and returns the pre-programmed (or default) decision.
        self.received.append((context, request, decision))
        return self._decisions.get(request.call_id, self._default)
