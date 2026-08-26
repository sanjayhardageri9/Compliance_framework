"""Sandbox execution contract.

Not one of the three named ABCs in the framework document's Section 14, but
built the same way and for the same reason: keep the sandbox swappable
(local Docker at L1 -> E2B microVM + gVisor at L3) without touching the
ToolCallInterceptor.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel

from aimw.models import ExecutionContext, ToolRequest


class SandboxResult(BaseModel):
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: float
    timed_out: bool = False


class BaseSandbox(ABC):
    """Isolated execution of an allowed tool call, deny-by-default egress."""

    @abstractmethod
    async def execute(
        self, request: ToolRequest, context: ExecutionContext
    ) -> SandboxResult: ...
