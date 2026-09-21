"""Hermetic isolated sandbox adapter (Phase 2) — NOT real E2B.

``HermeticIsolatedSandbox`` wraps ``SubprocessSandbox`` with stricter default
timeouts and an optional command/tool allowlist. It does not call the network
and does not provision microVMs.

L3 production swaps this adapter for real E2B (API key + template). Keep the
``BaseSandbox`` contract so the pipeline does not change.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Collection
from typing import Any

from aimw.models import ExecutionContext, ToolRequest
from aimw.sandbox.base import BaseSandbox, SandboxResult
from aimw.sandbox.subprocess_sandbox import SubprocessSandbox, ToolImplementation


class HermeticIsolatedSandbox(BaseSandbox):
    """Stricter SubprocessSandbox wrapper for offline / CI use.

    NOT E2B — no network, no microVM. Optional ``allowed_commands`` is a
    passthrough allowlist of ``\"tool.function\"`` keys; denied keys return a
    failed SandboxResult without invoking the underlying implementation.
    L3 swaps to E2B.
    """

    DEFAULT_TIMEOUT_S = 2.0

    def __init__(
        self,
        *,
        implementations: dict[str, ToolImplementation] | None = None,
        timeout_s: float | None = None,
        allowed_commands: Collection[str] | None = None,
        inner: SubprocessSandbox | None = None,
        # Accepted for API compatibility with the E2B stub; never used offline.
        api_key: str | None = None,
        template_id: str | None = None,
        **_: Any,
    ) -> None:
        if api_key is not None or template_id is not None:
            # Explicitly ignored: hermetic path never contacts E2B.
            pass
        self.api_key = None
        self.template_id = None
        effective_timeout = self.DEFAULT_TIMEOUT_S if timeout_s is None else timeout_s
        self.timeout_s = effective_timeout
        self._allowed = set(allowed_commands) if allowed_commands is not None else None
        self._inner = inner or SubprocessSandbox(
            implementations=implementations, timeout_s=effective_timeout
        )
        # Keep inner timeout in sync when caller passes a custom value
        if timeout_s is not None:
            self._inner._timeout_s = effective_timeout

    def register(self, tool_name: str, function_name: str, impl: ToolImplementation) -> None:
        self._inner.register(tool_name, function_name, impl)

    async def execute(self, request: ToolRequest, context: ExecutionContext) -> SandboxResult:
        key = f"{request.tool_name}.{request.function_name}"
        if self._allowed is not None and key not in self._allowed:
            return SandboxResult(
                stdout="",
                stderr=f"command not in allowlist: {key}",
                exit_code=126,
                duration_ms=0.0,
                timed_out=False,
            )
        return await self._inner.execute(request, context)


# Back-compat alias for the Phase 2 stub name.
E2BSandbox = HermeticIsolatedSandbox
