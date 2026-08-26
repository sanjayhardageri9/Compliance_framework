"""In-process sandbox stub.

NOT ISOLATED - FOR LOCAL DEV/TEST ONLY. This does not sandbox anything; it
runs a registered Python callable in-process so the governance pipeline can
be exercised end-to-end (tests, CI, the demo script) without a Docker
daemon or any external service. Real isolation is DockerSandbox's job.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable

from aimw.models import ExecutionContext, ToolRequest
from aimw.sandbox.base import BaseSandbox, SandboxResult

ToolImplementation = Callable[[ToolRequest, ExecutionContext], Awaitable[str]]


async def _default_implementation(request: ToolRequest, context: ExecutionContext) -> str:
    return f"ok: executed {request.tool_name}.{request.function_name}"


class SubprocessSandbox(BaseSandbox):
    """Non-isolated stub sandbox for tests/CI/demo. Do not use in production."""

    def __init__(
        self,
        implementations: dict[str, ToolImplementation] | None = None,
        timeout_s: float = 5.0,
    ) -> None:
        self._implementations = implementations or {}
        self._timeout_s = timeout_s

    def register(self, tool_name: str, function_name: str, impl: ToolImplementation) -> None:
        self._implementations[f"{tool_name}.{function_name}"] = impl

    async def execute(self, request: ToolRequest, context: ExecutionContext) -> SandboxResult:
        key = f"{request.tool_name}.{request.function_name}"
        impl = self._implementations.get(key, _default_implementation)
        start = time.monotonic()
        try:
            stdout = await asyncio.wait_for(impl(request, context), timeout=self._timeout_s)
            duration_ms = (time.monotonic() - start) * 1000
            return SandboxResult(stdout=stdout, stderr="", exit_code=0, duration_ms=duration_ms)
        except TimeoutError:
            duration_ms = (time.monotonic() - start) * 1000
            return SandboxResult(
                stdout="",
                stderr=f"execution exceeded {self._timeout_s}s timeout",
                exit_code=124,
                duration_ms=duration_ms,
                timed_out=True,
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as a failed result, not raised
            duration_ms = (time.monotonic() - start) * 1000
            return SandboxResult(
                stdout="", stderr=str(exc), exit_code=1, duration_ms=duration_ms
            )
