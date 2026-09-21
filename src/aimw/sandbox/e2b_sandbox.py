"""E2B microVM sandbox stub — NOT PRODUCTION.

Implements the ``BaseSandbox`` pattern from Phase 0:

    class BaseSandbox(ABC):
        async def execute(self, request: ToolRequest, context: ExecutionContext) -> SandboxResult: ...

Hermetic defaults remain ``SubprocessSandbox`` / ``DockerSandbox`` /
``RestrictedDockerSandbox``. Install ``aimw[enterprise]`` for real E2B.
"""

from __future__ import annotations

from typing import Any


class E2BSandbox:
    """L3 stub: execute allowed tool calls inside an E2B microVM.

    NOT PRODUCTION — Placeholder.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        template_id: str | None = None,
        timeout_s: float = 30.0,
        **_: Any,
    ) -> None:
        self.api_key = api_key
        self.template_id = template_id
        self.timeout_s = timeout_s

    async def execute(self, request: Any, context: Any) -> Any:
        """Mirror ``BaseSandbox.execute`` → ``SandboxResult``."""
        raise NotImplementedError(
            "E2BSandbox is a Phase 2 stub — install aimw[enterprise] and "
            "configure E2B credentials; hermetic sandboxes remain default"
        )
