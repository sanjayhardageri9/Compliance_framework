"""OPA (or Cedar-later) policy engine stub — NOT PRODUCTION.

Implements the ``BasePolicyEngine`` pattern from Phase 0
(``evaluate_tool_call`` → ``PolicyDecision``).

Hermetic defaults remain ``StaticPolicyEngine`` / ``DbBackedPolicyEngine``.
Install ``aimw[enterprise]`` for a real OPA/Cedar client.
"""

from __future__ import annotations

from typing import Any


class OpaEngine:
    """L3 stub: evaluate tool calls via Open Policy Agent.

    NOT PRODUCTION — Placeholder.
    """

    def __init__(
        self,
        *,
        opa_url: str | None = None,
        policy_package: str = "aimw/authz",
        **_: Any,
    ) -> None:
        self.opa_url = opa_url
        self.policy_package = policy_package

    def evaluate_tool_call(self, request: Any, context: Any) -> Any:
        """Mirror ``BasePolicyEngine.evaluate_tool_call``.

        Should return ``aimw.models.PolicyDecision`` when implemented.
        """
        raise NotImplementedError(
            "OpaEngine is a Phase 2 stub — wire OPA/Cedar via aimw[enterprise]; "
            "hermetic StaticPolicyEngine remains the default"
        )

    async def evaluate_tool_call_async(self, request: Any, context: Any) -> Any:
        """Optional async path for sidecar — also unimplemented."""
        raise NotImplementedError("OpaEngine async path is a Placeholder")
