"""OPA-compatible policy engine adapter (Phase 2) — NOT real OPA.

``RegoLitePolicyEngine`` / ``OpaCompatiblePolicyEngine`` wrap the hermetic
``StaticPolicyEngine`` (or optional ``DbBackedPolicyEngine``) behind
``BasePolicyEngine``. Accepts a ``PolicyRuleSet`` and delegates
``evaluate_tool_call`` to the wrapped engine.

L3 production swaps this adapter for a real OPA HTTP client (POST to
``/v1/data/...``) or Cedar; keep the same ``BasePolicyEngine`` contract so
``ToolCallInterceptor`` does not change.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from aimw.interfaces.policy_engine import BasePolicyEngine
from aimw.models import ExecutionContext, PolicyDecision, ToolRequest
from aimw.policy.rules import PolicyRuleSet
from aimw.policy.static_engine import StaticPolicyEngine


class RegoLitePolicyEngine(BasePolicyEngine):
    """Hermetic stand-in for OPA: delegates to StaticPolicyEngine.

    NOT real OPA / Rego. The ``opa_url`` / ``policy_package`` knobs are
    accepted for API shape compatibility and ignored offline.
    L3 swaps to real OPA HTTP.
    """

    def __init__(
        self,
        ruleset: PolicyRuleSet | None = None,
        *,
        engine: BasePolicyEngine | None = None,
        call_counter: Callable[[str], int] | None = None,
        opa_url: str | None = None,
        policy_package: str = "aimw/authz",
        **_: Any,
    ) -> None:
        self.opa_url = opa_url  # unused offline; documented for L3 swap
        self.policy_package = policy_package
        if engine is not None:
            self._delegate = engine
            self._ruleset = ruleset
        else:
            if ruleset is None:
                raise ValueError("ruleset is required when engine is not provided")
            self._ruleset = ruleset
            self._delegate = StaticPolicyEngine(ruleset, call_counter=call_counter)

    async def evaluate_tool_call(
        self, context: ExecutionContext, request: ToolRequest
    ) -> PolicyDecision:
        """Delegate allow/deny to the wrapped StaticPolicyEngine (or provided engine)."""
        return await self._delegate.evaluate_tool_call(context, request)


# Preferred alternate name used in design docs / tests.
OpaCompatiblePolicyEngine = RegoLitePolicyEngine

# Back-compat stub name from Phase 2 skeletons.
OpaEngine = RegoLitePolicyEngine
