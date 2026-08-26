"""L2 policy engine: DB-backed RBAC (Section 13's "Growth Tier" policy row).

Implements the same five-layer permission hierarchy as StaticPolicyEngine,
now including an explicit Global RBAC layer (Section 15.1, layer 1) that L1
didn't need: a context's roles must intersect the store's *active* role
set before any tool/function/parameter check runs, modeling
platform-wide access control on top of per-tool visibility. Everything
else - identity validity, tool/function access, parameter deny-patterns,
role gates, rate limiting, HITL approval - mirrors StaticPolicyEngine so
migrating a deployment from L1 to L2 changes only which engine is
instantiated.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable

from aimw.interfaces.policy_engine import BasePolicyEngine
from aimw.models import ExecutionContext, PolicyDecision, ToolRequest
from aimw.policy.db_rules import DbRuleStore
from aimw.policy.errors import PolicyEvaluationError

logger = logging.getLogger(__name__)


def _deny(reason: str) -> PolicyDecision:
    return PolicyDecision(allowed=False, reason=reason)


class DbBackedPolicyEngine(BasePolicyEngine):
    """L2 policy engine: rules read live from a DbRuleStore."""

    def __init__(
        self,
        store: DbRuleStore,
        call_counter: Callable[[str], int] | None = None,
    ) -> None:
        self._store = store
        self._call_counter = call_counter or (lambda _session_id: 0)

    async def evaluate_tool_call(
        self, context: ExecutionContext, request: ToolRequest
    ) -> PolicyDecision:
        try:
            return self._evaluate(context, request)
        except PolicyEvaluationError:
            raise
        except Exception as exc:  # noqa: BLE001 - re-raised deliberately, logged first
            logger.exception("db policy engine internal failure evaluating %s", request.call_id)
            raise PolicyEvaluationError(str(exc)) from exc

    def _evaluate(self, context: ExecutionContext, request: ToolRequest) -> PolicyDecision:
        store = self._store

        # 1. Identity validity (same shape as L1).
        for field_name in ("user_id", "agent_id", "roles"):
            if not getattr(context, field_name, None):
                return _deny(f"invalid identity context: missing or empty '{field_name}'")

        # 2. Global RBAC: at least one of the context's roles must be a
        # known, active role in the store. This is the layer L1's static
        # engine didn't have - platform-wide access, independent of any
        # specific tool.
        active_roles = store.active_roles()
        if not active_roles.intersection(context.roles):
            return _deny(
                f"no active platform role for context roles {context.roles}: global RBAC denied"
            )

        # 3. Tool-level access.
        if not store.tool_exists(request.tool_name):
            return _deny(f"tool not permitted: '{request.tool_name}'")
        visibility_roles = store.visibility_roles(request.tool_name)
        if visibility_roles and not any(role in context.roles for role in visibility_roles):
            return _deny(f"tool '{request.tool_name}' requires one of roles {visibility_roles}")

        # 4. Function-level access.
        allowed_functions = store.allowed_functions(request.tool_name)
        if request.function_name not in allowed_functions:
            return _deny(
                f"function not permitted: '{request.tool_name}.{request.function_name}'"
            )

        # 5. Parameter deny-patterns.
        deny_patterns = store.deny_patterns(request.tool_name)
        for param_name, patterns in deny_patterns.items():
            value = request.parameters.get(param_name)
            if value is None:
                continue
            value_str = str(value)
            for pattern in patterns:
                if re.search(pattern, value_str, flags=re.IGNORECASE):
                    excerpt = value_str[:40] + ("..." if len(value_str) > 40 else "")
                    return _deny(
                        f"parameter '{param_name}' matched deny-pattern '{pattern}' "
                        f"(excerpt: {excerpt!r})"
                    )

        # 6. Role-gated parameter values.
        role_gates = store.role_gates(request.tool_name)
        for gate, required_roles in role_gates.items():
            param_name, _, expected_value = gate.partition("=")
            actual_value = request.parameters.get(param_name)
            if actual_value is not None and str(actual_value) == expected_value:
                if not any(role in context.roles for role in required_roles):
                    return _deny(f"parameter '{gate}' requires one of roles {required_roles}")

        # 7. Session rate limit.
        current_calls = self._call_counter(context.session_id)
        rate_limit = store.rate_limit_per_session()
        if current_calls >= rate_limit:
            return _deny(f"rate limit exceeded: {current_calls} >= {rate_limit}")

        if store.requires_approval(request.tool_name, request.function_name):
            return PolicyDecision(
                allowed=True,
                reason="approved pending human-in-the-loop review",
                action_requirements=["human_approval"],
            )

        return PolicyDecision(allowed=True, reason="all policy checks passed")
