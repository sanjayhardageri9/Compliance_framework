"""L1 static allow/deny policy engine.

Implements the same five checks as the framework document's OPA Rego
reference policy (Section 15.2), in the same order, short-circuiting on the
first failure: compound-identity validity, tool-level access, function-level
access, parameter deny-patterns and role-gated parameter values, and a
session rate limit.

Internal exceptions are logged and re-raised rather than swallowed: this
engine's contract is "raise on internal failure, return a PolicyDecision on
a real decision." Fail-closed behavior on exceptions/timeouts is enforced
one layer up, by ToolCallInterceptor — this keeps the engine's own logic
simple to audit and the fail-closed guarantee centralized in one place.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable

from aimw.interfaces.policy_engine import BasePolicyEngine
from aimw.models import ExecutionContext, PolicyDecision, ToolRequest
from aimw.policy.errors import PolicyEvaluationError
from aimw.policy.rules import PolicyRuleSet

logger = logging.getLogger(__name__)


def _deny(reason: str) -> PolicyDecision:
    return PolicyDecision(allowed=False, reason=reason)


class StaticPolicyEngine(BasePolicyEngine):
    """L1 policy engine: static YAML-defined allow/deny rules."""

    def __init__(
        self,
        ruleset: PolicyRuleSet,
        call_counter: Callable[[str], int] | None = None,
    ) -> None:
        self._ruleset = ruleset
        # Injected, not owned: at L2/L3 this can be backed by Redis without
        # changing the engine. Defaults to "always zero calls so far".
        self._call_counter = call_counter or (lambda _session_id: 0)

    async def evaluate_tool_call(
        self, context: ExecutionContext, request: ToolRequest
    ) -> PolicyDecision:
        try:
            return self._evaluate(context, request)
        except PolicyEvaluationError:
            raise
        except Exception as exc:  # noqa: BLE001 - re-raised deliberately, logged first
            logger.exception("policy engine internal failure evaluating %s", request.call_id)
            raise PolicyEvaluationError(str(exc)) from exc

    def _evaluate(self, context: ExecutionContext, request: ToolRequest) -> PolicyDecision:
        ruleset = self._ruleset

        # 1. Compound-identity validity.
        for field_name in ruleset.identity_required_fields:
            value = getattr(context, field_name, None)
            if not value:
                return _deny(f"invalid identity context: missing or empty '{field_name}'")

        # 2. Tool-level access.
        if request.tool_name not in ruleset.allowed_tools or request.tool_name not in ruleset.tools:
            return _deny(f"tool not permitted: '{request.tool_name}'")
        tool_rule = ruleset.tools[request.tool_name]
        if tool_rule.visible_to_roles and not any(
            role in context.roles for role in tool_rule.visible_to_roles
        ):
            return _deny(
                f"tool '{request.tool_name}' requires one of roles {tool_rule.visible_to_roles}"
            )

        # 3. Function-level access.
        if request.function_name not in tool_rule.allowed_functions:
            return _deny(
                f"function not permitted: '{request.tool_name}.{request.function_name}'"
            )

        # 4. Parameter deny-patterns.
        for param_name, patterns in tool_rule.parameter_deny_patterns.items():
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

        # 5. Role-gated parameter values, e.g. "environment=production" -> ["ProductionAdmin"].
        for gate, required_roles in tool_rule.requires_role_for.items():
            param_name, _, expected_value = gate.partition("=")
            actual_value = request.parameters.get(param_name)
            if actual_value is not None and str(actual_value) == expected_value:
                if not any(role in context.roles for role in required_roles):
                    return _deny(
                        f"parameter '{gate}' requires one of roles {required_roles}"
                    )

        # 6. Session rate limit.
        current_calls = self._call_counter(context.session_id)
        if current_calls >= ruleset.rate_limit_per_session:
            return _deny(
                f"rate limit exceeded: {current_calls} >= {ruleset.rate_limit_per_session}"
            )

        # All checks passed. Gate on HITL approval if this function requires it.
        if request.function_name in tool_rule.requires_approval_functions:
            return PolicyDecision(
                allowed=True,
                reason="approved pending human-in-the-loop review",
                action_requirements=["human_approval"],
            )

        return PolicyDecision(allowed=True, reason="all policy checks passed")
