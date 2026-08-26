"""L1 tool registry: derives the permitted tool set from the static ruleset.

Embodies "least agency" at the schema level - an agent framework calls
get_permitted_tools() before constructing the tool schema handed to the
LLM, so a context is never even shown a tool/function it isn't entitled to.
This L1 implementation doesn't yet filter by context.roles/delegated_scopes
per-tool (the static ruleset has no per-role tool mapping); it exposes the
seam via _is_tool_visible so an L2 DB-backed RBAC registry can add that
without changing the BaseRegistry contract.
"""

from __future__ import annotations

from typing import Any

from aimw.interfaces.registry import BaseRegistry
from aimw.models import ExecutionContext
from aimw.policy.rules import PolicyRuleSet


class StaticToolRegistry(BaseRegistry):
    """L1 registry backed by the same static PolicyRuleSet as StaticPolicyEngine."""

    def __init__(self, ruleset: PolicyRuleSet) -> None:
        self._ruleset = ruleset

    def _is_tool_visible(self, tool_name: str, context: ExecutionContext) -> bool:
        if tool_name not in self._ruleset.allowed_tools:
            return False
        rule = self._ruleset.tools.get(tool_name)
        if rule is None:
            return False
        if not rule.visible_to_roles:
            return True
        return any(role in context.roles for role in rule.visible_to_roles)

    async def get_permitted_tools(self, context: ExecutionContext) -> list[dict[str, Any]]:
        manifests: list[dict[str, Any]] = []
        for tool_name in self._ruleset.allowed_tools:
            if tool_name not in self._ruleset.tools:
                continue
            if not self._is_tool_visible(tool_name, context):
                continue
            rule = self._ruleset.tools[tool_name]
            manifests.append(
                {
                    "tool_name": tool_name,
                    "functions": list(rule.allowed_functions),
                }
            )
        return manifests
