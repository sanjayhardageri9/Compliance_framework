"""L2 tool registry: DB-backed, sharing DbBackedPolicyEngine's rule store.

Same least-agency contract as StaticToolRegistry, now also honoring the
Global RBAC layer (a context whose roles aren't recognized in the store at
all sees no tools, not just a filtered set) so the registry's view of
"what can this context see" never drifts from the engine's view of "what
can this context do."
"""

from __future__ import annotations

from typing import Any

from aimw.interfaces.registry import BaseRegistry
from aimw.models import ExecutionContext
from aimw.policy.db_rules import DbRuleStore


class DbBackedToolRegistry(BaseRegistry):
    """L2 registry backed by the same DbRuleStore as DbBackedPolicyEngine."""

    def __init__(self, store: DbRuleStore) -> None:
        self._store = store

    def _is_tool_visible(self, tool_name: str, context: ExecutionContext) -> bool:
        active_roles = self._store.active_roles()
        if not active_roles.intersection(context.roles):
            return False  # global RBAC: unrecognized role sees nothing
        if not self._store.tool_exists(tool_name):
            return False
        visibility_roles = self._store.visibility_roles(tool_name)
        if not visibility_roles:
            return True
        return any(role in context.roles for role in visibility_roles)

    async def get_permitted_tools(self, context: ExecutionContext) -> list[dict[str, Any]]:
        manifests: list[dict[str, Any]] = []
        for tool_name in self._store.tool_names():
            if not self._is_tool_visible(tool_name, context):
                continue
            manifests.append(
                {
                    "tool_name": tool_name,
                    "functions": self._store.allowed_functions(tool_name),
                }
            )
        return manifests
