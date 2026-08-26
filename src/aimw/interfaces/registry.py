"""Abstract tool-discovery and permission-verification contract.

Implementations answer "what can this context even see" before an agent
framework constructs the tool schema handed to the LLM. This is where the
principle of least agency is enforced at the schema level: a context with
fewer roles/scopes should be offered a strict subset of tools.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from aimw.models import ExecutionContext


class BaseRegistry(ABC):
    """Tool discovery and permission verification."""

    @abstractmethod
    async def get_permitted_tools(self, context: ExecutionContext) -> list[dict[str, Any]]: ...
