"""Core data contracts shared by every governance component.

These three models are the stable wire format the rest of the SDK is built
against: a policy engine, guardrail, or registry implementation at any
maturity tier (L1 static lists through L3 OPA/Cedar) consumes and produces
exactly these shapes.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ExecutionContext(BaseModel):
    """Who is asking, on whose behalf, and with what standing authority."""

    model_config = ConfigDict(frozen=True)

    user_id: str
    agent_id: str
    session_id: str
    roles: list[str]
    delegated_scopes: list[str]
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolRequest(BaseModel):
    """A single proposed tool invocation awaiting a policy decision."""

    model_config = ConfigDict(frozen=True)

    tool_name: str
    function_name: str
    parameters: dict[str, Any]
    call_id: str


class PolicyDecision(BaseModel):
    """The outcome of evaluating a ToolRequest against policy."""

    allowed: bool
    reason: str
    modified_parameters: dict[str, Any] | None = None
    action_requirements: list[str] = Field(default_factory=list)
