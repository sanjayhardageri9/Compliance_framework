"""Declarative L1 policy rule format.

This mirrors the five-layer permission hierarchy the framework document
expresses in OPA Rego (Section 15.2) — global identity validity, tool-level
access, function-level access, parameter deny-patterns / role gates, and
rate limiting — but expressed as YAML validated into pydantic models rather
than hardcoded Python conditionals. Policy authors edit this file; upgrading
to a real OPA bundle at L3 is then a transliteration of this same shape,
not a redesign.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class ToolRule(BaseModel):
    """Access rules for a single tool."""

    tool_name: str
    allowed_functions: list[str]
    # roles allowed to even see/use this tool at all; empty = visible to any
    # authenticated context. Enforces least-agency at the registry level.
    visible_to_roles: list[str] = Field(default_factory=list)
    # parameter name -> list of regex patterns that, if matched, deny the call
    parameter_deny_patterns: dict[str, list[str]] = Field(default_factory=dict)
    # "param_name=value" -> list of roles required for that param value to be permitted
    requires_role_for: dict[str, list[str]] = Field(default_factory=dict)
    # function names that are allowed but require human-in-the-loop approval
    requires_approval_functions: list[str] = Field(default_factory=list)


class PolicyRuleSet(BaseModel):
    """The full L1 static rule set for one deployment."""

    identity_required_fields: list[str] = Field(
        default_factory=lambda: ["user_id", "agent_id", "roles"]
    )
    allowed_tools: list[str]
    tools: dict[str, ToolRule]
    rate_limit_per_session: int = 50


def load_ruleset(path: str | Path) -> PolicyRuleSet:
    """Load and validate a PolicyRuleSet from a YAML file."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return PolicyRuleSet.model_validate(raw)
