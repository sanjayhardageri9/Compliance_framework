"""Audit record shape.

Deliberately stores a *minimal, redacted* projection of the execution
context and tool parameters rather than the full objects: audit logs are
themselves a data-exposure surface, and the doc's own least-agency /
data-minimization principles apply to what we retain, not just to what an
agent can do. Parameter values are hashed by default (see
HashChainedJSONLLogger's redact_parameters flag) rather than stored raw.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class RedactedContext(BaseModel):
    user_id: str
    agent_id: str
    session_id: str
    roles: list[str]


class RedactedRequest(BaseModel):
    tool_name: str
    function_name: str
    call_id: str
    # param name -> sha256 hex digest of its stringified value (or raw value
    # if redaction is disabled - see HashChainedJSONLLogger).
    parameters: dict[str, str]


class AuditRecord(BaseModel):
    record_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    call_id: str
    context: RedactedContext
    request: RedactedRequest
    decision: dict[str, Any]
    sandbox_result: dict[str, Any] | None = None
    prev_hash: str
    record_hash: str = ""
