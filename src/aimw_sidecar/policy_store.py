"""In-memory versioned policy store for the Phase 1 sidecar.

Validates bodies against ``aimw.policy.rules.PolicyRuleSet`` when aimw is
available. Durable backends (SQLite / Postgres) are out of scope for Phase 1.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Literal
from uuid import uuid4

import yaml

from aimw.policy.rules import PolicyRuleSet

PolicyStatus = Literal["draft", "active", "superseded", "archived"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_body(body: dict[str, Any] | str | PolicyRuleSet) -> tuple[dict[str, Any], PolicyRuleSet]:
    """Normalize YAML/JSON/dict/PolicyRuleSet into (raw_dict, validated ruleset)."""
    if isinstance(body, PolicyRuleSet):
        raw = body.model_dump(mode="python")
        return raw, body
    if isinstance(body, str):
        loaded = yaml.safe_load(body)
        if not isinstance(loaded, dict):
            raise ValueError("policy YAML/JSON must deserialize to a mapping")
        raw = loaded
    elif isinstance(body, dict):
        raw = dict(body)
    else:
        raise TypeError(f"unsupported policy body type: {type(body)!r}")
    ruleset = PolicyRuleSet.model_validate(raw)
    return raw, ruleset


@dataclass
class PolicyVersion:
    """One immutable-ish version of a policy document."""

    id: str
    name: str
    version: int
    status: PolicyStatus
    body: dict[str, Any]
    ruleset: PolicyRuleSet
    created_at: datetime = field(default_factory=_utcnow)
    promoted_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class InMemoryPolicyStore:
    """Thread-safe in-memory CRUD + promote for policy versions."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._by_id: dict[str, PolicyVersion] = {}
        self._seq_by_name: dict[str, int] = {}
        self._active_id: str | None = None

    def list(self, *, name: str | None = None) -> list[PolicyVersion]:
        """Alias for ``list_policies`` (Phase 1 contract name)."""
        return self.list_policies(name=name)

    def list_policies(self, *, name: str | None = None) -> list[PolicyVersion]:
        with self._lock:
            items = list(self._by_id.values())
        if name is not None:
            items = [p for p in items if p.name == name]
        return sorted(items, key=lambda p: (p.name, p.version))

    def get(self, policy_id: str) -> PolicyVersion | None:
        with self._lock:
            return self._by_id.get(policy_id)

    def active(self) -> PolicyVersion | None:
        """Alias for ``get_active``."""
        return self.get_active()

    def get_active(self) -> PolicyVersion | None:
        with self._lock:
            if self._active_id is None:
                return None
            return self._by_id.get(self._active_id)

    def create(
        self,
        name: str,
        body: dict[str, Any] | str | PolicyRuleSet,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> PolicyVersion:
        raw, ruleset = _parse_body(body)
        with self._lock:
            next_ver = self._seq_by_name.get(name, 0) + 1
            self._seq_by_name[name] = next_ver
            pv = PolicyVersion(
                id=str(uuid4()),
                name=name,
                version=next_ver,
                status="draft",
                body=raw,
                ruleset=ruleset,
                metadata=dict(metadata or {}),
            )
            self._by_id[pv.id] = pv
            return pv

    def promote(self, policy_id: str) -> PolicyVersion:
        """Mark ``policy_id`` active; supersede previous active for same name."""
        with self._lock:
            target = self._by_id.get(policy_id)
            if target is None:
                raise KeyError(f"unknown policy id: {policy_id}")
            if target.status == "archived":
                raise ValueError("cannot promote archived policy")
            for other in self._by_id.values():
                if (
                    other.name == target.name
                    and other.status == "active"
                    and other.id != target.id
                ):
                    other.status = "superseded"
            target.status = "active"
            target.promoted_at = _utcnow()
            self._active_id = target.id
            return target
