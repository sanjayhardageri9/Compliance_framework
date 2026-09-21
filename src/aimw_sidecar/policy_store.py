"""In-memory versioned policy store interface (Phase 1 skeleton).

Durable backends (SQLite / Postgres / object store) are out of scope here.
Aligns with Phase 0 ``DbBackedPolicyEngine`` / ``PolicyRuleSet`` conceptually
but does not import aimw so the sidecar skeleton stays standalone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Literal
from uuid import uuid4

PolicyStatus = Literal["draft", "active", "superseded", "archived"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class PolicyVersion:
    """One immutable-ish version of a policy document."""

    id: str
    name: str
    version: int
    status: PolicyStatus
    body: dict[str, Any]
    created_at: datetime = field(default_factory=_utcnow)
    promoted_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class InMemoryPolicyStore:
    """Thread-safe in-memory CRUD + promote for policy versions.

    Interface only for Phase 1; promote is the sole mutation that flips
    ``active``. Callers (FastAPI routes) should not bypass this store.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._by_id: dict[str, PolicyVersion] = {}
        self._seq_by_name: dict[str, int] = {}
        self._active_id: str | None = None

    def list_policies(self, *, name: str | None = None) -> list[PolicyVersion]:
        with self._lock:
            items = list(self._by_id.values())
        if name is not None:
            items = [p for p in items if p.name == name]
        return sorted(items, key=lambda p: (p.name, p.version))

    def get(self, policy_id: str) -> PolicyVersion | None:
        with self._lock:
            return self._by_id.get(policy_id)

    def get_active(self) -> PolicyVersion | None:
        with self._lock:
            if self._active_id is None:
                return None
            return self._by_id.get(self._active_id)

    def create(
        self,
        name: str,
        body: dict[str, Any],
        *,
        metadata: dict[str, Any] | None = None,
    ) -> PolicyVersion:
        with self._lock:
            next_ver = self._seq_by_name.get(name, 0) + 1
            self._seq_by_name[name] = next_ver
            pv = PolicyVersion(
                id=str(uuid4()),
                name=name,
                version=next_ver,
                status="draft",
                body=dict(body),
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
            # Supersede other active versions with the same name
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

    # ---- hooks for durable adapters (not implemented) ----

    def load_from_disk(self, path: str) -> None:
        raise NotImplementedError("durable policy load is Phase 1+; use create()")

    def persist_to_disk(self, path: str) -> None:
        raise NotImplementedError("durable policy persist is Phase 1+")
