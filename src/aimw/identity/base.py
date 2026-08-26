"""Identity verification contract.

Not one of the three named ABCs in Section 14, built the same way for the
same reason: the "Identity" row of the tiered maturity model (Section 13)
changes shape at every tier - a single static bearer token at L1,
session-scoped service tokens at L2, full compound identity (JWT + agent
key + scope) at L3 - and the gateway should not need to change to move
between them.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from aimw.models import ExecutionContext


class BaseIdentityVerifier(ABC):
    """Verifies that a presented credential authorizes this ExecutionContext."""

    @abstractmethod
    def verify(self, credential: str, context: ExecutionContext) -> bool: ...
