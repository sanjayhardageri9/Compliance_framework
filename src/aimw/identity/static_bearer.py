"""L1 identity: a single static bearer token per deployment.

Extracted from the gateway shim so the "Identity" dimension follows the
same tiered-swap pattern as everything else - the gateway depends only on
BaseIdentityVerifier.
"""

from __future__ import annotations

from aimw.identity.base import BaseIdentityVerifier
from aimw.models import ExecutionContext


class StaticBearerTokenVerifier(BaseIdentityVerifier):
    """L1: token must be a member of a fixed, deployment-wide allow-set."""

    def __init__(self, valid_tokens: set[str] | None = None) -> None:
        # Empty set = accept-any, matching the gateway's original permissive
        # default when no tokens were configured.
        self._valid_tokens = valid_tokens or set()

    def verify(self, credential: str, context: ExecutionContext) -> bool:
        if not self._valid_tokens:
            return True
        return credential in self._valid_tokens
