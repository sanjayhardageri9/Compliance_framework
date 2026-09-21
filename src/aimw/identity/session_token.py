"""L2 identity: short-lived, session-scoped service tokens.

Upgrades from L1's single static bearer token (any holder acts as anyone)
to a token that is cryptographically bound to one session_id + agent_id
pair and expires. This is a deliberate stepping stone toward L3's full
compound identity (JWT + agent key + delegated scope, Section 13/15.3) -
the token format here already carries session + agent binding, just
without JWT's claim/scope structure or asymmetric signing.

Format: "<session_id>.<agent_id>.<expiry_epoch>.<hex_hmac_sha256>"
The HMAC covers "session_id:agent_id:expiry_epoch" under a shared secret.
"""

from __future__ import annotations

import hmac
import time
from hashlib import sha256

from aimw.identity.base import BaseIdentityVerifier
from aimw.models import ExecutionContext


class SessionTokenError(Exception):
    """Raised for a malformed token; callers should treat this as verify() == False."""


def _sign(secret: bytes, session_id: str, agent_id: str, expiry_epoch: int) -> str:
    message = f"{session_id}:{agent_id}:{expiry_epoch}".encode()
    return hmac.new(secret, message, sha256).hexdigest()


class SessionTokenIssuer(BaseIdentityVerifier):
    """Issues and verifies session-scoped service tokens."""

    def __init__(self, secret: bytes, ttl_seconds: int = 900) -> None:
        if not secret:
            raise ValueError("secret must be non-empty")
        self._secret = secret
        self._ttl_seconds = ttl_seconds

    def issue(self, context: ExecutionContext, now: float | None = None) -> str:
        # Token wire format is dotted; '.' inside IDs makes split(".", 3) ambiguous.
        if "." in context.session_id or "." in context.agent_id:
            raise ValueError(
                "session_id and agent_id must not contain '.' "
                "(reserved as the session-token field separator)"
            )
        expiry_epoch = int((now if now is not None else time.time()) + self._ttl_seconds)
        signature = _sign(self._secret, context.session_id, context.agent_id, expiry_epoch)
        return f"{context.session_id}.{context.agent_id}.{expiry_epoch}.{signature}"

    def verify(self, credential: str, context: ExecutionContext, now: float | None = None) -> bool:
        try:
            session_id, agent_id, expiry_str, signature = credential.split(".", 3)
            expiry_epoch = int(expiry_str)
        except (ValueError, AttributeError):
            return False

        if session_id != context.session_id or agent_id != context.agent_id:
            return False

        current_time = now if now is not None else time.time()
        if current_time > expiry_epoch:
            return False

        expected_signature = _sign(self._secret, session_id, agent_id, expiry_epoch)
        return hmac.compare_digest(signature, expected_signature)
