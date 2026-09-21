"""L1 identity: a single static bearer token per deployment.

Extracted from the gateway shim so the "Identity" dimension follows the
same tiered-swap pattern as everything else - the gateway depends only on
BaseIdentityVerifier.
"""

from __future__ import annotations

import hmac
from hashlib import sha256

from aimw.identity.base import BaseIdentityVerifier
from aimw.models import ExecutionContext


class StaticBearerTokenVerifier(BaseIdentityVerifier):
    """L1: token must be a member of a fixed, deployment-wide allow-set.

    Fail-closed by default: an empty allow-set rejects all credentials unless
    ``allow_unconfigured=True`` (explicit opt-in for demos/local shims).

    Constant-time compare approach
    ------------------------------
    Set membership via ``in`` is not constant-time. We pre-hash every
    configured token with SHA-256 (fixed 32-byte digests) and compare the
    SHA-256 digest of the presented credential to each configured digest
    with ``hmac.compare_digest``. Digests are equal length, so
    ``compare_digest`` is well-defined. We OR results without early-return
    on a match so which token matched does not short-circuit the loop.
    (Iteration count still depends on how many tokens are configured.)
    """

    def __init__(
        self,
        valid_tokens: set[str] | None = None,
        *,
        allow_unconfigured: bool = False,
    ) -> None:
        self._allow_unconfigured = allow_unconfigured
        tokens = set(valid_tokens) if valid_tokens else set()
        self._token_digests: tuple[bytes, ...] = tuple(
            sha256(token.encode("utf-8")).digest() for token in tokens
        )

    @classmethod
    def for_production(cls, valid_tokens: set[str]) -> StaticBearerTokenVerifier:
        """Build a production verifier; empty credentials are rejected at construction."""
        if not valid_tokens:
            raise ValueError(
                "production StaticBearerTokenVerifier requires a non-empty valid_tokens set"
            )
        return cls(valid_tokens, allow_unconfigured=False)

    def verify(self, credential: str, context: ExecutionContext) -> bool:
        if not self._token_digests:
            return self._allow_unconfigured
        credential_digest = sha256(credential.encode("utf-8")).digest()
        matched = False
        for token_digest in self._token_digests:
            # Avoid short-circuiting on the first match (token-index timing).
            matched = hmac.compare_digest(credential_digest, token_digest) or matched
        return matched
