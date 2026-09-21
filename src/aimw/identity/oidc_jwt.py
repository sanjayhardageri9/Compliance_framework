"""OIDC/JWT identity verifier stub — NOT PRODUCTION.

Implements the ``BaseIdentityVerifier`` pattern from Phase 0:

    class BaseIdentityVerifier(ABC):
        def verify(self, credential: str, context: ExecutionContext) -> bool: ...

Install ``aimw[enterprise]`` before using a real implementation.
Hermetic default remains ``StaticBearerTokenVerifier`` / ``SessionTokenIssuer``.
"""

from __future__ import annotations

from typing import Any


class OidcJwtVerifier:
    """L3 stub: validate JWT against OIDC JWKS / issuer.

    NOT PRODUCTION — Placeholder. Do not enable in live profiles.

    Intended constructor knobs (future):
      - issuer, audience, jwks_uri
      - required claims → ExecutionContext roles / agent_id mapping
    """

    def __init__(
        self,
        *,
        issuer: str | None = None,
        audience: str | None = None,
        jwks_uri: str | None = None,
        **_: Any,
    ) -> None:
        self.issuer = issuer
        self.audience = audience
        self.jwks_uri = jwks_uri

    def verify(self, credential: str, context: Any) -> bool:
        """Mirror ``BaseIdentityVerifier.verify``.

        Parameters
        ----------
        credential:
            Raw bearer JWT string.
        context:
            ``aimw.models.ExecutionContext`` (typed Any here to avoid hard
            dependency while this tree is a standalone design package).
        """
        raise NotImplementedError(
            "OidcJwtVerifier is a Phase 2 stub — install aimw[enterprise] "
            "and replace this Placeholder with a real JWKS-backed verifier"
        )
