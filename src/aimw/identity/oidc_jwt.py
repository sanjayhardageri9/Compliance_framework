"""Hermetic JWT identity verifier (Phase 2 adapter).

Provides ``HermeticJWTIdentityVerifier`` implementing ``BaseIdentityVerifier``
with stdlib-only HS256 JWT issue/verify for offline tests and demos.

Production / L3 should swap to a real OIDC JWKS-backed verifier (asymmetric
keys, issuer/audience validation against a remote IdP). This module never
fetches JWKS and does not call the network.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from aimw.identity.base import BaseIdentityVerifier
from aimw.models import ExecutionContext


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _hs256_sign(secret: bytes, signing_input: bytes) -> bytes:
    return hmac.new(secret, signing_input, hashlib.sha256).digest()


class HermeticJWTIdentityVerifier(BaseIdentityVerifier):
    """Offline HS256 JWT verifier bound to session/agent claims.

    NOT a production OIDC verifier — no JWKS, no network, HMAC only.
    Production should swap to real OIDC JWKS (RS256/ES256 + issuer/audience).
    """

    def __init__(
        self,
        secret: bytes,
        *,
        ttl_seconds: int = 900,
        issuer: str | None = "aimw-hermetic",
        audience: str | None = "aimw",
        # Accepted for API compatibility with the OIDC stub constructor
        jwks_uri: str | None = None,
        **_: Any,
    ) -> None:
        if not secret:
            raise ValueError("secret must be non-empty")
        if jwks_uri is not None:
            # Explicitly ignored: hermetic path never fetches remote JWKS.
            pass
        self._secret = secret
        self._ttl_seconds = ttl_seconds
        self.issuer = issuer
        self.audience = audience
        self.jwks_uri = None  # never used offline

    def issue(self, context: ExecutionContext, now: float | None = None) -> str:
        """Issue an HS256 JWT whose claims bind session_id + agent_id (+ roles)."""
        current = now if now is not None else time.time()
        iat = int(current)
        exp = iat + self._ttl_seconds
        header = {"alg": "HS256", "typ": "JWT"}
        payload: dict[str, Any] = {
            "sub": context.user_id,
            "session_id": context.session_id,
            "agent_id": context.agent_id,
            "roles": list(context.roles),
            "iat": iat,
            "exp": exp,
        }
        if self.issuer is not None:
            payload["iss"] = self.issuer
        if self.audience is not None:
            payload["aud"] = self.audience
        h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
        p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
        signing_input = f"{h_b64}.{p_b64}".encode("ascii")
        sig_b64 = _b64url_encode(_hs256_sign(self._secret, signing_input))
        return f"{h_b64}.{p_b64}.{sig_b64}"

    def verify(
        self, credential: str, context: ExecutionContext, now: float | None = None
    ) -> bool:
        """Verify HS256 JWT: signature, exp, and session/agent claim binding."""
        try:
            parts = credential.split(".")
            if len(parts) != 3:
                return False
            h_b64, p_b64, sig_b64 = parts
            signing_input = f"{h_b64}.{p_b64}".encode("ascii")
            expected_sig = _hs256_sign(self._secret, signing_input)
            presented_sig = _b64url_decode(sig_b64)
            if not hmac.compare_digest(expected_sig, presented_sig):
                return False

            header = json.loads(_b64url_decode(h_b64))
            if header.get("alg") != "HS256":
                return False

            payload = json.loads(_b64url_decode(p_b64))
            current = now if now is not None else time.time()
            exp = payload.get("exp")
            if exp is None or current > float(exp):
                return False

            if payload.get("session_id") != context.session_id:
                return False
            if payload.get("agent_id") != context.agent_id:
                return False

            if self.issuer is not None and payload.get("iss") != self.issuer:
                return False
            if self.audience is not None:
                aud = payload.get("aud")
                if isinstance(aud, list):
                    if self.audience not in aud:
                        return False
                elif aud != self.audience:
                    return False

            return True
        except (ValueError, TypeError, json.JSONDecodeError, KeyError):
            return False


# Back-compat alias for the Phase 2 stub name; prefer HermeticJWTIdentityVerifier.
OidcJwtVerifier = HermeticJWTIdentityVerifier
