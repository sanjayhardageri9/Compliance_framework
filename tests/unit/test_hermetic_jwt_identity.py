"""Hermetic JWT identity verifier tests (offline, stdlib HS256)."""

from __future__ import annotations

import time

import pytest

from aimw.identity.oidc_jwt import HermeticJWTIdentityVerifier
from aimw.models import ExecutionContext


def _ctx(**overrides: object) -> ExecutionContext:
    base = dict(
        user_id="u1",
        agent_id="agent-a",
        session_id="sess-1",
        roles=["operator"],
        delegated_scopes=[],
    )
    base.update(overrides)
    return ExecutionContext(**base)  # type: ignore[arg-type]


@pytest.fixture
def verifier() -> HermeticJWTIdentityVerifier:
    return HermeticJWTIdentityVerifier(b"test-secret-key", ttl_seconds=60)


def test_issue_and_verify_roundtrip(verifier: HermeticJWTIdentityVerifier) -> None:
    ctx = _ctx()
    token = verifier.issue(ctx)
    assert token.count(".") == 2
    assert verifier.verify(token, ctx) is True


def test_rejects_wrong_session_or_agent(verifier: HermeticJWTIdentityVerifier) -> None:
    ctx = _ctx()
    token = verifier.issue(ctx)
    assert verifier.verify(token, _ctx(session_id="other")) is False
    assert verifier.verify(token, _ctx(agent_id="other-agent")) is False


def test_rejects_expired_token(verifier: HermeticJWTIdentityVerifier) -> None:
    ctx = _ctx()
    past = time.time() - 1000
    token = verifier.issue(ctx, now=past)
    assert verifier.verify(token, ctx, now=time.time()) is False


def test_rejects_tampered_signature(verifier: HermeticJWTIdentityVerifier) -> None:
    ctx = _ctx()
    token = verifier.issue(ctx)
    h, p, s = token.split(".")
    tampered = f"{h}.{p}.{s[:-4]}aaaa"
    assert verifier.verify(tampered, ctx) is False


def test_rejects_malformed(verifier: HermeticJWTIdentityVerifier) -> None:
    ctx = _ctx()
    assert verifier.verify("not-a-jwt", ctx) is False
    assert verifier.verify("", ctx) is False


def test_implements_base_identity_verifier() -> None:
    from aimw.identity.base import BaseIdentityVerifier

    assert issubclass(HermeticJWTIdentityVerifier, BaseIdentityVerifier)
