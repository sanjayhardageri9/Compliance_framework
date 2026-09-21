from __future__ import annotations

import pytest

from aimw.identity.session_token import SessionTokenIssuer
from aimw.identity.static_bearer import StaticBearerTokenVerifier


def test_static_bearer_fail_closed_when_no_tokens_configured(context_factory):
    verifier = StaticBearerTokenVerifier()
    assert verifier.verify("anything", context_factory()) is False


def test_static_bearer_permissive_when_allow_unconfigured(context_factory):
    verifier = StaticBearerTokenVerifier(allow_unconfigured=True)
    assert verifier.verify("anything", context_factory()) is True


def test_static_bearer_rejects_unknown_token(context_factory):
    verifier = StaticBearerTokenVerifier({"secret-1"})
    assert verifier.verify("wrong", context_factory()) is False
    assert verifier.verify("secret-1", context_factory()) is True


def test_static_bearer_for_production_rejects_empty_credentials():
    with pytest.raises(ValueError, match="non-empty"):
        StaticBearerTokenVerifier.for_production(set())


def test_static_bearer_for_production_accepts_configured_token(context_factory):
    verifier = StaticBearerTokenVerifier.for_production({"prod-token"})
    assert verifier.verify("prod-token", context_factory()) is True
    assert verifier.verify("other", context_factory()) is False


def test_session_token_issue_and_verify_roundtrip(context_factory):
    issuer = SessionTokenIssuer(secret=b"test-secret", ttl_seconds=900)
    ctx = context_factory(session_id="s1", agent_id="a1")
    token = issuer.issue(ctx)
    assert issuer.verify(token, ctx) is True


def test_session_token_rejects_wrong_session(context_factory):
    issuer = SessionTokenIssuer(secret=b"test-secret")
    ctx1 = context_factory(session_id="s1", agent_id="a1")
    ctx2 = context_factory(session_id="s2", agent_id="a1")
    token = issuer.issue(ctx1)
    assert issuer.verify(token, ctx2) is False


def test_session_token_rejects_wrong_agent(context_factory):
    issuer = SessionTokenIssuer(secret=b"test-secret")
    ctx1 = context_factory(session_id="s1", agent_id="a1")
    ctx2 = context_factory(session_id="s1", agent_id="a2")
    token = issuer.issue(ctx1)
    assert issuer.verify(token, ctx2) is False


def test_session_token_issue_rejects_dot_in_session_id(context_factory):
    issuer = SessionTokenIssuer(secret=b"test-secret")
    ctx = context_factory(session_id="s.1", agent_id="a1")
    with pytest.raises(ValueError, match="must not contain"):
        issuer.issue(ctx)


def test_session_token_issue_rejects_dot_in_agent_id(context_factory):
    issuer = SessionTokenIssuer(secret=b"test-secret")
    ctx = context_factory(session_id="s1", agent_id="a.1")
    with pytest.raises(ValueError, match="must not contain"):
        issuer.issue(ctx)


def test_session_token_rejects_tampered_signature(context_factory):
    issuer = SessionTokenIssuer(secret=b"test-secret")
    ctx = context_factory(session_id="s1", agent_id="a1")
    token = issuer.issue(ctx)
    session_id, agent_id, expiry, sig = token.split(".", 3)
    tampered = f"{session_id}.{agent_id}.{expiry}.{'0' * len(sig)}"
    assert issuer.verify(tampered, ctx) is False


def test_session_token_rejects_expired(context_factory):
    issuer = SessionTokenIssuer(secret=b"test-secret", ttl_seconds=10)
    ctx = context_factory(session_id="s1", agent_id="a1")
    issued_at = 1_000_000.0
    token = issuer.issue(ctx, now=issued_at)
    assert issuer.verify(token, ctx, now=issued_at + 5) is True
    assert issuer.verify(token, ctx, now=issued_at + 11) is False


def test_session_token_rejects_malformed_credential(context_factory):
    issuer = SessionTokenIssuer(secret=b"test-secret")
    ctx = context_factory()
    assert issuer.verify("not-a-token", ctx) is False


def test_session_token_issuer_rejects_empty_secret():
    with pytest.raises(ValueError):
        SessionTokenIssuer(secret=b"")


def test_different_secrets_produce_different_signatures(context_factory):
    ctx = context_factory(session_id="s1", agent_id="a1")
    issuer_a = SessionTokenIssuer(secret=b"secret-a")
    issuer_b = SessionTokenIssuer(secret=b"secret-b")
    now = 1_000_000.0
    token_a = issuer_a.issue(ctx, now=now)
    assert issuer_b.verify(token_a, ctx, now=now) is False
