from __future__ import annotations

import pytest

from aimw.gateway.shim import GatewayAuthError, LiteLLMGatewayShim
from aimw.identity.session_token import SessionTokenIssuer
from aimw.identity.static_bearer import StaticBearerTokenVerifier


def test_default_gateway_allows_unconfigured_static_bearer(context_factory):
    gateway = LiteLLMGatewayShim()
    result = gateway.handle_inbound("hello", context_factory(), bearer_token="anything")
    assert result == "hello"


def test_gateway_rejects_invalid_static_token(context_factory):
    gateway = LiteLLMGatewayShim(identity_verifier=StaticBearerTokenVerifier({"good-token"}))
    with pytest.raises(GatewayAuthError):
        gateway.handle_inbound("hello", context_factory(), bearer_token="bad-token")


def test_gateway_accepts_valid_session_token(context_factory):
    issuer = SessionTokenIssuer(secret=b"secret")
    gateway = LiteLLMGatewayShim(identity_verifier=issuer)
    ctx = context_factory(session_id="s1", agent_id="a1")
    token = issuer.issue(ctx)
    result = gateway.handle_inbound("hello", ctx, bearer_token=token)
    assert result == "hello"


def test_gateway_rejects_session_token_for_wrong_context(context_factory):
    issuer = SessionTokenIssuer(secret=b"secret")
    gateway = LiteLLMGatewayShim(identity_verifier=issuer)
    ctx1 = context_factory(session_id="s1", agent_id="a1")
    ctx2 = context_factory(session_id="s2", agent_id="a1")
    token = issuer.issue(ctx1)
    with pytest.raises(GatewayAuthError):
        gateway.handle_inbound("hello", ctx2, bearer_token=token)


def test_gateway_rate_limit(context_factory):
    gateway = LiteLLMGatewayShim(rate_limit_per_minute=2)
    ctx = context_factory()
    gateway.handle_inbound("a", ctx, bearer_token="t")
    gateway.handle_inbound("b", ctx, bearer_token="t")
    with pytest.raises(GatewayAuthError):
        gateway.handle_inbound("c", ctx, bearer_token="t")
