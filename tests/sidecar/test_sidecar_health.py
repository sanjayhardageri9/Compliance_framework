"""Unit/API tests: healthz, auth, metrics, promote, approvals."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import TEST_TOKEN


@pytest.mark.asyncio
async def test_healthz(app) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["active_policy_id"] is not None


@pytest.mark.asyncio
async def test_metrics_endpoint(app, metrics) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/metrics")
    assert resp.status_code == 200
    assert "aimw_govern_total" in resp.text


@pytest.mark.asyncio
async def test_govern_missing_auth_401(app) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/v1/govern", json={"prompt": "hi"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_govern_bad_token_403(app) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/govern",
            json={"prompt": "hi", "bearer_token": "wrong", "roles": ["AgentExecutor"]},
            headers={"Authorization": "Bearer wrong"},
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_promote_and_active(app, auth_headers, policy_store) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        create = await client.post(
            "/v1/policies",
            headers=auth_headers,
            json={
                "name": "v2",
                "body": {
                    "identity_required_fields": ["user_id", "agent_id", "roles"],
                    "allowed_tools": ["search_tool"],
                    "rate_limit_per_session": 50,
                    "tools": {
                        "search_tool": {
                            "tool_name": "search_tool",
                            "allowed_functions": ["query"],
                        }
                    },
                },
            },
        )
        assert create.status_code == 200
        version_id = create.json()["id"]
        promo = await client.post(
            f"/v1/policies/{version_id}/promote",
            headers=auth_headers,
        )
        assert promo.status_code == 200
        assert promo.json()["status"] == "active"
        active = await client.get("/v1/policies/active", headers=auth_headers)
        assert active.status_code == 200
        assert active.json()["id"] == version_id


@pytest.mark.asyncio
async def test_approval_endpoint(app, auth_headers) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/approvals/call-123",
            headers=auth_headers,
            json={"resolution": "approve", "actor": "reviewer"},
        )
    assert resp.status_code == 200
    assert resp.json()["approved"] is True
    assert resp.json()["call_id"] == "call-123"
