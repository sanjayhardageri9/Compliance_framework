"""Integration: govern allow path + metrics + explain + audit (hermetic)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import TEST_TOKEN


@pytest.mark.asyncio
async def test_govern_allow_path_with_scripted_call(app, auth_headers, metrics) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/govern",
            headers=auth_headers,
            json={
                "prompt": "What's the weather?",
                "user_id": "u1",
                "agent_id": "a1",
                "session_id": "s1",
                "roles": ["AgentExecutor"],
                "scripted_tool_calls": [
                    {
                        "tool_name": "search_tool",
                        "function_name": "query",
                        "parameters": {"q": "weather"},
                        "call_id": "gov-allow-1",
                    }
                ],
            },
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tool_results"]
    tr = body["tool_results"][0]
    assert tr["call_id"] == "gov-allow-1"
    assert tr["allowed"] is True
    assert "audit_summary" in body
    snap = metrics.snapshot()
    assert snap["govern_total"] == 1
    assert snap["allow_total"] >= 1


@pytest.mark.asyncio
async def test_govern_deny_and_explain(app, auth_headers, metrics) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/govern",
            headers=auth_headers,
            json={
                "prompt": "drop everything",
                "user_id": "u1",
                "agent_id": "a1",
                "session_id": "s1",
                "roles": ["AgentExecutor"],
                "scripted_tool_calls": [
                    {
                        "tool_name": "unknown_tool",
                        "function_name": "boom",
                        "parameters": {},
                        "call_id": "gov-deny-1",
                    }
                ],
            },
        )
        assert resp.status_code == 200
        tr = resp.json()["tool_results"][0]
        assert tr["allowed"] is False

        explain = await client.get(
            "/v1/decisions/gov-deny-1/explain",
            headers=auth_headers,
        )
        assert explain.status_code == 200
        assert explain.json()["allowed"] is False

        missing = await client.get(
            "/v1/decisions/does-not-exist/explain",
            headers=auth_headers,
        )
        assert missing.status_code == 404

        audit = await client.get("/v1/audit?limit=10", headers=auth_headers)
        assert audit.status_code == 200
        assert audit.json()["count"] >= 1

    assert metrics.snapshot()["deny_total"] >= 1


@pytest.mark.asyncio
async def test_hitl_approval_then_govern(app, auth_headers) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Pre-approve the call_id, then govern a HITL-gated deploy.
        await client.post(
            "/v1/approvals/deploy-1",
            headers=auth_headers,
            json={"resolution": "approve"},
        )
        resp = await client.post(
            "/v1/govern",
            headers=auth_headers,
            json={
                "prompt": "deploy please",
                "user_id": "u1",
                "agent_id": "ops",
                "session_id": "s2",
                "roles": ["ProductionAdmin"],
                "scripted_tool_calls": [
                    {
                        "tool_name": "deploy_tool",
                        "function_name": "deploy",
                        "parameters": {"environment": "staging", "version": "1.0"},
                        "call_id": "deploy-1",
                    }
                ],
            },
        )
    assert resp.status_code == 200, resp.text
    tr = resp.json()["tool_results"][0]
    assert tr["allowed"] is True
    assert "human-approved" in tr["reason"] or tr["allowed"]
