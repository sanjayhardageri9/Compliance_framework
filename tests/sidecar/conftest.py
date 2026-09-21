"""Hermetic fixtures for sidecar tests.

Expects ``aimw`` on PYTHONPATH (install from the main package) and
``aimw_sidecar`` from this tree's ``src/``.
"""

from __future__ import annotations

import pytest

from aimw.hitl.approval import InMemoryApprovalQueue
from aimw.policy.rules import PolicyRuleSet

from aimw_sidecar.app import create_app
from aimw_sidecar.metrics import SidecarMetrics
from aimw_sidecar.policy_store import InMemoryPolicyStore

TEST_TOKEN = "test-sidecar-token"

MINIMAL_POLICY: dict = {
    "identity_required_fields": ["user_id", "agent_id", "roles"],
    "allowed_tools": ["search_tool", "deploy_tool"],
    "rate_limit_per_session": 50,
    "tools": {
        "search_tool": {
            "tool_name": "search_tool",
            "allowed_functions": ["query"],
        },
        "deploy_tool": {
            "tool_name": "deploy_tool",
            "allowed_functions": ["deploy"],
            "visible_to_roles": ["ProductionAdmin"],
            "requires_approval_functions": ["deploy"],
        },
    },
}


@pytest.fixture
def policy_store() -> InMemoryPolicyStore:
    store = InMemoryPolicyStore()
    pv = store.create("test", MINIMAL_POLICY, metadata={"fixture": True})
    store.promote(pv.id)
    return store


@pytest.fixture
def metrics() -> SidecarMetrics:
    return SidecarMetrics()


@pytest.fixture
def approval_queue() -> InMemoryApprovalQueue:
    return InMemoryApprovalQueue(default=False)


@pytest.fixture
def app(policy_store, metrics, approval_queue, tmp_path):
    return create_app(
        policy_store=policy_store,
        metrics=metrics,
        approval_queue=approval_queue,
        demo_mode=False,
        valid_bearer_tokens={TEST_TOKEN},
        audit_path=tmp_path / "audit.jsonl",
        seed_default_policy=False,
    )


@pytest.fixture
def auth_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {TEST_TOKEN}"}
