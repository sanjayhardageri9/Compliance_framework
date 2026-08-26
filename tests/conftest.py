from __future__ import annotations

from pathlib import Path

import pytest

from aimw.models import ExecutionContext
from aimw.policy.db_rules import DbRuleStore, connect, seed_example
from aimw.policy.rules import PolicyRuleSet, load_ruleset

EXAMPLE_POLICY_PATH = Path(__file__).parent.parent / "configs" / "policy.example.yaml"


@pytest.fixture
def example_ruleset() -> PolicyRuleSet:
    return load_ruleset(EXAMPLE_POLICY_PATH)


def make_context(
    user_id: str = "user-1",
    agent_id: str = "agent-1",
    session_id: str = "session-1",
    roles: list[str] | None = None,
    delegated_scopes: list[str] | None = None,
    metadata: dict[str, object] | None = None,
) -> ExecutionContext:
    return ExecutionContext(
        user_id=user_id,
        agent_id=agent_id,
        session_id=session_id,
        roles=roles if roles is not None else ["AgentExecutor"],
        delegated_scopes=delegated_scopes if delegated_scopes is not None else [],
        metadata=metadata if metadata is not None else {},
    )


@pytest.fixture
def context_factory():
    return make_context


@pytest.fixture
def db_store():
    """In-memory SQLite rule store, seeded with the same example data as the YAML fixture."""
    conn = connect(":memory:")
    seed_example(conn)
    try:
        yield DbRuleStore(conn)
    finally:
        conn.close()
