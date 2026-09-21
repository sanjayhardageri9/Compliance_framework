"""Unit tests for InMemoryPolicyStore."""

from __future__ import annotations

import pytest

from aimw.policy.rules import PolicyRuleSet

from aimw_sidecar.policy_store import InMemoryPolicyStore

MINIMAL = {
    "identity_required_fields": ["user_id", "agent_id", "roles"],
    "allowed_tools": ["search_tool"],
    "rate_limit_per_session": 10,
    "tools": {
        "search_tool": {
            "tool_name": "search_tool",
            "allowed_functions": ["query"],
        }
    },
}


def test_create_bumps_version_and_draft_status() -> None:
    store = InMemoryPolicyStore()
    a = store.create("p", MINIMAL)
    b = store.create("p", MINIMAL)
    assert a.version == 1
    assert b.version == 2
    assert a.status == "draft"
    assert b.status == "draft"
    assert isinstance(a.ruleset, PolicyRuleSet)


def test_promote_sets_active_and_supersedes() -> None:
    store = InMemoryPolicyStore()
    a = store.create("p", MINIMAL)
    b = store.create("p", MINIMAL)
    store.promote(a.id)
    assert store.get_active() is not None
    assert store.get_active().id == a.id  # type: ignore[union-attr]
    store.promote(b.id)
    assert store.get(a.id).status == "superseded"  # type: ignore[union-attr]
    assert store.get_active().id == b.id  # type: ignore[union-attr]


def test_create_from_yaml_string() -> None:
    store = InMemoryPolicyStore()
    yaml_text = """
identity_required_fields: [user_id, agent_id, roles]
allowed_tools: [search_tool]
rate_limit_per_session: 5
tools:
  search_tool:
    tool_name: search_tool
    allowed_functions: [query]
"""
    pv = store.create("yaml-pol", yaml_text)
    assert "search_tool" in pv.ruleset.allowed_tools


def test_create_rejects_invalid_body() -> None:
    store = InMemoryPolicyStore()
    with pytest.raises(Exception):
        store.create("bad", {"not": "a valid ruleset"})
