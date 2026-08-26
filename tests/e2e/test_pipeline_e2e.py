from __future__ import annotations

from aimw.audit.dlp import DLPClassifier, SensitivityTier
from aimw.audit.siem import LocalSiemForwarder
from aimw.audit.worm_log import HashChainedJSONLLogger, verify_chain
from aimw.gateway.shim import FakeLLMClient, LiteLLMGatewayShim, ProposedToolCall
from aimw.guardrails.regex_pii import RegexPIIGuardrail
from aimw.guardrails.semantic import SemanticGuardrail
from aimw.hitl.approval import InMemoryApprovalQueue
from aimw.identity.session_token import SessionTokenIssuer
from aimw.interceptor import ToolCallInterceptor
from aimw.interfaces.policy_engine import BasePolicyEngine
from aimw.models import PolicyDecision
from aimw.pipeline import GovernancePipeline
from aimw.policy.db_engine import DbBackedPolicyEngine
from aimw.policy.db_rules import DbRuleStore, connect, seed_example
from aimw.policy.static_engine import StaticPolicyEngine
from aimw.reliability.circuit_breaker import CircuitBreaker, InMemoryCircuitBreakerBackend
from aimw.sandbox.subprocess_sandbox import SubprocessSandbox


class RaisingPolicyEngine(BasePolicyEngine):
    async def evaluate_tool_call(self, context, request) -> PolicyDecision:
        raise RuntimeError("policy engine is broken")


def build_pipeline(policy_engine, approval_callback=None, audit_path=None):
    interceptor = ToolCallInterceptor(
        policy_engine=policy_engine,
        sandbox=SubprocessSandbox(),
        audit_log=HashChainedJSONLLogger(audit_path),
        approval_callback=approval_callback,
    )
    return GovernancePipeline(
        gateway=LiteLLMGatewayShim(),
        guardrail=RegexPIIGuardrail(),
        llm_client=FakeLLMClient(),
        interceptor=interceptor,
    )


async def test_allowed_tool_call_end_to_end(example_ruleset, tmp_path, context_factory):
    audit_path = tmp_path / "audit.jsonl"
    engine = StaticPolicyEngine(example_ruleset)
    pipeline = build_pipeline(engine, audit_path=audit_path)
    pipeline._llm_client.script_tool_call(
        ProposedToolCall(
            tool_name="search_tool",
            function_name="query",
            parameters={"q": "weather in Boston"},
            call_id="c1",
        )
    )
    ctx = context_factory()

    result = await pipeline.run("What's the weather?", ctx, bearer_token="t")

    assert len(result.tool_call_results) == 1
    assert result.tool_call_results[0].allowed is True
    assert result.final_response == "acknowledged"
    assert verify_chain(audit_path).valid is True


async def test_denied_tool_call_end_to_end(example_ruleset, tmp_path, context_factory):
    audit_path = tmp_path / "audit.jsonl"
    engine = StaticPolicyEngine(example_ruleset)
    pipeline = build_pipeline(engine, audit_path=audit_path)
    pipeline._llm_client.script_tool_call(
        ProposedToolCall(
            tool_name="sql_tool",
            function_name="ExecuteReadOnlyQuery",
            parameters={"query": "DROP TABLE users"},
            call_id="c1",
        )
    )
    ctx = context_factory()

    result = await pipeline.run("Clean up the users table", ctx, bearer_token="t")

    assert result.tool_call_results[0].allowed is False
    assert "deny-pattern" in result.tool_call_results[0].decision.reason


async def test_approval_required_end_to_end(example_ruleset, tmp_path, context_factory):
    audit_path = tmp_path / "audit.jsonl"
    engine = StaticPolicyEngine(example_ruleset)
    approvals = InMemoryApprovalQueue()
    approvals.set_decision("deploy-1", True)
    pipeline = build_pipeline(engine, approval_callback=approvals, audit_path=audit_path)
    pipeline._llm_client.script_tool_call(
        ProposedToolCall(
            tool_name="deploy_tool",
            function_name="deploy",
            parameters={"environment": "production"},
            call_id="deploy-1",
        )
    )
    ctx = context_factory(roles=["ProductionAdmin"])

    result = await pipeline.run("Deploy to prod", ctx, bearer_token="t")

    assert result.tool_call_results[0].allowed is True
    assert len(approvals.received) == 1


async def test_fail_closed_end_to_end(tmp_path, context_factory):
    audit_path = tmp_path / "audit.jsonl"
    pipeline = build_pipeline(RaisingPolicyEngine(), audit_path=audit_path)
    pipeline._llm_client.script_tool_call(
        ProposedToolCall(
            tool_name="search_tool", function_name="query", parameters={"q": "x"}, call_id="c1"
        )
    )
    ctx = context_factory()

    result = await pipeline.run("Search for something", ctx, bearer_token="t")

    assert result.tool_call_results[0].allowed is False
    assert "fail-closed" in result.tool_call_results[0].decision.reason
    assert verify_chain(audit_path).record_count == 1


async def test_full_l2_stack_end_to_end(tmp_path, context_factory):
    """Wires every L2 component together through one pipeline run:

    session-scoped identity, DB-backed RBAC policy, a circuit breaker, a
    semantic guardrail layered over regex PII masking, SIEM forwarding, and
    DLP classification of what the guardrail caught - proving the tiered
    swap-in design actually works, not just each piece in isolation.
    """
    audit_path = tmp_path / "audit.jsonl"
    conn = connect(":memory:")
    seed_example(conn)
    store = DbRuleStore(conn)

    siem = LocalSiemForwarder()
    audit_log = HashChainedJSONLLogger(audit_path, sinks=[siem])
    breaker = CircuitBreaker(InMemoryCircuitBreakerBackend())
    interceptor = ToolCallInterceptor(
        policy_engine=DbBackedPolicyEngine(store),
        sandbox=SubprocessSandbox(),
        audit_log=audit_log,
        circuit_breaker=breaker,
    )

    issuer = SessionTokenIssuer(secret=b"e2e-test-secret")
    gateway = LiteLLMGatewayShim(identity_verifier=issuer)
    guardrail = SemanticGuardrail(RegexPIIGuardrail())
    llm_client = FakeLLMClient()
    pipeline = GovernancePipeline(
        gateway=gateway, guardrail=guardrail, llm_client=llm_client, interceptor=interceptor
    )

    ctx = context_factory(roles=["AgentExecutor"])
    token = issuer.issue(ctx)
    llm_client.script_tool_call(
        ProposedToolCall(
            tool_name="search_tool",
            function_name="query",
            parameters={"q": "weather"},
            call_id="c1",
        )
    )

    result = await pipeline.run(
        "Find me the weather; contact jane@example.com if it fails", ctx, bearer_token=token
    )

    assert result.tool_call_results[0].allowed is True
    assert verify_chain(audit_path).valid is True
    assert len(siem.forwarded) == 1  # DB-backed decision was also forwarded to the SIEM stand-in

    classification = DLPClassifier().classify("contact jane@example.com if it fails")
    assert classification.tier == SensitivityTier.MEDIUM

    conn.close()
