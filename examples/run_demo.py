"""Runnable, no-external-services proof of the governance pipeline.

Walks through the Section 12.2 request flow end-to-end using nothing but
local stand-ins: an allowed tool call, a denied call (SQL deny-pattern
match), an approval-required call (shown both approved and denied), then
prints the full audit trail, verifies its hash chain, tampers with one byte
on disk, and re-verifies to demonstrate the tamper-evidence guarantee.

Run with:  python examples/run_demo.py
Requires no accounts, no API keys, no network access, and no Docker daemon.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

from aimw.audit.worm_log import verify_chain
from aimw.config import Settings
from aimw.factory import make_audit_log, make_sandbox
from aimw.gateway.shim import FakeLLMClient, LiteLLMGatewayShim, ProposedToolCall
from aimw.guardrails.regex_pii import RegexPIIGuardrail
from aimw.hitl.approval import InMemoryApprovalQueue
from aimw.identity.static_bearer import StaticBearerTokenVerifier
from aimw.interceptor import ToolCallInterceptor
from aimw.models import ExecutionContext
from aimw.pipeline import GovernancePipeline
from aimw.policy.rules import load_ruleset
from aimw.policy.static_engine import StaticPolicyEngine

POLICY_PATH = Path(__file__).parent.parent / "configs" / "policy.example.yaml"


def banner(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def show_result(label: str, result) -> None:
    for r in result.tool_call_results:
        print(f"  [{label}] allowed={r.allowed}  reason={r.decision.reason}")
        if r.sandbox_result is not None:
            print(f"           sandbox stdout: {r.sandbox_result.stdout}")


async def main() -> None:
    settings = Settings()
    audit_dir = Path(tempfile.mkdtemp(prefix="aimw_demo_"))
    audit_path = audit_dir / "audit.jsonl"
    print(f"Audit log: {audit_path}")

    ruleset = load_ruleset(POLICY_PATH)
    audit_log = make_audit_log(audit_path, settings)
    approvals = InMemoryApprovalQueue()

    def make_pipeline() -> GovernancePipeline:
        interceptor = ToolCallInterceptor(
            policy_engine=StaticPolicyEngine(ruleset),
            sandbox=make_sandbox(settings),
            audit_log=audit_log,
            approval_callback=approvals,
        )
        return GovernancePipeline(
            gateway=LiteLLMGatewayShim(
                identity_verifier=StaticBearerTokenVerifier(allow_unconfigured=True)
            ),
            guardrail=RegexPIIGuardrail(),
            llm_client=FakeLLMClient(),
            interceptor=interceptor,
        )

    analyst_ctx = ExecutionContext(
        user_id="user-jane",
        agent_id="agent-research",
        session_id="session-1",
        roles=["AgentExecutor"],
        delegated_scopes=[],
        metadata={},
    )
    admin_ctx = ExecutionContext(
        user_id="user-jane",
        agent_id="agent-ops",
        session_id="session-2",
        roles=["AgentExecutor", "ProductionAdmin"],
        delegated_scopes=[],
        metadata={},
    )

    # 1. Allowed call.
    banner("1. ALLOWED CALL - search_tool.query")
    pipeline = make_pipeline()
    pipeline._llm_client.script_tool_call(
        ProposedToolCall(
            tool_name="search_tool",
            function_name="query",
            parameters={"q": "weather in Boston"},
            call_id="demo-search-1",
        )
    )
    result = await pipeline.run("What's the weather in Boston?", analyst_ctx, bearer_token="t")
    show_result("allowed", result)

    # 2. Denied call - SQL deny-pattern match.
    banner("2. DENIED CALL - sql_tool.ExecuteReadOnlyQuery with DROP TABLE")
    pipeline = make_pipeline()
    pipeline._llm_client.script_tool_call(
        ProposedToolCall(
            tool_name="sql_tool",
            function_name="ExecuteReadOnlyQuery",
            parameters={"query": "DROP TABLE users"},
            call_id="demo-sql-1",
        )
    )
    result = await pipeline.run("Clean up the users table", analyst_ctx, bearer_token="t")
    show_result("denied", result)

    # 3a. Approval-required call - approved.
    banner("3a. APPROVAL-REQUIRED CALL, APPROVED - deploy_tool.deploy")
    approvals.set_decision("demo-deploy-approved", True)
    pipeline = make_pipeline()
    pipeline._llm_client.script_tool_call(
        ProposedToolCall(
            tool_name="deploy_tool",
            function_name="deploy",
            parameters={"environment": "production", "version": "v2.3.1"},
            call_id="demo-deploy-approved",
        )
    )
    result = await pipeline.run("Deploy v2.3.1 to production", admin_ctx, bearer_token="t")
    show_result("approved", result)
    raw_seen = approvals.received[-1][1]
    print(f"  Human reviewer saw the RAW payload: {raw_seen.parameters}")

    # 3b. Approval-required call - denied by the human reviewer.
    banner("3b. APPROVAL-REQUIRED CALL, DENIED - deploy_tool.deploy")
    approvals.set_decision("demo-deploy-denied", False)
    pipeline = make_pipeline()
    pipeline._llm_client.script_tool_call(
        ProposedToolCall(
            tool_name="deploy_tool",
            function_name="deploy",
            parameters={"environment": "production", "version": "v9.9.9-risky"},
            call_id="demo-deploy-denied",
        )
    )
    result = await pipeline.run("Deploy v9.9.9-risky to production", admin_ctx, bearer_token="t")
    show_result("denied-by-human", result)

    # 4. Audit trail + tamper-evidence demonstration.
    banner("4. AUDIT TRAIL + TAMPER-EVIDENCE CHECK")
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    print(f"  {len(lines)} audit records written to {audit_path}")
    before = verify_chain(audit_path)
    print(f"  verify_chain() before tampering: valid={before.valid} records={before.record_count}")

    print("  Tampering with record index 1 on disk (flipping its decision outcome)...")
    tampered_lines = list(lines)
    record = json.loads(tampered_lines[1])
    record["decision"]["allowed"] = not record["decision"]["allowed"]
    tampered_lines[1] = json.dumps(record)
    audit_path.write_text("\n".join(tampered_lines) + "\n", encoding="utf-8")

    after = verify_chain(audit_path)
    print(
        f"  verify_chain() after tampering:  valid={after.valid}  "
        f"first_broken_index={after.first_broken_index}"
    )
    assert before.valid is True
    assert after.valid is False
    print("\nTamper-evidence confirmed: the hash chain detected the modification.")


if __name__ == "__main__":
    asyncio.run(main())
