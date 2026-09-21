"""Factory wiring Settings + active policy into a live GovernancePipeline.

Fail-closed identity
--------------------
``StaticBearerTokenVerifier`` is constructed with ``allow_unconfigured=False``
unless ``demo_mode=True`` (or env ``AIMW_SIDECAR_DEMO_MODE`` truthy). Production
callers should pass a non-empty ``valid_bearer_tokens`` set (or
``AIMW_SIDECAR_BEARER_TOKENS`` comma-separated).
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any

from aimw.config import Settings
from aimw.factory import make_audit_log, make_sandbox
from aimw.gateway.shim import FakeLLMClient, LiteLLMGatewayShim
from aimw.guardrails.regex_pii import RegexPIIGuardrail
from aimw.hitl.approval import InMemoryApprovalQueue
from aimw.identity.base import BaseIdentityVerifier
from aimw.identity.static_bearer import StaticBearerTokenVerifier
from aimw.interceptor import InterceptorResult, ToolCallInterceptor
from aimw.pipeline import GovernancePipeline
from aimw.policy.rules import PolicyRuleSet, load_ruleset
from aimw.policy.static_engine import StaticPolicyEngine

from aimw_sidecar.metrics import SidecarMetrics
from aimw_sidecar.policy_store import InMemoryPolicyStore, PolicyVersion


def _env_truthy(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _tokens_from_env() -> set[str]:
    raw = os.environ.get("AIMW_SIDECAR_BEARER_TOKENS", "")
    return {t.strip() for t in raw.split(",") if t.strip()}


@dataclass
class DecisionLogEntry:
    """Best-effort in-memory explain payload keyed by tool call_id."""

    call_id: str
    allowed: bool
    reason: str
    tool_name: str
    function_name: str
    action_requirements: list[str]
    sandbox_stdout: str | None = None
    audit_record_id: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class SidecarRuntime:
    """Shared mutable state for the FastAPI app lifecycle."""

    settings: Settings
    policy_store: InMemoryPolicyStore
    approval_queue: InMemoryApprovalQueue
    metrics: SidecarMetrics
    identity: BaseIdentityVerifier
    demo_mode: bool
    audit_path: Path
    audit_log: Any
    llm_client: FakeLLMClient
    pipeline: GovernancePipeline
    decision_log: dict[str, DecisionLogEntry] = field(default_factory=dict)
    in_memory_audit: list[dict[str, Any]] = field(default_factory=list)
    _lock: RLock = field(default_factory=RLock, repr=False)

    def rebuild_pipeline(self, ruleset: PolicyRuleSet | None = None) -> GovernancePipeline:
        """Rebuild pipeline using active (or provided) policy ruleset."""
        with self._lock:
            active = self.policy_store.get_active()
            if ruleset is None:
                if active is not None:
                    ruleset = active.ruleset
                else:
                    ruleset = self._default_ruleset()
            interceptor = ToolCallInterceptor(
                policy_engine=StaticPolicyEngine(ruleset),
                sandbox=make_sandbox(self.settings),
                audit_log=self.audit_log,
                approval_callback=self.approval_queue,
                decision_timeout_s=self.settings.decision_timeout_s,
            )
            self.pipeline = GovernancePipeline(
                gateway=LiteLLMGatewayShim(identity_verifier=self.identity),
                guardrail=RegexPIIGuardrail(),
                llm_client=self.llm_client,
                interceptor=interceptor,
            )
            return self.pipeline

    def _default_ruleset(self) -> PolicyRuleSet:
        path = self.settings.policy_path
        if path.is_file():
            return load_ruleset(path)
        # Minimal allow-list so hermetic demos work without a checked-in path.
        return PolicyRuleSet.model_validate(
            {
                "identity_required_fields": ["user_id", "agent_id", "roles"],
                "allowed_tools": ["search_tool"],
                "rate_limit_per_session": 50,
                "tools": {
                    "search_tool": {
                        "tool_name": "search_tool",
                        "allowed_functions": ["query"],
                    }
                },
            }
        )

    def record_interceptor_results(self, results: list[InterceptorResult]) -> None:
        for result in results:
            call_id = result.audit_record.call_id
            entry = DecisionLogEntry(
                call_id=call_id,
                allowed=result.allowed,
                reason=result.decision.reason,
                tool_name=result.audit_record.request.tool_name,
                function_name=result.audit_record.request.function_name,
                action_requirements=list(result.decision.action_requirements),
                sandbox_stdout=(
                    result.sandbox_result.stdout if result.sandbox_result is not None else None
                ),
                audit_record_id=result.audit_record.record_id,
                raw={
                    "decision": result.decision.model_dump(),
                    "audit": result.audit_record.model_dump(),
                },
            )
            self.decision_log[call_id] = entry
            self.in_memory_audit.append(result.audit_record.model_dump())

            reason_l = result.decision.reason.lower()
            hit_approval = (
                "approval" in reason_l
                or "human-approved" in reason_l
                or "human_approval" in result.decision.action_requirements
            )
            if hit_approval:
                self.metrics.inc_approval_required()
            if result.allowed:
                self.metrics.inc_allow()
            else:
                self.metrics.inc_deny()

    def recent_audit(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Merge in-memory records with a best-effort tail of the audit file."""
        records = list(self.in_memory_audit)
        if self.audit_path.is_file():
            try:
                lines = self.audit_path.read_text(encoding="utf-8").splitlines()
                file_recs: list[dict[str, Any]] = []
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    import json

                    file_recs.append(json.loads(line))
                # Prefer file (authoritative) when present; fall back to memory.
                if file_recs:
                    records = file_recs
            except OSError:
                pass
        return records[-limit:]


def build_identity(
    *,
    demo_mode: bool,
    valid_bearer_tokens: set[str] | None,
) -> BaseIdentityVerifier:
    """Construct fail-closed StaticBearerTokenVerifier (demo opt-in only)."""
    tokens = set(valid_bearer_tokens) if valid_bearer_tokens is not None else _tokens_from_env()
    if tokens:
        return StaticBearerTokenVerifier(tokens, allow_unconfigured=False)
    if demo_mode:
        # Explicit demo/local opt-in — documented in IMPLEMENTATION.md.
        return StaticBearerTokenVerifier(allow_unconfigured=True)
    # Fail closed: empty allow-set rejects all credentials.
    return StaticBearerTokenVerifier(allow_unconfigured=False)


def build_runtime(
    *,
    settings: Settings | None = None,
    policy_store: InMemoryPolicyStore | None = None,
    approval_queue: InMemoryApprovalQueue | None = None,
    metrics: SidecarMetrics | None = None,
    demo_mode: bool | None = None,
    valid_bearer_tokens: set[str] | None = None,
    audit_path: Path | str | None = None,
    seed_default_policy: bool = True,
) -> SidecarRuntime:
    """Wire Settings + policy store + HITL queue into a SidecarRuntime."""
    cfg = settings if settings is not None else Settings()
    demo = _env_truthy("AIMW_SIDECAR_DEMO_MODE") if demo_mode is None else demo_mode
    store = policy_store or InMemoryPolicyStore()
    approvals = approval_queue or InMemoryApprovalQueue(default=False)
    mets = metrics or SidecarMetrics()
    identity = build_identity(demo_mode=demo, valid_bearer_tokens=valid_bearer_tokens)

    if audit_path is None:
        audit_dir = Path(tempfile.mkdtemp(prefix="aimw_sidecar_audit_"))
        path = audit_dir / "audit.jsonl"
    else:
        path = Path(audit_path)
    audit_log = make_audit_log(path, cfg)
    llm = FakeLLMClient()

    runtime = SidecarRuntime(
        settings=cfg,
        policy_store=store,
        approval_queue=approvals,
        metrics=mets,
        identity=identity,
        demo_mode=demo,
        audit_path=path,
        audit_log=audit_log,
        llm_client=llm,
        pipeline=None,  # type: ignore[arg-type]  # set below
    )

    if seed_default_policy and store.get_active() is None:
        try:
            default_path = cfg.policy_path
            if default_path.is_file():
                raw = default_path.read_text(encoding="utf-8")
                pv = store.create("default", raw, metadata={"source": str(default_path)})
                store.promote(pv.id)
        except Exception:  # noqa: BLE001 - seed is best-effort
            pass

    runtime.rebuild_pipeline()
    return runtime


def on_policy_promoted(runtime: SidecarRuntime, _pv: PolicyVersion) -> None:
    """Hook: rebuild pipeline after promote so govern uses the new ruleset."""
    runtime.rebuild_pipeline()
