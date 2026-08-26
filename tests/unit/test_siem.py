from __future__ import annotations

from aimw.audit.models import AuditRecord, RedactedContext, RedactedRequest
from aimw.audit.siem import BaseAuditSink, LocalSiemForwarder, forward_best_effort
from aimw.audit.worm_log import GENESIS_HASH, HashChainedJSONLLogger
from aimw.models import PolicyDecision, ToolRequest


def _record() -> AuditRecord:
    return AuditRecord(
        record_id="r1",
        call_id="c1",
        context=RedactedContext(user_id="u1", agent_id="a1", session_id="s1", roles=["r"]),
        request=RedactedRequest(tool_name="t", function_name="f", call_id="c1", parameters={}),
        decision={"allowed": True, "reason": "ok"},
        prev_hash=GENESIS_HASH,
    )


class RaisingSink(BaseAuditSink):
    def forward(self, record: AuditRecord) -> None:
        raise RuntimeError("sink unreachable")


def test_local_siem_forwarder_collects_records():
    forwarder = LocalSiemForwarder()
    forward_best_effort([forwarder], _record())
    assert len(forwarder.forwarded) == 1
    assert forwarder.forwarded[0].record_id == "r1"


def test_forward_best_effort_swallows_sink_exceptions():
    forwarder = LocalSiemForwarder()
    # RaisingSink must not prevent LocalSiemForwarder from still receiving the record.
    forward_best_effort([RaisingSink(), forwarder], _record())
    assert len(forwarder.forwarded) == 1


def test_logger_forwards_to_configured_sinks(tmp_path, context_factory):
    forwarder = LocalSiemForwarder()
    logger = HashChainedJSONLLogger(tmp_path / "audit.jsonl", sinks=[forwarder])
    ctx = context_factory()
    req = ToolRequest(tool_name="t", function_name="f", parameters={}, call_id="c1")
    logger.log_call(ctx, req, PolicyDecision(allowed=True, reason="ok"))
    assert len(forwarder.forwarded) == 1


def test_logger_with_no_sinks_does_not_forward(tmp_path, context_factory):
    logger = HashChainedJSONLLogger(tmp_path / "audit.jsonl")
    ctx = context_factory()
    req = ToolRequest(tool_name="t", function_name="f", parameters={}, call_id="c1")
    record = logger.log_call(ctx, req, PolicyDecision(allowed=True, reason="ok"))
    assert record.record_id  # just confirms it still works with sinks=None
