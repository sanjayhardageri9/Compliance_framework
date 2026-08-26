from __future__ import annotations

import json

from aimw.audit.worm_log import HashChainedJSONLLogger, verify_chain
from aimw.models import PolicyDecision, ToolRequest


def _req(call_id: str) -> ToolRequest:
    return ToolRequest(
        tool_name="search_tool", function_name="query", parameters={"q": "x"}, call_id=call_id
    )


def test_verify_chain_on_missing_or_empty_file_is_trivially_valid(tmp_path):
    path = tmp_path / "audit.jsonl"
    result = verify_chain(path)
    assert result.valid is True
    assert result.record_count == 0


def test_append_and_verify_chain_valid(tmp_path, context_factory):
    path = tmp_path / "audit.jsonl"
    logger = HashChainedJSONLLogger(path)
    ctx = context_factory()
    for i in range(5):
        logger.log_call(ctx, _req(f"call-{i}"), PolicyDecision(allowed=True, reason="ok"))

    result = verify_chain(path)
    assert result.valid is True
    assert result.record_count == 5


def test_tampering_is_detected_at_correct_index(tmp_path, context_factory):
    path = tmp_path / "audit.jsonl"
    logger = HashChainedJSONLLogger(path)
    ctx = context_factory()
    for i in range(4):
        logger.log_call(ctx, _req(f"call-{i}"), PolicyDecision(allowed=True, reason="ok"))

    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[2])
    tampered["decision"]["allowed"] = False
    lines[2] = json.dumps(tampered)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_chain(path)
    assert result.valid is False
    assert result.first_broken_index == 2


def test_redact_parameters_hashes_values_by_default(tmp_path, context_factory):
    path = tmp_path / "audit.jsonl"
    logger = HashChainedJSONLLogger(path, redact_parameters=True)
    ctx = context_factory()
    record = logger.log_call(
        ctx,
        ToolRequest(
            tool_name="sql_tool",
            function_name="ExecuteReadOnlyQuery",
            parameters={"query": "SELECT * FROM secret_table"},
            call_id="call-1",
        ),
        PolicyDecision(allowed=True, reason="ok"),
    )
    assert record.request.parameters["query"] != "SELECT * FROM secret_table"
    assert len(record.request.parameters["query"]) == 64  # sha256 hex digest length


def test_redact_parameters_disabled_stores_raw_values(tmp_path, context_factory):
    path = tmp_path / "audit.jsonl"
    logger = HashChainedJSONLLogger(path, redact_parameters=False)
    ctx = context_factory()
    record = logger.log_call(ctx, _req("call-1"), PolicyDecision(allowed=True, reason="ok"))
    assert record.request.parameters["q"] == "x"


def test_new_logger_instance_continues_existing_chain(tmp_path, context_factory):
    path = tmp_path / "audit.jsonl"
    ctx = context_factory()
    logger1 = HashChainedJSONLLogger(path)
    logger1.log_call(ctx, _req("call-1"), PolicyDecision(allowed=True, reason="ok"))

    logger2 = HashChainedJSONLLogger(path)
    logger2.log_call(ctx, _req("call-2"), PolicyDecision(allowed=True, reason="ok"))

    result = verify_chain(path)
    assert result.valid is True
    assert result.record_count == 2
