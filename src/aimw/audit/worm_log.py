"""Hash-chained, append-only JSONL audit logger.

This is the L1 stand-in for a real WORM (write-once-read-many) store. It
*detects* tampering after the fact via a hash chain that a completely
separate process can verify without trusting the writer's code path - it
does NOT *prevent* tampering the way OS/storage-level immutability would
(chattr +a, S3 Object Lock, Azure immutable blobs). That upgrade is an
explicit L2/L3 concern; do not present this as tamper-proof, only
tamper-evident.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aimw.audit.models import AuditRecord, RedactedContext, RedactedRequest
from aimw.audit.siem import BaseAuditSink, forward_best_effort
from aimw.models import ExecutionContext, PolicyDecision, ToolRequest

GENESIS_HASH = "0" * 64


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hash_value(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _compute_record_hash(prev_hash: str, record: AuditRecord) -> str:
    payload = record.model_dump(exclude={"record_hash"})
    return hashlib.sha256(prev_hash.encode("utf-8") + _canonical_bytes(payload)).hexdigest()


@dataclass
class ChainVerificationResult:
    valid: bool
    record_count: int
    first_broken_index: int | None = None


def verify_chain(path: str | Path) -> ChainVerificationResult:
    """Replay a log file and confirm every record's hash matches its content.

    Pure function over the file on disk - does not depend on any logger
    instance, so an independent auditor can validate a log it didn't write.
    """
    file_path = Path(path)
    if not file_path.exists() or file_path.stat().st_size == 0:
        return ChainVerificationResult(valid=True, record_count=0)

    prev_hash = GENESIS_HASH
    count = 0
    with file_path.open("r", encoding="utf-8") as f:
        for index, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            record = AuditRecord.model_validate_json(line)
            expected_hash = _compute_record_hash(prev_hash, record)
            if record.prev_hash != prev_hash or record.record_hash != expected_hash:
                return ChainVerificationResult(
                    valid=False, record_count=count, first_broken_index=index
                )
            prev_hash = record.record_hash
            count += 1
    return ChainVerificationResult(valid=True, record_count=count)


class HashChainedJSONLLogger:
    """Append-only, hash-chained JSONL audit log."""

    def __init__(
        self,
        path: str | Path,
        redact_parameters: bool = True,
        sinks: list[BaseAuditSink] | None = None,
    ) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._redact_parameters = redact_parameters
        self._sinks = sinks or []
        self._prev_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self._path.exists() or self._path.stat().st_size == 0:
            return GENESIS_HASH
        last_hash = GENESIS_HASH
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_hash = AuditRecord.model_validate_json(line).record_hash
        return last_hash

    def _redact_request(self, request: ToolRequest) -> RedactedRequest:
        if self._redact_parameters:
            params = {k: _hash_value(v) for k, v in request.parameters.items()}
        else:
            params = {k: str(v) for k, v in request.parameters.items()}
        return RedactedRequest(
            tool_name=request.tool_name,
            function_name=request.function_name,
            call_id=request.call_id,
            parameters=params,
        )

    def append(self, record: AuditRecord) -> AuditRecord:
        """Write a fully-formed record, computing prev_hash/record_hash for it."""
        record = record.model_copy(update={"prev_hash": self._prev_hash})
        record_hash = _compute_record_hash(self._prev_hash, record)
        record = record.model_copy(update={"record_hash": record_hash})
        with self._path.open("a", encoding="utf-8") as f:
            f.write(record.model_dump_json() + "\n")
        self._prev_hash = record_hash
        if self._sinks:
            forward_best_effort(self._sinks, record)
        return record

    def log_call(
        self,
        context: ExecutionContext,
        request: ToolRequest,
        decision: PolicyDecision,
        sandbox_result: dict[str, Any] | None = None,
    ) -> AuditRecord:
        """Convenience entrypoint: build a redacted AuditRecord and append it."""
        record = AuditRecord(
            record_id=str(uuid.uuid4()),
            call_id=request.call_id,
            context=RedactedContext(
                user_id=context.user_id,
                agent_id=context.agent_id,
                session_id=context.session_id,
                roles=list(context.roles),
            ),
            request=self._redact_request(request),
            decision=decision.model_dump(),
            sandbox_result=sandbox_result,
            prev_hash=GENESIS_HASH,  # overwritten by append()
        )
        return self.append(record)

    def verify(self) -> ChainVerificationResult:
        return verify_chain(self._path)
