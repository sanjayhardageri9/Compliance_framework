"""L2 audit forwarding: 'centralized SIEM' stand-in (Section 13's "Audit" row).

L1's audit story ends at a local hash-chained file. L2 additionally
forwards each record to a centralized sink - Datadog/Elastic in the
document's terms. BaseAuditSink is the extension point; LocalSiemForwarder
is the hermetic stand-in used here (an in-memory/local collector standing
in for a real SIEM ingest endpoint). A real HTTP-backed forwarder is a
straightforward subclass and is explicitly out of scope for this build
(see README) since it would require a live endpoint/credentials.

Forwarding is best-effort: a sink failure is logged and swallowed, never
allowed to break the authoritative local WORM write that already
succeeded.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from aimw.audit.models import AuditRecord

logger = logging.getLogger(__name__)


class BaseAuditSink(ABC):
    """A centralized destination an audit record is additionally forwarded to."""

    @abstractmethod
    def forward(self, record: AuditRecord) -> None: ...


class LocalSiemForwarder(BaseAuditSink):
    """Hermetic stand-in for a centralized SIEM: keeps forwarded records in memory."""

    def __init__(self) -> None:
        self.forwarded: list[AuditRecord] = []

    def forward(self, record: AuditRecord) -> None:
        self.forwarded.append(record)


def forward_best_effort(sinks: list[BaseAuditSink], record: AuditRecord) -> None:
    for sink in sinks:
        try:
            sink.forward(record)
        except Exception:  # noqa: BLE001 - forwarding must never break the local write
            logger.exception(
                "audit sink %s failed to forward record %s", type(sink).__name__, record.record_id
            )
