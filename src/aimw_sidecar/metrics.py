"""Prometheus-style counter / histogram names for the sidecar.

Concrete registry wiring is deferred until ``aimw[sidecar]`` is installed.
Names are stable contracts for the Phase 1 TEST_PLAN.
"""

from __future__ import annotations

# Counter names (Prometheus snake_case)
GOVERN_REQUESTS_TOTAL = "aimw_govern_requests_total"
GOVERN_DECISIONS_TOTAL = "aimw_govern_decisions_total"  # labels: outcome=allow|deny|hitl|error
POLICY_PROMOTIONS_TOTAL = "aimw_policy_promotions_total"
APPROVALS_RESOLVED_TOTAL = "aimw_approvals_resolved_total"  # labels: resolution=approve|deny
AUTH_FAILURES_TOTAL = "aimw_auth_failures_total"
AUDIT_QUERY_TOTAL = "aimw_audit_query_total"
EXPLAIN_REQUESTS_TOTAL = "aimw_explain_requests_total"

# Histogram / gauge names
GOVERN_LATENCY_SECONDS = "aimw_govern_latency_seconds"
ACTIVE_POLICY_VERSION = "aimw_active_policy_version"
PIPELINE_CIRCUIT_OPEN = "aimw_pipeline_circuit_open"  # gauge 0/1 per agent/tool key

ALL_COUNTER_NAMES: tuple[str, ...] = (
    GOVERN_REQUESTS_TOTAL,
    GOVERN_DECISIONS_TOTAL,
    POLICY_PROMOTIONS_TOTAL,
    APPROVALS_RESOLVED_TOTAL,
    AUTH_FAILURES_TOTAL,
    AUDIT_QUERY_TOTAL,
    EXPLAIN_REQUESTS_TOTAL,
)


def stub_metrics_text() -> str:
    """Minimal exposition text for GET /metrics before real registry exists."""
    lines = [
        "# HELP aimw_govern_requests_total Total govern requests",
        "# TYPE aimw_govern_requests_total counter",
        f"{GOVERN_REQUESTS_TOTAL} 0",
        "# HELP aimw_govern_decisions_total Decisions by outcome",
        "# TYPE aimw_govern_decisions_total counter",
        f'{GOVERN_DECISIONS_TOTAL}{{outcome="allow"}} 0',
        f'{GOVERN_DECISIONS_TOTAL}{{outcome="deny"}} 0',
        f'{GOVERN_DECISIONS_TOTAL}{{outcome="hitl"}} 0',
        f'{GOVERN_DECISIONS_TOTAL}{{outcome="error"}} 0',
    ]
    return "\n".join(lines) + "\n"
