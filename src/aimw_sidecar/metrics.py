"""In-process Prometheus-style counters for the sidecar.

No prometheus-client dependency required for Phase 1 — ``render_prometheus``
emits text exposition format from plain integer counters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock


@dataclass
class SidecarMetrics:
    """Thread-safe counters for govern outcomes."""

    govern_total: int = 0
    allow_total: int = 0
    deny_total: int = 0
    approval_required_total: int = 0
    errors_total: int = 0
    _lock: Lock = field(default_factory=Lock, repr=False, compare=False)

    def inc_govern(self) -> None:
        with self._lock:
            self.govern_total += 1

    def inc_allow(self) -> None:
        with self._lock:
            self.allow_total += 1

    def inc_deny(self) -> None:
        with self._lock:
            self.deny_total += 1

    def inc_approval_required(self) -> None:
        with self._lock:
            self.approval_required_total += 1

    def inc_errors(self) -> None:
        with self._lock:
            self.errors_total += 1

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "govern_total": self.govern_total,
                "allow_total": self.allow_total,
                "deny_total": self.deny_total,
                "approval_required_total": self.approval_required_total,
                "errors_total": self.errors_total,
            }

    def render_prometheus(self) -> str:
        """Return Prometheus text exposition for GET /metrics."""
        snap = self.snapshot()
        lines: list[str] = [
            "# HELP aimw_govern_total Total POST /v1/govern requests handled",
            "# TYPE aimw_govern_total counter",
            f"aimw_govern_total {snap['govern_total']}",
            "# HELP aimw_allow_total Tool calls allowed by policy (+ sandbox)",
            "# TYPE aimw_allow_total counter",
            f"aimw_allow_total {snap['allow_total']}",
            "# HELP aimw_deny_total Tool calls denied (policy, HITL, or fail-closed)",
            "# TYPE aimw_deny_total counter",
            f"aimw_deny_total {snap['deny_total']}",
            "# HELP aimw_approval_required_total Calls that touched HITL approval path",
            "# TYPE aimw_approval_required_total counter",
            f"aimw_approval_required_total {snap['approval_required_total']}",
            "# HELP aimw_errors_total Unhandled errors during /v1/govern",
            "# TYPE aimw_errors_total counter",
            f"aimw_errors_total {snap['errors_total']}",
        ]
        return "\n".join(lines) + "\n"


# Module-level default used when create_app does not inject a metrics instance.
default_metrics = SidecarMetrics()


def render_prometheus(metrics: SidecarMetrics | None = None) -> str:
    """Convenience wrapper matching the Phase 1 contract name."""
    return (metrics or default_metrics).render_prometheus()
