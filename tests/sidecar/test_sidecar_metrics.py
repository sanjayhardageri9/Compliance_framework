"""Unit tests for SidecarMetrics."""

from __future__ import annotations

from aimw_sidecar.metrics import SidecarMetrics, render_prometheus


def test_counters_increment_and_render() -> None:
    m = SidecarMetrics()
    m.inc_govern()
    m.inc_allow()
    m.inc_deny()
    m.inc_approval_required()
    m.inc_errors()
    text = m.render_prometheus()
    assert "aimw_govern_total 1" in text
    assert "aimw_allow_total 1" in text
    assert "aimw_deny_total 1" in text
    assert "aimw_approval_required_total 1" in text
    assert "aimw_errors_total 1" in text
    assert render_prometheus(m) == text
