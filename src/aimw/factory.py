"""Small Settings-backed constructors for sandbox + audit wiring.

GovernancePipeline still takes already-built collaborators; these helpers
are the thin Settings → component bridge used by demos (and any caller that
wants env-driven defaults without hand-wiring).
"""

from __future__ import annotations

from pathlib import Path

from aimw.audit.siem import BaseAuditSink
from aimw.audit.worm_log import HashChainedJSONLLogger
from aimw.config import Settings
from aimw.sandbox.base import BaseSandbox
from aimw.sandbox.docker_sandbox import DockerSandbox
from aimw.sandbox.subprocess_sandbox import SubprocessSandbox


def make_sandbox(
    settings: Settings | None = None,
    *,
    allowed_commands: frozenset[str] | set[str] | None = None,
    allow_unlisted: bool = False,
) -> BaseSandbox:
    """Select sandbox backend from ``Settings.sandbox_mode`` (default: subprocess).

    Docker mode is fail-closed: pass ``allowed_commands`` (argv[0] allowlist)
    or explicitly ``allow_unlisted=True`` for trusted local demos only.
    """
    cfg = settings if settings is not None else Settings()
    mode = cfg.sandbox_mode.strip().lower()
    if mode == "subprocess":
        return SubprocessSandbox(timeout_s=cfg.sandbox_timeout_s)
    if mode == "docker":
        return DockerSandbox(
            timeout_s=cfg.sandbox_timeout_s,
            allowed_commands=allowed_commands,
            allow_unlisted=allow_unlisted,
        )
    raise ValueError(
        f"unsupported sandbox_mode {cfg.sandbox_mode!r}; expected 'subprocess' or 'docker'"
    )


def make_audit_log(
    path: str | Path,
    settings: Settings | None = None,
    sinks: list[BaseAuditSink] | None = None,
) -> HashChainedJSONLLogger:
    """Build a WORM logger honoring ``Settings.redact_audit_parameters`` (default True)."""
    cfg = settings if settings is not None else Settings()
    return HashChainedJSONLLogger(
        path,
        redact_parameters=cfg.redact_audit_parameters,
        sinks=sinks,
    )
