"""aimw FastAPI sidecar control plane (Phase 1).

Wraps ``GovernancePipeline`` over HTTP. Requires optional extra ``aimw[sidecar]``.

Fail-closed identity: ``StaticBearerTokenVerifier`` rejects empty allow-sets
unless demo mode explicitly opts into ``allow_unconfigured=True`` (see
``runtime.build_runtime`` / ``AIMW_SIDECAR_DEMO_MODE``).
"""

from __future__ import annotations

__version__ = "0.1.0"

from aimw_sidecar.app import create_app

__all__ = ["__version__", "create_app"]
