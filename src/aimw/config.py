"""Runtime settings.

Every field has a safe, zero-configuration default so the test suite and
`examples/run_demo.py` run with no required environment variables, no
accounts, and no API keys - per the constraint that this SDK's L1 build
must be verifiable with nothing but a local Python environment.
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AIMW_")

    policy_path: Path = Path("configs/policy.example.yaml")
    audit_log_path: Path = Path("audit.jsonl")
    sandbox_mode: str = "subprocess"  # "subprocess" (default, hermetic) or "docker"
    decision_timeout_s: float = 2.0
    sandbox_timeout_s: float = 5.0
    redact_audit_parameters: bool = True
