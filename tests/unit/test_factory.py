from __future__ import annotations

import pytest

from aimw.config import Settings
from aimw.factory import make_audit_log, make_sandbox
from aimw.sandbox.docker_sandbox import DockerSandbox
from aimw.sandbox.subprocess_sandbox import SubprocessSandbox


def test_make_sandbox_defaults_to_subprocess() -> None:
    sandbox = make_sandbox(Settings())
    assert isinstance(sandbox, SubprocessSandbox)


def test_make_sandbox_docker_mode() -> None:
    sandbox = make_sandbox(Settings(sandbox_mode="docker"))
    assert isinstance(sandbox, DockerSandbox)


def test_make_sandbox_rejects_unknown_mode() -> None:
    with pytest.raises(ValueError, match="unsupported sandbox_mode"):
        make_sandbox(Settings(sandbox_mode="kvm"))


def test_make_audit_log_honors_redact_flag(tmp_path) -> None:
    logger = make_audit_log(tmp_path / "a.jsonl", Settings(redact_audit_parameters=False))
    assert logger._redact_parameters is False

    logger_redacted = make_audit_log(tmp_path / "b.jsonl", Settings(redact_audit_parameters=True))
    assert logger_redacted._redact_parameters is True


def test_make_sandbox_docker_passes_allowed_commands() -> None:
    sandbox = make_sandbox(
        Settings(sandbox_mode="docker"),
        allowed_commands=frozenset({"python"}),
    )
    assert isinstance(sandbox, DockerSandbox)
    assert sandbox._allowed_commands == frozenset({"python"})
    assert sandbox._allow_unlisted is False
