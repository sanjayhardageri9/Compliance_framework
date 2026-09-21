"""Hermetic DockerSandbox argv policy tests (no Docker daemon required).

Real container execution remains under ``@pytest.mark.docker`` in
``test_docker_sandbox.py`` and is excluded by default ``addopts``.
"""

from __future__ import annotations

import pytest

from aimw.models import ToolRequest
from aimw.sandbox.docker_sandbox import DockerSandbox, RestrictedDockerSandbox


def _req(command: object) -> ToolRequest:
    return ToolRequest(
        tool_name="search_tool",
        function_name="query",
        parameters={"command": command} if command is not None else {},
        call_id="c1",
    )


def test_build_command_requires_allowlist_by_default():
    sandbox = DockerSandbox()
    with pytest.raises(ValueError, match="allowed_commands"):
        sandbox._build_command(_req(["python", "-c", "print(1)"]))


def test_build_command_accepts_allowlisted_python_with_semicolon_in_script():
    # ';' inside python -c source is legitimate argv when not running a shell.
    sandbox = DockerSandbox(allowed_commands=frozenset({"python", "python3"}))
    assert sandbox._build_command(
        _req(["python", "-c", "import os; print(os.getuid())"])
    ) == ["python", "-c", "import os; print(os.getuid())"]


def test_build_command_rejects_unlisted_binary():
    sandbox = DockerSandbox(allowed_commands=frozenset({"python"}))
    with pytest.raises(ValueError, match="not in allowed_commands"):
        sandbox._build_command(_req(["bash", "-c", "id"]))


def test_build_command_rejects_shell_metacharacters_for_shell_binary():
    sandbox = DockerSandbox(allowed_commands=frozenset({"bash"}))
    with pytest.raises(ValueError, match="shell metacharacters"):
        sandbox._build_command(_req(["bash", "-c", "id; rm -rf /"]))


@pytest.mark.parametrize("bad_arg", ["a|b", "a&b", "a`b`", "a$(b)", "a>b", "a<b"])
def test_build_command_rejects_various_shell_metacharacters(bad_arg: str):
    sandbox = DockerSandbox(allowed_commands=frozenset({"bash"}))
    with pytest.raises(ValueError, match="shell metacharacters"):
        sandbox._build_command(_req(["bash", "-c", bad_arg]))


def test_build_command_rejects_embedded_newline():
    sandbox = DockerSandbox(allowed_commands=frozenset({"python"}))
    with pytest.raises(ValueError, match="newlines/NUL"):
        sandbox._build_command(_req(["python", "line1\nline2"]))


def test_allow_unlisted_skips_allowlist_but_still_blocks_shell_meta_and_newlines():
    sandbox = DockerSandbox(allow_unlisted=True)
    assert sandbox._build_command(_req(["custom-bin", "ok"])) == ["custom-bin", "ok"]
    with pytest.raises(ValueError, match="shell metacharacters"):
        sandbox._build_command(_req(["bash", "-c", "x;y"]))
    with pytest.raises(ValueError, match="newlines/NUL"):
        sandbox._build_command(_req(["custom-bin", "x\ny"]))


async def test_execute_returns_exit_2_on_policy_violation(context_factory):
    sandbox = DockerSandbox(allowed_commands=frozenset({"python"}))
    result = await sandbox.execute(_req(["bash", "-c", "id"]), context_factory())
    assert result.exit_code == 2
    assert "allowed_commands" in result.stderr


async def test_execute_missing_command_param_fails_safely(context_factory):
    sandbox = DockerSandbox(allowed_commands=frozenset({"python"}))
    result = await sandbox.execute(
        ToolRequest(tool_name="t", function_name="f", parameters={}, call_id="c1"),
        context_factory(),
    )
    assert result.exit_code == 2
    assert "command" in result.stderr


def test_restricted_docker_sandbox_inherits_allowlist_policy():
    sandbox = RestrictedDockerSandbox(allowed_commands=frozenset({"python"}))
    with pytest.raises(ValueError, match="not in allowed_commands"):
        sandbox._build_command(_req(["sh", "-c", "id"]))
