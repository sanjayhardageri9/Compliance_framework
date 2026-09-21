"""Docker-backed sandbox tests. Opt-in only: `pytest -m docker`.

Not run by default (see pyproject.toml addopts) since CI/reviewer machines
may not have a Docker daemon, even though this dev box does.

Command allowlist / metacharacter policy is covered hermetically in
``test_docker_sandbox_command_policy.py`` (always run).
"""

from __future__ import annotations

import pytest

from aimw.models import ToolRequest
from aimw.sandbox.docker_sandbox import DockerSandbox, RestrictedDockerSandbox

pytestmark = pytest.mark.docker

_ALLOWED = frozenset({"python"})


async def test_docker_sandbox_runs_command_with_no_network(context_factory):
    sandbox = DockerSandbox(
        image="python:3.11-slim", timeout_s=30.0, allowed_commands=_ALLOWED
    )
    ctx = context_factory()
    req = ToolRequest(
        tool_name="search_tool",
        function_name="query",
        parameters={"command": ["python", "-c", "print('hello from sandbox')"]},
        call_id="c1",
    )
    result = await sandbox.execute(req, ctx)
    assert result.exit_code == 0
    assert "hello from sandbox" in result.stdout


async def test_docker_sandbox_missing_command_param_fails_safely(context_factory):
    sandbox = DockerSandbox(allowed_commands=_ALLOWED)
    ctx = context_factory()
    req = ToolRequest(tool_name="search_tool", function_name="query", parameters={}, call_id="c1")
    result = await sandbox.execute(req, ctx)
    assert result.exit_code == 2
    assert "command" in result.stderr


async def test_restricted_docker_sandbox_runs_as_non_root(context_factory):
    sandbox = RestrictedDockerSandbox(
        image="python:3.11-slim", timeout_s=30.0, allowed_commands=_ALLOWED
    )
    ctx = context_factory()
    req = ToolRequest(
        tool_name="search_tool",
        function_name="query",
        parameters={"command": ["python", "-c", "import os; print(os.getuid())"]},
        call_id="c1",
    )
    result = await sandbox.execute(req, ctx)
    assert result.exit_code == 0
    assert result.stdout.strip() == "65534"


async def test_docker_sandbox_timeout(context_factory):
    sandbox = DockerSandbox(
        image="python:3.11-slim", timeout_s=1.0, allowed_commands=_ALLOWED
    )
    ctx = context_factory()
    req = ToolRequest(
        tool_name="search_tool",
        function_name="query",
        parameters={"command": ["python", "-c", "import time; time.sleep(30)"]},
        call_id="c1",
    )
    result = await sandbox.execute(req, ctx)
    assert result.timed_out is True
    assert result.exit_code == 124
