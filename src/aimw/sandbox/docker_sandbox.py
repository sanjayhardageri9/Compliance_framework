"""Docker-backed sandbox: real process isolation with deny-by-default egress.

Shells out to `docker run --rm --network none` so a sandboxed tool call has
no network access unless explicitly configured otherwise, with a hard
wall-clock timeout so a hung container can never hang the pipeline. This is
the L1 sandbox; L3 upgrades this to E2B microVM + gVisor + VPC-SC per the
framework document's tiered maturity model (Section 13).

Requires a working local Docker daemon. Tests exercising the real daemon are
marked `@pytest.mark.docker` and are not run by default. Command-argv
validation (allowlist + injection checks) is hermetic and covered without
Docker.
"""

from __future__ import annotations

import asyncio
import re
import shlex
import time
from pathlib import PurePosixPath

from aimw.models import ExecutionContext, ToolRequest
from aimw.sandbox.base import BaseSandbox, SandboxResult

# Newlines / NULs in argv are never legitimate for this interface and enable
# log/parser smuggling even with exec-form docker run.
_ARGV_ALWAYS_REJECT_RE = re.compile(r"[\n\r\x00]")

# When argv[0] is a shell, classic metacharacters turn -c scripts into RCE.
_SHELL_METACHAR_RE = re.compile(r"[;|&`$<>]")
_SHELL_BINARIES = frozenset(
    {"sh", "bash", "zsh", "dash", "csh", "tcsh", "fish", "busybox", "cmd.exe", "powershell"}
)


class DockerSandbox(BaseSandbox):
    """Runs a tool call's command inside an isolated, network-denied container.

    Fail-closed command policy
    --------------------------
    ``parameters["command"]`` must be a list of argv strings. By default the
    sandbox rejects every command unless the binary (``argv[0]``) is a member
    of ``allowed_commands``. Pass ``allow_unlisted=True`` only for trusted
    local demos. Newlines/NULs are always rejected; shell metacharacters are
    rejected when the binary is a known shell interpreter.
    """

    def __init__(
        self,
        image: str = "python:3.11-slim",
        timeout_s: float = 15.0,
        memory_limit: str = "256m",
        cpus: str = "1",
        allowed_commands: frozenset[str] | set[str] | None = None,
        *,
        allow_unlisted: bool = False,
    ) -> None:
        self._image = image
        self._timeout_s = timeout_s
        self._memory_limit = memory_limit
        self._cpus = cpus
        self._allowed_commands: frozenset[str] | None = (
            frozenset(allowed_commands) if allowed_commands is not None else None
        )
        self._allow_unlisted = allow_unlisted

    def _extra_docker_flags(self) -> list[str]:
        """Hook for subclasses (e.g. RestrictedDockerSandbox) to add flags."""
        return []

    def _validate_command(self, command: list[str]) -> list[str]:
        """Validate argv: shape, injection markers, allowlist."""
        if not command:
            raise ValueError("DockerSandbox command argv must be a non-empty list")
        validated: list[str] = []
        for part in command:
            text = str(part)
            if _ARGV_ALWAYS_REJECT_RE.search(text):
                raise ValueError(
                    f"newlines/NUL are not allowed in command args: {text!r}"
                )
            validated.append(text)

        binary = validated[0]
        binary_name = PurePosixPath(binary).name.lower()
        if binary_name in _SHELL_BINARIES:
            for part in validated[1:]:
                if _SHELL_METACHAR_RE.search(part):
                    raise ValueError(
                        f"shell metacharacters are not allowed when binary is a "
                        f"shell ({binary_name!r}): {part!r}"
                    )

        if self._allowed_commands is not None:
            if binary not in self._allowed_commands:
                raise ValueError(
                    f"command binary {binary!r} is not in allowed_commands "
                    f"{sorted(self._allowed_commands)}"
                )
        elif not self._allow_unlisted:
            raise ValueError(
                "DockerSandbox requires allowed_commands (fail-closed); "
                "pass allow_unlisted=True only for trusted local demos"
            )
        return validated

    def _build_command(self, request: ToolRequest) -> list[str]:
        # A real integration would map (tool_name, function_name, parameters)
        # to a specific, validated container command per tool. For this L1
        # stand-in, parameters are expected to carry an explicit "command"
        # (a list of args). Callers that have already passed policy evaluation
        # must still declare allowed_commands on the sandbox (or explicitly
        # opt into allow_unlisted for demos).
        command = request.parameters.get("command")
        if not command or not isinstance(command, list):
            raise ValueError(
                "DockerSandbox requires request.parameters['command'] to be a list of args"
            )
        return self._validate_command([str(part) for part in command])

    async def execute(self, request: ToolRequest, context: ExecutionContext) -> SandboxResult:
        try:
            inner_command = self._build_command(request)
        except ValueError as exc:
            return SandboxResult(stdout="", stderr=str(exc), exit_code=2, duration_ms=0.0)

        docker_command = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--memory",
            self._memory_limit,
            "--cpus",
            self._cpus,
            *self._extra_docker_flags(),
            self._image,
            *inner_command,
        ]

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *docker_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=self._timeout_s
                )
            except TimeoutError:
                proc.kill()
                await proc.wait()
                duration_ms = (time.monotonic() - start) * 1000
                return SandboxResult(
                    stdout="",
                    stderr=f"container execution exceeded {self._timeout_s}s timeout",
                    exit_code=124,
                    duration_ms=duration_ms,
                    timed_out=True,
                )
            duration_ms = (time.monotonic() - start) * 1000
            return SandboxResult(
                stdout=stdout_bytes.decode("utf-8", errors="replace"),
                stderr=stderr_bytes.decode("utf-8", errors="replace"),
                exit_code=proc.returncode or 0,
                duration_ms=duration_ms,
            )
        except FileNotFoundError:
            duration_ms = (time.monotonic() - start) * 1000
            return SandboxResult(
                stdout="",
                stderr="docker executable not found on PATH",
                exit_code=127,
                duration_ms=duration_ms,
            )

    @staticmethod
    def format_command_for_log(command: list[str]) -> str:
        return shlex.join(command)


class RestrictedDockerSandbox(DockerSandbox):
    """L2 sandbox: DockerSandbox hardened per Section 13's L2 "Sandboxing" row.

    Adds non-root execution, a read-only root filesystem, all Linux
    capabilities dropped, and no-new-privileges - a real step toward L3's
    E2B microVM + gVisor, still using plain Docker rather than a managed
    microVM service. Inherits the same fail-closed argv allowlist policy.
    """

    def _extra_docker_flags(self) -> list[str]:
        return [
            "--user",
            "65534:65534",  # nobody:nogroup
            "--read-only",
            # mounts a fresh in-container tmpfs, not a host temp path
            "--tmpfs",
            "/tmp",  # noqa: S108 # nosec B108
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
        ]
