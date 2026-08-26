"""Docker-backed sandbox: real process isolation with deny-by-default egress.

Shells out to `docker run --rm --network none` so a sandboxed tool call has
no network access unless explicitly configured otherwise, with a hard
wall-clock timeout so a hung container can never hang the pipeline. This is
the L1 sandbox; L3 upgrades this to E2B microVM + gVisor + VPC-SC per the
framework document's tiered maturity model (Section 13).

Requires a working local Docker daemon. Tests exercising this class are
marked `@pytest.mark.docker` and are not run by default.
"""

from __future__ import annotations

import asyncio
import shlex
import time

from aimw.models import ExecutionContext, ToolRequest
from aimw.sandbox.base import BaseSandbox, SandboxResult


class DockerSandbox(BaseSandbox):
    """Runs a tool call's command inside an isolated, network-denied container."""

    def __init__(
        self,
        image: str = "python:3.11-slim",
        timeout_s: float = 15.0,
        memory_limit: str = "256m",
        cpus: str = "1",
    ) -> None:
        self._image = image
        self._timeout_s = timeout_s
        self._memory_limit = memory_limit
        self._cpus = cpus

    def _extra_docker_flags(self) -> list[str]:
        """Hook for subclasses (e.g. RestrictedDockerSandbox) to add flags."""
        return []

    def _build_command(self, request: ToolRequest) -> list[str]:
        # A real integration would map (tool_name, function_name, parameters)
        # to a specific, validated container command per tool. For this L1
        # stand-in, parameters are expected to carry an explicit "command"
        # (a list of args) that the caller - which has already passed policy
        # evaluation - is responsible for constructing safely.
        command = request.parameters.get("command")
        if not command or not isinstance(command, list):
            raise ValueError(
                "DockerSandbox requires request.parameters['command'] to be a list of args"
            )
        return [str(part) for part in command]

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
    microVM service.
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
