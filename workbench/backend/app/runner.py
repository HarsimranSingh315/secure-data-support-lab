"""Runs allow-listed commands inside lab containers.

Design rules (see docs/workbench.md, "Threat model"):
  * Commands are fixed argv lists defined in checks.py. Nothing typed in the browser ever
    becomes part of a command, so there is no shell-injection path.
  * Every command runs under `timeout -s KILL` inside the target container.
  * Output is capped (MAX_OUTPUT bytes) before it is stored or returned.
  * Containers are found by their docker compose labels, so only this lab's services can be
    targeted - never an arbitrary container on the machine.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Protocol

PROJECT = os.environ.get("WB_PROJECT", "securedata-lab")
MAX_OUTPUT = 8_000
DEFAULT_TIMEOUT = 5

# Only these compose services can ever be targeted.
LAB_SERVICES = frozenset({"r1", "r2", "r3", "toolbox", "ldap", "db", "kms", "app", "dam"})


@dataclass
class ExecResult:
    service: str
    command: list[str]
    exit_code: int | None = None
    output: str = ""
    duration_ms: int = 0
    # None when the command ran; otherwise why it could not run
    error: str | None = None
    truncated: bool = False
    env: dict[str, str] = field(default_factory=dict)

    @property
    def ran(self) -> bool:
        return self.error is None

    @property
    def ok(self) -> bool:
        return self.error is None and self.exit_code == 0


class Runner(Protocol):
    def state(self, service: str) -> str: ...
    def exec(self, service: str, argv: list[str], timeout: int = DEFAULT_TIMEOUT,
             env: dict[str, str] | None = None) -> ExecResult: ...


def cap(text: str) -> tuple[str, bool]:
    if len(text) <= MAX_OUTPUT:
        return text, False
    return text[:MAX_OUTPUT] + "\n... (output truncated)", True


class DockerRunner:
    """Talks to the Docker Engine API through the mounted socket."""

    def __init__(self) -> None:
        import docker  # imported here so unit tests do not need the SDK
        self._docker = docker
        self._client = None

    def _c(self):
        if self._client is None:
            self._client = self._docker.from_env(timeout=10)
        return self._client

    def _find(self, service: str):
        if service not in LAB_SERVICES:
            raise ValueError(f"not a lab service: {service}")
        found = self._c().containers.list(all=True, filters={"label": [
            f"com.docker.compose.project={PROJECT}", f"com.docker.compose.service={service}"]})
        return found[0] if found else None

    def state(self, service: str) -> str:
        """running | exited | missing | docker_unavailable"""
        try:
            ctr = self._find(service)
        except self._docker.errors.DockerException:
            self._client = None
            return "docker_unavailable"
        return ctr.status if ctr else "missing"

    def exec(self, service, argv, timeout=DEFAULT_TIMEOUT, env=None) -> ExecResult:
        res = ExecResult(service=service, command=list(argv), env=dict(env or {}))
        state = self.state(service)
        if state != "running":
            res.error = {"docker_unavailable": "docker_unavailable",
                         "missing": "container_missing"}.get(state, "container_not_running")
            return res
        start = time.monotonic()
        try:
            ctr = self._find(service)
            out = ctr.exec_run(["timeout", "-s", "KILL", str(timeout), *argv],
                               environment=env or {}, stdout=True, stderr=True, demux=False)
        except self._docker.errors.DockerException as exc:
            res.error = "docker_unavailable"
            res.output = str(exc)[:500]
            return res
        finally:
            res.duration_ms = int((time.monotonic() - start) * 1000)
        res.exit_code = out.exit_code
        res.output, res.truncated = cap((out.output or b"").decode("utf-8", "replace"))
        if out.exit_code in (124, 137):  # timeout(1) exit codes
            res.error = "timeout"
        return res
