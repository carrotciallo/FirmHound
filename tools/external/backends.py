"""Execution backends for external analyzers: local / docker.

Both backends funnel through :func:`fsa.utils.proc.run_command`, which never
raises on non-zero exits and converts timeouts into a structured result.

Safety notes:
* ``docker`` backend mounts only paths that were staged under the analyzer's
  workdir (``tmp/external/<tool>/<run_id>/``), which sits inside the
  ``./tmp`` path whitelist in ``config/safety.yaml``.
* Analyzers run natively on Linux; there is no host-translation layer.
"""

from __future__ import annotations

import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fsa.utils.proc import RunResult, run_command


@dataclass
class BackendResult:
    """Normalized result of a backend invocation."""

    status: str  # ok | failed | timeout | missing
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    returncode: int = -1

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def _from_run_result(res: RunResult) -> BackendResult:
    """Map a :class:`RunResult` onto :class:`BackendResult`."""
    if res.status == "timeout":
        return BackendResult("timeout", res.stdout, res.stderr, returncode=-1)
    if res.status == "success":
        return BackendResult("ok", res.stdout, res.stderr, returncode=res.returncode)
    return BackendResult("failed", res.stdout, res.stderr, returncode=res.returncode)


# --------------------------------------------------------------------------- #
# local
# --------------------------------------------------------------------------- #


def run_local(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: float = 60.0,
    env: dict[str, str] | None = None,
) -> BackendResult:
    """Run a command on the host (Linux).

    ``env`` is merged over the current environment by :func:`run_command`, which
    lets callers pin ``LC_ALL=C`` or pass a PostgreSQL password without mutating
    the parent process.
    """
    if not cmd:
        return BackendResult("failed", stderr="empty command")
    executable = Path(cmd[0])
    if executable.is_absolute():
        if not executable.is_file():
            return BackendResult("missing", stderr=f"executable not found: {cmd[0]}")
    elif shutil.which(cmd[0]) is None:
        return BackendResult("missing", stderr=f"executable not found: {cmd[0]}")
    started = time.monotonic()
    result = _from_run_result(run_command(cmd, cwd=cwd, timeout=timeout, env=env))
    result.duration_s = round(time.monotonic() - started, 3)
    return result


# --------------------------------------------------------------------------- #
# docker
# --------------------------------------------------------------------------- #


def docker_available() -> tuple[bool, str]:
    """Return ``(available, detail)`` for the Docker daemon."""
    if shutil.which("docker") is None:
        return False, "docker executable not found"
    res = run_command(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=20.0)
    if res.status != "success":
        return False, (res.stderr or res.stdout or "docker daemon unreachable").strip()
    return True, (res.stdout or "").strip()


def docker_image_exists(image: str) -> bool:
    """Return True when ``image`` is present locally."""
    res = run_command(["docker", "image", "inspect", image], timeout=30.0)
    return res.status == "success"


def run_docker(
    image: str,
    cmd: list[str],
    *,
    mounts: dict[Path | str, str] | None = None,
    cwd: Path | None = None,
    timeout: float = 60.0,
    memory: str | None = None,
    entrypoint: str | None = None,
    env: dict[str, str] | None = None,
    extra_args: list[str] | None = None,
) -> BackendResult:
    """Run a command inside a throwaway container.

    Args:
        image: Image reference, e.g. ``smile0304/satc``.
        cmd: Command executed inside the container.
        mounts: Mapping of host path -> container path.
        memory: Optional hard memory limit, e.g. ``16g`` (Ghidra needs headroom).
        extra_args: Additional ``docker run`` flags appended before the image.
    """
    if not docker_image_exists(image):
        return BackendResult("missing", stderr=f"docker image not present: {image}")

    full: list[str] = ["docker", "run", "--rm"]
    for host, container in (mounts or {}).items():
        full += ["-v", f"{Path(host).resolve()}:{container}"]
    if memory:
        full += ["--memory", memory]
    for key, value in (env or {}).items():
        full += ["-e", f"{key}={value}"]
    if entrypoint:
        full += ["--entrypoint", entrypoint]
    full += list(extra_args or [])
    full += [image]
    full += [str(c) for c in cmd]
    started = time.monotonic()
    result = _from_run_result(run_command(full, cwd=cwd, timeout=timeout))
    result.duration_s = round(time.monotonic() - started, 3)
    return result


def run_container_cmd(
    container: str,
    cmd: list[str],
    *,
    timeout: float = 60.0,
) -> BackendResult:
    """Execute a command inside an already-running container (``docker exec``)."""
    full = ["docker", "exec", container] + [str(c) for c in cmd]
    started = time.monotonic()
    result = _from_run_result(run_command(full, timeout=timeout))
    result.duration_s = round(time.monotonic() - started, 3)
    return result


BACKENDS: dict[str, Any] = {
    "local": run_local,
    "docker": run_docker,
}
