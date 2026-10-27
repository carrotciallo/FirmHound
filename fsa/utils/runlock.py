"""Advisory process lock for a run directory.

The lock is a kernel ``flock``: it is released automatically when the owning
process exits, crashes, or is killed. That lets resume distinguish a stale
``status=running`` marker from a process that is actually still working.
"""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
from typing import IO


class RunLock:
    """Non-blocking exclusive lock on ``state/run.lock``."""

    def __init__(self, run_dir: str | Path) -> None:
        """Bind the lock to a run directory."""
        self.run_dir = Path(run_dir)
        self.path = self.run_dir / "state" / "run.lock"
        self._handle: IO[str] | None = None
        self.acquired = False

    def acquire(self) -> bool:
        """Try to take the lock; return False when another process holds it."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            handle.close()
            return False
        handle.seek(0)
        handle.truncate()
        handle.write(f"{os.getpid()}\n")
        handle.flush()
        self._handle = handle
        self.acquired = True
        return True

    def release(self) -> None:
        """Release the lock if this instance holds it."""
        if self._handle is None:
            return
        try:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        finally:
            self._handle.close()
            self._handle = None
            self.acquired = False

    def owner_pid(self) -> int | None:
        """Read the pid written by the current holder, if available."""
        try:
            return int(self.path.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return None
