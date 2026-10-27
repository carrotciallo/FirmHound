"""Run-directory lock: exclusive while held, released by the kernel."""

from __future__ import annotations

import os
from pathlib import Path

from fsa.utils.runlock import RunLock


def test_runlock_is_exclusive_and_releases(tmp_path: Path) -> None:
    first = RunLock(tmp_path)
    second = RunLock(tmp_path)

    assert first.acquire() is True
    assert first.owner_pid() == os.getpid()
    assert second.acquire() is False

    first.release()
    assert second.acquire() is True
    second.release()


def test_runlock_release_is_idempotent(tmp_path: Path) -> None:
    lock = RunLock(tmp_path)
    lock.release()

    assert lock.acquire() is True
    lock.release()
    lock.release()
    assert lock.acquired is False
