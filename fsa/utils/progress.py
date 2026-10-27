"""Real-time stage progress for the CLI.

This module is display-only: it never changes what a stage does. Progress is
written to stderr so that ``--json-output`` on stdout stays machine-readable.
"""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Protocol, TextIO

from fsa.utils import console

_TICK_SECONDS = 0.5
_MAX_DETAIL = 400


def _clean_text(text: object, limit: int) -> str:
    """Collapse whitespace and drop control characters before terminal output."""
    printable = "".join(ch if ch.isprintable() else " " for ch in str(text))
    return " ".join(printable.split())[:limit]


class PipelineProgress(Protocol):
    """Callback interface used by the orchestrator."""

    def stage_start(self, stage: str, index: int, total: int) -> None:
        """Called immediately before a stage runs."""

    def stage_end(self, stage: str, status: str, duration: float) -> None:
        """Called after a stage finishes, with its status and wall time."""


class StageProgress:
    """Render stage start/end lines, with a live timer on a terminal.

    On a TTY the current stage is rewritten in place every half second; when
    stderr is redirected, one start line and one end line are written instead
    so background logs still show forward motion.
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        stream: TextIO | None = None,
        prefix: str = "",
        interval: float = _TICK_SECONDS,
    ) -> None:
        """Create a reporter bound to ``stream`` (stderr by default)."""
        self.stream = stream if stream is not None else sys.stderr
        self.enabled = bool(enabled)
        self.prefix = prefix
        self.interval = max(0.1, float(interval))
        self._tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self._colour = console.use_colour(self.stream)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stage = ""
        self._index = 0
        self._total = 0
        self._started = 0.0
        self._width = 0
        self._detail = ""
        self._detail_written = 0.0

    def stage_start(self, stage: str, index: int, total: int) -> None:
        """Start reporting ``stage`` as the active stage."""
        if not self.enabled:
            return
        self._stage = stage
        self._index = index
        self._total = total
        self._started = time.monotonic()
        self._detail = ""
        self._detail_written = 0.0
        line = self._line("running", None)
        with self._lock:
            if self._tty:
                self._write("\r" + line)
                self._width = len(line)
            else:
                self._write(line + "\n")
        if self._tty:
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._tick, name="fsa-progress", daemon=True
            )
            self._thread.start()

    def stage_end(self, stage: str, status: str, duration: float) -> None:
        """Finish the active stage line with its status and duration."""
        if not self.enabled:
            return
        if self._thread is not None:
            self._stop.set()
            self._thread.join(timeout=1.0)
            self._thread = None
        line = self._line(status, duration)
        with self._lock:
            if self._tty:
                padding = " " * max(0, self._width - len(line))
                self._write("\r" + line + padding + "\n")
                self._width = 0
            else:
                self._write(line + "\n")
            self._detail = ""

    def detail(self, text: str) -> None:
        """Show tool-level detail beside the active stage.

        On a terminal the detail is folded into the refreshed line. When stderr
        is redirected, at most one detail line per second is written so long
        stages remain visible in logs without flooding them.
        """
        if not self.enabled or not self._stage:
            return
        text = _clean_text(text, _MAX_DETAIL)
        if not text:
            return
        with self._lock:
            self._detail = text
            if self._tty:
                return
            now = time.monotonic()
            if now - self._detail_written < 1.0:
                return
            self._detail_written = now
            counter = f"[{self._index}/{self._total}]"
            self._write(f"{self.prefix}{counter} {self._stage}  {text}\n")

    def note(self, text: str) -> None:
        """Print a one-off note without disturbing the live stage line."""
        if not self.enabled:
            return
        message = _clean_text(text, _MAX_DETAIL)
        if not message:
            return
        with self._lock:
            context = (
                f"[{self._index}/{self._total}] {self._stage}  "
                if self._stage
                else ""
            )
            line = f"{self.prefix}{context}{message}\n"
            if self._tty and self._stage:
                self._write("\r" + " " * self._width + "\r" + line)
                current = self._line("running", time.monotonic() - self._started)
                self._write("\r" + current)
                self._width = max(self._width, len(current))
            else:
                self._write(line)

    def _tick(self) -> None:
        while not self._stop.wait(self.interval):
            elapsed = time.monotonic() - self._started
            line = self._line("running", elapsed)
            with self._lock:
                padding = " " * max(0, self._width - len(line))
                self._write("\r" + line + padding)
                self._width = max(self._width, len(line))

    def _line(self, status: str, elapsed: float | None) -> str:
        counter = f"[{self._index}/{self._total}]"
        stage = console.paint(self._stage, console.BOLD_CYAN, enabled=self._colour)
        word = console.paint(
            status,
            console.STATUS_COLOURS.get(status, console.DIM),
            enabled=self._colour,
        )
        suffix = f"  · {self._detail}" if self._detail else ""
        if elapsed is None:
            return f"{self.prefix}{counter} {stage}  {word}{suffix}"
        return f"{self.prefix}{counter} {stage}  {word}  {elapsed:.1f}s{suffix}"

    def _write(self, text: str) -> None:
        try:
            self.stream.write(text)
            self.stream.flush()
        except (OSError, ValueError):
            # A closed or broken stderr must never break an analysis run.
            self.enabled = False


_current_progress: ContextVar[StageProgress | None] = ContextVar(
    "fsa_progress", default=None
)


def current_progress() -> StageProgress | None:
    """Return the reporter active in this execution context, if any."""
    return _current_progress.get()


@contextmanager
def use_progress(progress: StageProgress | None) -> Iterator[None]:
    """Expose ``progress`` to in-process tools for detail updates."""
    token = _current_progress.set(progress)
    try:
        yield
    finally:
        _current_progress.reset(token)


def report_detail(text: str) -> None:
    """Update the active stage detail from tool code (no-op when none is active)."""
    progress = _current_progress.get()
    if progress is not None:
        progress.detail(text)


def report_note(text: str) -> None:
    """Print a one-off note from tool code (no-op when no progress is active)."""
    progress = _current_progress.get()
    if progress is not None:
        progress.note(text)
