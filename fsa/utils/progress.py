"""Real-time stage progress for the CLI.

This module is display-only: it never changes what a stage does. Progress is
written to stderr so that ``--json-output`` on stdout stays machine-readable.

On a terminal, detailed updates are printed as normal (auto-wrapped) lines and
a single short status line is refreshed underneath them. Long details therefore
never wrap into the refresh area and fill the screen with repeated output.
"""

from __future__ import annotations

import os
import sys
import textwrap
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
    """Print detailed updates as lines and keep one live status line.

    On a TTY the status line is rewritten in place; details and notes are
    written above it as normal lines, wrapped to the terminal width. When
    stderr is redirected there is no status line: each event is one log line.
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
        with self._lock:
            if self._tty:
                self._draw_status("running", None)
            else:
                self._write(f"{self._context()}running\n")
        if self._tty:
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._tick, name="fsa-progress", daemon=True
            )
            self._thread.start()

    def stage_end(self, stage: str, status: str, duration: float) -> None:
        """Finish the active stage with a normal, wrapped summary line."""
        if not self.enabled:
            return
        if self._thread is not None:
            self._stop.set()
            self._thread.join(timeout=1.0)
            self._thread = None
        line = f"{self._context()}{status}  {duration:.1f}s"
        if self._detail:
            line += f"  · {self._detail}"
        with self._lock:
            if self._tty:
                self._clear_status()
                for chunk in self._wrap(line):
                    self._write(chunk + "\n")
                self._width = 0
            else:
                self._write(line + "\n")
            self._detail = ""

    def detail(self, text: str) -> None:
        """Show tool-level detail as a (wrapped) content line.

        On a TTY the line is printed above the live status line. When stderr is
        redirected, at most one detail line per second is written so long
        stages remain visible in logs without flooding them.
        """
        if not self.enabled or not self._stage:
            return
        message = _clean_text(text, _MAX_DETAIL)
        if not message:
            return
        with self._lock:
            self._detail = message
            if self._tty:
                self._clear_status()
                for chunk in self._wrap(f"{self._context()}{message}"):
                    self._write(chunk + "\n")
                self._draw_status("running", time.monotonic() - self._started)
                return
            now = time.monotonic()
            if now - self._detail_written < 1.0:
                return
            self._detail_written = now
            self._write(f"{self._context()}{message}\n")

    def note(self, text: str) -> None:
        """Print a one-off note without disturbing the live status line."""
        if not self.enabled:
            return
        message = _clean_text(text, _MAX_DETAIL)
        if not message:
            return
        with self._lock:
            context = self._context() if self._stage else self.prefix
            if self._tty:
                self._clear_status()
                for chunk in self._wrap(f"{context}{message}"):
                    self._write(chunk + "\n")
                if self._stage:
                    self._draw_status("running", time.monotonic() - self._started)
            else:
                self._write(f"{context}{message}\n")

    def _context(self) -> str:
        if not self._stage:
            return self.prefix
        return f"{self.prefix}[{self._index}/{self._total}] {self._stage}  "

    def _wrap(self, text: str) -> list[str]:
        width = max(20, self._terminal_width() - 1)
        if len(text) <= width:
            return [text]
        return textwrap.wrap(
            text,
            width=width,
            break_long_words=True,
            break_on_hyphens=False,
            subsequent_indent="  ",
        ) or [text]

    def _draw_status(self, status: str, elapsed: float | None) -> None:
        plain = f"{self._context()}{status}"
        if elapsed is not None:
            plain += f"  {elapsed:.1f}s"
        width = self._terminal_width()
        if len(plain) > width - 1:
            plain = plain[: max(1, width - 2)] + "…"
        visible = len(plain)
        padding = " " * max(0, self._width - visible)
        text = (
            console.paint(plain, console.BOLD_CYAN, enabled=True)
            if self._colour
            else plain
        )
        self._write("\r" + text + padding)
        self._width = max(self._width, visible)

    def _clear_status(self) -> None:
        self._write("\r" + " " * self._width + "\r")
        self._width = 0

    def _tick(self) -> None:
        while not self._stop.wait(self.interval):
            with self._lock:
                self._draw_status("running", time.monotonic() - self._started)

    def _terminal_width(self) -> int:
        try:
            return max(20, os.get_terminal_size(self.stream.fileno()).columns)
        except (OSError, ValueError, AttributeError):
            return 100

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
