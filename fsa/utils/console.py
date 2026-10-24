"""Terminal output helpers.

Colour follows the convention CPython itself uses: on when stdout is a
terminal, off when piped, and overridable with ``NO_COLOR`` / ``FORCE_COLOR``
so that captured logs and CI output stay readable.

Everything here is display only. Nothing in this module changes what a
command does, and every helper degrades to plain text when colour is off.
"""

from __future__ import annotations

import os
import sys
from typing import Any, TextIO

import click

# ANSI SGR codes. The names are the ones used across the CLI: a status word
# gets one of the status colours, a key gets DIM, a value that matters gets a
# bright variant.
DIM = "2"
RED = "31"
GREEN = "32"
YELLOW = "33"
BLUE = "34"
MAGENTA = "35"
CYAN = "36"
BOLD_RED = "1;31"
BOLD_GREEN = "1;32"
BOLD_YELLOW = "1;33"
BOLD_BLUE = "1;34"
BOLD_MAGENTA = "1;35"
BOLD_CYAN = "1;36"

# Every status string the pipeline can emit, mapped to the colour it gets.
# Anything missing from this table is printed dim, which is the safe default:
# an unknown status should not look like a success.
STATUS_COLOURS = {
    "ok": BOLD_GREEN,
    "done": BOLD_GREEN,
    "success": BOLD_GREEN,
    "ready": BOLD_GREEN,
    "degraded": BOLD_YELLOW,
    "partial": BOLD_YELLOW,
    "skipped": YELLOW,
    "missing": YELLOW,
    "needs_human_input": BOLD_YELLOW,
    "failed": BOLD_RED,
    "aborted": BOLD_RED,
    "error": BOLD_RED,
    "blocked_needs_decryption": BOLD_RED,
    "unknown": DIM,
}


def use_colour(stream: TextIO | None = None) -> bool:
    """Decide whether to colour output.

    NO_COLOR wins over everything, FORCE_COLOR overrides the TTY check, and
    with neither set the answer is "only when a human is looking".
    """
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR") or os.environ.get("CLICOLOR_FORCE"):
        return True
    target = stream if stream is not None else sys.stdout
    return bool(getattr(target, "isatty", lambda: False)())


def paint(text: Any, code: str, enabled: bool | None = None) -> str:
    """Wrap text in an ANSI colour, or return it untouched when colour is off."""
    if not (use_colour() if enabled is None else enabled):
        return str(text)
    return f"\x1b[{code}m{text}\x1b[0m"


def field(key: str, value: Any) -> str:
    """One ``KEY=value`` pair with the key dimmed, for grouped output."""
    return f"{paint(key.upper(), DIM)}={value}"


def status(value: Any) -> str:
    """Colour a status word by its meaning."""
    text = str(value)
    return paint(text, STATUS_COLOURS.get(text, DIM))


def label(text: str) -> str:
    """A heading or a field name."""
    return paint(text, BOLD_CYAN)


def muted(text: Any) -> str:
    """Secondary information: paths, counters, notes."""
    return paint(text, DIM)


def warn(text: Any) -> str:
    """A value that needs attention but did not fail."""
    return paint(text, BOLD_YELLOW)


def bad(text: Any) -> str:
    """A failed value or a missing dependency."""
    return paint(text, BOLD_RED)


def good(text: Any) -> str:
    """A value that is known to be fine."""
    return paint(text, BOLD_GREEN)


def echo(message: Any = "", **kwargs: Any) -> None:
    """``click.echo`` that keeps ANSI codes only when colour is on."""
    kwargs.setdefault("color", use_colour())
    click.echo(message, **kwargs)


def kv(key: str, value: Any) -> None:
    """Print one ``key: value`` line with a dimmed key."""
    echo(f"{muted(key)}: {value}")
