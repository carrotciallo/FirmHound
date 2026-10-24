"""Colour helpers: on for a terminal, off for pipes and captured output."""

from __future__ import annotations

import io

import pytest

from fsa.utils import console


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


class _Pipe(io.StringIO):
    def isatty(self) -> bool:
        return False


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("NO_COLOR", "FORCE_COLOR", "CLICOLOR_FORCE"):
        monkeypatch.delenv(name, raising=False)


def test_colour_follows_the_stream() -> None:
    assert console.use_colour(_Tty()) is True
    assert console.use_colour(_Pipe()) is False


def test_no_color_wins_over_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    assert console.use_colour(_Tty()) is False


def test_force_color_wins_over_a_pipe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert console.use_colour(_Pipe()) is True


def test_clicolor_force_is_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLICOLOR_FORCE", "1")
    assert console.use_colour(_Pipe()) is True


def test_paint_wraps_only_when_enabled() -> None:
    assert console.paint("ok", console.GREEN, enabled=True) == "\x1b[32mok\x1b[0m"
    assert console.paint("ok", console.GREEN, enabled=False) == "ok"


def test_status_uses_its_colour(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert console.status("done") == "\x1b[1;32mdone\x1b[0m"
    assert console.status("aborted") == "\x1b[1;31maborted\x1b[0m"
    assert console.status("degraded") == "\x1b[1;33mdegraded\x1b[0m"


def test_unknown_status_is_dim_not_green(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert console.status("something-new") == "\x1b[2msomething-new\x1b[0m"


def test_status_is_plain_when_colour_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    assert console.status("failed") == "failed"


def test_field_dims_the_key_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert console.field("status", "ok") == "\x1b[2mSTATUS\x1b[0m=ok"
