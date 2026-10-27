"""Tests for the display-only stage progress reporter."""

from __future__ import annotations

import io

import pytest

from fsa.utils.progress import StageProgress, report_detail, report_note, use_progress


class _TtyStringIO(io.StringIO):
    """StringIO that pretends to be a terminal; no fileno on purpose."""

    def isatty(self) -> bool:
        return True


def test_stage_progress_writes_start_and_end_when_not_a_tty() -> None:
    stream = io.StringIO()
    progress = StageProgress(enabled=True, stream=stream, prefix="[run-1] ")

    progress.stage_start("UNPACK", 3, 10)
    progress.stage_end("UNPACK", "ok", 1.26)

    text = stream.getvalue()
    assert "[run-1] [3/10] UNPACK" in text
    assert "running" in text
    assert "ok" in text
    assert "1.3s" in text


def test_stage_progress_disabled_writes_nothing() -> None:
    stream = io.StringIO()
    progress = StageProgress(enabled=False, stream=stream)

    progress.stage_start("UNPACK", 3, 10)
    progress.stage_end("UNPACK", "ok", 1.0)

    assert stream.getvalue() == ""


def test_tool_detail_reaches_the_active_stage() -> None:
    stream = io.StringIO()
    progress = StageProgress(enabled=True, stream=stream)
    progress.stage_start("AGENT_LOOP", 5, 10)

    with use_progress(progress):
        report_detail("agent step 10 · cand-1 · cross_check_imports_strings")

    progress.stage_end("AGENT_LOOP", "ok", 2.0)

    text = stream.getvalue()
    assert "AGENT_LOOP" in text
    assert "agent step 10" in text
    assert "cross_check_imports_strings" in text


def test_report_detail_without_active_progress_is_a_noop() -> None:
    report_detail("nothing should happen")


def test_note_prints_validated_model_line_and_strips_controls() -> None:
    stream = io.StringIO()
    progress = StageProgress(enabled=True, stream=stream)
    progress.stage_start("AGENT_LOOP", 5, 10)

    with use_progress(progress):
        report_note("model chose verify_auth_hint\n\x1b[31mconfidence 0.8")

    progress.stage_end("AGENT_LOOP", "ok", 1.0)

    text = stream.getvalue()
    assert "model chose verify_auth_hint" in text
    assert "\x1b" not in text
    assert "confidence 0.8" in text


def test_tty_detail_wraps_to_terminal_width_and_keeps_status_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    stream = _TtyStringIO()
    progress = StageProgress(enabled=True, stream=stream, interval=10.0)
    progress.stage_start("AGENT_LOOP", 5, 12)
    progress.detail("agent step 123/5000 · " + "candidate-detail " * 20)
    progress.stage_end("AGENT_LOOP", "ok", 1.0)

    text = stream.getvalue()
    assert "AGENT_LOOP" in text
    assert text.count("\n") >= 4
    visible = [line for line in text.replace("\r", "\n").split("\n") if line.strip()]
    assert all(len(line) <= 100 for line in visible)
