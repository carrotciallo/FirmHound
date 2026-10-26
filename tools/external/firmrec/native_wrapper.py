#!/usr/bin/env python3
"""Standalone launcher for a native upstream FirmRec checkout.

This file is executed by the **upstream FirmRec Python interpreter**, not by
FirmHound, so it deliberately has no FirmHound imports. It injects a synthetic
``firmrec.config`` module before any upstream module imports ``firmrec.consts``
or ``firmrec.econfig``. Upstream computes most path constants at import time, so
the injection order matters: our per-run paths must be visible before
``ConstPaths`` is constructed.

Usage::

    <firmrec-python> native_wrapper.py payload.json all
    <firmrec-python> native_wrapper.py payload.json 4.4

``payload.json`` is written per run under ``tmp/external/firmrec/<run_id>/`` and
contains the absolute ``gconfig`` values plus an optional upstream YAML config
path. The upstream checkout is only read; every writable path is per-run.
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path


class _GConfig(types.SimpleNamespace):
    """Small dict/attr hybrid matching upstream's ``gconfig`` usage."""

    def get(self, key: str, default: object = None) -> object:
        return getattr(self, key, default)

    def __getitem__(self, key: str) -> object:
        return getattr(self, key)

    def __setitem__(self, key: str, value: object) -> None:
        setattr(self, key, value)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and hasattr(self, key)


def _install_gconfig(payload: dict) -> _GConfig:
    gconfig = _GConfig(**payload["gconfig"])

    class _Config:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

    config_module = types.ModuleType("firmrec.config")
    config_module.gconfig = gconfig
    config_module.Config = _Config
    sys.modules["firmrec.config"] = config_module
    return gconfig


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.stderr.write("usage: native_wrapper.py <payload.json> [step]\n")
        return 2

    payload_path = Path(argv[1])
    try:
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"cannot read payload: {exc}\n")
        return 2

    repo = Path(payload["repo_dir"]).resolve()
    if not repo.is_dir():
        sys.stderr.write(f"FirmRec repo not found: {repo}\n")
        return 2
    sys.path.insert(0, str(repo))

    _install_gconfig(payload)

    import firmrec.consts as consts  # noqa: E402

    config_path = payload.get("upstream_config_path")
    if config_path and hasattr(consts, "ConstPaths"):
        for attr in ("CONFIG_PATH", "CONFIG_FILE"):
            if hasattr(consts.ConstPaths, attr):
                setattr(consts.ConstPaths, attr, str(config_path))

    from firmrec.pipeline.gen_cmds import firmrec_main  # noqa: E402

    sys.argv = [argv[0], *argv[2:]]
    firmrec_main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
