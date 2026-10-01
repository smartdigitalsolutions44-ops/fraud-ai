"""Terminal output: short status lines, colour only on a real terminal (``NO_COLOR`` honoured)."""

from __future__ import annotations

import os
import sys

from localrun.paths import IS_WINDOWS

_COLOUR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
if _COLOUR and IS_WINDOWS:  # pragma: no cover - enables VT sequences in the Windows console
    os.system("")  # noqa: S605 S607  # nosec B605 B607 - a documented no-op that turns VT on

_CODES = {"ok": "32", "warn": "33", "fail": "31", "dim": "2", "bold": "1", "accent": "36"}
_MARK = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL", "info": "    ", "step": ">>  "}


def paint(text: str, style: str) -> str:
    if not _COLOUR or style not in _CODES:
        return text
    return f"\033[{_CODES[style]}m{text}\033[0m"


def line(kind: str, text: str) -> None:
    style = {"ok": "ok", "warn": "warn", "fail": "fail", "step": "accent"}.get(kind, "dim")
    print(f"  {paint(_MARK.get(kind, '    '), style)} {text}", flush=True)


def heading(text: str) -> None:
    print(f"\n{paint(text, 'bold')}", flush=True)


def banner(title: str, rows: list[tuple[str, str]]) -> None:
    width = max(len(k) for k, _ in rows) + 2
    print()
    print(paint(f"  {title}", "bold"))
    for key, value in rows:
        print(f"  {paint(key.ljust(width), 'dim')}{value}")
    print(flush=True)
