"""Terminal styling and status messages.

Everything the user sees on stderr/stdout during a scan goes through here so
tags, colors, and indentation stay consistent. Color is used only when stdout
is a TTY (and never when NO_COLOR is set).
"""

import os
import sys

_RESET = "\033[0m"


def _color(code: str) -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _paint(code: str, text: str) -> str:
    return f"\033[{code}m{text}{_RESET}" if _color(code) else text


def info(msg: str) -> None:
    print(f"{_paint('36', '[*]')} {msg}")


def ok(msg: str) -> None:
    print(f"{_paint('32', '[+]')} {msg}")


def warn(msg: str) -> None:
    print(f"{_paint('33', '[!]')} {msg}", file=sys.stderr)


def err(msg: str) -> None:
    print(f"{_paint('31', '[x]')} {msg}", file=sys.stderr)


def detail(msg: str) -> None:
    print(f"    {_paint('2', '· ' + msg)}")


def die(msg: str, hint: str = "") -> None:
    """Print an error (with optional fix-it hint) and exit with status 1."""
    err(msg)
    if hint:
        print(f"    {_paint('2', hint)}", file=sys.stderr)
    raise SystemExit(1)
