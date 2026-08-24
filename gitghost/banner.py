import os
import sys

from . import __version__

_ART = r"""
   ____ _(_) /_____ _/ /_  ____  _____/ /_
  / __ `/ / __/ __ `/ __ \/ __ \/ ___/ __/
 / /_/ / / /_/ /_/ / / / /_/ (__  ) /_
 \__, /_/\__/\__, /_/ /_/\____/____/\__/
/____/      /____/
""".strip("\n").splitlines()

_TAGLINE = "the secrets you deleted are still in git history"


def print_banner() -> None:
    """Print the wordmark; plain text (and shorter) when not on a TTY."""
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        print(f"gitghost v{__version__} - {_TAGLINE}")
        return

    orange, dim, grey, reset = "\033[38;5;208m", "\033[2m", "\033[38;5;245m", "\033[0m"
    for line in _ART:
        print(orange + line + reset)
    print(f"{dim}{_TAGLINE}{reset} {grey}v{__version__}{reset}")
    print()
