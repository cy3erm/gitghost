import sys

from . import __version__

_ART = r"""
   ____ _(_) /_____ _/ /_  ____  _____/ /_
  / __ `/ / __/ __ `/ __ \/ __ \/ ___/ __/
 / /_/ / / /_/ /_/ / / / / /_/ (__  ) /_
 \__, /_/\__/\__, /_/ /_/\____/____/\__/
/____/      /____/
"""

_GHOST = r"""      .-.
     (o o)
     | O |
      \_/
"""


def banner():
    if not sys.stdout.isatty():
        return ""
    orange, dim, ghost_c, reset = "\033[38;5;208m", "\033[2m", "\033[38;5;250m", "\033[0m"
    art = _ART.strip("\n").splitlines()
    ghost = _GHOST.strip("\n").splitlines()
    width = max(len(l) for l in art) + 4
    out = []
    for i, line in enumerate(art):
        g = ghost[i] if i < len(ghost) else ""
        out.append(orange + line.ljust(width) + reset + ghost_c + g + reset)
    tag = f"{dim}  the secrets you deleted are still in git history{reset}   {orange}v{__version__}{reset}"
    return "\n".join(out) + "\n" + tag + "\n"


def print_banner():
    b = banner()
    if b:
        print(b)
