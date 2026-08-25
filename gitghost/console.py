"""Guided interactive mode.

Run gitghost bare (or with -i): the screen clears, the banner prints, you
pick a target, type it in, and the scan starts. Same engine and output as
the CLI — this is just a friendlier front door.
"""

import os
import sys

from .banner import print_banner
from .ui import err


def _clear_screen() -> None:
    if sys.stdout.isatty():
        if os.name == "nt":
            os.system("cls")
        else:
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.flush()


_CREDITS = "\033[2mby cy3erm\033[0m · \033[2mgithub.com/cy3erm/gitghost"
_RESET = "\033[0m"

_MENU = """
  \033[38;5;208m1\033[0m) Scan a GitHub user          public repos + gists
  \033[38;5;208m2\033[0m) Scan an organization       public repos of an org
  \033[38;5;208m3\033[0m) Scan a single repo         by owner/name or URL
  \033[38;5;208m4\033[0m) Scan a local checkout      a repo already on disk
"""

_PROMPTS = {
    "1": ("GitHub username", "user"),
    "2": ("Organization name", "org"),
    "3": ("Repo (owner/name or URL)", "repo"),
    "4": ("Path to local checkout", "local"),
}


def _input(prompt: str) -> str | None:
    """Read a line; None means the user wants out (Ctrl+C / EOF)."""
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return None


def _dispatch(kind: str, value: str, debug: bool) -> None:
    from .cli import run_identity, run_local, run_org, run_repo

    try:
        if kind == "user":
            run_identity(value, limit=30, out="gitghost-dossier.html")
        elif kind == "org":
            run_org(value, limit=30, out="gitghost-dossier.html")
        elif kind == "repo":
            run_repo(value, out="gitghost-dossier.html")
        elif kind == "local":
            run_local(value, value.rstrip("/").rsplit("/", 1)[-1] or "local-repo",
                      "gitghost-dossier.html")
    except SystemExit:
        pass  # die() already printed why; stay interactive
    except Exception as e:
        if debug:
            raise
        err(f"unexpected failure: {type(e).__name__}: {e}")
        print("    \033[2mrestart with --debug for the full traceback\033[0m")


def run_console(debug: bool = False) -> None:
    _clear_screen()
    print_banner()
    print(_CREDITS + _RESET)

    while True:
        print(_MENU)
        choice = _input("select a mode [1-4], q to quit > ")
        if choice is None or choice.lower() in ("q", "quit", "exit"):
            print("bye.")
            return
        if choice not in _PROMPTS:
            err(f"no mode {choice!r} — pick 1, 2, 3, 4, or q")
            continue

        label, kind = _PROMPTS[choice]
        value = _input(f"{label} > ")
        if value is None:
            print("\nbye.")
            return
        if not value:
            err("you need to enter something first")
            continue

        print()
        _dispatch(kind, value, debug)

        again = _input("\nscan another? [Y/n] > ")
        if again and again.lower().startswith("n"):
            print("bye.")
            return
