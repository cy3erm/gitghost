"""Interactive console — a small Metasploit-style shell.

Set a target and options, then `run`. Running clears the terminal, prints the
banner, and executes the scan. The same scan functions as the CLI do the work,
so behavior and output are identical.

Launch with:  gitghost            (bare, on a TTY)
              gitghost -i         (explicit)
"""

import os
import shlex
import sys

from .banner import print_banner
from .ui import err, info

try:
    import readline  # noqa: F401 — arrow keys / history on Unix
except ImportError:
    readline = None


def _clear_screen() -> None:
    if sys.stdout.isatty():
        if os.name == "nt":
            os.system("cls")
        else:
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.flush()


# target -> (description, cli flag name)
TARGETS = ("local", "repo", "org", "user")

_BOOL_SETTINGS = {"gists", "network", "members"}
_INT_SETTINGS = {"limit", "jobs"}
_STR_SETTINGS = TARGETS + ("name", "out")

_DEFAULTS: dict[str, object] = {
    "local": "", "repo": "", "org": "", "user": "",
    "name": "local-repo",
    "limit": 30, "jobs": 4,
    "out": "gitghost-dossier.html",
    "gists": True, "network": False, "members": False,
}

_HELP = """\
  set <key> <value>   set an option (see `show` for keys)
  show                display current options
  run                 clear screen + banner, then execute the configured scan
  clear               clear screen and reprint the banner
  help                this message
  exit                quit

targets (set exactly one):
  user <name>         GitHub username to audit
  org <name>          organization's public repos
  repo <owner/name>   one repo by URL or owner/name
  local <path>        a checkout already on disk

options:
  limit <n>           max repos per identity      (default 30)
  jobs <n>            parallel clones/scans       (default 4)
  out <path>          report path                 (default gitghost-dossier.html)
  gists on|off        also scan public gists      (default on)
  network on|off      with user: crawl followers/following
  members on|off      with org: crawl public members
  name <label>        label for local scans       (default local-repo)"""


class Console:
    def __init__(self, debug: bool = False) -> None:
        self.debug = debug
        self.settings: dict[str, object] = dict(_DEFAULTS)

    # ------------------------------------------------------------ helpers

    @property
    def _prompt(self) -> str:
        target = next((t for t in TARGETS if self.settings[t]), "?")
        return "\033[38;5;208mgitghost\033[0m [\033[36m" + str(target) \
            + "\033[0m] > "

    def _parse_bool(self, value: str) -> bool | None:
        v = value.lower()
        if v in ("on", "true", "yes", "1"):
            return True
        if v in ("off", "false", "no", "0"):
            return False
        return None

    def _active_target(self) -> tuple[str, str] | None:
        for t in TARGETS:
            value = self.settings[t]
            if value:
                return t, str(value)
        return None

    # ------------------------------------------------------------ commands

    def cmd_set(self, args: list[str]) -> None:
        if len(args) != 2:
            err("usage: set <key> <value>   (keys: see `show`)")
            return
        key, raw = args
        if key in TARGETS:
            for t in TARGETS:
                self.settings[t] = ""
            self.settings[key] = raw
            info(f"{key} -> {raw}")
            return
        if key in _INT_SETTINGS:
            try:
                n = int(raw)
            except ValueError:
                err(f"{key} must be a number")
                return
            if n < 1:
                err(f"{key} must be >= 1")
                return
            self.settings[key] = n
            info(f"{key} -> {n}")
            return
        if key in _BOOL_SETTINGS:
            b = self._parse_bool(raw)
            if b is None:
                err(f"{key} takes on|off (got {raw!r})")
                return
            self.settings[key] = b
            info(f"{key} -> {'on' if b else 'off'}")
            return
        if key in _STR_SETTINGS:
            self.settings[key] = raw
            info(f"{key} -> {raw}")
            return
        err(f"unknown option {key!r} (keys: see `show`)")

    def cmd_show(self, _args: list[str]) -> None:
        width = max(len(k) for k in self.settings)
        print()
        for k, v in self.settings.items():
            marker = "*" if (k in TARGETS and v) else " "
            value = "(on)" if v is True else "(off)" if v is False else v
            print(f" {marker} {k:<{width}}   {value}")
        print()

    def cmd_run(self, debug: bool) -> None:
        from .cli import run_local, run_org, run_repo, run_identity

        target = self._active_target()
        if not target:
            err("no target set — use e.g.  set user octocat")
            return
        kind, value = target

        s = self.settings
        limit, jobs = int(s["limit"]), int(s["jobs"])
        out = str(s["out"])

        _clear_screen()
        print_banner()

        try:
            if kind == "user":
                run_identity(value, limit, out, jobs=jobs,
                             gists=bool(s["gists"]), network=bool(s["network"]))
            elif kind == "org":
                run_org(value, limit, out, jobs=jobs,
                        members=bool(s["members"]), gists=bool(s["gists"]))
            elif kind == "repo":
                run_repo(value, out)
            elif kind == "local":
                run_local(value, str(s["name"]) or "local-repo", out)
        except SystemExit:
            pass  # die() already printed the reason; stay in the console
        except Exception as e:
            if self.debug:
                raise
            err(f"unexpected failure: {type(e).__name__}: {e}")
            info("restart with --debug for the full traceback")
        info("done. back at the prompt.")

    # ------------------------------------------------------------ main loop

    def repl(self) -> None:
        _clear_screen()
        print_banner()
        print("type \033[2mhelp\033[0m for commands, \033[2mshow\033[0m for current options.\n")

        while True:
            try:
                line = input(self._prompt).strip()
            except (EOFError, KeyboardInterrupt):
                print("\nbye.")
                return
            if not line:
                continue

            try:
                parts = shlex.split(line)
            except ValueError:
                err("could not parse that line (unbalanced quote?)")
                continue
            cmd, args = parts[0].lower(), parts[1:]

            if cmd in ("exit", "quit", "q"):
                return
            elif cmd == "help":
                print(_HELP)
            elif cmd == "clear":
                _clear_screen()
                print_banner()
            elif cmd == "set":
                self.cmd_set(args)
            elif cmd in ("show", "options"):
                self.cmd_show(args)
            elif cmd == "run":
                try:
                    self.cmd_run(debug=self.debug)
                except KeyboardInterrupt:
                    print()
                    err("scan interrupted — partial results discarded")
            else:
                err(f"unknown command {cmd!r} — type help")


def run_console(debug: bool = False) -> None:
    Console(debug=debug).repl()
