import os
import sys

from . import __version__

_ART = r"""
                     .-') _               ('-. .-.               .-')    .-') _
                    (  OO) )             ( OO )  /              ( OO ). (  OO) )
  ,----.     ,-.-') /     '._  ,----.    ,--. ,--. .-'),-----. (_)---\_)/     '._
 '  .-./-')  |  |OO)|'--...__)'  .-./-') |  | |  |( OO'  .-.  '/    _ | |'--...__)
 |  |_( O- ) |  |  \'--.  .--'|  |_( O- )|   .|  |/   |  | |  |\  :` `. '--.  .--'
 |  | .--, \ |  |(_/   |  |   |  | .--, \|       |\_) |  |\|  | '..`''.)   |  |
(|  | '. (_/,|  |_.'   |  |  (|  | '. (_/|  .-.  |  \ |  | |  |.-._)   \   |  |
 |  '--'  |(_|  |      |  |   |  '--'  | |  | |  |   `'  '-'  '\       /   |  |
  `------'   `--'      `--'    `------'  `--' `--'     `-----'  `-----'    `--'
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
