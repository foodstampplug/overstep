"""The startup wordmark, printed to stderr at the top of a run."""

from __future__ import annotations

from . import __version__

_ART = r"""
  _____   _____ _ __ ___| |_ ___ _ __
 / _ \ \ / / _ \ '__/ __| __/ _ \ '_ \
| (_) \ V /  __/ |  \__ \ ||  __/ |_) |
 \___/ \_/ \___|_|  |___/\__\___| .__/
                                |_|
"""

_CYAN = "\033[36m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def banner(color: bool = True) -> str:
    art = _ART.strip("\n")
    tag = f"authorization / BOLA differential tester · v{__version__}"
    notice = "authorized testing only · in-scope only · reads-only unless --include-writes"
    if color:
        art = f"{_CYAN}{art}{_RESET}"
        tag = f"{_DIM}{tag}{_RESET}"
        notice = f"{_DIM}{notice}{_RESET}"
    return f"{art}\n  {tag}\n  {notice}\n"
