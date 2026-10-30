"""`oathkey about`: who made this, and how to check it is the real one."""

from __future__ import annotations

import sys

from . import __version__

HOMEPAGE = "https://github.com/calasdan-sketch/oathkey"
PYPI = "https://pypi.org/project/oathkey/"


def text() -> str:
    return f"""  oathkey {__version__}
  A free tool that keeps your API keys safe. Made by Calas Automations Inc.
  It runs on this computer; it has no account and sends nothing to us.

  To check this is the real program:
    1. See what is installed:   pip show oathkey
       (Author: Calas Automations Inc.; Home-page: the GitHub address below)
    2. The package page:        {PYPI}
    3. The source code:         {HOMEPAGE}
  The permission windows it shows say "oathkey" in the title. The name of the
  AI program in them (for example Claude Code) is what that program reports about
  itself; oathkey cannot prove it.
"""


def cmd_about(out=None) -> int:
    (out or sys.stdout).write(text())
    return 0
