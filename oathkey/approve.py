"""Ask the person before something risky happens.

Preferred: a real pop-up window from the operating system. It works even
when the AI app has no terminal (Claude Desktop, Cursor), and a program
cannot answer it by typing into a console. If no pop-up is possible we ask
on the console device itself and require a random 4-digit code that is only
shown on screen. If neither is possible the answer is NO.

Honest limit: a program running as you that can drive your screen
(UI automation) could still click a pop-up. SECURITY.md says so.
"""
from __future__ import annotations

import os
import random
import shutil
import subprocess
import sys

TIMEOUT = 120
MAX_SHOWN = 900      # broker refuses requests whose description is longer


def _tool(*paths):
    """First of these ABSOLUTE paths that is a real file. Never searches PATH
    or the current folder, so a program an AI dropped there cannot answer the
    pop-up for you."""
    for p in paths:
        if p and os.path.isfile(p):
            return p
    return None


def _safe(text: str, limit: int = MAX_SHOWN) -> str:
    s = "".join(c if c.isprintable() else " " for c in str(text))
    return s if len(s) <= limit else s[:limit] + "...[+%d more characters]" % (len(s) - limit)


def dialog(summary: str) -> bool | None:
    """True/False from a pop-up, or None if no pop-up could be shown."""
    msg = _safe(summary) + "\n\nAllow this?"
    env = dict(os.environ, SEA_MSG=msg)
    try:
        if os.name == "nt":
            root = os.environ.get("SystemRoot") or r"C:\Windows"
            ps = _tool(os.path.join(root, "System32", "WindowsPowerShell",
                                    "v1.0", "powershell.exe"))
            if not ps:
                return None
            cmd = [ps, "-NoProfile", "-NonInteractive", "-Command",
                   "Add-Type -AssemblyName System.Windows.Forms; "
                   "$r=[System.Windows.Forms.MessageBox]::Show($env:SEA_MSG,"
                   "'oathkey - permission needed','YesNo','Warning','Button2'); "
                   "if($r -eq 'Yes'){exit 0}else{exit 1}"]
            return subprocess.run(cmd, env=env, timeout=TIMEOUT,
                                  capture_output=True).returncode == 0
        if sys.platform == "darwin":
            osa = _tool("/usr/bin/osascript")
            if not osa:
                return None
            r = subprocess.run(
                [osa, "-e",
                 'display dialog (system attribute "SEA_MSG") with title '
                 '"oathkey - permission needed" buttons {"No","Yes"} '
                 'default button "No" with icon caution'],
                env=env, timeout=TIMEOUT, capture_output=True, text=True)
            return r.returncode == 0 and "button returned:Yes" in r.stdout
        for names, argv in ((("zenity",), ["--question", "--no-markup",
                                           "--title=oathkey", "--text=" + msg]),
                            (("kdialog",), ["--yesno", msg, "--title", "oathkey"])):
            exe = _tool(*[d + "/" + n for n in names for d in ("/usr/bin", "/bin")])
            if exe:
                return subprocess.run([exe] + argv, timeout=TIMEOUT,
                                      capture_output=True).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return None
    return None


def _flush(inp) -> None:
    try:
        if os.name == "nt":
            import msvcrt
            while msvcrt.kbhit():
                msvcrt.getwch()
        else:
            import termios
            termios.tcflush(inp.fileno(), termios.TCIFLUSH)
    except Exception:
        pass


def console(summary: str) -> bool:
    """Ask on the console device, with a code shown only on screen."""
    dev_in, dev_out = (("CONIN$", "CONOUT$") if os.name == "nt"
                       else ("/dev/tty", "/dev/tty"))
    code = "%04d" % random.SystemRandom().randrange(10000)
    try:
        with open(dev_out, "w", encoding="utf-8") as out, \
                open(dev_in, encoding="utf-8") as inp:
            _flush(inp)
            out.write(f"\noathkey needs your permission:\n  {_safe(summary)}\n"
                      f"To allow, type {code} and press Enter (anything else = no): ")
            out.flush()
            return inp.readline().strip() == code
    except OSError:
        return False


def ask_person(summary: str) -> bool:
    shown = dialog(summary)
    if shown is not None:
        return shown
    return console(summary)
