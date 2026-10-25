"""A yes/no question in a window of the operating system, outside the agent's reach.

The person's permission for agent-driven key capture is asked here, by the
MCP server itself, not by anything the agent can type into. Windows: a system
MessageBox. macOS: osascript. Linux: zenity or kdialog. With no graphical
session (SSH, a container, a server) there is no window: `confirm` returns
None and the caller falls back to the terminal command, which is weaker
(an agent can fake a terminal) and is labelled that way.

Not a lock against an agent that has full computer-use control of the screen
and presses the button itself; it stops every agent that works through files
and shell commands.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

TIMEOUT_SECONDS = 180


def available(platform: str | None = None, env=None, which=shutil.which) -> bool:
    platform = platform or sys.platform
    env = os.environ if env is None else env
    if platform == "win32":
        return True
    if platform == "darwin":
        return bool(which("osascript")) and not env.get("SSH_CONNECTION")
    if env.get("SSH_CONNECTION") or not (env.get("DISPLAY") or env.get("WAYLAND_DISPLAY")):
        return False
    return bool(which("zenity") or which("kdialog"))


def _applescript_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _message_box(title: str, message: str) -> bool:
    import ctypes
    MB_YESNO, MB_ICONQUESTION, MB_DEFBUTTON2 = 0x4, 0x20, 0x100
    MB_SETFOREGROUND, MB_TOPMOST = 0x10000, 0x40000
    answer = ctypes.windll.user32.MessageBoxW(
        None, message, title,
        MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST)
    return answer == 6          # IDYES


def confirm(title: str, message: str, platform: str | None = None, env=None,
            which=shutil.which, run=subprocess.run, message_box=_message_box) -> bool | None:
    """True when the person pressed the allowing button, False when they
    declined or closed the window, None when no window can be shown."""
    platform = platform or sys.platform
    if not available(platform, env, which):
        return None
    try:
        if platform == "win32":
            return bool(message_box(title, message))
        if platform == "darwin":
            script = (f'display dialog "{_applescript_text(message)}" with title '
                      f'"{_applescript_text(title)}" buttons {{"Deny", "Allow"}} '
                      f'default button "Deny" cancel button "Deny" with icon caution '
                      f'giving up after {TIMEOUT_SECONDS}')
            done = run(["osascript", "-e", script], capture_output=True, timeout=TIMEOUT_SECONDS + 10)
            return done.returncode == 0 and b"gave up:true" not in (done.stdout or b"") \
                and b"Allow" in (done.stdout or b"")
        if which("zenity"):
            done = run(["zenity", "--question", "--title", title, "--text", message,
                        "--ok-label", "Allow", "--cancel-label", "Deny", "--default-cancel",
                        f"--timeout={TIMEOUT_SECONDS}"], capture_output=True,
                       timeout=TIMEOUT_SECONDS + 10)
            return done.returncode == 0
        done = run(["kdialog", "--title", title, "--yesno", message, "--yes-label", "Allow",
                    "--no-label", "Deny"], capture_output=True, timeout=TIMEOUT_SECONDS + 10)
        return done.returncode == 0
    except Exception:
        return False        # a window that failed is a "no", never a "yes"
