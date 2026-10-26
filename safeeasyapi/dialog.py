"""A yes/no question in a window of the operating system, outside the agent's reach.

The person's permission for agent-driven key capture is asked here, by the
MCP server itself, not by anything the agent can type into. Windows: a system
MessageBox (with a timeout). macOS: osascript. Linux: zenity or kdialog,
found only in fixed system folders (safeexec.py) and run with a fixed
environment. With no graphical session (SSH, a container, a server) there is
no window: `confirm` returns None and the caller falls back to the terminal
command, which is weaker (an agent can fake a terminal) and is labelled so.

What this is, honestly: a real gate against an agent that works through files
and shell commands and cannot run code as the same user as this server. It is
NOT a gate against an agent that can run code as that user (it can drive the
same OS interfaces) or that controls the screen and presses the button itself.

Answers: True (allowed), False (declined or closed), None (no window could be
shown, or nobody answered in time - not a refusal, and may be asked again).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time

from . import safeexec

TIMEOUT_SECONDS = 180


def available(platform: str | None = None, env=None, which=safeexec.find) -> bool:
    platform = platform or sys.platform
    env = os.environ if env is None else env
    # NOTE: this switch is read from the server's environment, which the MCP client's
    # config sets; an agent that can edit that config can set it (and so fall back to
    # the advisory terminal route). It is a convenience, not a lock.
    if env.get("SAFEEASYAPI_NO_WINDOW") == "1":
        return False                    # the person turned windows off for this server
    if platform == "win32":
        return True
    if platform == "darwin":
        return bool(which("osascript")) and not env.get("SSH_CONNECTION")
    if env.get("SSH_CONNECTION") or not (env.get("DISPLAY") or env.get("WAYLAND_DISPLAY")):
        return False
    return bool(which("zenity") or which("kdialog"))


MAX_TITLE = 90
MAX_MESSAGE = 1600
MAX_PATH = 120


def plain(text: str, limit: int = MAX_MESSAGE) -> str:
    """Text that cannot mislead: ASCII only (a look-alike letter from another
    alphabet becomes '?'), no control characters except line breaks, cut to
    `limit` characters."""
    text = re.sub(r"[^\x20-\x7e\n]", "?", str(text))
    return text if len(text) <= limit else text[:limit - 3] + "..."


def short_path(path: str, limit: int = MAX_PATH) -> str:
    """The END of a path (where the project is), plain, at most `limit` long."""
    path = plain(path, 10_000)
    return path if len(path) <= limit else "..." + path[-(limit - 3):]


def why_unavailable(platform: str | None = None, env=None, explain=safeexec.explain) -> str | None:
    """When the only reason there is no window is that a helper program was
    REFUSED (not root-owned ...), say so; else None."""
    platform = platform or sys.platform
    names = ("osascript",) if platform == "darwin" else (
        () if platform == "win32" else ("zenity", "kdialog"))
    for name in names:
        why = explain(name)
        if why:
            return why
    return None


def markup_free(text: str) -> str:
    """No characters a rich-text widget could read as markup."""
    return re.sub(r"[<>&]", "?", text)


def _applescript_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _message_box(title: str, message: str, seconds: int = TIMEOUT_SECONDS) -> bool | None:
    """True / False, or None when nobody answered within `seconds`.
    MessageBoxTimeoutW (user32, long-standing but undocumented) closes the box
    itself; without it a watchdog thread posts WM_CLOSE to the box."""
    import ctypes
    import threading
    MB_YESNO, MB_ICONQUESTION, MB_DEFBUTTON2 = 0x4, 0x20, 0x100
    MB_SETFOREGROUND, MB_TOPMOST = 0x10000, 0x40000
    flags = MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST
    user32 = ctypes.windll.user32
    timeout_fn = getattr(user32, "MessageBoxTimeoutW", None)
    if timeout_fn is not None:
        answer = timeout_fn(None, message, title, flags, 0, int(seconds * 1000))
        return None if answer == 32000 else answer == 6        # 32000: timed out
    done = threading.Event()

    def watchdog():
        if not done.wait(seconds):
            WM_CLOSE = 0x10
            hwnd = user32.FindWindowW(None, title)
            if hwnd:
                user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
    timer = threading.Thread(target=watchdog, daemon=True)
    timer.start()
    started = time.monotonic()
    try:
        answer = user32.MessageBoxW(None, message, title, flags)
    finally:
        done.set()
    if answer == 6:
        return True
    # a box closed by the watchdog answers IDNO (7) after the full time
    return None if time.monotonic() - started >= seconds - 1 else False


def _launch_failed(code: int, err: bytes = b"") -> bool:
    """Not an answer: an odd exit status, or exit 1 WITH an error message (the
    display could not be opened, a flag is unknown ...). A real "No" is exit 1
    and silence."""
    return code not in (0, 1, 5) or (code == 1 and bool((err or b"").strip()))


def _no_or_failure(done) -> bool | None:
    """False only for an explicit No (exit 1, empty stderr); else None."""
    if done.returncode == 1 and not (done.stderr or b"").strip():
        return False
    return None


def confirm(title: str, message: str, platform: str | None = None, env=None,
            which=safeexec.find, run=safeexec.run, message_box=_message_box) -> bool | None:
    """True when the person pressed the allowing button, False ONLY when they
    declined (or closed the window), None when no window can be shown, nobody
    answered in time, or the helper failed (crash, unsupported flag, odd exit
    status): a failure is never turned into the person's "no"."""
    platform = platform or sys.platform
    if not available(platform, env, which):
        return None
    title, message = plain(title, MAX_TITLE), plain(message)
    try:
        if platform == "win32":
            answer = message_box(title, message)
            return None if answer is None else bool(answer)
        if platform == "darwin":
            script = (f'display dialog "{_applescript_text(message)}" with title '
                      f'"{_applescript_text(title)}" buttons {{"Deny", "Allow"}} '
                      f'default button "Deny" cancel button "Deny" with icon caution '
                      f'giving up after {TIMEOUT_SECONDS}')
            done = run([which("osascript"), "-e", script], capture_output=True,
                       timeout=TIMEOUT_SECONDS + 10)
            out, err = done.stdout or b"", done.stderr or b""
            if b"gave up:true" in out:
                return None
            if done.returncode == 0:
                return True if b"Allow" in out else None
            # pressing Deny / Esc is "User canceled" (-128); anything else is a failure
            return False if (b"-128" in err or b"User canceled" in err) else None
        if which("zenity"):
            base = [which("zenity"), "--question", "--title", title, "--text", message,
                    "--ok-label", "Allow", "--cancel-label", "Deny"]
            first = base + ["--no-markup", "--default-cancel", f"--timeout={TIMEOUT_SECONDS}"]
            done = run(first, capture_output=True, timeout=TIMEOUT_SECONDS + 10)
            if _launch_failed(done.returncode, done.stderr):
                # an old zenity does not know --no-markup / --default-cancel: ask again
                # without them, with the markup characters taken out of the text
                again = list(base)
                again[again.index("--text") + 1] = markup_free(message)
                again.append(f"--timeout={TIMEOUT_SECONDS}")
                done = run(again, capture_output=True, timeout=TIMEOUT_SECONDS + 10)
            if done.returncode == 5:            # zenity: timed out
                return None
            if done.returncode == 0:
                return True
            return _no_or_failure(done)
        done = run([which("kdialog"), "--title", title, "--yesno", markup_free(message),
                    "--yes-label", "Allow", "--no-label", "Deny"], capture_output=True,
                   timeout=TIMEOUT_SECONDS + 10)
        if done.returncode == 0:
            return True
        return _no_or_failure(done)
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None
