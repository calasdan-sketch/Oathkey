"""`safeeasyapi hook`: stop an AI agent reading your .env files.

Claude Code can run a small program before every tool call (a "PreToolUse
hook") and that program can say no. `hook install` adds one to Claude Code's
settings; `hook check` is that program. When the agent tries to Read, Grep
or run a Bash command that touches a .env file, the answer is "deny" and the
reason is handed back to the agent in plain words.

This is a guardrail, not a sandbox. It catches the direct ways (cat .env,
Read .env, grep KEY .env, source .env). A determined or confused program can
still build a file name out of pieces; keep keys out of the files too
(`safeeasyapi connect <service> --store keychain`).

The hook format lives in decision_json() and the settings shape in
hook_entry(): the two places to change if Claude Code changes either.
Checked against https://code.claude.com/docs/en/hooks (see the README for what
could not be confirmed).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import sysconfig
import tempfile

from . import recipes as recipes_mod

MATCHER = "Read|Grep|Bash"
HOOK_TIMEOUT = 10            # seconds (Claude Code's own default is 600)
MAX_STDIN = 1024 * 1024
TEMPLATE_SUFFIXES = frozenset({"example", "sample", "template", "dist",
                               "defaults", "default", "tpl", "schema"})
_ON_WINDOWS = os.name == "nt"

# .env, .env.local, .env.production, prod.env, .envrc - not a word that
# merely contains "env" (environment.py, my.environment). A match must start
# at the beginning of a path part, and end the name.
ENV_NAME_RE = re.compile(
    r"(?<![\w.\-])(?P<name>(?:\.env(?:rc)?(?P<suffix>(?:\.[\w\-]+)*)|[\w\-]+(?:\.[\w\-]+)*\.env))"
    r"(?![\w\-]|\.\w)", re.IGNORECASE)

REASON = (
    "safeeasyapi blocked this because {what} is a .env file, which holds "
    "secret API keys. Anything you read goes into your memory and the "
    "conversation log. Do not try another way to read it. If you need a key to run "
    "something, ask the person to run the command themselves, or use "
    "`safeeasyapi run <service> -- <command>`, which hands the key to the "
    "command without showing it. If you only need to know which variables "
    "exist, read .env.example instead.")


# ------------------------------------------------------------------ the check

def is_env_name(name: str) -> bool:
    """Is this file name a real .env file (not a template like .env.example)?"""
    m = ENV_NAME_RE.fullmatch(name.strip())
    if not m:
        return False
    return not _is_template(m)


def _is_template(m: re.Match) -> bool:
    suffix = (m.group("suffix") or "")
    parts = [p for p in suffix.split(".") if p]
    return bool(parts) and parts[-1].lower() in TEMPLATE_SUFFIXES


def find_env_files(text: str) -> list[str]:
    """Every .env-style file name mentioned in a path or a shell command that
    is not a template."""
    found = []
    for m in ENV_NAME_RE.finditer(text.replace("\\", "/")):
        if not _is_template(m):
            found.append(m.group("name"))
    return found


def _strings(value) -> list[str]:
    return [value] if isinstance(value, str) else []


def touched_text(payload: dict) -> list[str]:
    """The strings of a tool call that name files. One small function so the
    tool field names are in one place (Read: file_path; Grep: path, glob;
    Bash: command)."""
    tool = payload.get("tool_name")
    args = payload.get("tool_input")
    if not isinstance(args, dict):
        return []
    if tool == "Read":
        return _strings(args.get("file_path")) + _strings(args.get("path"))
    if tool == "Grep":
        return _strings(args.get("path")) + _strings(args.get("glob"))
    if tool == "Bash":
        return _strings(args.get("command"))
    return []


def decide(payload) -> str | None:
    """None to stay out of the way, or the name of the .env file refused."""
    if not isinstance(payload, dict):
        return None
    for text in touched_text(payload):
        hits = find_env_files(text)
        if hits:
            return hits[0]
    return None


def decision_json(reason: str) -> dict:
    """The answer Claude Code expects from a PreToolUse hook that says no
    (exit status 0 and this on stdout)."""
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}


def check(stdin_text: str) -> tuple[int, str]:
    """The hook program: (exit status, stdout text). Only ever answers "deny";
    for everything else it says nothing, so Claude Code's normal permission
    rules still apply (an "allow" here would skip them). Bad input is a
    non-blocking error (status 1): a broken hook must not stop all work."""
    try:
        payload = json.loads(stdin_text)
    except ValueError:
        return 1, ""
    name = decide(payload)
    if name is None:
        return 0, ""
    what = recipes_mod.printable(name)
    return 0, json.dumps(decision_json(REASON.format(what=f"'{what}'"))) + "\n"


def cmd_check(stdin=None, out=None, err=None) -> int:
    stdin = stdin or sys.stdin
    out = out or sys.stdout
    err = err or sys.stderr
    try:
        text = stdin.read(MAX_STDIN)
    except (OSError, ValueError):
        err.write("safeeasyapi hook check: could not read its input.\n")
        return 1
    status, answer = check(text)
    if status:
        err.write("safeeasyapi hook check: the input was not the JSON "
                  "Claude Code sends; nothing was blocked.\n")
        return status
    out.write(answer)
    return 0


# ----------------------------------------------------------------- the settings

def user_settings_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".claude", "settings.json")


def project_settings_path(cwd: str | None = None) -> str:
    return os.path.join(cwd or os.getcwd(), ".claude", "settings.json")


def _quote(arg: str) -> str:
    if _ON_WINDOWS:
        return '"' + arg.replace('"', '\\"') + '"' if re.search(r'[\s&()^%!]', arg) else arg
    return shlex.quote(arg)


def console_script() -> str | None:
    """Absolute path of this install's `safeeasyapi` program, or None."""
    name = "safeeasyapi.exe" if _ON_WINDOWS else "safeeasyapi"
    candidates = [os.path.join(os.path.dirname(os.path.abspath(sys.executable)), name)]
    try:
        candidates.append(os.path.join(sysconfig.get_path("scripts"), name))
    except (KeyError, OSError):
        pass
    found = shutil.which("safeeasyapi")
    if found:
        candidates.append(found)
    for path in candidates:
        path = os.path.abspath(path)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def hook_command() -> str:
    """The shell command Claude Code will run: the installed program by its
    full path, so nothing is looked up on a search path an agent could change;
    or, where there is no such program, this Python in isolated mode (-I:
    ignores the current folder and PYTHON* variables)."""
    script = console_script()
    if script:
        return f"{_quote(script)} hook check"
    return f"{_quote(os.path.abspath(sys.executable))} -I -m safeeasyapi hook check"


def hook_entry(command: str | None = None) -> dict:
    """One matcher group in settings.json -> hooks -> PreToolUse."""
    return {"matcher": MATCHER, "hooks": [{
        "type": "command",
        "command": command or hook_command(),
        "timeout": HOOK_TIMEOUT,
    }]}


def is_ours(handler) -> bool:
    cmd = handler.get("command") if isinstance(handler, dict) else None
    return (isinstance(cmd, str) and cmd.rstrip().endswith("hook check")
            and "safeeasyapi" in cmd)


class SettingsError(Exception):
    """The settings file cannot be safely changed. The text is for a person."""


def load_settings(path: str) -> dict:
    try:
        with open(path, encoding="utf-8-sig") as f:
            raw = f.read()
    except FileNotFoundError:
        return {}
    except OSError as e:
        raise SettingsError(f"{path} could not be read ({e.strerror or e})")
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        raise SettingsError(f"{path} is not valid JSON, so I left it alone. "
                            f"Fix it (or move it aside) and run this again.")
    if not isinstance(data, dict):
        raise SettingsError(f"{path} does not hold a JSON object, so I left it alone.")
    return data


def _pretool_list(data: dict, create: bool) -> list | None:
    hooks = data.get("hooks")
    if hooks is None:
        if not create:
            return None
        hooks = data["hooks"] = {}
    if not isinstance(hooks, dict):
        raise SettingsError("the \"hooks\" part of the settings is not an "
                            "object, so I left the file alone.")
    groups = hooks.get("PreToolUse")
    if groups is None:
        if not create:
            return None
        groups = hooks["PreToolUse"] = []
    if not isinstance(groups, list):
        raise SettingsError("\"hooks.PreToolUse\" in the settings is not a "
                            "list, so I left the file alone.")
    return groups


def _our_handlers(groups: list):
    for group in groups:
        inner = group.get("hooks") if isinstance(group, dict) else None
        if isinstance(inner, list):
            for handler in inner:
                if is_ours(handler):
                    yield group, handler


def merge_install(data: dict, command: str) -> str:
    """Add the hook to `data` in place without touching anyone else's.
    Returns "added", "updated" or "unchanged"."""
    groups = _pretool_list(data, create=True)
    mine = list(_our_handlers(groups))
    if not mine:
        groups.append(hook_entry(command))
        return "added"
    changed = False
    for group, handler in mine:
        if handler.get("command") != command or handler.get("timeout") != HOOK_TIMEOUT:
            handler["command"], handler["timeout"] = command, HOOK_TIMEOUT
            changed = True
        if group.get("matcher") != MATCHER:
            group["matcher"] = MATCHER
            changed = True
    return "updated" if changed else "unchanged"


def merge_uninstall(data: dict) -> int:
    """Remove only our handlers (and groups left empty by that). Returns how
    many handlers were removed."""
    groups = _pretool_list(data, create=False)
    if not groups:
        return 0
    removed = 0
    for group in list(groups):
        inner = group.get("hooks") if isinstance(group, dict) else None
        if not isinstance(inner, list):
            continue
        keep = [h for h in inner if not is_ours(h)]
        if len(keep) != len(inner):
            removed += len(inner) - len(keep)
            if keep:
                group["hooks"] = keep
            else:
                groups.remove(group)
    if removed and not groups:
        del data["hooks"]["PreToolUse"]
        if not data["hooks"]:
            del data["hooks"]
    return removed


def save_settings(path: str, data: dict, had_file: bool) -> None:
    """Write atomically; keep one copy of the old file next to it."""
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    if had_file:
        backup = path + ".safeeasyapi-backup"
        if not os.path.exists(backup):
            shutil.copy2(path, backup)
    fd, tmp = tempfile.mkstemp(prefix=".settings-", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
        if had_file:
            try:
                os.chmod(tmp, os.stat(path).st_mode & 0o777)
            except OSError:
                pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def self_test(command: str, run=subprocess.run) -> bool:
    """Run the installed command on a made-up Read of .env and see that it
    says no."""
    sample = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Read",
                         "tool_input": {"file_path": "/tmp/.env"}})
    try:
        done = run(command, input=sample.encode(), capture_output=True,
                   shell=True, timeout=30)
        answer = json.loads(done.stdout.decode("utf-8", "replace"))
        return answer["hookSpecificOutput"]["permissionDecision"] == "deny"
    except Exception:
        return False


def _resolve_path(args) -> str:
    if getattr(args, "settings", None):
        return args.settings
    return project_settings_path() if args.project else user_settings_path()


def cmd_hook(args, out=None, err=None, run=subprocess.run) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    action = args.hook_cmd
    if action == "check":
        return cmd_check()
    path = _resolve_path(args)
    shown = recipes_mod.printable(path)
    try:
        if action == "status":
            return _status(args, out, run)
        data = load_settings(path)
        had_file = os.path.exists(path)
        if action == "install":
            command = hook_command()
            result = merge_install(data, command)
            if result != "unchanged":
                save_settings(path, data, had_file)
            out.write(f"  {'Already installed' if result == 'unchanged' else result.capitalize()}"
                      f": the safeeasyapi hook in {shown}\n")
            out.write("  From now on Claude Code asks it before every Read, Grep and "
                      "Bash call, and it refuses .env files.\n")
            out.write("  Restart Claude Code (or open /hooks) so it picks the change up.\n")
            if not self_test(command, run):
                out.write("  Warning: a test run of the hook did not answer as expected, "
                          "so it may not be protecting you yet.\n"
                          f"  Command: {recipes_mod.printable(command)}\n")
                return 1
            return 0
        removed = merge_uninstall(data)
        if removed:
            save_settings(path, data, had_file)
            out.write(f"  Removed the safeeasyapi hook from {shown}. "
                      f"Your other hooks were not touched.\n")
        else:
            out.write(f"  No safeeasyapi hook found in {shown}; nothing changed.\n")
        return 0
    except SettingsError as e:
        err.write(f"error: {recipes_mod.printable(e)}\n")
        return 2
    except OSError as e:
        err.write(f"error: could not change {shown}: {e.strerror or e}\n")
        return 2


def _status(args, out, run) -> int:
    paths = ([args.settings] if getattr(args, "settings", None)
             else [user_settings_path(), project_settings_path()])
    installed = False
    for path in paths:
        shown = recipes_mod.printable(path)
        try:
            data = load_settings(path)
            groups = _pretool_list(data, create=False) or []
        except SettingsError as e:
            out.write(f"  {shown}: cannot tell - {recipes_mod.printable(e)}\n")
            continue
        mine = [h for _g, h in _our_handlers(groups)]
        if not mine:
            out.write(f"  {shown}: not installed\n")
            continue
        installed = True
        command = mine[0].get("command", "")
        works = self_test(command, run)
        out.write(f"  {shown}: installed, "
                  f"{'blocks a test read of .env' if works else 'but a test run did NOT block - reinstall it'}\n")
    if not installed:
        out.write("  Not installed. Run: safeeasyapi hook install\n")
    return 0 if installed else 1
