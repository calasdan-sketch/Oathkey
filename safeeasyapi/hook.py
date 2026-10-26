"""`safeeasyapi hook`: stop an AI agent reading your .env files.

Claude Code can run a small program before every tool call (a "PreToolUse
hook") and that program can say no. `hook install` adds one to Claude Code's
settings; `hook check` is that program. When the agent tries to Read, Grep,
or run a Bash, PowerShell or Monitor command that touches a .env file, or
tries to Edit, Write, MultiEdit or NotebookEdit one, the answer is "deny" and
the reason is handed back to the agent in plain words.

This is a guardrail, not a sandbox. It catches the direct ways (cat .env,
Read .env, grep KEY .env, source .env). A determined or confused program can
still build a file name out of pieces, sweep a folder (`grep -r KEY .`) or go
through a tool this hook is not attached to; keep keys out of the files too
(`safeeasyapi connect <service> --store keychain`). The README lists what it
does NOT stop.

Two safety rules for the code below:
* Nothing read from a settings file is ever executed. `hook status` runs only
  the command THIS install would generate, never one it found in a file (a
  cloned repository's .claude/settings.json is not trusted).
* Our own entry is recognised by a marker or by an exact command, never by
  "it looks like ours", and `install` always writes into a group of its own.

The hook format lives in decision_json() and the settings shape in
hook_handler() / hook_entry(): the places to change if Claude Code changes
either. Checked against https://code.claude.com/docs/en/hooks (see the
README for what could not be confirmed).
"""

from __future__ import annotations

import datetime
import hashlib
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

# Tools that can show a file's contents or run a command that does:
#   Read, Grep      - the file tools (tool_input: file_path / path / glob)
#   Bash, PowerShell - shell commands (tool_input.command)
#   Monitor         - runs a command in the background and streams its output
# Tools that would put a key INTO a file (0.5.2):
#   Edit, Write, MultiEdit, NotebookEdit - refused for a real .env file, because
#   a key typed by the agent has passed through the agent, and a Write can
#   overwrite the person's keys. Templates (.env.example) stay writable, and
#   SAFEEASYAPI_HOOK_ALLOW_WRITE=1 turns the write check off. Glob (names
#   only) is not matched.
MATCHER = "Read|Grep|Bash|PowerShell|Monitor|Edit|Write|MultiEdit|NotebookEdit"
WRITE_TOOLS = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})
ALLOW_WRITE_VAR = "SAFEEASYAPI_HOOK_ALLOW_WRITE"
MARKER = "safeeasyapi hook"      # the statusMessage that marks our handler
HOOK_TIMEOUT = 10            # seconds (Claude Code's own default is 600)
MAX_STDIN = 64 * 1024 * 1024  # read this much of Claude Code's JSON, no less
BACKUPS_TO_KEEP = 20
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
    "conversation log. Do not try another way to read it. If you need a key, call "
    "the safeeasyapi tool `capture_key` (service name): you click the vendor's "
    "Copy button in the browser and safeeasyapi takes the key from the clipboard "
    "without showing it to you (`needs_keys` lists which keys are missing). Only "
    "if capture_key is unavailable, tell the person to run `safeeasyapi connect "
    "<service>`; never ask for the key in chat. "
    "If a command needs the key to run, ask the person to run it themselves "
    "(`safeeasyapi run <service> -- <command>`) - do not run it for them. If "
    "you only need to know which variables exist, read .env.example instead.")

WRITE_REASON = (
    "Claude can't write to {what} - your keys stay out of the chat. "
    "Call the safeeasyapi tool `capture_key` (or `needs_keys` to see which key is "
    "missing) - or, if capture is unavailable, tell the person to run: "
    "safeeasyapi connect <service>  (or edit the file yourself).")


STEAL_REASON = (
    "safeeasyapi blocked this because it would {what}. Stored keys must stay "
    "out of the chat. Do not try another way. Call the safeeasyapi tool "
    "`capture_key` (or `needs_keys`); if capture is unavailable, ask the person "
    "to run the command themselves.")

# Ways a shell can pull a stored key out, or print it unredacted. Each is
# (regex, what it does). They are matched against the whole command text.
_SAFE = r"(?:^|[\s;&|`(\"'])"
STEAL_RULES = (
    (re.compile(r"safeeasyapi\b(?:(?!\s--\s)[^\n;&|])*\s--no-r\w*", re.I),
     "run a command with the key and turn output hiding off"),
    (re.compile(_SAFE + r"secret-tool\s+(?:lookup|search)\b", re.I), "read the Linux keyring"),
    (re.compile(_SAFE + r"security\s+(?:find-\w+-password|dump-keychain|export)\b", re.I),
     "read the macOS keychain"),
    (re.compile(_SAFE + r"cmdkey(?:\.exe)?\b", re.I), "read Windows stored credentials"),
    (re.compile(r"\b(?:Get-Secret|Get-SecretInfo|Get-StoredCredential|PasswordVault|CredRead|CredEnumerate|vaultcmd)\b", re.I),
     "read Windows stored credentials"),
    (re.compile(_SAFE + r"(?:kwallet-query|gnome-keyring-query|keyring\s+(?:get|--list)|pass\s+show)\b", re.I),
     "read a password store"),
    (re.compile(r"\b(?:import|from)\s+keyring\b|\bkeyring\.get_password\b", re.I), "read the keyring from code"),
    (re.compile(r"/proc/[\w$*{}/-]*/environ", re.I), "read another program's environment"),
    (re.compile(r"(?:^|[\s/\\~=:;&|(<>])\.safeeasyapi(?![\w])", re.I), "read safeeasyapi's own store"),
    (re.compile(r"consent\.key|agent-consent|\.safe\W*easy", re.I), "touch safeeasyapi's consent files"),
    (re.compile(_SAFE + r"(?:pbpaste|wl-paste|Get-Clipboard|xclip\b[^\n;&|]*\s-(?:o\b|out\b)|xsel\b[^\n;&|]*\s(?:-o\b|--output\b))", re.I),
     "read the clipboard"),
    (re.compile(r"\b(?:Windows\.Forms\.Clipboard|GetClipboardData|pyperclip|clipboard_get)\b", re.I),
     "read the clipboard from code"),
)


# What only the person may do (grant an agent the right to capture keys), and
# the files that record it. Matched against the command with quotes, carets,
# backslashes and shell variables taken out (STEAL_RULES are matched that way
# too), so allow""-agent, sec""ret-tool and a${x}llow-agent do not slip through.
# A SPEED BUMP, not a lock: it catches the plain and the lightly disguised
# forms only. See consent.py for what protects the grant itself.
CONSENT_RULES = (
    (re.compile(r"allow[-_]agent|agent[-_]consent|allowcmd|safeeasyapi\.(?:consent|capture)\b|"
                r"(?:consent|capture)_mod\b|consent\.(?:grant|_save_grants)|capture\.grant", re.I),
     "give itself permission to capture keys (only the person may)"),
)


def _squash(text: str) -> tuple[str, str]:
    """`text` without quotes, carets, backticks and backslashes; and also
    without shell variables."""
    plain = re.sub(r"[\'\"`^\\]", "", text)
    return plain, re.sub(r"\$\{[^}]*\}|\$\w+|\$\(\)", "", plain)


def steals_key(text: str) -> str | None:
    """What a shell command / path would do to a stored key, or None. A speed
    bump, not a lock: it reads the text of the call, and a program that builds
    its command at run time gets past it."""
    flat = text.replace("\\", "/") if "safeeasyapi" in text else text
    variants = (text, flat, *_squash(text))
    for rx, what in STEAL_RULES:
        if any(rx.search(v) for v in variants):
            return what
    for variant in variants:
        for rx, what in CONSENT_RULES:
            if rx.search(variant):
                return what
    return None


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
    """The strings of a tool call that name files or run commands. One small
    function so the tool field names are in one place (Read: file_path, path;
    Grep: path, glob; Bash and PowerShell: command; Monitor: command)."""
    tool = payload.get("tool_name")
    args = payload.get("tool_input")
    if not isinstance(args, dict):
        return []
    if tool in WRITE_TOOLS:
        # the one place for the write tools' field names: Edit, Write and
        # MultiEdit use file_path; NotebookEdit uses notebook_path. All three
        # names are read for every one of them so a rename cannot slip past.
        return [v for k in ("file_path", "notebook_path", "path")
                for v in _strings(args.get(k))]
    if tool == "Read":
        return _strings(args.get("file_path")) + _strings(args.get("path"))
    if tool == "Grep":
        return _strings(args.get("path")) + _strings(args.get("glob"))
    if tool in ("Bash", "PowerShell"):
        return _strings(args.get("command"))
    if tool == "Monitor":
        # the Monitor input is not documented field by field: look at every
        # text it carries (a command, or a WebSocket address) except the note
        return [v for k, v in args.items()
                if isinstance(v, str) and k != "description"]
    return []


def decide(payload) -> str | None:
    """None to stay out of the way, or the name of the .env file refused."""
    if not isinstance(payload, dict):
        return None
    if payload.get("tool_name") in WRITE_TOOLS and writes_allowed():
        return None
    for text in touched_text(payload):
        hits = find_env_files(text)
        if hits:
            return hits[0]
        if re.search(r"[\'\"`^]", text):
            # c''at .e''nv: the shell joins the pieces, so look at the joined text too
            for variant in _squash(text):
                hits = find_env_files(variant)
                if hits:
                    return hits[0]
    return None


def decide_steal(payload) -> str | None:
    """None, or what a Bash / PowerShell / Monitor / Read / Grep call would
    do to a stored key (see STEAL_RULES)."""
    if not isinstance(payload, dict):
        return None
    for text in touched_text(payload):
        what = steals_key(text)
        if what:
            return what
    return None


def writes_allowed(environ=None) -> bool:
    return (environ if environ is not None else os.environ).get(ALLOW_WRITE_VAR, "").strip() == "1"


def decision_json(reason: str) -> dict:
    """The answer Claude Code expects from a PreToolUse hook that says no
    (exit status 0 and this on stdout)."""
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}




def _read_all(stdin) -> str:
    """Everything Claude Code sent (up to MAX_STDIN), as text. Bytes that are
    not UTF-8 are replaced, never an error."""
    source = getattr(stdin, "buffer", None) or stdin
    data = source.read(MAX_STDIN)
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return data


def check(stdin_text: str) -> tuple[int, str]:
    """The hook program: (exit status, stdout text). Only ever answers "deny";
    for everything else it says nothing, so Claude Code's normal permission
    rules still apply (an "allow" here would skip them).

    Input that is not the JSON Claude Code sends (too big to parse, cut off,
    nested too deeply) is NOT waved through: the raw text is searched for a
    .env file name and, if one is there, the call is refused. Only when that
    finds nothing is it a non-blocking error (status 1): a broken hook must
    not stop all work unless you installed it with --fail-closed."""
    try:
        payload = json.loads(stdin_text)
    except (ValueError, RecursionError):
        # undo JSON's escapes so that "cat\t.env" or "...\\.env" still shows its name
        flat = re.sub(r'\\[nrtbf"]', " ", stdin_text.replace("\\\\", "/"))
        hits = find_env_files(flat)
        if hits:
            what = recipes_mod.printable(hits[0])
            return 0, json.dumps(decision_json(REASON.format(what=f"'{what}'"))) + "\n"
        what = steals_key(flat)
        if what:
            return 0, json.dumps(decision_json(STEAL_REASON.format(what=what))) + "\n"
        return 1, ""
    name = decide(payload)
    if name is None:
        what = decide_steal(payload)
        if what:
            return 0, json.dumps(decision_json(STEAL_REASON.format(what=what))) + "\n"
        return 0, ""
    what = recipes_mod.printable(name)
    if payload.get("tool_name") in WRITE_TOOLS:
        reason = WRITE_REASON.format(what=f"'{what}'")
    else:
        reason = REASON.format(what=f"'{what}'")
    return 0, json.dumps(decision_json(reason)) + "\n"


def cmd_check(stdin=None, out=None, err=None) -> int:
    stdin = stdin or sys.stdin
    out = out or sys.stdout
    err = err or sys.stderr
    try:
        text = _read_all(stdin)
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


def _in_current_folder(path: str) -> bool:
    """Is `path` a file of the folder we are running in? Compared as the
    folders themselves, not as text: the same folder has more than one
    spelling (/var/... and /private/var/... on macOS, a link, 8.3 names or a
    different case on Windows), and getcwd() gives only one of them."""
    here = os.getcwd()
    folder = os.path.dirname(os.path.abspath(path))
    try:
        if os.path.samefile(folder, here):
            return True
    except OSError:
        pass
    def norm(p):
        return os.path.normcase(os.path.realpath(p))
    return norm(folder) == norm(here)


def console_script() -> str | None:
    """Absolute path of this install's `safeeasyapi` program, or None."""
    name = "safeeasyapi.exe" if _ON_WINDOWS else "safeeasyapi"
    candidates = [os.path.join(os.path.dirname(os.path.abspath(sys.executable)), name)]
    try:
        candidates.append(os.path.join(sysconfig.get_path("scripts"), name))
    except (KeyError, OSError):
        pass
    found = shutil.which("safeeasyapi")
    # never a program that sits in the current folder (Windows looks there first)
    if found and not _in_current_folder(found):
        candidates.append(found)
    for path in candidates:
        path = os.path.abspath(path)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def hook_argv() -> list[str]:
    """The program and arguments Claude Code will start: the installed program
    by its full path, so nothing is looked up on a search path an agent could
    change; or, where there is no such program, this Python in isolated mode
    (-I: ignores the current folder and PYTHON* variables)."""
    script = console_script()
    if script:
        return [script, "hook", "check"]
    return [os.path.abspath(sys.executable), "-I", "-m", "safeeasyapi", "hook", "check"]


def _shell_quote(arg: str) -> str:
    if _ON_WINDOWS:
        # forward slashes: a backslash path is eaten by Git Bash
        arg = arg.replace("\\", "/")
        return '"' + arg + '"' if re.search(r"[\s&()^%!]", arg) else arg
    return shlex.quote(arg)


def hook_command() -> str:
    """The command as ONE string, for Claude Code's shell form (`sh -c` on
    macOS and Linux, Git Bash on Windows). Used on POSIX and, on Windows, only
    with --shell-form (older Claude Code)."""
    return " ".join(_shell_quote(a) for a in hook_argv())


def hook_handler(shell_form: bool | None = None, fail_closed: bool = False) -> dict:
    """The handler Claude Code stores: on Windows the documented exec form
    (`command` is the program, `args` its arguments, no shell, so a backslash
    or a space in the path cannot be mangled); elsewhere the shell string,
    which every Claude Code version understands. `shell_form=True` forces the
    string on Windows too, for a Claude Code that predates `args`."""
    if shell_form is None:
        shell_form = not _ON_WINDOWS
    handler: dict = {"type": "command"}
    if shell_form:
        handler["command"] = hook_command()
    else:
        argv = hook_argv()
        handler["command"], handler["args"] = argv[0], argv[1:]
    handler["timeout"] = HOOK_TIMEOUT
    handler["statusMessage"] = MARKER
    if fail_closed:
        handler["onFailure"] = "block"      # Claude Code 2.1.295 or later
    return handler


def hook_entry(handler: dict | None = None) -> dict:
    """One matcher group in settings.json -> hooks -> PreToolUse."""
    return {"matcher": MATCHER, "hooks": [handler or hook_handler()]}


def _unquote(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    return token


def _is_our_command_string(cmd: str) -> bool:
    """Exactly `<safeeasyapi program> hook check` or `<python> -I -m
    safeeasyapi hook check` - what 0.5.0 wrote - and nothing else: no extra
    words, no `&&`, no other program."""
    try:
        tokens = [_unquote(t) for t in shlex.split(cmd, posix=False)]
    except ValueError:
        return False
    if tokens[-2:] != ["hook", "check"]:
        return False
    if len(tokens) == 3:
        return re.split(r"[\\/]", tokens[0])[-1].lower() in ("safeeasyapi", "safeeasyapi.exe")
    return len(tokens) == 6 and tokens[2:4] == ["-m", "safeeasyapi"] and tokens[1] == "-I"


def is_ours(handler) -> bool:
    """Is this handler the one safeeasyapi wrote? Yes if it carries our
    marker, or if its command is exactly one that 0.5.0 wrote. A hook that
    merely mentions safeeasyapi (`safeeasyapi scan`, `... hook check; evil`)
    is not ours."""
    if not isinstance(handler, dict):
        return False
    if handler.get("statusMessage") == MARKER:
        return True
    cmd = handler.get("command")
    return (isinstance(cmd, str) and "args" not in handler
            and _is_our_command_string(cmd))


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


def _inner(group):
    inner = group.get("hooks") if isinstance(group, dict) else None
    return inner if isinstance(inner, list) else None


def _our_handlers(groups: list):
    for group in groups:
        for handler in _inner(group) or ():
            if is_ours(handler):
                yield group, handler


def _is_our_own_group(group) -> bool:
    inner = _inner(group)
    return bool(inner) and all(is_ours(h) for h in inner)


def merge_install(data: dict, handler: dict | str) -> str:
    """Put our hook into `data` in place without touching anyone else's.
    It always lives in a matcher group of its own. A group that holds other
    people's handlers is never edited, except that OUR handler is taken out
    of it (an older install may have put it there). Returns "added",
    "updated" or "unchanged"."""
    if isinstance(handler, str):                    # a bare command string
        handler = dict(hook_handler(shell_form=True), command=handler)
    groups = _pretool_list(data, create=True)
    desired = hook_entry(handler)
    changed = False
    for group in list(groups):                      # our handler in a shared group
        inner = _inner(group)
        if inner and not _is_our_own_group(group) and any(is_ours(h) for h in inner):
            group["hooks"] = [h for h in inner if not is_ours(h)]
            changed = True
    own = [g for g in groups if _is_our_own_group(g)]
    if not own:
        groups.append(desired)
        return "added"
    first = own[0]
    for extra in own[1:]:
        groups.remove(extra)
        changed = True
    if first.get("matcher") != desired["matcher"] or first.get("hooks") != desired["hooks"]:
        first["matcher"], first["hooks"] = desired["matcher"], desired["hooks"]
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
        inner = _inner(group)
        if inner is None:
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


def backup_dir() -> str:
    """Where copies of changed settings files go: under the user's home, never
    inside a project (a project's .claude/ folder is often committed)."""
    return os.path.join(os.path.expanduser("~"), ".safeeasyapi", "backups")


def _backup(target: str) -> str:
    folder = backup_dir()
    os.makedirs(folder, mode=0o700, exist_ok=True)
    tag = hashlib.sha256(target.encode("utf-8", "replace")).hexdigest()[:8]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    dest = os.path.join(folder, f"{tag}-{os.path.basename(target)}-{stamp}.bak")
    shutil.copy2(target, dest)
    try:
        os.chmod(dest, 0o600)
    except OSError:
        pass
    old = sorted(n for n in os.listdir(folder)
                 if n.startswith(tag + "-") and n.endswith(".bak"))
    for name in old[:-BACKUPS_TO_KEEP]:
        try:
            os.unlink(os.path.join(folder, name))
        except OSError:
            pass
    return dest


def save_settings(path: str, data: dict, had_file: bool) -> str | None:
    """Write atomically. A symbolic link is followed, so the file it points to
    is changed and the link stays a link. Every change first copies the old
    file to a new backup under ~/.safeeasyapi/backups (the last 20 per file are
    kept); returns the backup's path, or None for a new file."""
    target = os.path.realpath(path)
    folder = os.path.dirname(target)
    os.makedirs(folder, exist_ok=True)
    backup = _backup(target) if had_file and os.path.isfile(target) else None
    fd, tmp = tempfile.mkstemp(prefix=".settings-", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
        if had_file:
            try:
                os.chmod(tmp, os.stat(target).st_mode & 0o777)
            except OSError:
                pass
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return backup


def self_test(handler: dict | str, run=subprocess.run) -> bool:
    """Start the hook the way Claude Code does - exec form: the program with
    its arguments, no shell; shell form: `sh -c <string>` - on a made-up Read
    of .env and see that it says no. `handler` is always one THIS install
    generated, never one read from a file."""
    if isinstance(handler, str):
        handler = {"command": handler}
    sample = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Read",
                         "tool_input": {"file_path": "/tmp/.env"}})
    if "args" in handler:
        argv = [handler["command"], *handler["args"]]
    elif _ON_WINDOWS:
        argv = hook_argv()          # Git Bash cannot be started faithfully here
    else:
        argv = ["/bin/sh", "-c", handler["command"]]
    try:
        done = run(argv, input=sample.encode(), capture_output=True,
                   shell=False, timeout=30, cwd=tempfile.gettempdir())
        answer = json.loads(done.stdout.decode("utf-8", "replace"))
        return answer["hookSpecificOutput"]["permissionDecision"] == "deny"
    except Exception:
        return False


def _resolve_path(args) -> str:
    if getattr(args, "settings", None):
        return args.settings
    return project_settings_path() if args.project else user_settings_path()


def _backup_note(backup: str | None, project: bool) -> str:
    text = ""
    if backup:
        text += f"  The old file was copied to {recipes_mod.printable(backup)}\n"
    return text


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
            handler = hook_handler(shell_form=True if getattr(args, "shell_form", False) else None,
                                   fail_closed=getattr(args, "fail_closed", False))
            result = merge_install(data, handler)
            backup = None
            if result != "unchanged":
                backup = save_settings(path, data, had_file)
            out.write(f"  {'Already installed' if result == 'unchanged' else result.capitalize()}"
                      f": the safeeasyapi hook in {shown}\n")
            out.write(_backup_note(backup, getattr(args, "project", False)))
            out.write("  From now on Claude Code asks it before every Read, Grep, Bash, "
                      "PowerShell, Monitor, Edit, Write, MultiEdit and NotebookEdit call, "
                  "and it refuses .env files.\n")
            if getattr(args, "project", False):
                out.write("  This is the project's settings file: commit it if you want the "
                          "team to have the hook. Your hook's backups are kept outside the "
                          "project, in ~/.safeeasyapi/backups.\n")
            out.write("  Restart Claude Code (or open /hooks) so it picks the change up.\n")
            if not self_test(handler, run):
                out.write("  Warning: a test run of the hook did not answer as expected, "
                          "so it may not be protecting you yet.\n"
                          f"  Command: {recipes_mod.printable(_describe(handler))}\n")
                return 1
            return 0
        removed = merge_uninstall(data)
        if removed:
            backup = save_settings(path, data, had_file)
            out.write(f"  Removed the safeeasyapi hook from {shown}. "
                      f"Your other hooks were not touched.\n")
            out.write(_backup_note(backup, False))
        else:
            out.write(f"  No safeeasyapi hook found in {shown}; nothing changed.\n")
        return 0
    except SettingsError as e:
        err.write(f"error: {recipes_mod.printable(e)}\n")
        return 2
    except OSError as e:
        err.write(f"error: could not change {shown}: {e.strerror or e}\n")
        return 2


def _describe(handler: dict) -> str:
    return " ".join([handler.get("command", ""), *handler.get("args", [])])


def _status(args, out, run) -> int:
    paths = ([args.settings] if getattr(args, "settings", None)
             else [user_settings_path(), project_settings_path()])
    expected = hook_handler()
    tested: bool | None = None
    installed = False
    problem = False
    for path in paths:
        shown = recipes_mod.printable(path)
        try:
            data = load_settings(path)
            groups = _pretool_list(data, create=False) or []
        except SettingsError as e:
            out.write(f"  {shown}: cannot tell - {recipes_mod.printable(e)}\n")
            continue
        mine = list(_our_handlers(groups))
        if not mine:
            out.write(f"  {shown}: not installed\n")
            continue
        installed = True
        group, handler = mine[0]
        # NOTHING in the file is run: only the command this install generates
        if tested is None:
            tested = self_test(expected, run)
        notes = []
        if group.get("matcher") != MATCHER:
            notes.append("OUTDATED: it does not watch Edit, Write, MultiEdit and "
                         "NotebookEdit like this version does (run "
                         "`safeeasyapi hook install` to update it)")
        same = (handler.get("command") == expected["command"]
                and handler.get("args") == expected.get("args"))
        if not same:
            notes.append("its command is not the one this installation would write "
                         "(not run; `safeeasyapi hook install` rewrites it)")
        if tested:
            result = "this install's hook blocks a test read of .env"
        else:
            result = "but a test run of this install's hook did NOT block - reinstall it"
            problem = True
        extra = ("; " + "; ".join(notes)) if notes else ""
        out.write(f"  {shown}: installed, {result}{extra}\n")
    if not installed:
        out.write("  Not installed. Run: safeeasyapi hook install\n")
    return 0 if installed and not problem else 1
