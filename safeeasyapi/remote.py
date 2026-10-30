"""`safeeasyapi remote` / `trust-server` / `deploy`: use a stored key on ANOTHER
machine, over ssh.

    safeeasyapi trust-server root@203.0.113.7            # once per server
    safeeasyapi remote --as calas github root@203.0.113.7 -- git -C /opt/app pull
    safeeasyapi deploy --dir /opt/app --as calas root@203.0.113.7

The key is read here (OS keychain first, then the .env file), sent to the
other machine on ssh's standard input, turned into an environment variable
for that one command, and forgotten. It is never put in a command line
(so never in `ps`, shell history or a log), never printed, and never written
to a file on the other machine.

For `github` the token is also turned into git's HTTP header - scoped to
https://github.com/ only - so a plain `git pull` just works on the far side.

Safety rules: a server must be confirmed by a person (on a real terminal)
before a key is ever sent to it; ssh never waits for a password during
`remote`; variable names that can change how a program runs (LD_PRELOAD,
BASH_ENV, PATH...) are refused.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys

from . import keychain as keychain_mod
from . import recipes as recipes_mod
from . import store as store_mod

# user@host, host, [v6]: letters, digits and . _ - @ : [ ] only. fullmatch, not
# `$`, so a trailing newline cannot slip through.
_HOST = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@:\[\]-]*")
_USER = re.compile(r"[a-z_][a-z0-9_-]*")
_VAR = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# names that change how a program starts or which program runs
_DANGEROUS = re.compile(
    r"(LD_.*|DYLD_.*|BASH_ENV|ENV|PATH|IFS|SHELL|HOME|USER|LOGNAME|PS4|PROMPT_COMMAND|"
    r"GIT_(SSH|SSH_COMMAND|ASKPASS|EXEC_PATH|CONFIG.*|DIR|WORK_TREE|PROXY_COMMAND)|"
    r"SSH_ASKPASS|NODE_OPTIONS|NODE_PATH|PYTHON.*|PERL5?LIB|PERL5?OPT|RUBYOPT|RUBYLIB|"
    r"JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|CLASSPATH)", re.IGNORECASE)

# git on the far side: token -> HTTP header for github.com ONLY, appended after
# any config the server already has, no prompt, no stored credential.
_GITHUB_PRELUDE = (
    'export GIT_TERMINAL_PROMPT=0; _sea_n=${GIT_CONFIG_COUNT:-0}; '
    'export "GIT_CONFIG_KEY_${_sea_n}=http.https://github.com/.extraHeader" '
    '"GIT_CONFIG_VALUE_${_sea_n}=Authorization: Basic '
    '$(printf "x-access-token:%s" "$GITHUB_TOKEN" | base64 | tr -d "\\n")"; '
    'GIT_CONFIG_COUNT=$((_sea_n+1)); export GIT_CONFIG_COUNT; unset _sea_n; ')


class RemoteError(Exception):
    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


def home_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".safeeasyapi")


def check_host(host: str) -> str:
    if not _HOST.fullmatch(host or ""):
        raise RemoteError(f"'{host}' is not a plain user@host address.", 2)
    return host


def check_var(var: str) -> str:
    if not _VAR.fullmatch(var) or _DANGEROUS.fullmatch(var):
        raise RemoteError(f"the variable name '{var}' is not allowed on a remote "
                          "machine (it could change how programs start).", 1)
    return var


# --- which servers a person has confirmed -----------------------------------

def _hosts_path() -> str:
    return os.path.join(home_dir(), "hosts.json")


def known_hosts() -> dict:
    try:
        with open(_hosts_path(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def remember_host(host: str, service: str) -> None:
    data = known_hosts()
    data.setdefault(host, [])
    if service not in data[host]:
        data[host].append(service)
    os.makedirs(home_dir(), exist_ok=True)
    tmp = _hosts_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, _hosts_path())


def confirm_host(host: str, service: str, ask=input, isatty=None) -> None:
    """A person must say yes, on a real terminal, before a key goes to a server
    for the first time. An agent or script cannot answer this."""
    if service in known_hosts().get(host, []):
        return
    tty = sys.stdin.isatty() if isatty is None else isatty
    if not tty:
        raise RemoteError(
            f"'{host}' has not been confirmed for '{service}' yet. Run "
            f"`safeeasyapi trust-server {host}` yourself in a terminal first "
            "(a key is never sent to a server nobody confirmed).", 1)
    answer = ask(f"  Send your '{service}' key to {host}? [y/N] ").strip().lower()
    if answer not in ("y", "yes"):
        raise RemoteError("cancelled - nothing was sent.", 1)
    remember_host(host, service)


# --- the key itself ---------------------------------------------------------

def collect_values(recipe: dict, env_file: str, backend=None) -> dict:
    """The stored value for every variable of the recipe. Never printed."""
    values: dict = {}
    if backend is None:
        backend = keychain_mod.detect_backend()
    env_values: dict = {}
    for var in recipes_mod.env_vars(recipe):
        check_var(var)
        value = None
        if backend:
            try:
                value = keychain_mod.read(recipe["service"], var, backend)
            except keychain_mod.KeychainUnavailable as e:
                raise RemoteError(f"the OS keychain did not answer ({e}); unlock "
                                  "it and try again.", 1)
            except keychain_mod.KeychainError:
                value = None            # simply not stored there
        if not value:
            if not env_values and os.path.exists(env_file):
                try:
                    store_mod.refuse_link(env_file)
                    env_values = store_mod.load_env(env_file)
                except OSError as e:
                    raise RemoteError(f"will not read {env_file}: {e}", 1)
            value = env_values.get(var)
        if not value:
            raise RemoteError(
                f"no stored key for '{recipe['service']}' ({var}). Run "
                f"`safeeasyapi connect {recipe['service']}` first.", 1)
        if "\n" in value or "\r" in value or "\0" in value:
            raise RemoteError(f"the stored {var} has a line break in it; "
                              "run `safeeasyapi rotate` to replace it.", 1)
        values[var] = value
    return values


def build_script(recipe: dict, command: list[str], run_as: str | None = None) -> str:
    """The shell text that runs on the far side. Contains NO secret: it only
    reads the values from its own standard input, one per line."""
    if not command:
        raise RemoteError("no command: safeeasyapi remote <service> <host> "
                          "-- <command>", 2)
    parts = []
    for i, var in enumerate(recipes_mod.env_vars(recipe)):
        check_var(var)
        parts.append(f'IFS= read -r _sea_{i}; export {var}="$_sea_{i}"; '
                     f'unset _sea_{i}; ')
    prelude = "".join(parts)
    if recipe["service"] == "github":
        prelude += _GITHUB_PRELUDE
    if len(command) == 1 and " " in command[0]:
        # "cd /opt && git pull" as ONE word: run it as a shell line
        cmd = "sh -c " + shlex.quote(command[0])
    else:
        cmd = " ".join(shlex.quote(c) for c in command)
    if run_as:
        if not _USER.fullmatch(run_as):
            raise RemoteError(f"'{run_as}' is not a plain user name.", 2)
        # runuser keeps the environment; only root on Linux may use it.
        cmd = (f"command -v runuser >/dev/null 2>&1 || {{ echo 'error: --as needs "
               f"a root login on a Linux server' >&2; exit 126; }}; "
               f"exec runuser -u {run_as} -- {cmd}")
    else:
        cmd = "exec " + cmd
    return prelude + cmd


def key_for(host: str) -> str | None:
    """The key trust-server made for this host, if there is one."""
    p = os.path.join(home_dir(), "keys", _safe_name(host) + "_ed25519")
    return p if os.path.exists(p) else None


def _safe_name(host: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", host)


_SAFE_SSH_OPTS = {"port", "connecttimeout", "serveraliveinterval",
                  "serveralivecountmax", "compression", "ipqos"}


def check_ssh_args(extra: list[str] | None) -> list[str]:
    """Only a few harmless ssh options may be passed through. `-o
    ProxyCommand=...`, `LocalCommand`, `-F`, `-J` and friends run programs
    or change who we trust, so an AI that can pick them can run anything."""
    args = list(extra or [])
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-p" and i + 1 < len(args) and args[i + 1].isdigit():
            i += 2
            continue
        glued = a.startswith("-o") and len(a) > 2
        if glued or (a == "-o" and i + 1 < len(args)):
            name, _, val = (a[2:] if glued else args[i + 1]).partition("=")
            name = name.strip().lower()
            ok = ((name in _SAFE_SSH_OPTS
                   or (name == "stricthostkeychecking" and val in ("yes", "ask")))
                  and "\n" not in val)
            if ok:
                i += 1 if glued else 2
                continue
        raise RemoteError(f"ssh option not allowed: {a!r}. Only -p and "
                          "-o with Port, ConnectTimeout, ServerAliveInterval, "
                          "ServerAliveCountMax, Compression are accepted.", 2)
    return args


def ssh_command(host: str, script: str, extra: list[str] | None = None,
                identity: str | None = None) -> list[str]:
    extra = check_ssh_args(extra)
    ident = ["-i", identity, "-o", "IdentitiesOnly=yes"] if identity else []
    # user-supplied options come FIRST: ssh keeps the first value it sees
    return (["ssh", "-T"] + list(extra or []) + ident
            + ["-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
               "-o", "StrictHostKeyChecking=accept-new"]
            + ["--", host, "sh -c " + shlex.quote(script)])


def explain_failure(code: int, host: str) -> None:
    if code == 255:
        print(f"error: ssh could not connect or log in to {host}. Likely causes: "
              "the server does not trust this PC yet (run `safeeasyapi "
              f"trust-server {host}`), wrong address or port, a firewall, or the "
              f"server's key changed. Run `ssh {host} true` to see ssh's own "
              "message.", file=sys.stderr)
    elif code == 127:
        print("error: the server could not find that program. Put the whole "
              "command after `--` (for example `-- git -C /opt/app pull`). "
              "`cd`, `&&` and `|` are not programs: quote the whole line.",
              file=sys.stderr)


def run_remote(recipe: dict, host: str, command: list[str], env_file: str = ".env",
               run_as: str | None = None, ssh_args: list[str] | None = None,
               runner=subprocess.run, backend=None, ask=input, isatty=None) -> int:
    check_host(host)
    if command and command[0] == "--":
        command = command[1:]
    script = build_script(recipe, command, run_as)
    confirm_host(host, recipe["service"], ask=ask, isatty=isatty)
    values = collect_values(recipe, env_file, backend)
    payload = "".join(values[v] + "\n" for v in recipes_mod.env_vars(recipe))
    argv = ssh_command(host, script, ssh_args, key_for(host))
    try:
        done = runner(argv, input=payload.encode("utf-8"))
    except FileNotFoundError:
        raise RemoteError("ssh is not installed here (on Windows: Settings > "
                          "Apps > Optional features > OpenSSH Client).", 1)
    explain_failure(done.returncode, host)
    return done.returncode


# --- trust-server: one command instead of five ------------------------------

def ensure_ssh_access(host: str, runner=subprocess.run, out=print) -> str:
    """Make this PC trusted by `host`: make a dedicated key, install it (one
    password prompt in the person's own terminal), and prove it works."""
    check_host(host)
    keydir = os.path.join(home_dir(), "keys")
    os.makedirs(keydir, exist_ok=True)
    key = os.path.join(keydir, _safe_name(host) + "_ed25519")

    def works() -> bool:
        r = runner(["ssh", "-T", "-i", key, "-o", "IdentitiesOnly=yes", "-o",
                    "BatchMode=yes", "-o", "ConnectTimeout=15", "-o",
                    "StrictHostKeyChecking=accept-new", "--", host, "true"],
                   capture_output=True)
        return r.returncode == 0

    if os.path.exists(key) and works():
        out(f"  {host} already trusts this PC.")
        return key
    if not os.path.exists(key):
        r = runner(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                    "safeeasyapi-" + _safe_name(host), "-f", key])
        if r.returncode != 0:
            raise RemoteError("could not make an ssh key (is the OpenSSH client "
                              "installed?).", 1)
    pub = open(key + ".pub", encoding="utf-8").read().strip()
    install = ("umask 077; mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys "
               "&& chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys")
    out(f"  Installing a key on {host} - if it asks, type that server's login "
        "password (it is typed into ssh, not into this tool).")
    r = runner(["ssh", "-o", "StrictHostKeyChecking=accept-new", "--", host,
                install], input=(pub + "\n").encode("utf-8"))
    if r.returncode != 0 or not works():
        out("  Could not install it automatically. Paste this ONE line into the "
            f"server's own console (typing works even where pasting does not):\n\n"
            f"    mkdir -p ~/.ssh && echo '{pub}' >> ~/.ssh/authorized_keys\n\n"
            f"  then run `safeeasyapi trust-server {host}` again.")
        raise RemoteError("the server does not trust this PC yet.", 1)
    out(f"  {host} now trusts this PC.")
    return key
