"""`safeeasyapi remote`: use a stored key on ANOTHER machine, over ssh.

    safeeasyapi remote github root@203.0.113.7 --as calas -- \
        git -C /opt/app pull --ff-only

The key is read here (OS keychain first, then the .env file), sent to the
other machine on ssh's standard input, turned into an environment variable
for that one command, and forgotten. It is never put in a command line
(so never in `ps`, shell history or a log), never printed, and never written
to a file on the other machine.

For `github` the token is also turned into git's HTTP header, so a plain
`git pull` / `git clone https://github.com/...` just works on the far side.

Needs: ssh access with a key (BatchMode: it will never stop to ask for a
password, because a hidden password prompt is exactly what an automated
helper must not be waiting on).
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys

from . import keychain as keychain_mod
from . import recipes as recipes_mod
from . import store as store_mod

# user@host, host, [v6]: letters, digits and . _ - @ : [ ] only. Anything
# else (spaces, quotes, a leading dash that ssh would read as an option) is
# refused before ssh ever sees it.
_HOST = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@:\[\]-]*$")
_USER = re.compile(r"^[a-z_][a-z0-9_-]*$")
_VAR = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# git on the far side: token -> HTTP header, no prompt, no stored credential.
_GITHUB_PRELUDE = (
    'export GIT_TERMINAL_PROMPT=0 GIT_CONFIG_COUNT=1 '
    'GIT_CONFIG_KEY_0=http.extraHeader '
    'GIT_CONFIG_VALUE_0="Authorization: Basic '
    '$(printf "x-access-token:%s" "$GITHUB_TOKEN" | base64 | tr -d "\\n")"; ')


class RemoteError(Exception):
    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


def check_host(host: str) -> str:
    if not _HOST.match(host or ""):
        raise RemoteError(f"'{host}' is not a plain user@host address.", 2)
    return host


def collect_values(recipe: dict, env_file: str, backend=None) -> dict:
    """The stored value for every variable of the recipe. Never printed."""
    values: dict = {}
    if backend is None:
        backend = keychain_mod.detect_backend()
    env_values: dict = {}
    for var in recipes_mod.env_vars(recipe):
        value = None
        if backend:
            try:
                value = keychain_mod.read(recipe["service"], var, backend)
            except keychain_mod.KeychainError:
                value = None
        if not value:
            if not env_values and os.path.exists(env_file):
                env_values = store_mod.load_env(env_file)
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
        if not _VAR.match(var):
            raise RemoteError(f"unsafe variable name '{var}' in the recipe.", 1)
        parts.append(f'IFS= read -r _sea_{i}; export {var}="$_sea_{i}"; '
                     f'unset _sea_{i}; ')
    prelude = "".join(parts)
    if recipe["service"] == "github":
        prelude += _GITHUB_PRELUDE
    cmd = " ".join(shlex.quote(c) for c in command)
    if run_as:
        if not _USER.match(run_as):
            raise RemoteError(f"'{run_as}' is not a plain user name.", 2)
        # runuser keeps the environment; `-u user --` runs as that user.
        cmd = f"runuser -u {run_as} -- {cmd}"
    return prelude + "exec " + cmd


def ssh_command(host: str, script: str, extra: list[str] | None = None) -> list[str]:
    return (["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
             "-o", "StrictHostKeyChecking=accept-new"]
            + list(extra or []) + ["--", host, "sh -c " + shlex.quote(script)])


def run_remote(recipe: dict, host: str, command: list[str], env_file: str = ".env",
               run_as: str | None = None, ssh_args: list[str] | None = None,
               runner=subprocess.run, backend=None) -> int:
    check_host(host)
    if command and command[0] == "--":
        command = command[1:]
    script = build_script(recipe, command, run_as)
    values = collect_values(recipe, env_file, backend)
    payload = "".join(values[v] + "\n" for v in recipes_mod.env_vars(recipe))
    argv = ssh_command(host, script, ssh_args)
    try:
        done = runner(argv, input=payload.encode("utf-8"))
    except FileNotFoundError:
        raise RemoteError("ssh is not installed here (on Windows: Settings > "
                          "Apps > Optional features > OpenSSH Client).", 1)
    code = done.returncode
    if code == 255:
        print("error: ssh could not log in. This helper never asks for a "
              "password; the server must already trust your ssh key "
              f"(`ssh-copy-id {host}`).", file=sys.stderr)
    return code
