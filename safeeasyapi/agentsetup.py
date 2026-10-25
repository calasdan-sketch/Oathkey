"""Set up an AI client to use safeeasyapi: its MCP config, and its rules file.

`setup-agent <client>` prints (or with --write adds) the exact MCP server entry,
with the ABSOLUTE path of this Python, so the client does not depend on PATH.
`skill install --for <client>` puts the agent rules in the file that client
reads (AGENTS.md, .cursor/rules/safeeasyapi.mdc, GEMINI.md) inside a marked
block that is replaced on the next install and never touches the rest of the
file.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

from . import recipes as recipes_mod

CLIENTS = ("claude-code", "claude-desktop", "cursor", "codex", "gemini")
BEGIN = "<!-- safeeasyapi:begin (managed by `safeeasyapi skill install`; edits inside are replaced) -->"
END = "<!-- safeeasyapi:end -->"

HONEST = """
  What is enforced where (be honest with yourself about this):
    - The MCP tools never return a key: true for every client.
    - The hook that blocks an agent from reading .env files exists ONLY in Claude
      Code. Cursor, Codex, Gemini and Claude Desktop have no such hook: their agent
      can read a .env file if it tries. For those clients the OS keychain is the
      safer place for keys, and this setup uses it when one is available.
    - The permission window (consent) is shown by safeeasyapi itself, for every client.
"""


def server_entry(client: str, keychain_ok: bool) -> dict:
    args = ["-m", "safeeasyapi", "mcp"]
    if client != "claude-code" and keychain_ok:
        args += ["--default-store", "keychain"]
    return {"command": os.path.abspath(sys.executable), "args": args}


def config_path(client: str, home: str, cwd: str, platform: str | None = None) -> str | None:
    platform = platform or sys.platform
    if client == "claude-desktop":
        if platform == "win32":
            return os.path.join(os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming"),
                                "Claude", "claude_desktop_config.json")
        if platform == "darwin":
            return os.path.join(home, "Library", "Application Support", "Claude",
                                "claude_desktop_config.json")
        return os.path.join(home, ".config", "Claude", "claude_desktop_config.json")
    if client == "cursor":
        return os.path.join(cwd, ".cursor", "mcp.json")
    if client == "gemini":
        return os.path.join(home, ".gemini", "settings.json")
    if client == "codex":
        return os.path.join(home, ".codex", "config.toml")
    return None


def _toml(entry: dict) -> str:
    q = lambda s: json.dumps(s)
    return (f"[mcp_servers.safeeasyapi]\ncommand = {q(entry['command'])}\n"
            f"args = [{', '.join(q(a) for a in entry['args'])}]\n")


def _atomic_write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".sea-")
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.replace(tmp, path)


def cmd_setup_agent(args, out=None, home: str | None = None, cwd: str | None = None,
                    keychain_ok: bool | None = None) -> int:
    out = out or sys.stdout
    home = home or os.path.expanduser("~")
    cwd = cwd or os.getcwd()
    client = args.client
    if keychain_ok is None:
        from . import keychain as keychain_mod
        try:
            keychain_ok = keychain_mod.detect_backend() is not None
        except Exception:
            keychain_ok = False
    entry = server_entry(client, keychain_ok)
    path = config_path(client, home, cwd)
    if client == "claude-code":
        cmd = " ".join(json.dumps(x) if " " in x else x
                       for x in ["claude", "mcp", "add", "safeeasyapi", "--", entry["command"], *entry["args"]])
        out.write(f"  Run this once:\n\n    {cmd}\n\n"
                  f"  then `safeeasyapi hook install` (blocks the agent reading .env files)\n"
                  f"  and `safeeasyapi skill install`.\n")
        return 0
    if client == "codex":
        block = _toml(entry)
        if not args.write:
            out.write(f"  Add to {recipes_mod.printable(path)}:\n\n{block}\n")
        else:
            existing = ""
            if os.path.isfile(path):
                with open(path, encoding="utf-8") as f:
                    existing = f.read()
            if "[mcp_servers.safeeasyapi]" in existing:
                out.write(f"  {recipes_mod.printable(path)} already has safeeasyapi; left alone.\n")
            else:
                _atomic_write(path, existing + ("\n" if existing and not existing.endswith("\n") else "") + block)
                out.write(f"  ✓ added to {recipes_mod.printable(path)}\n")
    else:
        snippet = json.dumps({"mcpServers": {"safeeasyapi": entry}}, indent=2)
        if not args.write:
            out.write(f"  Add to {recipes_mod.printable(path)}:\n\n{snippet}\n")
        else:
            data = {}
            if os.path.isfile(path):
                try:
                    with open(path, encoding="utf-8") as f:
                        data = json.load(f)
                except (OSError, ValueError):
                    out.write(f"  {recipes_mod.printable(path)} is not valid JSON; I will not "
                              f"touch it. Add the entry by hand:\n\n{snippet}\n")
                    return 1
                if not isinstance(data, dict):
                    return 1
            servers = data.setdefault("mcpServers", {})
            if not isinstance(servers, dict):
                return 1
            servers["safeeasyapi"] = entry
            _atomic_write(path, json.dumps(data, indent=2) + "\n")
            out.write(f"  ✓ wrote the safeeasyapi entry to {recipes_mod.printable(path)} "
                      f"(your other entries are kept). Restart the client.\n")
    out.write(HONEST)
    if client != "claude-code" and not keychain_ok:
        out.write("  No OS keychain was found, so keys will go to a .env file.\n")
    return 0


# ------------------------------------------------------------- rules files

def rules_target(client: str, base: str) -> str | None:
    return {"codex": os.path.join(base, "AGENTS.md"),
            "cursor": os.path.join(base, ".cursor", "rules", "safeeasyapi.mdc"),
            "gemini": os.path.join(base, "GEMINI.md")}.get(client)


def _skill_body(text: str) -> str:
    """SKILL.md without its front matter."""
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            return text[end + 4:].lstrip("\n")
    return text


def install_rules(client: str, base: str, text: str, out) -> int:
    path = rules_target(client, base)
    block = f"{BEGIN}\n{_skill_body(text).rstrip()}\n{END}\n"
    if os.path.islink(path):
        out.write(f"  {recipes_mod.printable(path)} is a link; I will not write through it.\n")
        return 1
    existing = ""
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            existing = f.read()
    elif os.path.exists(path):
        out.write(f"  {recipes_mod.printable(path)} is not a plain file.\n")
        return 1
    if BEGIN in existing and END in existing:
        head, rest = existing.split(BEGIN, 1)
        tail = rest.split(END, 1)[1].lstrip("\n")
        new = head + block + ("\n" + tail if tail else "")
    else:
        header = ""
        if client == "cursor" and not existing:
            header = "---\ndescription: API keys with safeeasyapi\nalwaysApply: true\n---\n"
        new = existing + ("\n\n" if existing.strip() else "") + header + block \
            if existing.strip() else header + block
    if new == existing:
        out.write(f"  Already up to date: {recipes_mod.printable(path)}\n")
        return 0
    _atomic_write(path, new)
    out.write(f"  ✓ wrote the safeeasyapi block to {recipes_mod.printable(path)}\n")
    return 0
