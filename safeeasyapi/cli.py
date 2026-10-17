"""SafeEasyAPI CLI: `safeeasyapi` - the safe tunnel for API keys."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from . import connect as connect_mod
from . import keychain as keychain_mod
from . import mcp as mcp_mod
from . import publicapis as pa_mod
from . import recipes as recipes_mod


def _harden_streams() -> None:
    """Never crash on a console that cannot encode the check mark, the
    warning sign or a non-ASCII API name (cp1252 on Windows): replace
    instead of raising UnicodeEncodeError half-way through a connect."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None or getattr(stream, "errors", None) != "strict":
            continue
        try:
            reconfigure(errors="replace")
        except (OSError, ValueError):
            pass


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="safeeasyapi",
        description="Safe tunnel for API keys: guided, validated, "
                    "securely stored. The key is never displayed or logged.")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name, help_text in (("connect", "Connect a service (guided key setup)."),
                            ("rotate", "Replace the stored key for a service.")):
        c = sub.add_parser(name, help=help_text)
        c.add_argument("service", help="Service slug (see `safeeasyapi list`).")
        c.add_argument("--env-file", default=".env",
                       help="Where to store the key with --store env "
                            "(default: .env).")
        c.add_argument("--store", choices=["env", "keychain"], default="env",
                       help="env: owner-only .env file (default). keychain: "
                            "the OS keychain (macOS Keychain, Windows "
                            "Credential Manager, secret-tool on Linux), "
                            "falling back to the .env file when none is "
                            "available; use `safeeasyapi run` to consume it.")
        c.add_argument("--no-browser", action="store_true",
                       help="Don't auto-open the key page.")

    sub.add_parser("list", help="List services with saved recipes.")

    a = sub.add_parser("add", help="Capture a new service recipe interactively.")
    a.add_argument("--recipes-dir", default=None,
                   help="Write the recipe here instead of "
                        f"{recipes_mod.user_recipes_dir()}.")

    r = sub.add_parser("run", help="Run a command with a keychain-stored key "
                                   "in its environment (never printed).")
    r.add_argument("service", help="Service slug.")
    r.add_argument("command", nargs=argparse.REMAINDER,
                   help="command after -- : safeeasyapi run stripe -- python app.py")

    sub.add_parser("mcp", help="Run the MCP server on stdio (for Claude Code).")

    f = sub.add_parser("find", help="Find free public APIs for a task.")
    f.add_argument("query", help="What you need, e.g. 'weather', 'crypto price'.")
    f.add_argument("--auth", default=None,
                   help="Filter by auth, e.g. No, apiKey, OAuth.")
    f.add_argument("--category", default=None, help="Filter by category.")
    f.add_argument("--limit", type=int, default=10)
    f.add_argument("--refresh", action="store_true",
                   help="Re-download the directory (cached 7 days).")
    return p


def _cmd_list(catalog: dict) -> int:
    if not catalog:
        print("no recipes yet - add one with `safeeasyapi add`.")
        return 0
    print("\n  services with saved key recipes:\n")
    for slug in sorted(catalog):
        r = catalog[slug]
        print(f"    {slug:12} {r['display']:20} -> {r['env_var']}")
    print("\n  `safeeasyapi connect <service>` to set one up.\n")
    return 0


def _prompt(text: str, default: str = "") -> str:
    try:
        val = input(f"  {text}" + (f" [{default}]" if default else "") + ": ")
    except (EOFError, KeyboardInterrupt):
        print("\ncancelled.")
        sys.exit(1)
    return val.strip() or default


def _cmd_add(recipes_dir: str | None) -> int:
    print("\n  Capture a new service recipe - teach it once, use it forever.\n")
    service = _prompt("slug (lowercase, no spaces)", "").lower().replace(" ", "-")
    if not service:
        print("  slug is required.")
        return 1
    recipe = {
        "service": service,
        "display": _prompt("display name"),
        "key_url": _prompt("URL of the page where keys are minted"),
        "env_var": _prompt("env var name (e.g. HEADROOM_API_KEY)").upper(),
        "scopes": [s.strip() for s in
                   _prompt("scopes to select (comma-separated, optional)").split(",")
                   if s.strip()],
        "docs": _prompt("docs URL (optional)"),
        "steps": [],
        "validate": {},
    }
    print("  exact click-path steps (blank line to finish):")
    while True:
        s = _prompt(f"step {len(recipe['steps']) + 1}")
        if not s:
            break
        recipe["steps"].append(s)
    print("  validation - one API call that proves the key works:")
    recipe["validate"] = {
        "method": _prompt("HTTP method", "GET").upper(),
        "url": _prompt("validation URL"),
        "auth": {"type": _prompt("auth type (bearer/header/basic)", "bearer").lower()},
        "expect": [int(x) for x in
                   _prompt("expected status codes (comma-separated)", "200").split(",")],
    }
    if recipe["validate"]["auth"]["type"] == "header":
        recipe["validate"]["auth"]["header"] = _prompt("header name")
    try:
        path = recipes_mod.save_recipe(recipe, recipes_dir)
    except recipes_mod.RecipeError as e:
        print(f"  recipe incomplete: {e}")
        return 1
    print(f"\n  ✓ recipe saved to {path}\n")
    return 0


def _cmd_find(args) -> int:
    try:
        text = pa_mod.fetch(refresh=args.refresh)
    except Exception as e:
        print(f"couldn't fetch the public API directory: {e}")
        print("check your connection and try --refresh later.")
        return 2
    entries = pa_mod.parse(text)
    hits = pa_mod.search(entries, args.query, auth=args.auth,
                         category=args.category, limit=args.limit)
    if not hits:
        print(f"no public APIs match '{args.query}'.")
        return 0
    print(f"\n  public APIs matching '{args.query}':\n")
    for e in hits:
        # All directory strings are community-sourced: sanitize before
        # printing so escape sequences can't execute against the terminal.
        name = pa_mod.sanitize_display(e["name"])
        desc = pa_mod.sanitize_display(e["description"])
        url = pa_mod.sanitize_display(e["url"])
        category = pa_mod.sanitize_display(e["category"])
        auth_tag = "" if e["auth"] == "No" else f" [{e['auth']}]"
        print(f"    {name}{auth_tag}")
        print(f"      {desc}")
        print(f"      {url}  ({category})")
        if e["auth"] == "apiKey":
            print("      needs a key - save its recipe with `safeeasyapi add`.")
    print()
    return 0


def keychain_store(recipe: dict, env_file: str, out=None,
                   backend: str | None = None, keychain=keychain_mod):
    """store_fn for `--store keychain`: the OS keychain when the platform
    has one, otherwise the owner-only .env file - and say which."""
    out = out or sys.stdout
    backend = backend or keychain.detect_backend()

    def _store(env_var: str, key: str) -> str:
        if backend is None:
            out.write("  (no OS keychain available on this system - "
                      "storing in the .env file instead)\n")
            return connect_mod.store_in_env_file(env_file)(env_var, key)
        try:
            used = keychain.store(recipe["service"], env_var, key, backend)
        except keychain.KeychainError as e:
            out.write(f"  ({e} - storing in the .env file instead)\n")
            return connect_mod.store_in_env_file(env_file)(env_var, key)
        return (f"stored {env_var} in the {keychain.label(used)} "
                f"(never displayed, never logged); use it with "
                f"`safeeasyapi run {recipe['service']} -- <command>`")
    return _store


def _cmd_run(recipe: dict, command: list[str]) -> int:
    cmd = list(command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("error: no command: safeeasyapi run <service> -- <command>",
              file=sys.stderr)
        return 2
    backend = keychain_mod.detect_backend()
    if backend is None:
        print("error: no OS keychain on this system - the key is in your "
              ".env file; load that instead.", file=sys.stderr)
        return 1
    try:
        return keychain_mod.run_with_key(recipe, cmd, backend)
    except keychain_mod.KeychainError:
        print(f"error: no key for '{recipe['service']}' in the "
              f"{keychain_mod.label(backend)} - run "
              f"`safeeasyapi connect {recipe['service']} --store keychain`.",
              file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    _harden_streams()
    parser = _build_parser()
    args = parser.parse_args(argv)
    catalog = recipes_mod.load_recipes()

    if args.cmd == "list":
        return _cmd_list(catalog)
    if args.cmd == "find":
        return _cmd_find(args)
    if args.cmd == "add":
        return _cmd_add(args.recipes_dir)
    if args.cmd == "mcp":
        return mcp_mod.serve(catalog)
    if args.cmd in ("connect", "rotate", "run"):
        recipe = catalog.get(args.service)
        if not recipe:
            print(f"unknown service '{args.service}'.")
            _cmd_list(catalog)
            return 1
        if args.cmd == "run":
            return _cmd_run(recipe, args.command)
        import webbrowser
        opener = (lambda url: None) if args.no_browser else webbrowser.open
        store_fn = None
        if args.store == "keychain":
            store_fn = keychain_store(recipe, args.env_file)
        if args.cmd == "rotate":
            print(f"\n  rotating {recipe['display']} - the stored key will be replaced.\n")
        return connect_mod.connect(recipe, env_file=args.env_file,
                                   browser_open=opener, store_fn=store_fn)
    return 0


if __name__ == "__main__":
    sys.exit(main())
