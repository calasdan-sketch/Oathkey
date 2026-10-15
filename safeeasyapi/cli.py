"""SafeEasyAPI CLI: `safeeasyapi` — the safe tunnel for API keys."""

import argparse
import json
import sys

from . import __version__
from . import connect as connect_mod
from . import mcp as mcp_mod
from . import publicapis as pa_mod
from . import recipes as recipes_mod


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="safeeasyapi",
        description="Safe tunnel for API keys: guided, validated, "
                    "securely stored. The key is never displayed or logged.")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("connect", help="Connect a service (guided key setup).")
    c.add_argument("service", help="Service slug (see `safeeasyapi list`).")
    c.add_argument("--env-file", default=".env",
                   help="Where to store the key (default: .env).")
    c.add_argument("--no-browser", action="store_true",
                   help="Don't auto-open the key page.")

    r = sub.add_parser("rotate", help="Replace the stored key for a service.")
    r.add_argument("service", help="Service slug.")
    r.add_argument("--env-file", default=".env")
    r.add_argument("--no-browser", action="store_true")

    sub.add_parser("list", help="List services with saved recipes.")

    a = sub.add_parser("add", help="Capture a new service recipe interactively.")
    a.add_argument("--recipes-dir", default=None,
                   help="Write the recipe here instead of the built-in dir.")

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
        print("no recipes yet — add one with `safeeasyapi add`.")
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
    print("\n  Capture a new service recipe — teach it once, use it forever.\n")
    service = _prompt("slug (lowercase, no spaces)", "").lower().replace(" ", "-")
    if not service:
        print("  slug is required."); return 1
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
    print("  validation — one API call that proves the key works:")
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
            print(f"      needs a key — save its recipe with `safeeasyapi add`.")
    print()
    return 0


def main(argv: list[str] | None = None) -> int:
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
    if args.cmd in ("connect", "rotate"):
        recipe = catalog.get(args.service)
        if not recipe:
            print(f"unknown service '{args.service}'.")
            _cmd_list(catalog)
            return 1
        import webbrowser
        opener = (lambda url: None) if getattr(args, "no_browser", False) else webbrowser.open
        env_file = getattr(args, "env_file", ".env")
        if args.cmd == "rotate":
            print(f"\n  rotating {recipe['display']} — the stored key will be replaced.\n")
        return connect_mod.connect(recipe, env_file=env_file, browser_open=opener)
    return 0


if __name__ == "__main__":
    sys.exit(main())
