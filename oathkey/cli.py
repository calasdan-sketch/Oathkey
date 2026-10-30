"""Oathkey CLI: `oathkey` - the safe tunnel for API keys."""

from __future__ import annotations

import argparse
import errno
import json
import os
import sys

from . import __version__
from . import connect as connect_mod
from . import keychain as keychain_mod
from . import mcp as mcp_mod
from . import publicapis as pa_mod
from . import recipes as recipes_mod
from . import store as store_mod


def _harden_streams() -> None:
    """Never crash on a console that cannot encode the check mark, the
    warning sign or a non-ASCII API name (cp1252 on Windows): replace
    instead of raising UnicodeEncodeError half-way through a connect."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        # Both handlers raise UnicodeEncodeError on a character the code
        # page lacks: "strict" (the default) and "surrogateescape" (what a
        # piped stdout reports on Windows 11 / Python 3.11, with cp1252).
        if reconfigure is None or getattr(stream, "errors", None) not in (
                "strict", "surrogateescape"):
            continue
        try:
            reconfigure(errors="replace")
        except (OSError, ValueError):
            pass


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="oathkey",
        description="Safe tunnel for API keys: guided, validated, "
                    "securely stored. The key is never displayed or logged.")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name, help_text in (("get", "One command: opens the key page, takes the key from your copy, tests it, and saves it in the OS keychain. Nothing is shown."),
                            ("connect", "Connect a service (guided key setup)."),
                            ("rotate", "Replace the stored key for a service.")):
        c = sub.add_parser(name, help=help_text)
        c.add_argument("service", help="Service slug (see `oathkey list`).")
        c.add_argument("--env-file", default=".env",
                       help="Where to store the key with --store env "
                            "(default: .env).")
        c.add_argument("--store", choices=["env", "keychain"], default=None,
                       help="env: owner-only .env file (default). keychain: "
                            "the OS keychain (macOS Keychain, Windows "
                            "Credential Manager, secret-tool on Linux), "
                            "falling back to the .env file when none is "
                            "available; use `oathkey run` to consume it.")
        c.add_argument("--no-clipboard", action="store_true",
                       help="(get) Use the hidden paste prompt instead of copy-and-go.")
        c.add_argument("--no-browser", action="store_true",
                       help="Don't auto-open the key page.")
        c.add_argument("--clipboard", action="store_true",
                       help="Copy-and-go: click the vendor's Copy button and the key "
                            "is taken from the clipboard (then emptied) - no pasting.")
        c.add_argument("--via-cli", action="store_true",
                       help="Get the key from the vendor's own CLI after its browser "
                            "sign-in (built-in recipes that support it, e.g. github).")

    ls = sub.add_parser("list", help="List services with saved recipes.")
    ls.add_argument("--json", action="store_true", help="Machine-readable output.")

    fg = sub.add_parser("forget", help="Remove a stored key: from the OS "
                                       "keychain and from the .env file.")
    fg.add_argument("service", help="Service slug.")
    fg.add_argument("--env-file", default=".env",
                    help="The .env file to remove the entry from (default: .env).")

    a = sub.add_parser("add", help="Capture a new service recipe interactively.")
    a.add_argument("--recipes-dir", default=None,
                   help="Write the recipe here instead of "
                        f"{recipes_mod.user_recipes_dir()}.")

    r = sub.add_parser("run", help="Run a command with a keychain-stored key "
                                   "in its environment (never printed).")
    r.add_argument("service", help="Service slug.")
    r.add_argument("command", nargs="*",
                   help="command after -- : oathkey run stripe -- python app.py")

    rm = sub.add_parser("remote", help="Use a stored key on another machine over "
                                        "ssh (key goes over stdin, never on a command line).")
    rm.add_argument("service", help="Service slug.")
    rm.add_argument("host", help="user@host to ssh into (key-based login).")
    rm.add_argument("--as", dest="run_as", default=None,
                    help="Run the command as this user on the far side (runuser).")
    rm.add_argument("--env-file", default=".env",
                    help="Read the key from this .env file if the keychain has none.")
    rm.add_argument("--ssh-arg", action="append", default=[],
                    help="Extra ssh argument, e.g. --ssh-arg=-i --ssh-arg=~/.ssh/key")
    rm.add_argument("command", nargs="*",
                    help="command after -- : oathkey remote github root@host -- git pull")

    sc = sub.add_parser("scan", help="Look for API keys lying around where an AI (or a "
                                     "thief) can read them. Never prints a key.")
    sc.add_argument("paths", nargs="*", default=["."], help="Folders/files (default: here).")
    sc.add_argument("--no-home", action="store_true",
                    help="Do not check shell history and AI-tool settings in your home folder.")
    sc.add_argument("--json", action="store_true", help="Machine-readable output.")
    sc.add_argument("--git", action="store_true", help="Also look through every past commit.")
    sc.add_argument("--staged", action="store_true",
                    help="Only check what is about to be committed (for the pre-commit hook).")
    sc.add_argument("--install-hook", action="store_true",
                    help="Install a git pre-commit hook that blocks commits containing keys.")

    dc = sub.add_parser("doctor", help="Check this computer is ready (keychain, ssh, git).")
    dc.add_argument("--json", action="store_true", help="Machine-readable output.")

    ts = sub.add_parser("trust-server", help="Make a server trust this PC (makes an ssh "
                                             "key, installs it, proves it works).")
    ts.add_argument("host", help="user@host")

    dp = sub.add_parser("deploy", help="One step: trust the server, send the key, "
                                       "git pull, optionally restart.")
    dp.add_argument("host", help="user@host")
    dp.add_argument("--service", default="github", help="Key to use (default github).")
    dp.add_argument("--dir", required=True, help="Repository folder on the server.")
    dp.add_argument("--as", dest="run_as", default=None,
                    help="Run git as this user on the server (needs root login).")
    dp.add_argument("--then", default=None,
                    help="A command line to run on the server afterwards, e.g. "
                         "'systemctl restart myapp'.")
    dp.add_argument("--env-file", default=".env",
                    help="Read the key from this .env file if the keychain has none.")

    sub.add_parser("mcp", help="Run the MCP server on stdio (for Claude Code).")

    ins = sub.add_parser("install", help="Plug oathkey into your AI tools (Claude "
                                         "Desktop, Cursor, VS Code, Claude Code). Shows "
                                         "the change and asks first.")
    ins.add_argument("targets", nargs="*", help="claude-desktop, cursor, claude-code, vscode "
                                                "(default: the ones found)")
    ins.add_argument("--yes", action="store_true", help="Do not ask.")
    un = sub.add_parser("uninstall", help="Remove oathkey from your AI tools' settings "
                                          "(your saved keys are not touched).")
    un.add_argument("targets", nargs="*")
    un.add_argument("--yes", action="store_true", help="Do not ask.")
    sub.add_parser("start", help="First run: check this computer, look for loose "
                                 "keys, and say what to do next.")
    stt = sub.add_parser("status", help="What is connected, and is the activity log intact.")
    stt.add_argument("--json", action="store_true", help="Machine-readable output.")
    stt.add_argument("--env-file", default=".env")
    au = sub.add_parser("audit", help="Check the activity log has not been tampered with.")
    au.add_argument("action", choices=["verify", "show"])
    au.add_argument("--json", action="store_true")
    au.add_argument("--last", type=int, default=20, help="how many entries to show")
    ca = sub.add_parser("call", help="Call a connected service's API; the key is "
                                     "added for you and hidden from the output.")
    ca.add_argument("service")
    ca.add_argument("method", help="GET, or POST/PUT/PATCH/DELETE (asks you first).")
    ca.add_argument("path", help="like /user")
    ca.add_argument("--query", action="append", default=[], help="name=value (repeatable)")
    ca.add_argument("--data", default=None, help="JSON body for POST/PUT/PATCH")
    ca.add_argument("--json", action="store_true")
    ca.add_argument("--env-file", default=".env")
    sv = sub.add_parser("serve", help="Open a local web door for AI tools without MCP "
                                      "(OpenAI-style functions, Ollama, scripts).")
    sv.add_argument("--port", type=int, default=8787)
    sv.add_argument("--env-file", default=".env")

    stp = sub.add_parser("selftest", help="Attack oathkey with a made-up key and a pretend server; shows pass or fail.")
    stp.add_argument("--json", action="store_true")
    f = sub.add_parser("find", help="Find free public APIs for a task.")
    f.add_argument("query", help="What you need, e.g. 'weather', 'crypto price'.")
    f.add_argument("--auth", default=None,
                   help="Filter by auth, e.g. No, apiKey, OAuth.")
    f.add_argument("--category", default=None, help="Filter by category.")
    f.add_argument("--limit", type=int, default=10)
    f.add_argument("--refresh", action="store_true",
                   help="Re-download the directory (cached 7 days).")
    return p


def _cmd_list(catalog: dict, as_json: bool = False) -> int:
    if as_json:
        import json as _json
        print(_json.dumps([{"service": s, "display": catalog[s]["display"],
                            "env_vars": list(recipes_mod.env_vars(catalog[s]))}
                           for s in sorted(catalog)]))
        return 0
    if not catalog:
        print("no recipes yet - add one with `oathkey add`.")
        return 0
    print("\n  services with saved key recipes:\n")
    for slug in sorted(catalog):
        r = catalog[slug]
        # a recipe is somebody else's text: nothing in it may drive the terminal
        print(f"    {recipes_mod.printable(slug):14} "
              f"{recipes_mod.printable(r['display'], words=True):38} -> "
              f"{', '.join(recipes_mod.printable(v) for v in recipes_mod.env_vars(r))}")
    print("\n  `oathkey get <service>` to set one up.\n")
    return 0


def _prompt(text: str, default: str = "") -> str:
    try:
        val = input(f"  {text}" + (f" [{default}]" if default else "") + ": ")
    except (EOFError, KeyboardInterrupt):
        print("\ncancelled.")
        sys.exit(1)
    return val.strip() or default


def _parse_expect(text: str) -> list[int]:
    """'200, 201' -> [200, 201]; anything that is not a 3-digit status is a
    ValueError with a message meant for a human, not a traceback."""
    codes = []
    for part in text.split(","):
        part = part.strip()
        if not part.isdigit() or not 100 <= int(part) <= 599:
            raise ValueError(
                f"expected HTTP status codes like 200 or 200,201 - got {part!r}")
        codes.append(int(part))
    if not codes:
        raise ValueError("at least one expected status code is required")
    return codes


def _cmd_add(recipes_dir: str | None) -> int:
    print("\n  Capture a new service recipe - teach it once, use it forever.\n")
    service = _prompt("slug (lowercase, no spaces)", "").lower().replace(" ", "-")
    if not service:
        print("  slug is required.")
        return 1
    if not recipes_mod.SLUG_RE.match(service):
        # the slug becomes the file name <slug>.json: "../../evil" or
        # "my service!" must never reach the filesystem
        print(f"  '{service}' is not a valid slug: use lowercase letters, "
              "digits, '-' or '_' (1-64 chars), e.g. 'my-api'.")
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
    }
    try:
        recipe["validate"]["expect"] = _parse_expect(
            _prompt("expected status codes (comma-separated)", "200"))
    except ValueError as e:
        print(f"  {e}")
        return 1
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
            print("      needs a key - save its recipe with `oathkey add`.")
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
                f"`oathkey run {recipe['service']} -- <command>`")
    return _store


def _describe_links(links) -> str:
    """The other names of a file, for a message: the ones in its folder by
    name (shown so that a hostile file name cannot drive the terminal), the
    rest as a count."""
    parts = [recipes_mod.printable(name) for name in links.names]
    if links.elsewhere == 1:
        parts.append("1 in another folder")
    elif links.elsewhere:
        parts.append(f"{links.elsewhere} in other folders")
    return ", ".join(parts)


def _cmd_forget(recipe: dict, env_file: str, out=None,
                keychain=keychain_mod, remove_env=store_mod.remove_key) -> int:
    """Remove the service's key everywhere it may have been stored: the OS
    keychain entry (when this platform has one) and every ENV_VAR= line in
    the .env file. Says what was removed; never shows the key."""
    out = out or sys.stdout
    service, env_var = recipe["service"], recipe["env_var"]
    removed = []
    keychain_problem = None
    backend = keychain.detect_backend()
    if backend is not None:
        try:
            if keychain.delete(service, env_var, backend):
                removed.append(f"the {keychain.label(backend)} entry")
        except keychain.KeychainError as e:
            # The keychain tool hung or would not start. The .env file is
            # still ours to clean, so carry on - and say plainly that the
            # keychain entry may still be there.
            keychain_problem = str(e)
    # Other names of the file are asked BEFORE the rewrite: afterwards
    # env_file is a new file with one name, and the old one lives on, key
    # and all, under the others.
    links = store_mod.other_links(env_file)
    env_problem = None
    try:
        lines = remove_env(env_var, env_file)
    except OSError as e:
        # A link, a file that is not plain text, no permission. What was
        # removed above stays removed, and the leftover copies below are ours
        # to remove whatever happens to .env: carry on, and say what could
        # not be done only after saying what was.
        lines, env_problem = 0, e.strerror or str(e)
    if lines:
        removed.append(f"{env_var} from {env_file}")
    # A write that was killed halfway leaves a whole copy of the file behind.
    gone, stuck = store_mod.remove_leftovers(env_var, env_file)
    for path in gone:
        removed.append(f"a leftover copy in {recipes_mod.printable(path)} "
                       f"(from an interrupted write)")
    problems = []           # what is not done yet, in the order it was found
    if keychain_problem:
        problems.append(
            f"  \u2717 could not remove the {keychain.label(backend)} "
            f"entry: {keychain_problem}.\n"
            f"    The key may still be stored there \u2014 run "
            f"`oathkey forget {service}` again when it answers.\n")
    if env_problem:
        problems.append(
            f"  \u2717 could not rewrite {recipes_mod.printable(env_file)}: "
            f"{recipes_mod.printable(env_problem)}.\n"
            f"    The key may still be stored there - fix that and run "
            f"`oathkey forget {service}` again.\n")
    for path, why in stuck:
        problems.append(
            f"  \u2717 could not remove {recipes_mod.printable(path)}: "
            f"{recipes_mod.printable(why)}.\n"
            f"    It is a leftover copy of {recipes_mod.printable(env_file)} "
            f"from an interrupted write and still holds the key - delete it "
            f"yourself.\n")
    if lines and links:
        problems.append(
            f"  \u2717 {recipes_mod.printable(env_file)} also has other names "
            f"(hard links): {_describe_links(links)}.\n"
            f"    They still hold the old contents, {env_var} included - "
            f"rewriting a file cannot change its other names.\n"
            f"    oathkey does not delete files it did not make; delete "
            f"them yourself if they are stray backups.\n")
    if not removed:
        for text in problems:
            out.write(text)
        if problems:
            return 1
        out.write(f"  nothing stored for '{service}' (checked "
                  f"{keychain.label(backend)} and {env_file}).\n")
        return 0
    # What was done comes first, then what was not: "forgot" only when that
    # is all of it.
    lead = "removed" if problems else f"forgot {service}: removed"
    out.write(f"  \u2713 {lead} {' and '.join(removed)}.\n")
    if isinstance(lines, int) and lines > 1:
        # every one of them, or an older line would take over again
        both = "both" if lines == 2 else f"all {lines}"
        out.write(f"    note: {env_var} appeared {store_mod.times(lines)} in "
                  f"{env_file}; I removed {both}.\n")
    for text in problems:
        out.write(text)
    return 1 if problems else 0


def _cmd_run(recipe: dict, command: list[str]) -> int:
    cmd = list(command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("error: no command: oathkey run <service> -- <command>",
              file=sys.stderr)
        return 2
    backend = keychain_mod.detect_backend()
    if backend is None:
        print("error: no OS keychain on this system - the key is in your "
              ".env file; load that instead.", file=sys.stderr)
        return 1
    try:
        # before the keychain is asked for the key: a typo costs no unlock
        cmd[0] = keychain_mod.locate_program(cmd[0])
    except keychain_mod.CannotRun as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code
    try:
        # Output no person is watching live (an AI agent reads it, or it is
        # piped) is scrubbed so the child cannot print the key back.
        try:
            real_pipe = (hasattr(sys.stdout, "buffer") and not sys.stdout.isatty())
        except (ValueError, AttributeError):
            real_pipe = False
        return keychain_mod.run_with_key(recipe, cmd, backend, scrub=real_pipe)
    except keychain_mod.CannotRun as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code
    except keychain_mod.KeychainUnavailable as e:
        print(f"error: the {keychain_mod.label(backend)} did not give the key "
              f"for '{recipe['service']}': {e}.", file=sys.stderr)
        return 1
    except keychain_mod.KeychainError:
        print(f"error: no key for '{recipe['service']}' in the "
              f"{keychain_mod.label(backend)} - run "
              f"`oathkey connect {recipe['service']} --store keychain`.",
              file=sys.stderr)
        return 1


# True on Windows. A module-level flag (not os.name read on the spot) so a
# test can switch it and check both platforms' behaviour from either one.
_ON_WINDOWS = os.name == "nt"


def is_closed_pipe(exc: BaseException) -> bool:
    """Is `exc` what writing to a pipe nobody reads any more looks like?

    On POSIX that is BrokenPipeError (errno EPIPE). On Windows it is NOT:
    print() of small output works because it is only buffered, and the
    flush - or, under ``python -u``, the print() itself - raises a plain
    OSError with errno 22 (EINVAL) and no winerror (measured on Windows 11
    with Python 3.11). EINVAL is only taken for a closed pipe there: on any
    other system it is a real error and must not be swallowed. And only the
    plain kind: it must carry no file name (EnvFileRefused is an OSError
    with errno EINVAL too, as can be any failed file operation on a path)
    and no winerror (a failed Win32 call such as starting a program), while
    an error from writing to a pipe has neither."""
    if not isinstance(exc, OSError):
        return False
    if isinstance(exc, BrokenPipeError) or exc.errno == errno.EPIPE:
        return True
    return (_ON_WINDOWS and exc.errno == errno.EINVAL
            and exc.filename is None
            and getattr(exc, "winerror", None) is None)


def _after_broken_pipe() -> int:
    """The reader of our output went away (``oathkey list | head -1``).
    That is not worth a traceback: stop quietly. Python flushes stdout again
    when it exits and would fail a second time ("Exception ignored in ...",
    exit status 120), so fd 1 is pointed at the null device first - the
    recipe from the Python documentation; measured on Windows 11, it makes
    that last flush succeed there too. The status is 1, as Python itself
    uses for EPIPE."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, sys.stdout.fileno())
        finally:
            os.close(devnull)
    except (OSError, ValueError, AttributeError):
        pass    # stdout has no real descriptor (a test's StringIO) or is gone
    return 1


def _flush_stdout() -> None:
    flush = getattr(sys.stdout, "flush", None)
    if flush is not None:
        flush()


def _interrupted() -> int:
    """Ctrl-C: say so in a line, not a traceback, and use the status a shell
    reports for a program SIGINT stopped (128 + 2)."""
    try:
        sys.stderr.write("\ninterrupted.\n")
        sys.stderr.flush()
    except (OSError, ValueError):
        pass    # nobody is reading stderr either
    return 130


START_HERE = """
  oathkey - let your AI use your API keys without ever seeing them.

  Start here:
    oathkey get github      save a key (opens the page; you click Copy)
    oathkey install         plug oathkey into Claude, Cursor or VS Code
    oathkey selftest        watch it attack itself
    oathkey doctor          check this computer

  All commands:  oathkey --help      What it does not stop:  see SECURITY.md
"""


def _unknown_service(catalog: dict, name: str, show_all: bool = False) -> None:
    import difflib
    close = difflib.get_close_matches(str(name).lower(), list(catalog), n=3, cutoff=0.5)
    msg = f"unknown service '{recipes_mod.printable(name)}'."
    if close:
        msg += " Did you mean: " + ", ".join(close) + "?"
    print(msg + "  (`oathkey list` shows all; `oathkey add` makes your own.)")
    if show_all:
        _cmd_list(catalog)


def main(argv: list[str] | None = None) -> int:
    if (argv is None and len(sys.argv) == 1) or argv == []:
        print(START_HERE)
        return 0
    try:
        try:
            code = _main(argv)
        except SystemExit:
            # argparse prints --version / --help and exits by exception; what
            # it printed is still in the buffer
            _flush_stdout()
            raise
        # A pipe that was closed on us shows up when the buffer is flushed -
        # here, where it can be handled, not in the interpreter's own exit.
        _flush_stdout()
        return code
    except OSError as e:
        # Any command, and the MCP loop, end up here: BrokenPipeError on
        # POSIX, a plain OSError(EINVAL) on Windows. Anything else is a real
        # error and goes on its way.
        if is_closed_pipe(e):
            return _after_broken_pipe()
        raise
    except KeyboardInterrupt:
        # Any command, the MCP loop and `run` end up here.
        return _interrupted()


def _main(argv: list[str] | None = None) -> int:
    _harden_streams()
    parser = _build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    tail: list[str] = []
    # everything after the first "--" is the command to run, never an option
    if argv and argv[0] in ("remote", "run") and "--" in argv:
        i = argv.index("--")
        argv, tail = argv[:i], argv[i + 1:]
    args = parser.parse_args(argv)
    if args.cmd in ("remote", "run"):
        args.command = tail
    catalog = recipes_mod.load_recipes()

    if args.cmd == "list":
        return _cmd_list(catalog, getattr(args, "json", False))
    if args.cmd == "find":
        return _cmd_find(args)
    if args.cmd == "add":
        return _cmd_add(args.recipes_dir)
    if args.cmd == "mcp":
        return mcp_mod.serve(catalog)
    if args.cmd == "install":
        from . import clients
        return clients.run(args.targets, args.yes)
    if args.cmd == "selftest":
        from . import selftest
        return selftest.cmd_selftest(args.json)
    if args.cmd == "uninstall":
        from . import clients
        return clients.remove(args.targets, args.yes)
    if args.cmd in ("start", "status", "audit", "call", "serve"):
        from . import cmds
        if args.cmd == "start":
            return cmds.cmd_start(catalog, ".env")
        if args.cmd == "status":
            return cmds.cmd_status(catalog, args.env_file, args.json)
        if args.cmd == "audit":
            return cmds.cmd_audit(args.action, args.json, args.last)
        if args.cmd == "serve":
            return cmds.cmd_serve(catalog, args.port, args.env_file)
        recipe = catalog.get(args.service)
        if not recipe:
            _unknown_service(catalog, args.service)
            return cmds.NOT_FOUND
        return cmds.cmd_call(recipe, args)
    if args.cmd in ("scan", "doctor"):
        import json as _json
        from . import scan as scan_mod
        if args.cmd == "scan" and args.install_hook:
            try:
                print("hook installed:", scan_mod.install_hook(args.paths[0]))
                return 0
            except OSError as e:
                print(f"error: {e}", file=sys.stderr)
                return 1
        if args.cmd == "scan" and args.staged:
            g = scan_mod.scan_git(args.paths[0], staged=True)
            if g.get("error"):
                print(f"error: {g['error']}", file=sys.stderr)
                return 2
            if g["findings"]:
                print("oathkey: a key looks like it is about to be committed:\n"
                      + scan_mod.format_git(g), file=sys.stderr)
                return 1
            return 0
        if args.cmd == "scan":
            res = scan_mod.scan(args.paths, include_home=not args.no_home)
            if args.git:
                res["git"] = scan_mod.scan_git(args.paths[0])
                res["findings"] = res["findings"] + [
                    dict(f, line=0, file=f["file"] + "@" + f["commit"])
                    for f in res["git"]["findings"]]
            print(_json.dumps(res, indent=2) if args.json else scan_mod.format_report(res))
            return 1 if res["findings"] else 0
        res = scan_mod.doctor()
        print(_json.dumps(res, indent=2) if args.json else scan_mod.format_doctor(res))
        return 0 if res["ok"] else 1
    if args.cmd in ("trust-server", "deploy"):
        from . import remote as remote_mod
        try:
            if args.cmd == "trust-server":
                remote_mod.ensure_ssh_access(args.host)
                return 0
            recipe = catalog.get(args.service)
            if not recipe:
                _unknown_service(catalog, args.service)
                return 1
            remote_mod.ensure_ssh_access(args.host)
            code = remote_mod.run_remote(
                recipe, args.host, ["git", "-C", args.dir, "pull", "--ff-only"],
                env_file=args.env_file, run_as=args.run_as)
            if code == 0 and args.then:
                import subprocess
                key = remote_mod.key_for(args.host)
                ident = ["-i", key, "-o", "IdentitiesOnly=yes"] if key else []
                code = subprocess.run(["ssh", "-T", *ident, "-o", "BatchMode=yes",
                                       "--", args.host, args.then]).returncode
            return code
        except remote_mod.RemoteError as e:
            print(f"error: {e}", file=sys.stderr)
            return e.code
    if args.cmd in ("get", "connect", "rotate", "run", "forget", "remote"):
        if getattr(args, "store", None) is None:
            args.store = "keychain" if args.cmd == "get" else "env"
        recipe = catalog.get(args.service)
        if not recipe:
            _unknown_service(catalog, args.service)
            return 1
        if args.cmd == "remote":
            from . import remote as remote_mod
            try:
                return remote_mod.run_remote(recipe, args.host, args.command,
                                             env_file=args.env_file, run_as=args.run_as,
                                             ssh_args=args.ssh_arg)
            except remote_mod.RemoteError as e:
                print(f"error: {e}", file=sys.stderr)
                return e.code
        if args.cmd == "run":
            return _cmd_run(recipe, args.command)
        if args.cmd == "forget":
            # one pass per stored value: an App ID and its secret are both removed
            return max(_cmd_forget(dict(recipe, env_var=var), args.env_file)
                       for var in recipes_mod.env_vars(recipe))
        import webbrowser
        if (args.cmd == "get" and args.store == "keychain"
                and args.env_file == ".env" and keychain_mod.detect_backend() is None):
            print("error: this computer has no keychain, and I won't leave a key in a "
                  "file in your project folder\n(an AI tool could read it). Choose a "
                  "private place yourself:  oathkey connect "
                  f"{args.service} --env-file <path to a private .env>",
                  file=sys.stderr)
            return 1
        opener = (lambda url: None) if args.no_browser else webbrowser.open
        store_fn = None
        if args.store == "keychain":
            store_fn = keychain_store(recipe, args.env_file)
        if args.cmd == "rotate":
            print(f"\n  rotating "
                  f"{recipes_mod.printable(recipe['display'], words=True)} - "
                  f"the stored key will be replaced.\n")
        clip = None
        if args.clipboard or (args.cmd == "get" and not args.no_clipboard):
            from . import clipboard as clipboard_mod
            try:
                clip = clipboard_mod.backend()
            except clipboard_mod.Unavailable as e:
                print(f"  (copy-and-go unavailable: {recipes_mod.printable(e)} - "
                      f"using the hidden paste instead)")
        return connect_mod.connect(recipe, env_file=args.env_file,
                                   browser_open=opener, store_fn=store_fn,
                                   clipboard=clip, via_cli=args.via_cli)
    return 0


if __name__ == "__main__":
    sys.exit(main())
