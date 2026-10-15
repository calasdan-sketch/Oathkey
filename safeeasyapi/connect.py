"""The guided connect flow: steps -> hidden paste -> validate -> store.

Nothing in this module ever prints or logs the key. The key lives in
three places only: the user's clipboard, this function's local variable,
and the destination file.
"""

from __future__ import annotations

import getpass
import sys
import urllib.parse
import webbrowser

from . import store as store_mod
from . import validate as validate_mod

MAX_ATTEMPTS = 3
# Typed confirmation required when the validation URL is on a different
# domain than the key page. Not case-sensitive, but it must be the whole
# word — Enter alone or "y" aborts.
CONFIRM_WORD = "yes"


def _print_steps(recipe: dict, out=None) -> None:
    out = out or sys.stdout
    out.write(f"\n  Connect {recipe['display']}  (key opens in your browser)\n\n")
    for i, step in enumerate(recipe["steps"], 1):
        out.write(f"    {i}. {step}\n")
    if recipe.get("scopes"):
        out.write(f"\n  Select these scopes: {', '.join(recipe['scopes'])}\n")
    out.write(f"\n  Key page: {recipe['key_url']}\n\n")
    out.flush()


def render_validation_preview(recipe: dict, out=None) -> None:
    """Print exactly where the key will be sent for validation — the HTTP
    method and the full URL. Shown BEFORE the key is ever asked for, so a
    poisoned recipe can't turn `safeeasyapi connect` into a key harvest."""
    out = out or sys.stdout
    v = recipe["validate"]
    method = str(v.get("method", "GET")).upper()
    out.write(f"\n  This key will be validated with: {method} {v['url']}\n")
    out.flush()


def _host(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or ""


def _require_cross_domain_confirmation(recipe: dict, out,
                                       confirm_in=input) -> bool:
    """If the validation URL is on a different domain than the key page,
    require the user to type the confirmation word. Returns True when the
    flow may proceed."""
    v = recipe["validate"]
    if _host(v["url"]).lower() == _host(recipe["key_url"]).lower():
        return True
    out.write("  ⚠ The validation URL is on a DIFFERENT domain than the key "
              "page above.\n")
    out.write("    Your key will be sent to both domains. Make sure you "
              "trust both.\n")
    try:
        answer = confirm_in(f"  Type '{CONFIRM_WORD}' to continue: ")
    except (EOFError, KeyboardInterrupt):
        out.write("\ncancelled.\n")
        return False
    if (answer or "").strip().lower() != CONFIRM_WORD:
        out.write("  cancelled — no key was asked for, nothing was sent.\n")
        return False
    return True


def connect(
    recipe: dict,
    env_file: str = ".env",
    browser_open=webbrowser.open,
    prompt=getpass.getpass,
    out=None,
    validate_fn=validate_mod.validate_key,
    confirm_in=input,
) -> int:
    """Run the guided flow. Returns 0 on success, 1 on failure.

    Injectable browser_open/prompt/validate_fn/confirm_in exist for tests.
    """
    out = out or sys.stdout
    _print_steps(recipe, out)
    try:
        browser_open(recipe["key_url"])
    except Exception as e:
        out.write(f"  (couldn't open a browser: {e} — open the URL above manually)\n")

    # Preview exactly where the key will go BEFORE asking for it.
    render_validation_preview(recipe, out)
    if not _require_cross_domain_confirmation(recipe, out, confirm_in):
        return 1

    key = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            key = prompt("  Paste your API key (hidden): ").strip()
        except (EOFError, KeyboardInterrupt):
            out.write("\ncancelled.\n")
            return 1
        if not key:
            out.write("  empty — try again.\n")
            continue
        out.write("  validating…\n")
        out.flush()
        try:
            ok = validate_fn(recipe["validate"], key)
        except validate_mod.ValidationError as e:
            out.write(f"  couldn't reach the API: {e}\n")
            return 1
        if ok:
            break
        left = MAX_ATTEMPTS - attempt
        out.write(f"  key rejected by the API."
                  f"{f' {left} tries left.' if left else ''}\n")
        # Scrub the rejected key immediately.
        key = None
    else:
        out.write("  giving up — double-check the key and run me again.\n")
        return 1

    try:
        path, updated = store_mod.store_key(recipe["env_var"], key, env_file)
    finally:
        # Scrub the key from this frame whatever happens.
        key = None
        del key
    verb = "updated" if updated else "added"
    out.write(f"\n  ✓ {verb} {recipe['env_var']} in {path} "
              f"(mode 0600 — never displayed, never logged)\n")
    return 0
