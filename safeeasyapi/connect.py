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

# Multi-label public suffixes (from the Public Suffix List) under which the
# NEXT label is the registrant. "api.example.co.uk" and
# "dashboard.example.co.uk" are the same owner; "a.co.uk" and "b.co.uk"
# are not. Hosting platforms whose sub-domains belong to different
# customers are listed too: evil.github.io is NOT trusted by good.github.io.
PUBLIC_SUFFIXES = frozenset({
    # country second-level registries
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "net.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br",
    "co.nz", "net.nz", "org.nz",
    "co.za", "org.za", "web.za",
    "co.in", "net.in", "org.in", "firm.in",
    "co.kr", "or.kr", "ne.kr",
    "com.cn", "net.cn", "org.cn",
    "com.tw", "org.tw", "idv.tw",
    "com.hk", "org.hk", "edu.hk",
    "com.sg", "org.sg", "edu.sg",
    "com.mx", "org.mx",
    "com.ar", "org.ar",
    "com.tr", "org.tr",
    "co.id", "or.id", "web.id",
    "co.il", "org.il",
    "com.pl", "net.pl",
    "co.th", "in.th",
    "com.my", "org.my",
    "com.ph", "org.ph",
    "com.vn", "net.vn",
    "com.ua", "net.ua",
    "com.ru", "net.ru", "org.ru",
    "co.ke", "or.ke",
    "com.ng", "org.ng",
    "com.eg",
    "com.sa",
    "com.pk",
    "com.bd",
    "com.pe", "com.co", "com.ve", "com.ec", "com.uy", "com.py", "com.bo",
    "com.gt", "com.do",
    # hosting platforms: every sub-domain is a different customer
    "github.io", "gitlab.io", "herokuapp.com", "vercel.app", "netlify.app",
    "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "appspot.com",
    "azurewebsites.net", "cloudfront.net", "amazonaws.com", "onrender.com",
    "fly.dev", "railway.app", "ngrok.io", "ngrok.app", "ngrok-free.app",
    "trycloudflare.com", "repl.co", "replit.app", "glitch.me", "surge.sh",
    "now.sh", "deno.dev", "supabase.co",
})


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


def _normalize_host(host: str) -> str:
    """A hostname in the one spelling used to compare hosts: lower case, no
    trailing dot, and - for an internationalised name - its ASCII (IDNA /
    punycode, ``xn--``) form, so ``bücher.example`` and
    ``xn--bcher-kva.example`` are the same host. That is also the name
    Python's own HTTP stack resolves and puts in the Host header
    (``str.encode("idna")``), so the comparison sees the host the key will
    really go to. A name the codec rejects (an empty or over-long label, a
    forbidden character) stays as lower-case text: it then equals only
    itself, the safe direction for an "is this the same owner?" test."""
    host = (host or "").lower().rstrip(".")
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        return host


def _to_unicode(host: str) -> str:
    """The display spelling of a normalized host: ``xn--`` labels decoded.
    A name that is not valid punycode (or never was ASCII) is returned as is."""
    try:
        return host.lower().encode("ascii").decode("idna")
    except UnicodeError:
        return host


def describe_domain(domain: str) -> str:
    """How a domain is named in a warning: itself, or - when it is an
    internationalised one - the Unicode spelling with its ``xn--`` form in
    brackets beside it, so a look-alike letter (a Cyrillic "a" in
    "apple.com") cannot hide behind a name that looks identical."""
    shown = _to_unicode(domain)
    return domain if shown == domain else f"{shown} [{domain}]"


def _host(url: str) -> str:
    """The URL's host in comparison form (see _normalize_host). urlsplit has
    already dropped user:password@ and the :port, and lower-cased the name."""
    return _normalize_host(urllib.parse.urlsplit(url).hostname or "")


def registrable_domain(host: str) -> str:
    """The part of a hostname one party registers: the last two labels,
    or three under a known multi-label public suffix (co.uk, github.io).

        api.github.com        -> github.com
        dashboard.stripe.com  -> stripe.com
        api.example.co.uk     -> example.co.uk
        evil.github.io        -> evil.github.io   (platform: per-customer)
        www.bücher.example    -> xn--bcher-kva.example   (punycode form)

    IP addresses, localhost and single labels are returned unchanged.
    """
    host = _normalize_host(host)
    labels = host.split(".")
    if len(labels) < 3 or all(part.isdigit() for part in labels):
        return host
    if ".".join(labels[-2:]) in PUBLIC_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def same_owner(url_a: str, url_b: str) -> bool:
    """Do two URLs live under the same registrable domain?"""
    a, b = registrable_domain(_host(url_a)), registrable_domain(_host(url_b))
    return bool(a) and a == b


def _require_cross_domain_confirmation(recipe: dict, out,
                                       confirm_in=input) -> bool:
    """If the validation URL belongs to a different owner than the key
    page (different registrable domain — api.stripe.com and
    dashboard.stripe.com are both stripe.com and need no prompt), require
    the user to type the confirmation word. Returns True when the flow may
    proceed."""
    v = recipe["validate"]
    if same_owner(v["url"], recipe["key_url"]):
        return True
    host = _host(v["url"])
    if recipe.get("_builtin") and host in {
            _normalize_host(h) for h in v.get("trusted_hosts") or []}:
        # A built-in (reviewed, shipped-with-the-code) recipe may vouch for
        # its vendor's second domain: api.anthropic.com for a key page on
        # claude.com. A recipe from ~/.safeeasyapi never gets this shortcut.
        out.write(f"  (validation host {describe_domain(host)} is this "
                  f"vendor's API domain — built-in recipe)\n")
        return True
    domains = [registrable_domain(host),
               registrable_domain(_host(recipe["key_url"]))]
    shown = [describe_domain(d) for d in domains]
    out.write(f"  ⚠ The validation URL is on a DIFFERENT domain than the key "
              f"page above ({shown[0]} vs {shown[1]}).\n")
    if shown != domains:
        out.write("    Names with letters from other alphabets can look "
                  "exactly like another site's; the xn-- spelling in "
                  "brackets is the real one.\n")
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


def store_in_env_file(env_file: str):
    """Default store: ENV_VAR=<key> in `env_file`, owner-only. Returns a
    callable (env_var, key) -> description for the success line."""
    def _store(env_var: str, key: str) -> str:
        stored = store_mod.store_key_result(env_var, key, env_file)
        verb = "updated" if stored.updated else "added"
        text = (f"{verb} {env_var} in {stored.path} "
                f"({stored.protection} - never displayed, never logged)")
        if stored.duplicates:
            # Said plainly, because the person may not know: of several
            # lines for one variable the last one is the one that counts.
            text += (f"\n    note: {env_var} appears "
                     f"{store_mod.times(stored.duplicates + 1)} in "
                     f"{stored.path}; I updated the one that takes effect "
                     f"(the last one).")
        return text
    return _store


def connect(
    recipe: dict,
    env_file: str = ".env",
    browser_open=webbrowser.open,
    prompt=getpass.getpass,
    out=None,
    validate_fn=validate_mod.validate_key,
    confirm_in=input,
    store_fn=None,
) -> int:
    """Run the guided flow. Returns 0 on success, 1 on failure.

    `store_fn(env_var, key) -> description` decides where the validated
    key goes (default: the .env file). Injectable browser_open / prompt /
    validate_fn / confirm_in / store_fn exist for tests and the CLI.
    """
    out = out or sys.stdout
    if store_fn is None:
        # The key is headed for the .env file. If that file is one we will
        # not edit (a link, a UTF-16 file) say so NOW - before the browser
        # opens and before a key is pasted and sent to the API - instead of
        # after the person has done all of it.
        try:
            store_mod.check_env_file(env_file)
        except OSError as e:
            out.write(f"\n  ✗ {env_file}: {e.strerror or e}.\n"
                      f"    Nothing was asked for and nothing was sent.\n")
            return 1
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

    store_fn = store_fn or store_in_env_file(env_file)
    try:
        description = store_fn(recipe["env_var"], key)
    except OSError as e:
        # e.g. --env-file in a folder that is a file, or not writable.
        # The error names the path, never the key. The key is NOT saved;
        # the user still has it on the clipboard.
        out.write(f"\n  ✗ the key was validated but could NOT be saved: "
                  f"{e.strerror or e} ({e.filename or env_file})\n"
                  f"    Nothing was written. Fix the path (or pass "
                  f"--env-file) and run me again.\n")
        return 1
    finally:
        # Scrub the key from this frame whatever happens.
        key = None
        del key
    out.write(f"\n  ✓ {description}\n")
    return 0
