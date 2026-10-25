"""What an AI agent may ask for, and the only things it gets back.

The handshake: the agent says WHICH key it needs; a person gets the key from
the vendor into the project using `safeeasyapi connect`. The agent never
sees, reads or writes a key, so a key is never in its chat or its logs.

Every answer here is built from a short fixed list of fields - a service
name, a variable NAME, a status word, a sentence for the human - and is then
passed through guard_text(), which blanks any secret value this process can
reach (a variable in its environment, a value in the project's .env), in its
raw form and the common re-writings (redact.py). It is two locks: the answer
is never built from a value, and if one ever got in, it would be removed.
"""

from __future__ import annotations

import json
import os
import re
import time

from . import detect as detect_mod
from . import manifest as manifest_mod
from . import presence as presence_mod
from . import recipes as recipes_mod
from . import redact as redact_mod
from . import store as store_mod

MAX_SERVICES = 100
OPEN_COOLDOWN = 30.0         # seconds between two openings of one key page
_LAST_OPEN: dict[str, float] = {}
STATUSES = ("present", "missing", "unknown")
AGENT_RULE = ("Do not ask the person to paste a key into chat, and do not read or "
              "write .env files or any file holding keys. Ask the person to run "
              "the command below in their own terminal; the key goes from the "
              "vendor page straight to the project without passing through you.")


def secrets_in_reach(catalog: dict, cwd: str | None = None, environ=None) -> list[str]:
    """Secret-looking values this process can reach: the catalog's variables in
    its environment, and every value in the project's .env (not the keychain:
    reading that can pop an unlock dialog). Only used to blank them out."""
    environ = os.environ if environ is None else environ
    found: list[str] = []
    for recipe in catalog.values():
        for var in recipes_mod.env_vars(recipe):
            value = environ.get(var)
            if value and len(value) >= redact_mod.MIN_LENGTH:
                found.append(value)
    cwd = cwd or os.getcwd()
    path = os.path.join(cwd, ".env")
    try:
        store_mod.refuse_link(path)
        if os.path.isfile(path):
            for value in list(store_mod.load_env(path).values())[:200]:
                if len(value) >= redact_mod.MIN_LENGTH:
                    found.append(value)
    except (OSError, ValueError):
        pass
    return found


def guard_text(text: str, catalog: dict, cwd: str | None = None, environ=None) -> str:
    """`text` with every reachable secret value (and its common re-writings)
    replaced by [REDACTED]."""
    values = secrets_in_reach(catalog, cwd, environ)
    if not values:
        return text
    return redact_mod.Redactor(values).text(text)


def clean_slug(service) -> str | None:
    """The service name if it is a plain slug, else None. An argument that is
    not one is never echoed back (it could be a key pasted by mistake)."""
    return service if isinstance(service, str) and recipes_mod.SLUG_RE.match(service) else None


def _bad_service(catalog: dict) -> dict:
    return {"error": "service must be a short name from list_services, like 'stripe'",
            "isError": True}


def _status(variables, env_file: str, store: str) -> str:
    if store == "keychain":
        return "unknown"        # not checked from here: asking the keychain can prompt the person
    have = presence_mod.env_names(env_file)
    return "present" if all(v in have for v in variables) else "missing"


def _project_manifest(root: str):
    path = os.path.join(root, manifest_mod.FILE_NAME)
    if not os.path.isfile(path):
        return None
    try:
        return manifest_mod.load(path)
    except manifest_mod.ManifestError:
        return None


def request_connect(service, catalog: dict, open_key_page: bool = False,
                    opener=None, cwd: str | None = None) -> dict:
    """The agent asks for a key. Returns only {service, env_var(s), status,
    instructions}. `open_key_page` opens the vendor's key page in the
    person's own browser (nothing else is started)."""
    slug = clean_slug(service)
    recipe = catalog.get(slug) if slug else None
    if recipe is None:
        return {"error": "no such service. Call list_services for the names I know.",
                "isError": True}
    root = cwd or os.getcwd()
    manifest = _project_manifest(root)
    store = "env"
    env_file = os.path.join(root, ".env")
    if manifest:
        env_file = os.path.join(root, manifest.get("env_file") or ".env")
        for item in manifest["services"]:
            if item["service"] == slug:
                store = item.get("store", "env")
    variables = recipes_mod.env_vars(recipe)
    status = _status(variables, env_file, store)
    out = {"service": slug, "env_var": recipe["env_var"], "env_vars": variables,
           "status": status}
    if status == "present":
        out["instructions"] = (f"{recipe['display']} is already set up. Use the variable "
                               f"{recipe['env_var']} from the environment; do not read its value.")
        return out
    out["instructions"] = (
        f"Ask the person to run, in their own terminal: safeeasyapi connect {slug}"
        f"{' --store keychain' if store == 'keychain' else ''}. It opens the key page, "
        f"takes the key safely and stores it as {recipe['env_var']}. "
        f"Run `safeeasyapi run {slug} -- <your command>` to use it. " + AGENT_RULE)
    out["key_page"] = recipe["key_url"]
    if open_key_page:
        if opener is None:
            import webbrowser
            opener = webbrowser.open
        now = time.monotonic()
        if now - _LAST_OPEN.get(slug, -1e9) < OPEN_COOLDOWN:
            out["opened_key_page"] = False      # an agent cannot make tabs pile up
            out["note"] = "the key page was opened a moment ago"
        else:
            _LAST_OPEN[slug] = now
            try:
                opener(recipe["key_url"])
                out["opened_key_page"] = True
            except Exception:
                out["opened_key_page"] = False
    return out


def needs_keys(project, catalog: dict, cwd: str | None = None) -> dict:
    """Which keys does this project use, and which are not stored yet? Reads
    variable NAMES from safeeasyapi.json, .env.example-style templates and
    source code (never a real .env's contents), and only checks whether a
    value exists."""
    root = cwd or os.getcwd()
    if project not in (None, ""):
        if not isinstance(project, str) or "\x00" in project:
            return {"error": "project must be a folder path", "isError": True}
        root = os.path.abspath(project)
    if not os.path.isdir(root):
        return {"error": "that folder does not exist", "isError": True}
    manifest = _project_manifest(root)
    env_file = os.path.join(root, (manifest or {}).get("env_file") or ".env")
    wanted: dict[str, dict] = {}
    for item in (manifest or {}).get("services", []):
        recipe = catalog.get(item["service"])
        wanted[item["service"]] = {
            "service": item["service"],
            "env_vars": manifest_mod.service_vars(item, recipe),
            "store": item.get("store", "env")}
    for found in detect_mod.detect(root, catalog)[0]:
        wanted.setdefault(found["service"], dict(found, store="env"))
    services = []
    for slug in sorted(wanted)[:MAX_SERVICES]:
        info = wanted[slug]
        services.append({"service": slug, "env_vars": info["env_vars"],
                         "status": _status(info["env_vars"], env_file, info["store"])})
    missing = [s["service"] for s in services if s["status"] == "missing"]
    out = {"services": services, "missing": missing,
           "source": "safeeasyapi.json" if manifest else "variable names found in the project"}
    if missing:
        out["instructions"] = (
            "Ask the person to run, in their own terminal: safeeasyapi setup "
            "(or safeeasyapi connect <service> for one). " + AGENT_RULE)
    else:
        out["instructions"] = "Nothing is missing."
    return out


def as_text(payload: dict, catalog: dict, cwd: str | None = None) -> str:
    """The JSON text of an answer, with reachable secrets blanked."""
    return guard_text(json.dumps(payload), catalog, cwd)
