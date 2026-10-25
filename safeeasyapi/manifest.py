"""`safeeasyapi.json`: which services a project needs, and nothing secret.

A project file you COMMIT, so a teammate (or you, on a new laptop) can run
`safeeasyapi setup` and be walked through every key the project needs:

    {
      "version": 1,
      "max_age_days": 90,
      "services": [
        {"service": "openai", "env_vars": ["OPENAI_API_KEY"]},
        {"service": "stripe", "env_vars": ["STRIPE_SECRET_KEY"], "store": "keychain"}
      ]
    }

It holds names only: service slugs, variable names, where each key is kept.
A file with any other member, or with something that looks like a key where
a name belongs, is refused - so it can never become a place a key hides.
"""

from __future__ import annotations

import json
import os
import re
import tempfile

from . import recipes as recipes_mod

FILE_NAME = "safeeasyapi.json"
VERSION = 1
STORES = ("env", "keychain")
DEFAULT_MAX_AGE_DAYS = 90
MAX_BYTES = 256 * 1024
MAX_SERVICES = 200
TOP_KEYS = {"version", "max_age_days", "services", "env_file"}
SERVICE_KEYS = {"service", "env_vars", "store"}


class ManifestError(ValueError):
    """The manifest cannot be used. The text names the problem, never a value."""


def find(start: str | None = None) -> str | None:
    """The nearest safeeasyapi.json at or above `start` (default: here)."""
    here = os.path.realpath(start or os.getcwd())
    for _ in range(64):
        candidate = os.path.join(here, FILE_NAME)
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(here)
        if parent == here:
            return None
        here = parent
    return None


def validate(data) -> dict:
    if not isinstance(data, dict):
        raise ManifestError("the manifest must be a JSON object")
    extra = set(data) - TOP_KEYS
    if extra:
        raise ManifestError(f"unknown member(s) in the manifest: "
                            f"{', '.join(sorted(recipes_mod.printable(k) for k in extra))}")
    if data.get("version", VERSION) != VERSION:
        raise ManifestError(f"this safeeasyapi reads manifest version {VERSION}")
    age = data.get("max_age_days", DEFAULT_MAX_AGE_DAYS)
    if not isinstance(age, int) or isinstance(age, bool) or not 1 <= age <= 3650:
        raise ManifestError("max_age_days must be a whole number of days (1-3650)")
    env_file = data.get("env_file")
    if env_file is not None and not (isinstance(env_file, str) and env_file
                                     and "\x00" not in env_file and len(env_file) < 260
                                     and not os.path.isabs(env_file)
                                     and ".." not in env_file.replace("\\", "/").split("/")):
        raise ManifestError("env_file must be a relative path inside the project")
    services = data.get("services")
    if not isinstance(services, list) or len(services) > MAX_SERVICES:
        raise ManifestError("services must be a list")
    seen = set()
    for item in services:
        if not isinstance(item, dict):
            raise ManifestError("each service must be an object")
        extra = set(item) - SERVICE_KEYS
        if extra:
            raise ManifestError(f"unknown member(s) in a service: "
                                f"{', '.join(sorted(recipes_mod.printable(k) for k in extra))}")
        slug = item.get("service")
        if not isinstance(slug, str) or not recipes_mod.SLUG_RE.match(slug):
            raise ManifestError("each service needs a 'service' name like 'stripe'")
        if slug in seen:
            raise ManifestError(f"service '{slug}' is listed twice")
        seen.add(slug)
        names = item.get("env_vars", [])
        if not isinstance(names, list) or not all(
                isinstance(n, str) and recipes_mod.ENV_VAR_RE.match(n) and len(n) <= 100
                for n in names):
            raise ManifestError(f"service '{slug}': env_vars must be variable NAMES "
                                f"like OPENAI_API_KEY (never a value)")
        if item.get("store", "env") not in STORES:
            raise ManifestError(f"service '{slug}': store must be 'env' or 'keychain'")
    return data


def load(path: str) -> dict:
    try:
        if os.path.islink(path):
            raise ManifestError(f"{FILE_NAME} is a link; refusing to follow it")
        with open(path, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except OSError as e:
        raise ManifestError(f"cannot read {FILE_NAME}: {e.strerror or e}") from None
    if len(raw) > MAX_BYTES:
        raise ManifestError(f"{FILE_NAME} is too big")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise ManifestError(f"{FILE_NAME} is not valid JSON") from None
    return validate(data)


def save(path: str, data: dict) -> None:
    """Write atomically. The file is meant to be committed, so it is a normal
    (not owner-only) file; validate() has just proved it holds names only."""
    validate(data)
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".safeeasyapi.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def service_vars(item: dict, recipe: dict | None) -> list[str]:
    """The variable names for a manifest service: its own list, else the recipe's."""
    if item.get("env_vars"):
        return list(item["env_vars"])
    return recipes_mod.env_vars(recipe) if recipe else []
