"""Agent-driven key capture: the agent drives the browser, this process takes the key.

The person tells the agent "connect GitHub". The agent opens the vendor's
key page with its own browser tools, makes the key and clicks the vendor's
own Copy button. THIS process (the MCP server, running as the person on
their own computer) sees the clipboard change, takes the new key-shaped
value, EMPTIES the clipboard, tests the key with the vendor, stores it
(.env or the OS keychain) and tells the agent only: stored, which variable,
where, how long. The key is never in a tool result, an error, a log, the
chat or on screen, and the agent never types it anywhere.

Guards (all of them, because the agent is not the owner of the key):
  - the person said yes once for this project and service, in their own
    terminal (`safeeasyapi allow-agent <service>`), recorded in the user's
    home folder - a place the agent's tools and the hook do not reach;
  - built-in recipes only (their validation hosts are reviewed);
  - one capture at a time, a time limit (10 to 180 s), few starts per hour;
  - only a value that CHANGES the clipboard after arming, and only one that
    has the service's key format; what was on the clipboard before is wiped
    and never used;
  - a Windows clipboard history (Win+V) keeps a copy this cannot remove:
    refused unless the person accepted that when granting;
  - a key the vendor rejects, or that cannot be stored, is kept nowhere.
"""

from __future__ import annotations

import datetime
import json
import os
import secrets
import tempfile
import threading
import time

from . import clipboard as clipboard_mod
from . import connect as connect_mod
from . import ledger as ledger_mod
from . import manifest as manifest_mod
from . import recipes as recipes_mod
from . import redact as redact_mod
from . import store as store_mod
from . import validate as validate_mod

MIN_TIMEOUT = 10.0
DEFAULT_TIMEOUT = 120.0
MAX_TIMEOUT = 180.0
MAX_STATUS_WAIT = 60.0
STARTS_PER_HOUR = 6
POLL = 0.1
CONSENT_VERSION = 1


# ---------------------------------------------------------------- consent

def consent_path() -> str:
    """~/.safeeasyapi/agent-consent.json, resolved when asked (HOME may change)."""
    return os.path.join(os.path.expanduser("~"), ".safeeasyapi", "agent-consent.json")


def project_root(cwd: str | None = None) -> str:
    """The folder holding safeeasyapi.json (found upward), else `cwd`."""
    here = cwd or os.getcwd()
    found = manifest_mod.find(here)
    return os.path.realpath(os.path.dirname(found) if found else here)


def _load_grants(path: str | None = None) -> list[dict]:
    try:
        with open(path or consent_path(), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError, RecursionError):
        return []
    items = data.get("grants") if isinstance(data, dict) else None
    return [g for g in (items or []) if isinstance(g, dict)
            and isinstance(g.get("project"), str) and isinstance(g.get("service"), str)]


def _save_grants(grants: list[dict], path: str | None = None) -> None:
    path = path or consent_path()
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".consent-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"version": CONSENT_VERSION, "grants": grants}, f, indent=2)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _same(a: str, b: str) -> bool:
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


def consent_for(project: str, service: str, path: str | None = None) -> dict | None:
    """The person's grant for this project and service, or None."""
    for g in _load_grants(path):
        if g["service"] == service and _same(g["project"], project):
            return g
    return None


def grant(project: str, service: str, history_ok: bool = False,
          path: str | None = None, now: datetime.datetime | None = None) -> None:
    grants = [g for g in _load_grants(path)
              if not (g["service"] == service and _same(g["project"], project))]
    stamp = (now or datetime.datetime.now(datetime.timezone.utc)).replace(microsecond=0)
    grants.append({"project": os.path.realpath(project), "service": service,
                   "clipboard_history_ok": bool(history_ok), "granted": stamp.isoformat()})
    _save_grants(grants, path)


def revoke(project: str, service: str | None = None, path: str | None = None) -> int:
    """Remove the grant(s); how many were removed."""
    grants = _load_grants(path)
    keep = [g for g in grants if not (_same(g["project"], project)
                                      and (service is None or g["service"] == service))]
    if len(keep) != len(grants):
        _save_grants(keep, path)
    return len(grants) - len(keep)


def grants_for(project: str, path: str | None = None) -> list[dict]:
    return [g for g in _load_grants(path) if _same(g["project"], project)]


# ---------------------------------------------------------------- the capture

def length_class(n: int) -> str:
    return "short (under 32 characters)" if n < 32 else (
        "medium (32 to 63 characters)" if n < 64 else "long (64 characters or more)")


class _Capture:
    def __init__(self, slug: str, recipe: dict, root: str, env_file: str, store: str,
                 timeout: float, started: float):
        self.id = secrets.token_hex(4)
        self.slug = slug
        self.recipe = recipe
        self.root = root
        self.env_file = env_file
        self.store = store
        self.deadline = started + timeout
        self.timeout = timeout
        self.state = "waiting"
        self.message = ""
        self.waiting_for = ""
        self.ignored = 0
        self.stored_in: list[str] = []
        self.length_classes: list[str] = []
        self.note: str | None = None
        self.history_note: str | None = None
        self.cancel = threading.Event()
        self.done = threading.Event()

    def public(self) -> dict:
        out = {"capture_id": self.id, "service": self.slug, "state": self.state,
               "env_vars": recipes_mod.env_vars(self.recipe)}
        if self.message:
            out["message"] = self.message
        if self.state == "waiting":
            out["waiting_for"] = self.waiting_for
        if self.ignored:
            out["ignored_clipboard_changes"] = self.ignored
        if self.state == "stored":
            out["stored"] = True
            out["stored_in"] = self.stored_in
            out["key_length"] = self.length_classes
        if self.note:
            out["vendor_note"] = self.note
        if self.history_note:
            out["clipboard_history_warning"] = self.history_note
        return out


class Manager:
    """One capture at a time. Everything the outside world touches is a
    parameter, so tests use a fake clipboard and a fake vendor."""

    def __init__(self, backend=clipboard_mod.backend,
                 validate_fn=validate_mod.validate_key,
                 history_fn=clipboard_mod.history_warning,
                 now=time.monotonic, sleep=time.sleep, poll: float = POLL,
                 consent_file: str | None = None,
                 timeout_limits: tuple[float, float] = (MIN_TIMEOUT, MAX_TIMEOUT),
                 starts_per_hour: int = STARTS_PER_HOUR, store_factory=None,
                 record_fn=ledger_mod.record):
        self.backend = backend
        self.validate_fn = validate_fn
        self.history_fn = history_fn
        self.now = now
        self.sleep = sleep
        self.poll = poll
        self.consent_file = consent_file
        self.limits = timeout_limits
        self.starts_per_hour = starts_per_hour
        self.store_factory = store_factory
        self.record_fn = record_fn
        self._lock = threading.Lock()
        self._current: _Capture | None = None
        self._starts: list[float] = []

    # ---- the three actions

    def start(self, slug: str, recipe: dict, cwd: str | None, timeout=None,
              replace: bool = False) -> dict:
        root = project_root(cwd)
        if recipe.get("_builtin") is not True:
            return _refused("agent capture works only with the recipes that ship with "
                            "safeeasyapi; a recipe of your own is not allowed. Ask the "
                            "person to run `safeeasyapi connect " + slug + "` themselves.")
        grant_ = consent_for(root, slug, self.consent_file)
        if grant_ is None:
            return {"state": "consent_needed", "service": slug, "message": (
                "The person has not allowed agent-driven key capture for this service "
                "in this project. Ask them, in plain words, whether you may do it. If "
                "they agree, tell them to run this in their OWN terminal (you cannot "
                "and must not run it): safeeasyapi allow-agent " + slug +
                " - then call capture_key again. Until then do not open the key page "
                "or click anything.")}
        try:
            get, clear = self.backend()
        except clipboard_mod.Unavailable:
            return {"state": "unavailable", "service": slug, "message": (
                "This computer's clipboard cannot be read from here (no clipboard "
                "tool, or no desktop session). Ask the person to run: safeeasyapi "
                "connect " + slug + " in their own terminal.")}
        warning = None
        try:
            warning = self.history_fn()
        except Exception:
            warning = None
        if warning and not grant_.get("clipboard_history_ok"):
            return {"state": "refused", "service": slug, "clipboard_history": True,
                    "message": (
                        "Windows clipboard history is on: it would keep a copy of the key "
                        "after this tool empties the clipboard, and nothing can remove "
                        "that copy. Nothing was started. Tell the person: either turn "
                        "clipboard history off (Settings > System > Clipboard) and ask "
                        "again, or - if they accept the risk - run in their own "
                        "terminal: safeeasyapi allow-agent " + slug +
                        " --allow-clipboard-history")}
        env_file, store = _where(root, slug, recipe)
        if env_file is None:
            return _refused("safeeasyapi.json has an env_file that is not allowed; "
                            "ask the person to fix it.")
        if store == "env":
            try:
                store_mod.check_env_file(env_file)
            except OSError as e:
                return _refused(f"the key file cannot be used ({e.strerror or 'refused'}); "
                                "nothing was started. Ask the person to look at it.")
        with self._lock:
            if self._current is not None and not self._current.done.is_set():
                return {"state": "busy", "service": self._current.slug,
                        "message": "A capture is already running. Use action=status "
                                   "or action=cancel; only one runs at a time."}
            t = self.now()
            self._starts[:] = [s for s in self._starts if t - s < 3600]
            if len(self._starts) >= self.starts_per_hour:
                return {"state": "refused", "service": slug, "message": (
                    "Too many captures were started in the last hour. Wait, or ask "
                    "the person to run safeeasyapi connect " + slug + " themselves.")}
            low, high = self.limits
            try:
                seconds = float(timeout) if timeout is not None else DEFAULT_TIMEOUT
            except (TypeError, ValueError):
                seconds = DEFAULT_TIMEOUT
            seconds = max(low, min(high, seconds)) if seconds == seconds else DEFAULT_TIMEOUT
            if not replace and _present(recipe, env_file, store):
                return {"state": "already_stored", "service": slug,
                        "env_vars": recipes_mod.env_vars(recipe), "message": (
                            "The key is already stored. Do not capture another unless "
                            "the person asked to replace it (then pass replace=true).")}
            self._starts.append(t)
            cap = _Capture(slug, recipe, root, env_file, store, seconds, t)
            cap.history_note = warning
            self._current = cap
        # The "before" picture is taken HERE, before start() returns: a Copy
        # that happens a moment later must count as new, not as old.
        first = recipes_mod.fields(recipe)[0]
        seen = _snapshot(get, clear, _gate(first))
        threading.Thread(target=self._run, args=(cap, get, clear, seen), daemon=True).start()
        out = cap.public()
        out["timeout_seconds"] = int(seconds)
        out["message"] = ("Armed. Now, in the browser, create the key and click the "
                          "vendor's Copy button - nothing else. Then call "
                          "capture_key with action=status (it can wait up to "
                          f"{int(MAX_STATUS_WAIT)} seconds).")
        return out

    def status(self, wait=None) -> dict:
        cap = self._current
        if cap is None:
            return {"state": "idle", "message": "No capture has been started."}
        try:
            seconds = max(0.0, min(MAX_STATUS_WAIT, float(wait or 0)))
        except (TypeError, ValueError):
            seconds = 0.0
        cap.done.wait(seconds)
        return cap.public()

    def cancel(self) -> dict:
        cap = self._current
        if cap is None or cap.done.is_set():
            return {"state": "idle", "message": "Nothing is running."}
        cap.cancel.set()
        cap.done.wait(5)
        return cap.public()

    # ---- the worker

    def _run(self, cap: _Capture, get, clear, seen) -> None:
        values: dict[str, str] = {}
        try:
            self._collect(cap, get, clear, values, seen)
            if cap.state == "waiting":
                self._finish(cap, values)
        except Exception:                       # never lets the key into a message
            cap.state = "failed"
            cap.message = "Capture failed unexpectedly. Nothing was saved."
        finally:
            values.clear()
            if cap.state == "waiting":
                cap.state = "failed"
            cap.done.set()

    def _collect(self, cap, get, clear, values, seen) -> None:
        fields = recipes_mod.fields(cap.recipe)
        single = len(fields) == 1 and fields[0]["name"] == recipes_mod.DEFAULT_FIELD
        for index, field in enumerate(fields):
            cap.waiting_for = "the key" if single else f"the {field['label']}"
            gate = _gate(field)
            if index:
                seen = _snapshot(get, clear, gate)
            while True:
                if cap.cancel.is_set():
                    cap.state = "cancelled"
                    cap.message = "Cancelled. Nothing was saved."
                    return
                if self.now() >= cap.deadline:
                    cap.state = "timeout"
                    cap.message = ("No key was copied in time. Nothing was saved. If "
                                   "the person's browser needed a login, 2FA, a CAPTCHA "
                                   "or a password, ask them to do that in the browser, "
                                   "then start again.")
                    return
                self.sleep(self.poll)
                current = (get() or "").strip()
                if current == seen:
                    continue
                seen = current
                if not current:
                    continue
                if current in values.values():
                    continue
                if clipboard_mod.looks_like(current, gate):
                    values[field["name"]] = current
                    clear()                     # emptied the moment it is taken
                    break
                cap.ignored += 1                # something else was copied: not used
            current = None

    def _finish(self, cap, values) -> None:
        recipe = cap.recipe
        fields = recipes_mod.fields(recipe)
        single = len(fields) == 1 and fields[0]["name"] == recipes_mod.DEFAULT_FIELD
        scrub = redact_mod.Redactor(list(values.values()))
        if cap.store == "env":
            for value in values.values():
                if store_mod.unsafe_reason(value):
                    cap.state = "failed"
                    cap.message = ("The copied value has a character a .env file cannot "
                                   "hold safely, so it is not a usable key. Nothing was "
                                   "sent or saved.")
                    return
        try:
            ok = self.validate_fn(recipe["validate"],
                                  values[recipes_mod.DEFAULT_FIELD] if single else dict(values))
        except validate_mod.UnsendableKey:
            cap.state = "failed"
            cap.message = "The copied value cannot be used as a key. Nothing was saved."
            return
        except validate_mod.ValidationError as e:
            cap.state = "failed"
            cap.message = ("The vendor could not be reached or answered oddly: "
                           + scrub.text(recipes_mod.printable(e))[:200]
                           + ". Nothing was saved.")
            return
        if not ok:
            cap.state = "failed"
            cap.message = ("The vendor rejected the copied value - it was not the key, "
                           "or it is expired. Nothing was saved. Check which button "
                           "was clicked, then start again.")
            return
        cap.note = getattr(ok, "note", None) and scrub.text(
            recipes_mod.printable(ok.note, words=True))
        store_fn = (self.store_factory or _default_store)(recipe, cap.env_file, cap.store)
        saved = []
        try:
            for field in fields:
                saved.append(store_fn(field["env_var"], values[field["name"]]))
        except Exception as e:
            cap.state = "failed"
            why = scrub.text(recipes_mod.printable(getattr(e, "strerror", None) or e))[:200]
            cap.message = (f"The key was valid but could NOT be saved ({why}). It is "
                           "not kept anywhere. " + (
                               "Only part was written; ask the person to run "
                               f"safeeasyapi forget {cap.slug}." if saved else
                               "Nothing was written."))
            return
        cap.stored_in = [scrub.text(_first_line(d)) for d in saved]
        cap.length_classes = [length_class(len(v)) for v in values.values()]
        cap.state = "stored"
        cap.message = ("Stored and the clipboard was emptied. The key was not shown "
                       "to you and must not be looked for. Use the variable by name.")
        try:
            self.record_fn(cap.root, cap.slug, cap.store)
        except Exception:
            pass


def _gate(field: dict):
    """The key format a copied value must have: the recipe's accept pattern, or
    its detect pattern when that is a documented ("known") shape; else None
    (a plausible single-token value)."""
    return field.get("accept") or (field.get("detect")
                                   if field.get("detect_confidence") == "known" else None)


def _snapshot(get, clear, gate) -> str:
    """What is on the clipboard now is OLD. Key-like content is wiped, so that
    copying the same key again counts as a change; anything else is just
    remembered as 'before'."""
    seen = (get() or "").strip()
    if seen and (clipboard_mod.looks_like(seen, None) or clipboard_mod.looks_like(seen, gate)):
        clear()
        return ""
    return seen


def _first_line(text: str) -> str:
    return (text or "").splitlines()[0] if text else ""


def _refused(message: str) -> dict:
    return {"state": "refused", "message": message}


def _where(root: str, slug: str, recipe: dict):
    manifest = None
    path = os.path.join(root, manifest_mod.FILE_NAME)
    if os.path.isfile(path):
        try:
            manifest = manifest_mod.load(path)
        except manifest_mod.ManifestError:
            manifest = None
    try:
        env_file = manifest_mod.env_file_in(root, manifest)
    except manifest_mod.ManifestError:
        return None, None
    store = "env"
    for item in (manifest or {}).get("services", []):
        if item["service"] == slug:
            store = item.get("store", "env")
    return env_file, store


def _present(recipe: dict, env_file: str, store: str) -> bool:
    if store == "keychain":
        return False
    from . import presence as presence_mod
    have = presence_mod.env_names(env_file)
    return all(v in have for v in recipes_mod.env_vars(recipe))


def _default_store(recipe: dict, env_file: str, store: str):
    """store_fn for an agent capture. Never asks the person anything: a
    keychain that fails does not fall back to a plain file."""
    if store == "keychain":
        from . import cli as cli_mod
        import io
        return cli_mod.keychain_store(recipe, env_file, out=io.StringIO(),
                                      interactive=lambda: False)
    return connect_mod.store_in_env_file(env_file)


_MANAGER: Manager | None = None


def default_manager() -> Manager:
    global _MANAGER
    if _MANAGER is None:
        _MANAGER = Manager()
    return _MANAGER


def set_manager(manager: Manager | None) -> None:
    """For tests: replace (or reset) the process-wide manager."""
    global _MANAGER
    _MANAGER = manager
