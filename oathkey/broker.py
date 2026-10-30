"""The broker: let an AI call an API without ever holding the key.

The AI says only: service, method, path, query, body. The broker picks the
host (from the recipe, never from the AI), adds the credential itself,
refuses private/internal addresses, does not follow redirects, hides the key
(in many encodings) from whatever comes back, and writes a tamper-evident
log line (never the query string, body or headers).

What it cannot do: stop a prompt-injected AI from using an allowed API for
something harmful within its permissions. That is why writes need a person's
approval and why the log exists. See SECURITY.md.
"""
from __future__ import annotations

import contextlib
import functools
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import validate as _v
from .scrub import Scrubber, loosely_contains

MAX_BODY_OUT = 1_000_000      # most we read back
MAX_BODY_IN = 256_000         # most the AI may send
READ_METHODS = {"GET", "HEAD"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_PATH_OK = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*")
_EXPOSED_HEADERS = ("content-type", "content-length", "retry-after",
                    "x-ratelimit-remaining", "x-ratelimit-reset", "location")

MAX_REVIEW = 900     # longest request description a person can really read

# AWS "GET" requests can still mint new credentials (GetSessionToken,
# AssumeRole, ...). For signed AWS services only plain look-ups are allowed.
_SIGV4_STS_OK = {"GetCallerIdentity"}
_SIGV4_OK_PREFIX = ("Describe", "List")
_SIGV4_OK_EXACT = {"GetCallerIdentity", "GetAccountSummary"}


def check_sigv4_action(recipe: dict, url: str) -> None:
    spec = (recipe.get("validate") or {}).get("auth", {})
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query, keep_blank_values=True)
    actions = q.get("Action", [])
    if len(actions) > 1:
        raise BrokerError("more than one Action; refused", 5)
    action = actions[0] if actions else ""
    if spec.get("service") == "sts":
        if action not in _SIGV4_STS_OK:
            raise BrokerError("through this tool, AWS STS may only be asked "
                              "'GetCallerIdentity' (other STS actions create new "
                              "keys); refused", 5)
    elif action and not (action in _SIGV4_OK_EXACT or action.startswith(_SIGV4_OK_PREFIX)):
        raise BrokerError(f"AWS action '{action[:40]}' is not a plain look-up; refused", 5)


def _clean(text, limit=80) -> str:
    return "".join(c if c.isprintable() else "?" for c in str(text))[:limit]


class BrokerError(Exception):
    """A refusal or failure. The text never contains the key."""

    def __init__(self, message: str, code: int = 5):
        super().__init__(message)
        self.code = code        # 5 = refused by policy, 7 = network, 4 = auth


class Policy:
    """What this session may do. Defaults are the safe ones."""

    def __init__(self, allow_write: bool = False, max_calls: int = 100,
                 max_per_minute: int = 30, approve=None):
        self.allow_write = allow_write
        self.max_calls = max_calls
        self.max_per_minute = max_per_minute
        self.approve = approve          # callable(summary) -> bool, or None
        self._stamps: list[float] = []
        self.calls = 0
        self.denials = 0
        self.approved_hosts: set[tuple[str, str]] = set()
        self.lock = threading.RLock()           # one decision at a time

    def count(self, now: float | None = None) -> None:
        with self.lock:
            now = time.monotonic() if now is None else now
            self._stamps = [t for t in self._stamps if now - t < 60]
            if self.calls >= self.max_calls:
                raise BrokerError(f"Limit of {self.max_calls} calls reached for "
                                  "this session. Restart the AI app to reset.", 5)
            if len(self._stamps) >= self.max_per_minute:
                raise BrokerError("Too many calls per minute; wait a minute "
                                  "and retry.", 5)
            self.calls += 1
            self._stamps.append(now)

    def ask(self, summary: str) -> bool:
        """Ask the person, one prompt at a time; after 3 refusals stop asking."""
        with self.lock:
            if self.approve is None:
                return False
            if self.denials >= 3:
                raise BrokerError("The person said no three times; no more "
                                  "requests this session.", 5)
            yes = bool(self.approve(summary))
            if not yes:
                self.denials += 1
            return yes


# ---- address safety ----------------------------------------------------------

def is_public_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        # IPv6 forms that carry an IPv4 address inside: judge that one too
        inner = []
        if ip.ipv4_mapped:
            inner.append(ip.ipv4_mapped)
        if ip.sixtofour:
            inner.append(ip.sixtofour)
        if ip.teredo:
            inner.extend(ip.teredo)
        if ip in ipaddress.ip_network("64:ff9b::/96"):
            inner.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if inner:
            return all(is_public_ip(str(i)) for i in inner)
    return ip.is_global and not ip.is_multicast


def resolve_public(host: str, port: int = 443, resolver=None) -> str:
    """One public IP for host, or refuse. Every address it resolves to must
    be public, so a name that also points inside is not accepted."""
    infos = (resolver or socket.getaddrinfo)(host, port, type=socket.SOCK_STREAM)
    ips = []
    for info in infos:
        ip = info[4][0].split("%")[0]
        if not is_public_ip(ip):
            raise BrokerError(f"{host} resolves to a private or internal "
                              "address; refused", 5)
        ips.append(ip)
    if not ips:
        raise BrokerError(f"could not resolve {host}", 7)
    return ips[0]


class _Pinned(http.client.HTTPSConnection):
    """Connect to the IP we already checked, but verify the certificate for
    the real name (so DNS cannot change its answer between check and use)."""

    def __init__(self, host, ip=None, **kw):
        super().__init__(host, **kw)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _real_send(req: urllib.request.Request, ip: str, timeout: float):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    class Pin(urllib.request.HTTPSHandler):
        def https_open(self, r):
            return self.do_open(functools.partial(_Pinned, ip=ip), r)

    # ProxyHandler({}) ignores HTTP(S)_PROXY: a proxy would defeat the pin
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         Pin(), NoRedirect())
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        resp = e
    except (urllib.error.URLError, OSError, http.client.HTTPException):
        raise BrokerError("network error talking to the API", 7) from None
    except ValueError:
        raise BrokerError("the HTTP library refused the request", 7) from None
    with resp:
        body = resp.read(MAX_BODY_OUT + 1)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return getattr(resp, "status", None) or resp.code, headers, body


# ---- the call ------------------------------------------------------------------

def allowed_host(recipe: dict) -> str:
    url = (recipe.get("validate") or {}).get("url", "")
    p = urllib.parse.urlsplit(url)
    if p.scheme != "https" or not p.hostname:
        raise BrokerError(f"recipe '{recipe.get('service')}' has no https "
                          "host to call", 5)
    return p.hostname.lower()


def check_path(path: str) -> str:
    if not isinstance(path, str) or not _PATH_OK.fullmatch(path):
        raise BrokerError("path must start with / and use only URL path "
                          "characters", 5)
    if path.startswith("//"):
        raise BrokerError("path may not start with //", 5)
    low = path.lower()
    if (";" in path or "%25" in low or "%00" in low or "%2f" in low or "//" in path
            or "%u" in low or "%c0" in low or "%c1" in low):
        raise BrokerError("path contains an encoding or character that "
                          "servers read differently; refused", 5)
    decoded = path
    for _ in range(4):                       # decode to a fixed point
        nxt = urllib.parse.unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    segments = decoded.split("/")
    if ".." in segments or "." in segments[1:-1] or "\\" in decoded or "\x00" in decoded:
        raise BrokerError("path may not contain . or .. segments", 5)
    return path


# query names that turn a harmless GET into an action on some servers
_OVERRIDE_KEYS = {"method", "_method", "$httpmethod", "x-http-method-override",
                  "http_method", "httpmethod"}


def build_url(recipe: dict, path: str, query: dict | None) -> tuple[str, str]:
    host = allowed_host(recipe)
    auth = (recipe.get("validate") or {}).get("auth", {})
    query = dict(query or {})
    if auth.get("type") == "query" and auth.get("param") in query:
        raise BrokerError("the credential parameter is set by the broker", 5)
    if len(query) > 50:
        raise BrokerError("too many query parameters", 5)
    for k, v in query.items():
        if not isinstance(k, str) or not isinstance(v, (str, int, float, bool)):
            raise BrokerError("query values must be plain text or numbers", 5)
        if k.strip().lower() in _OVERRIDE_KEYS:
            raise BrokerError(f"query parameter '{k}' can change what a GET "
                              "does on some servers; refused", 5)
        if auth.get("type") == "query" and k.strip().lower() == str(auth.get("param", "")).lower():
            raise BrokerError("the credential parameter is set by the broker", 5)
    q = urllib.parse.urlencode(query)
    url = f"https://{host}{check_path(path)}" + (f"?{q}" if q else "")
    if urllib.parse.urlsplit(url).hostname != host:       # belt and braces
        raise BrokerError("host mismatch; refused", 5)
    return host, url


NO_APPROVAL = ("The person did not approve this (or no approval window could "
               "be shown). Do not retry; tell the person to allow it, then ask "
               "again.")


def describe(recipe: dict, method: str, host: str, url: str, data) -> str:
    """What the person is asked to approve. Shows everything that matters."""
    parts = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    text = f"{method} https://{host}{parts.path}"
    if q:
        text += "  query: " + ", ".join(f"{k}={v[:60]}" for k, v in q)
    if data:
        text += (f"  body: {len(data)} bytes, sha256 "
                 f"{hashlib.sha256(data).hexdigest()[:12]}, starts: "
                 f"{data[:160].decode('utf-8', 'replace')!r}")
    return f"Using your '{recipe['service']}' key:  " + text


def credentials(recipe: dict, values: dict):
    from .recipes import fields
    flds = fields(recipe)
    if len(flds) == 1:
        return values[flds[0]["env_var"]]
    return {f["name"]: values[f["env_var"]] for f in flds}


def call(recipe: dict, values: dict, method: str, path: str,
         query: dict | None = None, body=None, policy: Policy | None = None,
         audit=None, send=None, resolver=None, timeout: float = 20.0) -> dict:
    """One brokered API call. `values` = {env_var: key}. Returns a dict that
    is safe to hand to an AI: status, a few headers, the (scrubbed) body."""
    policy = policy or Policy()
    method = str(method).upper()
    if method not in READ_METHODS | WRITE_METHODS:
        raise BrokerError("method not supported", 5)
    try:
        host, url = build_url(recipe, path, query)
    except BrokerError:
        _log(audit, recipe, method, "?", _clean(path), 0, 0, "refused")
        raise
    auth_type = (recipe.get("validate") or {}).get("auth", {}).get("type", "bearer")
    if method in WRITE_METHODS and auth_type == "aws_sigv4":
        raise BrokerError("this service signs requests; only reads are "
                          "supported through the broker", 5)
    if auth_type == "aws_sigv4":
        try:
            check_sigv4_action(recipe, url)
        except BrokerError:
            _log(audit, recipe, method, host, _clean(path), 0, 0, "refused")
            raise

    data = None
    if body is not None:
        if method in READ_METHODS:
            raise BrokerError("GET/HEAD may not have a body", 5)
        if isinstance(body, bytes):
            data = body
        elif isinstance(body, str):
            data = body.encode()
        else:
            data = json.dumps(body).encode()
        if len(data) > MAX_BODY_IN:
            raise BrokerError("request body too large", 5)

    # permission: counted first (so floods are limited before they can
    # nag the person), then writes need a grant or a person's yes
    policy.count()
    with policy.lock:
        if method in WRITE_METHODS and not policy.allow_write:
            summary = describe(recipe, method, host, url, data)
            if len(summary) > MAX_REVIEW:
                _log(audit, recipe, method, host, path, 0, 0, "refused")
                raise BrokerError("This request is too long for you to review "
                                  "safely, so it was refused. Ask for something "
                                  "smaller.", 5)
            if not policy.ask(summary):
                _log(audit, recipe, method, host, path, 0, 0, "denied")
                raise BrokerError(NO_APPROVAL, 5)
        elif (recipe["service"], host) not in policy.approved_hosts:
            if policy.approve is not None:
                if not policy.ask(f"First use of '{recipe['service']}' "
                                  f"(talks to {host}). Read-only requests will "
                                  "then be allowed this session."):
                    _log(audit, recipe, method, host, path, 0, 0, "denied")
                    raise BrokerError(NO_APPROVAL, 5)
            policy.approved_hosts.add((recipe["service"], host))

    if audit is not None:
        audit.ready()
    creds = credentials(recipe, values)
    spec = dict(recipe["validate"])
    spec["url"] = url
    token = None
    if auth_type == "oauth2_client_credentials":
        token = _v._fetch_token(spec, _v._creds(creds), timeout)
    req = _v._build_request(spec, creds, token)       # builds GET + credential
    req.method = method
    if data is not None:
        req.data = data
        req.add_header("Content-Type", "application/json")
    try:
        ip = resolve_public(host, 443, resolver)
    except BrokerError:
        _log(audit, recipe, method, host, path, 0, 0, "refused")
        raise

    started = time.time()
    try:
        status, headers, raw = (send or _real_send)(req, ip, timeout)
    except BrokerError:
        _log(audit, recipe, method, host, path, 0, 0, "network-error")
        raise

    secrets = [v for v in values.values() if isinstance(v, str)]
    if token:
        secrets.append(token)           # the OAuth token we minted is a secret too
    sc = Scrubber(secrets)
    ctype = headers.get("content-type", "")
    textual = any(t in ctype for t in ("json", "text", "xml", "html", "x-www-form"))
    if textual and headers.get("content-encoding", "").lower() not in ("", "identity"):
        shown = "[response is compressed; not shown]"
    elif textual:
        # scrub everything we read, then clip (a key at the cut line is caught)
        whole = (sc.feed(raw) + sc.flush())
        if loosely_contains(whole.decode("utf-8", "replace"), secrets):
            shown = "[response withheld: it appears to contain the key in a disguised form]"
        else:
            shown = whole[:MAX_BODY_OUT].decode("utf-8", "replace")
    else:
        shown = f"[binary {len(raw)} bytes sha256 {hashlib.sha256(raw).hexdigest()[:16]}]"
    keep = {}
    for k in _EXPOSED_HEADERS:
        if k in headers:
            hs = Scrubber(secrets)
            keep[k] = (hs.feed(headers[k].encode()) + hs.flush()).decode("utf-8", "replace")
    _log(audit, recipe, method, host, path, status, len(raw), "ok",
         ms=int((time.time() - started) * 1000))
    return {"status": status, "headers": keep, "body": shown,
            "truncated": len(raw) > MAX_BODY_OUT}


# ---- audit log (hash chained) -------------------------------------------------

def _log(audit, recipe, method, host, path, status, size, result, ms=0):
    if audit is None:
        return
    try:
        audit.write({"service": recipe.get("service"), "method": method,
                     "host": host, "path": path.split("?")[0], "status": status,
                     "bytes": size, "result": result, "ms": ms})
    except OSError:
        pass            # ready() already refused to act when the log is unwritable


@contextlib.contextmanager
def _file_lock(path: str):
    """One writer at a time across processes (MCP + serve + call may all run).
    If the lock cannot be taken we carry on: the in-process lock still holds."""
    fd = None
    locked = False
    try:
        fd = os.open(path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        if os.name == "nt":
            import msvcrt
            for _ in range(100):
                try:
                    os.lseek(fd, 0, 0)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    locked = True
                    break
                except OSError:
                    time.sleep(0.05)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
            locked = True
    except OSError:
        pass
    try:
        yield
    finally:
        if fd is not None:
            try:
                if locked and os.name == "nt":
                    import msvcrt
                    os.lseek(fd, 0, 0)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
            os.close(fd)


class AuditLog:
    """Append-only JSON lines; each line holds the hash of the line before.
    Change or remove any line and verify() says so. Never records query
    strings, bodies or headers."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    _lock = threading.Lock()

    def _last_hash(self) -> str:
        try:
            with open(self.path, "rb") as f:
                lines = f.read().splitlines()
        except OSError:
            return "0" * 64
        for line in reversed(lines):             # skip junk at the end
            try:
                return json.loads(line)["hash"]
            except (ValueError, KeyError, TypeError):
                continue
        return "0" * 64

    def ready(self) -> None:
        """Refuse to act if we could not record it afterwards."""
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            os.close(fd)
        except OSError:
            raise BrokerError("The activity log cannot be written, so "
                              "nothing was sent.", 5) from None

    @property
    def anchor_path(self) -> str:
        return self.path + ".head"

    def _count(self) -> int:
        n = 0
        try:
            with open(self.path, "rb") as f:
                for line in f.read().splitlines():
                    try:
                        json.loads(line)["hash"]
                        n += 1
                    except (ValueError, KeyError, TypeError):
                        continue
        except OSError:
            pass
        return n

    def _read_anchor(self):
        try:
            with open(self.anchor_path, encoding="utf-8") as f:
                count, h = f.read().split()
            return int(count), h
        except (OSError, ValueError):
            return None

    def _save_anchor(self, count: int, h: str) -> None:
        """A second small file holding how many entries there should be and
        the last hash, so cutting the end off the log (or deleting it) shows.
        Someone running as you can rewrite both files; this catches accidents
        and casual tampering, not a determined attacker (see SECURITY.md)."""
        tmp = self.anchor_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(f"{count} {h}\n")
            os.replace(tmp, self.anchor_path)
        except OSError:
            pass

    def write(self, entry: dict) -> None:
        with AuditLog._lock, _file_lock(self.path):   # one writer at a time
            count = self._count()
            entry = dict(entry, ts=int(time.time()), prev=self._last_hash())
            entry["hash"] = hashlib.sha256(
                json.dumps(entry, sort_keys=True).encode()).hexdigest()
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, (json.dumps(entry, sort_keys=True) + "\n").encode())
                os.fsync(fd)
            finally:
                os.close(fd)
            self._save_anchor(count + 1, entry["hash"])

    def verify(self) -> tuple[bool, int]:
        prev, n = "0" * 64, 0
        try:
            with open(self.path, "rb") as f:
                for line in f.read().splitlines():
                    e = json.loads(line)
                    h = e.pop("hash")
                    if e.get("prev") != prev or h != hashlib.sha256(
                            json.dumps(e, sort_keys=True).encode()).hexdigest():
                        return False, n
                    prev, n = h, n + 1
        except FileNotFoundError:
            a = self._read_anchor()
            return (a is None or a[0] == 0), 0
        except (ValueError, KeyError):
            return False, n
        a = self._read_anchor()
        if a is not None and (n < a[0] or (n == a[0] and prev != a[1])):
            return False, n            # entries were cut off or replaced
        return True, n
