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

import functools
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from . import validate as _v
from .scrub import Scrubber

MAX_BODY_OUT = 1_000_000      # most we read back
MAX_BODY_IN = 256_000         # most the AI may send
READ_METHODS = {"GET", "HEAD"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_PATH_OK = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*")
_EXPOSED_HEADERS = ("content-type", "content-length", "retry-after",
                    "x-ratelimit-remaining", "x-ratelimit-reset", "location")


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
        self.approved_hosts: set[tuple[str, str]] = set()

    def count(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self._stamps = [t for t in self._stamps if now - t < 60]
        if self.calls >= self.max_calls:
            raise BrokerError("call limit for this session reached", 5)
        if len(self._stamps) >= self.max_per_minute:
            raise BrokerError("too many calls per minute; wait and retry", 5)
        self.calls += 1
        self._stamps.append(now)


# ---- address safety ----------------------------------------------------------

def is_public_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
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
    decoded = urllib.parse.unquote(path)
    segments = decoded.split("/")
    if ".." in segments or "." in segments[1:-1] or "\\" in decoded:
        raise BrokerError("path may not contain . or .. segments", 5)
    return path


def build_url(recipe: dict, path: str, query: dict | None) -> tuple[str, str]:
    host = allowed_host(recipe)
    auth = (recipe.get("validate") or {}).get("auth", {})
    query = dict(query or {})
    if auth.get("type") == "query" and auth.get("param") in query:
        raise BrokerError("the credential parameter is set by the broker", 5)
    for k, v in query.items():
        if not isinstance(k, str) or not isinstance(v, (str, int, float, bool)):
            raise BrokerError("query values must be plain text or numbers", 5)
    q = urllib.parse.urlencode(query)
    url = f"https://{host}{check_path(path)}" + (f"?{q}" if q else "")
    if urllib.parse.urlsplit(url).hostname != host:       # belt and braces
        raise BrokerError("host mismatch; refused", 5)
    return host, url


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
    host, url = build_url(recipe, path, query)
    auth_type = (recipe.get("validate") or {}).get("auth", {}).get("type", "bearer")
    if method in WRITE_METHODS and auth_type == "aws_sigv4":
        raise BrokerError("this service signs requests; only reads are "
                          "supported through the broker", 5)

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

    # permission: writes need a grant or a person's yes, every time
    if method in WRITE_METHODS and not policy.allow_write:
        summary = f"{method} https://{host}{urllib.parse.urlsplit(url).path}"
        if not (policy.approve and policy.approve(summary)):
            raise BrokerError("writes are not allowed in this session "
                              "(no approval given)", 5)
    elif (recipe["service"], host) not in policy.approved_hosts:
        if policy.approve is not None:
            if not policy.approve(f"first use of {recipe['service']} -> {host}"):
                raise BrokerError("not approved", 5)
        policy.approved_hosts.add((recipe["service"], host))
    policy.count()

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
    ip = resolve_public(host, 443, resolver)

    started = time.time()
    try:
        status, headers, raw = (send or _real_send)(req, ip, timeout)
    except BrokerError:
        _log(audit, recipe, method, host, path, 0, 0, "network-error")
        raise

    secrets = [v for v in values.values() if isinstance(v, str)]
    sc = Scrubber(secrets)
    clip = raw[:MAX_BODY_OUT]
    ctype = headers.get("content-type", "")
    textual = any(t in ctype for t in ("json", "text", "xml", "html", "x-www-form"))
    if textual:
        shown = (sc.feed(clip) + sc.flush()).decode("utf-8", "replace")
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
    audit.write({"service": recipe.get("service"), "method": method,
                 "host": host, "path": path.split("?")[0], "status": status,
                 "bytes": size, "result": result, "ms": ms})


class AuditLog:
    """Append-only JSON lines; each line holds the hash of the line before.
    Change or remove any line and verify() says so. Never records query
    strings, bodies or headers."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def _last_hash(self) -> str:
        try:
            with open(self.path, "rb") as f:
                last = f.read().splitlines()[-1]
            return json.loads(last)["hash"]
        except (OSError, IndexError, ValueError, KeyError):
            return "0" * 64

    def write(self, entry: dict) -> None:
        entry = dict(entry, ts=int(time.time()), prev=self._last_hash())
        entry["hash"] = hashlib.sha256(
            json.dumps(entry, sort_keys=True).encode()).hexdigest()
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, (json.dumps(entry, sort_keys=True) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)

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
            return True, 0
        except (ValueError, KeyError):
            return False, n
        return True, n


# ---- approval from the real terminal, never from piped input -------------------

def tty_approve(summary: str) -> bool:
    """Ask on the console device itself. An AI that can pipe text into our
    stdin cannot answer this. No console = no."""
    dev_in, dev_out = (("CONIN$", "CONOUT$") if os.name == "nt"
                       else ("/dev/tty", "/dev/tty"))
    try:
        with open(dev_out, "w", encoding="utf-8") as out, \
                open(dev_in, encoding="utf-8") as inp:
            out.write(f"\nsafeeasyapi: an AI wants to: {_safe(summary)}\nAllow? [y/N] ")
            out.flush()
            return inp.readline().strip().lower() in ("y", "yes")
    except OSError:
        return False


def _safe(text: str) -> str:
    return "".join(c for c in text if c.isprintable())[:200]
