"""Key validation: one minimal API call to prove the key works.

Only the HTTP status is inspected - response bodies are discarded
immediately so nothing secret-adjacent lingers.

Redirects: the credential header travels ONLY to the origin named in the
recipe. If the validation endpoint redirects to another host, another
port, or from https to http, the credential is stripped before the
redirect is followed (what browsers and `requests` do) and the result is
reported as a validation error, because a response from somewhere else
proves nothing about the key.
"""

from __future__ import annotations

import base64
import http.client
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "safeeasyapi/0.3.0"
DEFAULT_PORTS = {"http": 80, "https": 443}
REJECT_DEFAULT = (401, 403)


class ValidationError(Exception):
    pass


def _credential_header(spec: dict) -> str:
    auth = spec.get("auth", {})
    atype = auth.get("type", "bearer")
    if atype in ("bearer", "basic"):
        return "Authorization"
    if atype == "header":
        return auth["header"]
    raise ValidationError(f"unknown auth type: {atype}")


def _build_request(spec: dict, key: str) -> urllib.request.Request:
    """The one request that proves the key. Auth shapes:

    - bearer: ``Authorization: <scheme> <key>`` — scheme defaults to
      ``Bearer``; Deepgram uses ``Token``, Discord bots use ``Bot``.
    - header: the raw key in the named header (``x-api-key``, ``xi-api-key``).
    - basic:  HTTP Basic with the key as the password when ``username`` is
      given (Mailgun: ``api:<key>``), else the key as the username.

    ``spec["headers"]`` adds static headers some APIs insist on
    (``anthropic-version``, ``Notion-Version``); the credential header
    always wins over a same-named static one.
    """
    method = spec.get("method", "GET").upper()
    url = spec["url"]
    auth = spec.get("auth", {})
    atype = auth.get("type", "bearer")
    headers: dict[str, str] = {"User-Agent": USER_AGENT}
    for name, value in (spec.get("headers") or {}).items():
        headers[str(name)] = str(value)
    if atype == "bearer":
        scheme = auth.get("scheme") or "Bearer"
        headers["Authorization"] = f"{scheme} {key}"
    elif atype == "header":
        headers[auth["header"]] = key
    elif atype == "basic":
        username = auth.get("username")
        pair = f"{username}:{key}" if username else f"{key}:"
        creds = base64.b64encode(pair.encode()).decode()
        headers["Authorization"] = f"Basic {creds}"
    else:
        raise ValidationError(f"unknown auth type: {atype}")
    return urllib.request.Request(url, headers=headers, method=method)


def _origin(url: str) -> tuple[str, str, int | None]:
    p = urllib.parse.urlsplit(url)
    scheme = (p.scheme or "").lower()
    try:
        port = p.port
    except ValueError:
        port = None
    return scheme, (p.hostname or "").lower(), port or DEFAULT_PORTS.get(scheme)


def should_strip_auth(old_url: str, new_url: str) -> bool:
    """True when following old_url -> new_url must drop credentials:
    any change of host, a change of scheme (including https -> http),
    or a change of port. Mirrors requests' Session.should_strip_auth,
    minus its one leniency (http -> https upgrades): recipes are https
    already, so an upgrade never legitimately happens."""
    old_scheme, old_host, old_port = _origin(old_url)
    new_scheme, new_host, new_port = _origin(new_url)
    return (old_host != new_host or old_scheme != new_scheme
            or old_port != new_port)


class _CredentialScrubbingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects like urllib does, but never carry the credential
    header across an origin change. Remembers that it had to strip."""

    def __init__(self, credential_header: str):
        super().__init__()
        self._cred = credential_header.lower()
        self.stripped_to: str | None = None

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is None:
            return None
        if should_strip_auth(req.full_url, newurl):
            for name in list(new_req.headers) + list(new_req.unredirected_hdrs):
                if name.lower() == self._cred:
                    new_req.remove_header(name)
            self.stripped_to = newurl
        return new_req


def validate_key(spec: dict, key: str, timeout: float = 10.0) -> bool:
    """Return True if the API accepts the key (status in spec['expect']).

    Raises ValidationError on network failure, or when the endpoint
    redirected off-origin (the key was NOT sent there). Never logs the key.
    """
    req = _build_request(spec, key)
    expect = set(spec.get("expect", [200]))
    # statuses that mean "the API looked at the key and said no" (Google
    # answers 400 to a bad key, Brave 422) — a verdict, not a crash
    reject = set(spec.get("reject") or REJECT_DEFAULT)
    scrubber = _CredentialScrubbingRedirectHandler(_credential_header(spec))
    opener = urllib.request.build_opener(scrubber)
    try:
        try:
            with opener.open(req, timeout=timeout) as resp:
                status = resp.status
        except urllib.error.HTTPError as e:
            status = e.code
    except urllib.error.URLError as e:
        raise ValidationError(f"network error during validation: {e.reason}")
    except http.client.HTTPException as e:
        # BadStatusLine / RemoteDisconnected / IncompleteRead: something
        # answered, but not with HTTP (a proxy page, a TLS mismatch, a
        # non-HTTP service on the port). Not a crash, not a verdict.
        raise ValidationError(
            f"validation endpoint did not speak HTTP ({type(e).__name__}: "
            f"{str(e)[:80]!r}); check the recipe's validate.url")
    except OSError as e:
        raise ValidationError(f"network error during validation: {e}")
    if scrubber.stripped_to is not None:
        raise ValidationError(
            "validation endpoint redirected to a different origin "
            f"({scrubber.stripped_to}); the key was not sent there. "
            "Fix the recipe's validate.url to point at the final endpoint.")
    if status in expect:
        return True
    if status in reject:
        return False  # key rejected (validation failed, not a crash)
    raise ValidationError(f"validation endpoint error: HTTP {status}")
