"""`oathkey selftest` - the tool attacks itself and shows pass or fail.

Everything here is local and harmless: a made-up key, a pretend server
(no network is used) and a throw-away log file. No real key is touched.

What it proves: the broker's rules hold against the attacks listed below.
What it does NOT prove: that nothing else can go wrong (see SECURITY.md).
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import tempfile
import urllib.parse

from . import broker

HOST = "selftest.example"
PUBLIC_IP = "93.184.216.34"


def _recipe() -> dict:
    return {"service": "selftest", "display": "Selftest", "env_var": "SELFTEST_KEY",
            "fields": [{"env_var": "SELFTEST_KEY", "label": "key", "name": "key"}],
            "validate": {"method": "GET", "url": f"https://{HOST}/user",
                         "auth": {"type": "bearer"}, "expect": [200]}}


def _resolver(*ips):
    def r(host, port, type=None):
        return [(2, 1, 6, "", (ip, port)) for ip in ips]
    return r


def _fake_server(body_fn, headers=None):
    """A pretend API. Records what it was sent and answers with body_fn()."""
    seen = []

    def send(req, ip, timeout):
        seen.append((req, ip))
        h = {"content-type": "application/json"}
        h.update(headers or {})
        return 200, h, body_fn(req)
    send.seen = seen
    return send


def _approve_all():
    return broker.Policy(approve=lambda s: True)


def _call(key, send, path="/user", method="GET", policy=None, audit=None,
          resolver=None, query=None, body=None):
    return broker.call(_recipe(), {"SELFTEST_KEY": key}, method, path, query, body,
                       policy=policy or _approve_all(), audit=audit, send=send,
                       resolver=resolver or _resolver(PUBLIC_IP))


def _refused(fn) -> tuple[bool, str]:
    try:
        fn()
    except broker.BrokerError as e:
        return True, f"refused ({str(e)[:60]})"
    return False, "it was ALLOWED"


# ---- attacks --------------------------------------------------------------------

def _leak_case(label, transform):
    def run(key):
        send = _fake_server(lambda req: json.dumps({"echo": transform(key)}).encode())
        out = _call(key, send)
        text = json.dumps(out)
        b64s = {base64.b64encode(key.encode()[i:]).decode().rstrip("=")[:12] for i in range(3)}
        bad = key in text or key[::-1] in text or key.encode().hex() in text \
            or urllib.parse.quote(key, safe="") in text and urllib.parse.quote(key, safe="") != key \
            or any(b in text for b in b64s if len(b) >= 12)
        return (not bad), ("key not visible in the reply" if not bad else "KEY VISIBLE in the reply")
    return (f"A server that echoes the key back ({label}) is hidden", run)


def _leak_attacks():
    cases = [
        ("plain text", lambda k: k),
        ("base64", lambda k: base64.b64encode(k.encode()).decode()),
        ("hex", lambda k: k.encode().hex()),
        ("URL-encoded", lambda k: urllib.parse.quote(k, safe="")),
        ("reversed", lambda k: k[::-1]),
        ("with dashes between letters", lambda k: "-".join(k)),
        ("with spaces between letters", lambda k: " ".join(k)),
    ]
    return [_leak_case(n, t) for n, t in cases]


def _header_leak(key):
    send = _fake_server(lambda req: b"{}", headers={"content-type": "application/json; k=" + key})
    out = _call(key, send)
    return key not in json.dumps(out), "key not visible in the reply headers"


def _attack_reaches_api(key):
    send = _fake_server(lambda req: b"{}")
    _call(key, send)
    req, ip = send.seen[0]
    ok = (req.get_header("Authorization") == "Bearer " + key
          and urllib.parse.urlsplit(req.full_url).hostname == HOST and ip == PUBLIC_IP)
    return ok, "the key goes only to the recipe's own host, on the checked address"


def _paths():
    bad = ["/a/../b", "/a/./b", "//evil.example/x", "/a%2fb", "/a;x", "/%252e%252e/x",
           "/a\\b", "http://evil.example/x", "user", "/a%00b"]
    out = []
    for p in bad:
        def run(key, p=p):
            send = _fake_server(lambda req: b"{}")
            ok, detail = _refused(lambda: _call(key, send, path=p))
            return ok and not send.seen, detail
        out.append((f"Odd path {p!r} is refused", run))
    return out


def _private_ips():
    cases = [("127.0.0.1", ("127.0.0.1",)), ("10.0.0.5", ("10.0.0.5",)),
             ("192.168.1.9", ("192.168.1.9",)), ("169.254.169.254 (cloud secrets)", ("169.254.169.254",)),
             ("::1", ("::1",)), ("public + private mixed (rebinding)", (PUBLIC_IP, "127.0.0.1"))]
    out = []
    for label, ips in cases:
        def run(key, ips=ips):
            send = _fake_server(lambda req: b"{}")
            ok, detail = _refused(lambda: _call(key, send, resolver=_resolver(*ips)))
            return ok and not send.seen, detail
        out.append((f"Server name pointing at {label} is refused", run))
    return out


def _override_query(key):
    send = _fake_server(lambda req: b"{}")
    ok, d = _refused(lambda: _call(key, send, query={"_method": "DELETE"}))
    return ok and not send.seen, d


def _write_denied(key):
    send = _fake_server(lambda req: b"{}")
    pol = broker.Policy(approve=lambda s: False)
    ok, d = _refused(lambda: _call(key, send, method="POST", path="/x", policy=pol, body={"a": 1}))
    return ok and not send.seen, d


def _write_no_prompt(key):
    send = _fake_server(lambda req: b"{}")
    ok, d = _refused(lambda: _call(key, send, method="DELETE", path="/x",
                                   policy=broker.Policy(approve=None)))
    return ok and not send.seen, d


def _read_with_body(key):
    send = _fake_server(lambda req: b"{}")
    ok, d = _refused(lambda: _call(key, send, body={"a": 1}))
    return ok and not send.seen, d


def _flood(key):
    send = _fake_server(lambda req: b"{}")
    pol = broker.Policy(approve=lambda s: True, max_calls=3)
    for _ in range(3):
        _call(key, send, policy=pol)
    ok, d = _refused(lambda: _call(key, send, policy=pol))
    return ok and len(send.seen) == 3, d


def _log_tests():
    def with_log(fn):
        def run(key):
            d = tempfile.mkdtemp(prefix="oathkey-selftest-")
            path = os.path.join(d, "audit.log")
            try:
                return fn(key, broker.AuditLog(path), path)
            finally:
                try:
                    os.remove(path)
                    os.rmdir(d)
                except OSError:
                    pass
        return run

    def keyless(key, log, path):
        send = _fake_server(lambda req: b"{}")
        for _ in range(3):
            _call(key, send, audit=log, query={"token": "x"})
        text = open(path, encoding="utf-8").read()
        ok, n = log.verify()
        return (key not in text and "token" not in text and ok and n == 3), \
            "log holds no key and no query text, and verifies"

    def edited(key, log, path):
        send = _fake_server(lambda req: b"{}")
        for _ in range(3):
            _call(key, send, audit=log)
        lines = open(path, encoding="utf-8").read().splitlines()
        lines[1] = lines[1].replace('"ok"', '"ok "')
        open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        ok, _ = log.verify()
        return (not ok), "an edited log line is detected"

    def removed(key, log, path):
        send = _fake_server(lambda req: b"{}")
        for _ in range(3):
            _call(key, send, audit=log)
        lines = open(path, encoding="utf-8").read().splitlines()
        del lines[1]
        open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        ok, _ = log.verify()
        return (not ok), "a deleted log line is detected"

    def unwritable(key, log, path):
        send = _fake_server(lambda req: b"{}")
        bad = broker.AuditLog(os.path.dirname(path))   # a folder cannot be written as a file
        ok, d = _refused(lambda: _call(key, send, audit=bad))
        return ok and not send.seen, "nothing is sent when the log cannot be written"

    return [("The activity log holds no key", with_log(keyless)),
            ("Editing the activity log is detected", with_log(edited)),
            ("Deleting from the activity log is detected", with_log(removed)),
            ("If the log cannot be written, nothing is sent", with_log(unwritable))]


def attacks():
    items = []
    items += _leak_attacks()
    items.append(("A server that echoes the key in a header is hidden", _header_leak))
    items.append(("The key reaches only the recipe's own server", _attack_reaches_api))
    items += _paths()
    items += _private_ips()
    items.append(("A query that changes the HTTP method is refused", _override_query))
    items.append(("A write is refused when the person says no", _write_denied))
    items.append(("A write is refused when no one can be asked", _write_no_prompt))
    items.append(("A read request with a body is refused", _read_with_body))
    items.append(("A flood of calls is stopped at the limit", _flood))
    items += _log_tests()
    return items


def run_all() -> list[dict]:
    key = "sk_selftest_" + secrets.token_hex(12)       # made up, used nowhere else
    results = []
    for name, fn in attacks():
        try:
            ok, detail = fn(key)
        except Exception as e:                           # a crash is a failure
            ok, detail = False, f"crashed: {type(e).__name__}"
        results.append({"attack": name, "pass": bool(ok), "detail": detail})
    return results


def cmd_selftest(as_json: bool = False) -> int:
    results = run_all()
    failed = [r for r in results if not r["pass"]]
    if as_json:
        print(json.dumps({"passed": len(results) - len(failed), "total": len(results),
                          "results": results}))
    else:
        print("\noathkey selftest - attacking itself with a made-up key and a "
              "pretend server\n(no network, no real key used)\n")
        for r in results:
            print(f"  {'PASS' if r['pass'] else 'FAIL'}  {r['attack']}")
            if not r["pass"]:
                print(f"        -> {r['detail']}")
        print(f"\n{len(results) - len(failed)} of {len(results)} attacks stopped.")
        if failed:
            print("Some attacks got through. Please report this (see SECURITY.md).\n")
        else:
            print("This checks the rules above only. It cannot show that nothing "
                  "else can go wrong\n(see SECURITY.md for what oathkey does not stop).\n")
    return 1 if failed else 0
