"""Command-line doors onto the broker: status, call, audit, serve, start.

Exit codes (stable, for scripts and AIs): 0 ok, 1 problem, 2 bad usage,
3 not found, 5 refused by policy, 7 network.
"""
from __future__ import annotations

import json
import os
import sys

from . import broker
from . import approve as approve_mod
from . import recipes as recipes_mod

OK, PROBLEM, USAGE, NOT_FOUND, POLICY, NETWORK = 0, 1, 2, 3, 5, 7


def _home() -> str:
    from . import remote
    return remote.home_dir()


def _have_key(recipe: dict, env_file: str) -> bool:
    from . import remote
    try:
        remote.collect_values(recipe, env_file)
        return True
    except remote.RemoteError:
        return False


def _emit(obj, as_json: bool, text: str) -> None:
    print(json.dumps(obj, indent=2) if as_json else text)


# ---- status ---------------------------------------------------------------------

def cmd_status(catalog: dict, env_file: str, as_json: bool) -> int:
    rows = [{"service": s, "key_stored": _have_key(r, env_file)}
            for s, r in sorted(catalog.items())]
    ok, n = broker.AuditLog(os.path.join(_home(), "audit.log")).verify()
    info = {"python": sys.version.split()[0], "services": len(rows),
            "with_keys": sum(r["key_stored"] for r in rows),
            "audit_log_ok": ok, "audit_entries": n,
            "connected": [r["service"] for r in rows if r["key_stored"]]}
    head = ("oathkey is ready." if info["with_keys"]
            else "Not ready yet: no key is saved. Run `oathkey start`.")
    text = (f"{head}\n"
            f"  services known: {info['services']}   with a key stored: "
            f"{info['with_keys']}\n"
            f"  connected: {', '.join(info['connected']) or 'none yet'}\n"
            f"  activity log: {'intact' if ok else 'check FAILED - run `oathkey audit show`'} "
            f"({n} entries)")
    _emit(info, as_json, text)
    return OK if ok else PROBLEM


# ---- call -----------------------------------------------------------------------

def cmd_call(recipe: dict, args) -> int:
    from . import remote
    query = {}
    for item in args.query or []:
        k, sep, v = item.partition("=")
        if not sep:
            print("error: --query needs name=value", file=sys.stderr)
            return USAGE
        query[k] = v
    body = None
    if args.data:
        try:
            body = json.loads(args.data)
        except ValueError:
            print("error: --data must be valid JSON", file=sys.stderr)
            return USAGE
    policy = broker.Policy(allow_write=False, approve=approve_mod.ask_person)
    audit = broker.AuditLog(os.path.join(_home(), "audit.log"))
    try:
        values = remote.collect_values(recipe, args.env_file)
        out = broker.call(recipe, values, args.method, args.path, query or None,
                          body, policy=policy, audit=audit)
    except remote.RemoteError:
        print(f"error: no key stored for '{recipe['service']}'. Run "
              f"`oathkey get {recipe['service']}` first.", file=sys.stderr)
        return NOT_FOUND
    except broker.BrokerError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code if e.code in (POLICY, NETWORK) else PROBLEM
    if args.json:
        print(json.dumps(out))
    else:
        print(f"[{out['status']}]")
        print(out["body"])
    return OK if out["status"] < 400 else PROBLEM


# ---- audit ----------------------------------------------------------------------

def cmd_audit(action: str, as_json: bool, last: int = 20) -> int:
    log = broker.AuditLog(os.path.join(_home(), "audit.log"))
    if action == "reset":
        kept = log.reset()
        print("started a fresh activity log." +
              (f" The old one was kept as {kept}" if kept else ""))
        return OK
    if action == "show":
        import time as _t
        intact, _n = log.verify()
        if not intact and not as_json:
            print("WARNING: the activity log does not check out - entries may "
                  "have been edited, cut off or deleted. What follows may be "
                  "false.\n")
        rows = []
        try:
            with open(log.path, "rb") as f:
                for line in f.read().splitlines()[-max(1, last):]:
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        pass
        except OSError:
            pass
        if as_json:
            print(json.dumps({"intact": intact,
                              "problem": None if intact else
                              (log.broken_reason() or "the log does not check out"),
                              "entries": rows}, indent=2))
        elif not rows:
            print("nothing yet - no AI has used a key through oathkey.")
        for e in ([] if as_json else rows):
            when = _t.strftime("%Y-%m-%d %H:%M", _t.localtime(e.get("ts", 0)))
            c = broker._clean
            print(f"{when}  {c(e.get('service'))}  {c(e.get('method'), 10)} "
                  f"{c(e.get('host'))}{c(e.get('path'))}  -> {c(e.get('status'), 6)} "
                  f"({c(e.get('result'), 20)})")
        return OK if intact else PROBLEM
    ok, n = log.verify()
    why = "" if ok else f" - {log.broken_reason() or 'the log does not check out'}"
    _emit({"intact": ok, "entries": n}, as_json,
          f"activity log: {'intact' if ok else 'TAMPERED'} ({n} entries){why}")
    return OK if ok else PROBLEM


# ---- serve (local web door) ---------------------------------------------------

def cmd_serve(catalog: dict, port: int, env_file: str) -> int:
    from . import httpd, remote
    tokfile = os.path.join(_home(), "http.token")
    token = httpd.load_or_make_token(tokfile)
    policy = broker.Policy(approve=approve_mod.ask_person)
    audit = broker.AuditLog(os.path.join(_home(), "audit.log"))
    srv = httpd.make_server(catalog, lambda r: remote.collect_values(r, env_file),
                            token, policy, audit, port=port)
    p = srv.server_address[1]
    print(f"oathkey web door is open at http://127.0.0.1:{p}\n"
          f"  token file (keep private): {tokfile}\n"
          f"  AIs send:  Authorization: Bearer <token>   GET /tools   POST /call\n"
          f"  Only this computer can reach it. Ctrl+C to close.")
    httpd.serve_forever(srv)
    return OK


# ---- start: the first five minutes ------------------------------------------------

def cmd_start(catalog: dict, env_file: str) -> int:
    from . import scan as scan_mod
    print("\noathkey - your AI can use your keys, and never see them.\n")
    d = scan_mod.doctor()
    print(scan_mod.format_doctor(d))
    res = scan_mod.scan(["."], include_home=True)
    n = len(res["findings"])
    if n:
        print(f"\nHeads up: {n} place(s) where a key is lying around in plain "
              "text. Run `oathkey scan` to see where (it never shows the "
              "key).")
    else:
        print("\nNo loose keys found nearby. Good.")
    have = [s for s, r in catalog.items() if _have_key(r, env_file)]
    if have:
        print(f"\nConnected already: {', '.join(sorted(have))}.")
        print("Next: run `oathkey install` to plug it into Claude, Cursor or "
              "VS Code (or `oathkey serve` for other AI tools). Then fully "
              "quit and reopen that app.")
    else:
        print("\nNext: connect your first service, for example:\n"
              "  oathkey get github")
    return OK if d["ok"] else PROBLEM
