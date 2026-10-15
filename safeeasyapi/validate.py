"""Key validation: one minimal API call to prove the key works.

Only the HTTP status is inspected — response bodies are discarded
immediately so nothing secret-adjacent lingers.
"""

from __future__ import annotations

import base64
import urllib.error
import urllib.request


class ValidationError(Exception):
    pass


def _build_request(spec: dict, key: str) -> urllib.request.Request:
    method = spec.get("method", "GET").upper()
    url = spec["url"]
    auth = spec.get("auth", {})
    atype = auth.get("type", "bearer")
    headers: dict[str, str] = {"User-Agent": "safeeasyapi/0.1.0"}
    if atype == "bearer":
        headers["Authorization"] = f"Bearer {key}"
    elif atype == "header":
        headers[auth["header"]] = key
    elif atype == "basic":
        creds = base64.b64encode(f"{key}:".encode()).decode()
        headers["Authorization"] = f"Basic {creds}"
    else:
        raise ValidationError(f"unknown auth type: {atype}")
    return urllib.request.Request(url, headers=headers, method=method)


def validate_key(spec: dict, key: str, timeout: float = 10.0) -> bool:
    """Return True if the API accepts the key (status in spec['expect']).

    Raises ValidationError on network failure. Never logs the key.
    """
    req = _build_request(spec, key)
    expect = set(spec.get("expect", [200]))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status in expect
    except urllib.error.HTTPError as e:
        # 401/403 = key rejected (validation failed, not a crash).
        if e.code in (401, 403):
            return False
        raise ValidationError(f"validation endpoint error: HTTP {e.code}")
    except urllib.error.URLError as e:
        raise ValidationError(f"network error during validation: {e.reason}")
    except OSError as e:
        raise ValidationError(f"network error during validation: {e}")
