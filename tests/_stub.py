"""A local stand-in for a vendor's API, for tests that must make no real
network calls: it listens on 127.0.0.1 only and answers from a table."""

import http.server
import json
import threading


class Stub:
    """routes: {(method, path): (status, body_text_or_dict, headers)} ; the
    default answer is 404. `seen` records every request (method, path,
    headers, body) so a test can check exactly what was sent."""

    def __init__(self, routes=None):
        self.routes = dict(routes or {})
        self.seen = []
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _answer(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                path = self.path.split("?")[0]
                stub.seen.append({"method": self.command, "path": self.path,
                                  "headers": {k.lower(): v for k, v in self.headers.items()},
                                  "body": body})
                route = (stub.routes.get((self.command, path))
                         or stub.routes.get(("*", path)) or (404, "", {}))
                status, payload, headers = (tuple(route) + ({},))[:3]
                data = payload if isinstance(payload, str) else json.dumps(payload)
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data.encode())))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data.encode())

            do_GET = do_POST = do_HEAD = _answer

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.02), daemon=True)

    @property
    def base(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
