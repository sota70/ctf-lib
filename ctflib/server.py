"""Minimal express-style web server (standard library only).

    from ctflib import route, listen

    @route("/hook")
    def hook(req, res):
        print(req.query.get("c"))
        res.json({"ok": True})

    listen(8000)

Handy for XSS/SSRF callbacks: every request is logged and kept in ``app.hits``.
"""

from __future__ import annotations

import json as _json
import socket
import threading
import time
import traceback
import urllib.parse
from datetime import datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__all__ = ["App", "Request", "Response", "app", "route", "listen", "get", "post", "hits", "wait_hit"]

_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")

_STATUS_TEXT = {
    200: "OK", 201: "Created", 204: "No Content", 301: "Moved Permanently",
    302: "Found", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 500: "Internal Server Error",
}


class Request:
    """The ``req`` argument handed to a controller.

    Example:
        >>> app.log = False                     # keep the doctest output clean
        >>> _ = route("/echo", lambda req, res: res.json(
        ...     {"method": req.method, "path": req.path, "q": req.query}))
        >>> _ = listen(port=0, background=True, quiet=True)
        >>> from ctflib import get
        >>> get("http://127.0.0.1:%d/echo?id=7" % app.port).json()
        {'method': 'GET', 'path': '/echo', 'q': {'id': '7'}}
        >>> app.close()
    """

    def __init__(self, handler, body, params=None):
        self.raw = handler
        self.method = handler.command
        self.url = handler.path
        parts = urllib.parse.urlsplit(handler.path)
        self.path = urllib.parse.unquote(parts.path)
        self.query_string = parts.query
        self.headers = {k.lower(): v for k, v in handler.headers.items()}
        self.body = body
        self.params = params or {}
        self.ip = handler.client_address[0]
        self.time = datetime.now()

    @property
    def query_all(self):
        """Query string as ``{name: [values]}``."""
        return urllib.parse.parse_qs(self.query_string, keep_blank_values=True)

    @property
    def query(self):
        """Query string as ``{name: first_value}``."""
        return {k: v[0] for k, v in self.query_all.items()}

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")

    @property
    def form(self):
        """Body parsed as ``application/x-www-form-urlencoded``."""
        return {k: v[0] for k, v in urllib.parse.parse_qs(self.text, keep_blank_values=True).items()}

    def json(self, default=None):
        """Body parsed as JSON (returns *default* if it is not valid JSON)."""
        try:
            return _json.loads(self.text)
        except (ValueError, UnicodeDecodeError):
            return default

    @property
    def cookies(self):
        jar = SimpleCookie()
        jar.load(self.headers.get("cookie", ""))
        return {k: morsel.value for k, morsel in jar.items()}

    def __repr__(self):
        return f"<Request {self.method} {self.url} from {self.ip}>"


class Response:
    """The ``res`` argument handed to a controller. Setters are chainable.

    Example:
        >>> app.log = False
        >>> @route("/admin")
        ... def admin(req, res):
        ...     res.status(403).set("X-Flag", "sknb{x}").text("denied")
        >>> _ = listen(port=0, background=True, quiet=True)
        >>> from ctflib import get
        >>> r = get("http://127.0.0.1:%d/admin" % app.port)
        >>> r.status, r.text, r.headers["x-flag"]
        (403, 'denied', 'sknb{x}')
        >>> app.close()
    """

    def __init__(self, handler):
        self.raw = handler
        self.status_code = 200
        self.headers = {"Content-Type": "text/html; charset=utf-8"}
        self.cookies = []
        self.sent = False

    def status(self, code):
        self.status_code = int(code)
        return self

    def set(self, name, value):
        self.headers[name] = str(value)
        return self

    header = set

    def type(self, content_type):
        return self.set("Content-Type", content_type)

    def cookie(self, name, value, path="/", **options):
        parts = [f"{name}={value}", f"Path={path}"]
        for key, val in options.items():
            key = key.replace("_", "-").title()
            if val is True:
                parts.append(key)
            elif val not in (False, None):
                parts.append(f"{key}={val}")
        self.cookies.append("; ".join(parts))
        return self

    def json(self, payload):
        self.set("Content-Type", "application/json")
        return self.send(_json.dumps(payload, ensure_ascii=False).encode("utf-8"))

    def html(self, markup):
        self.set("Content-Type", "text/html; charset=utf-8")
        return self.send(markup)

    def text(self, body):
        self.set("Content-Type", "text/plain; charset=utf-8")
        return self.send(body)

    def redirect(self, location, code=302):
        return self.status(code).set("Location", location).send(b"")

    def send(self, body=b""):
        """Write the response. Calling it twice is a no-op."""
        if self.sent:
            return self
        if isinstance(body, (dict, list)):
            self.headers["Content-Type"] = "application/json"
            body = _json.dumps(body, ensure_ascii=False)
        if isinstance(body, str):
            body = body.encode("utf-8")
        elif not isinstance(body, (bytes, bytearray)):
            body = str(body).encode("utf-8")

        self.sent = True
        handler = self.raw
        reason = _STATUS_TEXT.get(self.status_code, "")
        handler.send_response(self.status_code, reason)
        for name, value in self.headers.items():
            handler.send_header(name, value)
        for cookie in self.cookies:
            handler.send_header("Set-Cookie", cookie)
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(body)
        return self

    end = send


class _Route:
    def __init__(self, pattern, controller, methods=None):
        self.pattern = pattern
        self.controller = controller
        self.methods = {m.upper() for m in methods} if methods else None
        self.segments = [s for s in pattern.strip("/").split("/") if s != ""] if pattern != "/" else []
        self.catch_all = pattern in ("*", "/*")

    def match(self, method, path):
        """Return the captured params dict, or ``None`` if the route misses."""
        if self.methods and method.upper() not in self.methods:
            return None
        if self.catch_all:
            return {}
        parts = [s for s in path.strip("/").split("/") if s != ""]
        params = {}
        for i, seg in enumerate(self.segments):
            if seg == "*":
                params["*"] = "/".join(parts[i:])
                return params
            if i >= len(parts):
                return None
            if seg.startswith(":"):
                params[seg[1:]] = urllib.parse.unquote(parts[i])
            elif seg != parts[i]:
                return None
        return params if len(parts) == len(self.segments) else None


def _endpoint_from(controller):
    """``def hook(req, res)`` -> ``/hook``; ``index`` and ``root`` mean ``/``."""
    name = getattr(controller, "__name__", None)
    if not name or name == "<lambda>":
        raise ValueError("cannot derive an endpoint from this controller -- pass the path explicitly")
    if name in ("index", "root"):
        return "/"
    return "/" + name.strip("_").replace("__", "/")


class App:
    """Route table + server. Create your own, or use the module level default.

    Example:
        >>> my = App(log=False)
        >>> @my.route("/hook")
        ... def hook(req, res):
        ...     res.json({"seen": req.query.get("id")})
        >>> _ = my.listen(port=0, background=True, quiet=True)
        >>> from ctflib import get
        >>> get("http://127.0.0.1:%d/hook?id=7" % my.port).json()
        {'seen': '7'}
        >>> len(my.hits)
        1
        >>> my.close()
    """

    def __init__(self, log=True):
        self.routes = []
        self.log = log
        self.hits = []
        self.server = None
        self._hit_event = threading.Event()
        self._fallback = None

    # -- registration ------------------------------------------------------ #
    def route(self, endpoint=None, controller=None, methods=None):
        """Bind a controller to *endpoint*. Meant to be used as an annotation::

            @app.route("/hook")
            def hook(req, res):
                res.json({"ok": True})

            @app.route                  # endpoint taken from the function name
            def hook(req, res): ...     # -> /hook  ("index" means /)

            app.route("/hook", hook)    # plain call, controller as 2nd argument

        The controller always receives ``(req, res)``, express style. Paths
        support ``:name`` params and a trailing ``*``. The decorated function is
        returned unchanged, so annotations can be stacked to give one controller
        several endpoints.
        """
        # bare @app.route on a function -- derive the path from its name
        if callable(endpoint) and controller is None:
            fn = endpoint
            return self.route(_endpoint_from(fn), fn, methods)

        if controller is None:
            def decorator(fn):
                self.route(_endpoint_from(fn) if endpoint is None else endpoint, fn, methods)
                return fn
            return decorator

        self.routes.append(_Route(endpoint, controller, methods))
        return controller

    def get(self, endpoint=None, controller=None):
        return self.route(endpoint, controller, methods=["GET"])

    def post(self, endpoint=None, controller=None):
        return self.route(endpoint, controller, methods=["POST"])

    def put(self, endpoint=None, controller=None):
        return self.route(endpoint, controller, methods=["PUT"])

    def delete(self, endpoint=None, controller=None):
        return self.route(endpoint, controller, methods=["DELETE"])

    all = route

    def default(self, controller):
        """Controller used when no route matches (instead of a 404)."""
        self._fallback = controller
        return controller

    # -- dispatch ---------------------------------------------------------- #
    def handle(self, handler, body):
        path = urllib.parse.urlsplit(handler.path).path
        for entry in self.routes:
            params = entry.match(handler.command, path)
            if params is not None:
                req, res = Request(handler, body, params), Response(handler)
                self._record(req)
                try:
                    entry.controller(req, res)
                except Exception:
                    traceback.print_exc()
                    if not res.sent:
                        res.status(500).text("Internal Server Error")
                if not res.sent:
                    res.send(b"")
                return

        req, res = Request(handler, body), Response(handler)
        self._record(req)
        if self._fallback is not None:
            try:
                self._fallback(req, res)
            except Exception:
                traceback.print_exc()
                if not res.sent:
                    res.status(500).text("Internal Server Error")
        if not res.sent:
            res.status(404).text("Not Found")

    def _record(self, req):
        self.hits.append(req)
        self._hit_event.set()
        if self.log:
            line = f"[{req.time:%H:%M:%S}] {req.ip} {req.method} {req.url}"
            if req.body:
                line += f"\n  body: {req.text[:2000]}"
            print(line, flush=True)

    def wait_hit(self, timeout=None, since=None):
        """Block until a *new* request arrives; returns it (or ``None`` on timeout).

        *since* is a hit count to compare against -- pass ``0`` to accept a
        request that already arrived before the call.
        """
        start = len(self.hits) if since is None else since
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            self._hit_event.clear()  # cleared first so a hit landing here is not lost
            if len(self.hits) > start:
                return self.hits[-1]
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                return None
            self._hit_event.wait(remaining)

    # -- serving ----------------------------------------------------------- #
    def listen(self, port=8000, host="0.0.0.0", background=False, quiet=False):
        """Start the server on *port*.

        Blocks until Ctrl-C unless ``background=True``, in which case the
        ``ThreadingHTTPServer`` is returned so you can keep scripting.
        """
        app = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "ctflib"
            protocol_version = "HTTP/1.1"

            def _dispatch(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length > 0 else b""
                app.handle(self, body)

            def log_message(self, *args):
                pass  # App._record already logs

        for method in _METHODS:
            setattr(Handler, f"do_{method}", Handler._dispatch)

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.server = Server((host, port), Handler)
        if not quiet:
            shown = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
            print(f"[*] listening on http://{shown}:{port}  (local ip: {_local_ip()})", flush=True)

        if background:
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
            return self.server
        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] bye", flush=True)
        finally:
            self.close()
        return self.server

    def close(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    @property
    def port(self):
        return self.server.server_address[1] if self.server else None


def _local_ip():
    """Best-effort LAN address, so you know what to put in your payload."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


#: Default app backing the module level helpers.
app = App()


def route(endpoint=None, controller=None, methods=None):
    """Bind a controller on the default app -- ``@route("/x")`` or ``route("/x", fn)``.

    See :meth:`App.route` for the endpoint patterns.

    Example:
        >>> app.log = False
        >>> @route("/hook")
        ... def hook(req, res):
        ...     res.text("pong")
        >>> _ = listen(port=0, background=True, quiet=True)
        >>> from ctflib import get
        >>> get("http://127.0.0.1:%d/hook" % app.port).text
        'pong'
        >>> app.close()
    """
    return app.route(endpoint, controller, methods)


def get(endpoint=None, controller=None):
    return app.get(endpoint, controller)


def post(endpoint=None, controller=None):
    return app.post(endpoint, controller)


def listen(port=8000, host="0.0.0.0", background=False, quiet=False):
    """Start the default app's server.

    Blocks until Ctrl-C unless ``background=True``. ``port=0`` picks a free
    port, which ``app.port`` reads back.

    Example:
        >>> _ = listen(port=0, background=True, quiet=True)
        >>> isinstance(app.port, int)
        True
        >>> app.close()

    In a challenge you normally want the blocking form on a port the target can
    reach::

        listen(8000)
    """
    return app.listen(port, host, background, quiet)


def hits():
    """Every request the default app has served, oldest first.

    Example:
        >>> app.log = False
        >>> _ = route("/beacon", lambda req, res: res.text("ok"))
        >>> _ = listen(port=0, background=True, quiet=True)
        >>> from ctflib import get
        >>> _ = get("http://127.0.0.1:%d/beacon?id=7" % app.port)
        >>> hits()[-1].query
        {'id': '7'}
        >>> app.close()
    """
    return app.hits


def wait_hit(timeout=None, since=None):
    """Block until the default app gets a new request -- see :meth:`App.wait_hit`.

    Example:
        >>> import threading
        >>> from ctflib import get
        >>> app.log = False
        >>> _ = route("/x", lambda req, res: res.text("ok"))
        >>> _ = listen(port=0, background=True, quiet=True)
        >>> threading.Timer(0.05, get, ["http://127.0.0.1:%d/x" % app.port]).start()
        >>> wait_hit(timeout=5).path
        '/x'
        >>> app.close()
    """
    return app.wait_hit(timeout, since)
