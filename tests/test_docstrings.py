"""Every name in ``ctflib.__all__`` carries a runnable ``Example:``.

Two checks live here. :class:`TestExampleCoverage` asserts that each exported
function or class has a doctest in its docstring, and ``load_tests`` runs those
doctests for real.

Rules
    Exempt are constants and instances (``ELEMENT_NODE``, ``app``), aliases
    whose target already carries the example (``b64e`` shares ``b64encode``'s
    docstring, so the check passes once the body is documented), and anything
    decorated with :func:`ctflib._meta.no_example`.

    ``ELLIPSIS`` and ``NORMALIZE_WHITESPACE`` are on. ``...`` is for folding a
    long repr, not for skipping an output you did not feel like typing.

    ``# doctest: +SKIP`` is allowed in exactly one place: ``reverse_shell``,
    which blocks on ``accept()`` and cannot be demonstrated in-process. The
    HTTP shortcuts talk to the echo server below through the injected ``URL``;
    ``listen`` and ``wait_hit`` use ``background=True`` and a short timeout.

    Every export is checked, whatever module it comes from, so a new module
    cannot slip in undocumented.
"""

import doctest
import importlib
import inspect
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ctflib

MODULES = ("b64", "urlcodec", "flag", "dom", "client", "server", "shell")

OPTIONFLAGS = doctest.ELLIPSIS | doctest.NORMALIZE_WHITESPACE

PAGE = (
    b"<html><head><title>Login</title></head><body>"
    b"<!-- sknb{doctest_flag} -->"
    b'<form name="login" action="/login" method="post">'
    b'<input type="hidden" name="csrf_token" value="a1b2">'
    b'<input name="username"><input type="password" name="password">'
    b"</form></body></html>"
)


class _EchoHandler(BaseHTTPRequestHandler):
    """Deterministic responses for the doctests -- no clock, no randomness."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass  # keep unittest output clean

    def _send(self, status, body, ctype="text/plain; charset=utf-8", **headers):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for key, value in headers.items():
            self.send_header(key.replace("_", "-"), value)
        self.end_headers()
        self.wfile.write(body)

    def _route(self):
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        if path == "/echo":
            return self._send(200, self.command.encode() + b" " + self.path.encode()
                              + (b"\n" + body if body else b""))
        if path == "/flag":
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if path == "/json":
            return self._send(200, b'{"user": "admin", "id": 1}', "application/json")
        if path == "/redirect":
            return self._send(302, b"", Location="/echo")
        self._send(404, b"not found")

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _route

    def do_HEAD(self):
        self._send(200, b"")


def _start_echo_server():
    """Start the echo server on a free port and return ``http://host:port``."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return "http://127.0.0.1:%d" % server.server_address[1]


def _exported_definitions():
    """``(name, object)`` for every export that is a function or a class."""
    for name in ctflib.__all__:
        obj = getattr(ctflib, name)
        if inspect.isfunction(obj) or inspect.isclass(obj):
            yield name, obj


class TestExampleCoverage(unittest.TestCase):
    def test_every_export_has_an_example(self):
        missing = sorted(
            name for name, obj in _exported_definitions()
            if not getattr(obj, "__no_example__", False)
            and ">>>" not in (obj.__doc__ or "")
        )
        self.assertEqual(missing, [], "no Example: block in %s" % ", ".join(missing))

    def test_no_export_is_undocumented(self):
        undocumented = sorted(
            name for name, obj in _exported_definitions()
            if not (obj.__doc__ or "").strip()
        )
        self.assertEqual(undocumented, [])


def load_tests(loader, tests, pattern):
    url = _start_echo_server()
    for name in MODULES:
        module = importlib.import_module("ctflib." + name)
        globs = dict(vars(module), URL=url)
        try:
            tests.addTests(doctest.DocTestSuite(module, globs=globs, optionflags=OPTIONFLAGS))
        except ValueError:  # module has no doctests yet
            pass
    return tests


if __name__ == "__main__":
    unittest.main()
