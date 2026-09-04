"""Integration tests: the package namespace, Response's DOM helpers and the CLI."""

import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ctflib
from ctflib import Response

ROOT = Path(__file__).resolve().parents[1]

PAGE = (
    b"<html><head><title>Login</title></head><body>"
    b"<!-- TODO: drop sknb{in_comment} -->"
    b'<a class="admin" href="/adm/panel">panel</a>'
    b'<form name="login" action="/login" method="post">'
    b'<input type="hidden" name="csrf_token" value="a1b2">'
    b'<input name="username"><input type="password" name="password">'
    b"</form></body></html>"
)


def _response(body=PAGE):
    return Response("http://target/login", 200, {"content-type": "text/html"}, body)


def _cli(*args, **kwargs):
    """Run ``python -m ctflib ...`` and return the completed process."""
    return subprocess.run(
        [sys.executable, "-m", "ctflib"] + list(args),
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs
    )


class TestNamespace(unittest.TestCase):
    def test_every_exported_name_exists(self):
        missing = [name for name in ctflib.__all__ if not hasattr(ctflib, name)]
        self.assertEqual(missing, [])

    def test_all_has_no_duplicates(self):
        self.assertEqual(len(ctflib.__all__), len(set(ctflib.__all__)))

    def test_star_import_matches_all(self):
        namespace = {}
        exec("from ctflib import *", namespace)
        del namespace["__builtins__"]
        self.assertEqual(sorted(namespace), sorted(ctflib.__all__))

    def test_no_ambiguous_bare_names(self):
        # dom and urlcodec both define "parse"; neither may claim the top level
        for name in ("parse", "stringify", "decode_all"):
            self.assertNotIn(name, ctflib.__all__)

    def test_renamed_exports_are_the_originals(self):
        from ctflib import b64, dom, urlcodec
        self.assertIs(ctflib.parse_dom, dom.parse)
        self.assertIs(ctflib.url_decode_all, urlcodec.decode_all)
        self.assertIs(ctflib.qs_parse, urlcodec.qs_parse)
        self.assertIs(ctflib.b64e, b64.b64encode)

    def test_http_names_survived_the_new_modules(self):
        # urlcodec has a "parse_qs"/"urlencode"; it must not shadow the client
        self.assertIs(ctflib.get, ctflib.client.get)
        self.assertIs(ctflib.Response, ctflib.client.Response)
        self.assertIs(ctflib.head, ctflib.client.head)
        self.assertIs(ctflib.ServerRequest, ctflib.server.Request)

    def test_js_spelled_aliases_are_exported(self):
        self.assertIs(ctflib.encodeURIComponent, ctflib.encode_uri_component)
        self.assertIs(ctflib.decodeURI, ctflib.decode_uri)

    def test_docstring_lists_the_new_sections(self):
        for label in ("HTML / DOM", "Base64", "URL encoding"):
            self.assertIn(label, ctflib.__doc__)


class TestResponseDom(unittest.TestCase):
    def test_dom_parses_the_body(self):
        doc = _response().dom()
        self.assertEqual(doc.title, "Login")
        self.assertEqual(doc.comments, ["TODO: drop sknb{in_comment}"])

    def test_dom_is_memoised(self):
        response = _response()
        self.assertIs(response.dom(), response.dom())

    def test_query_selector(self):
        response = _response()
        self.assertEqual(response.query_selector('input[name="csrf_token"]')["value"], "a1b2")
        self.assertIsNone(response.query_selector("table"))
        self.assertEqual(len(response.query_selector_all("input")), 3)

    def test_forms(self):
        form = _response().forms[0]
        self.assertEqual(form.method, "POST")
        self.assertEqual(form.fields, {"csrf_token": "a1b2", "username": "", "password": ""})
        self.assertEqual(form.url("http://target/login"), "http://target/login")
        self.assertEqual(
            form.fill(username="admin"),
            {"csrf_token": "a1b2", "username": "admin", "password": ""},
        )

    def test_empty_body_still_gives_a_document(self):
        response = Response("http://target/", 204, {}, b"")
        self.assertEqual(response.forms, [])
        self.assertEqual(response.query_selector_all("a"), [])

    def test_dom_import_is_not_circular(self):
        out = subprocess.run(
            [sys.executable, "-c", "import ctflib.client; print(ctflib.client.Response)"],
            cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(out.returncode, 0, out.stderr.decode())


class TestCli(unittest.TestCase):
    def test_b64_encode_from_stdin(self):
        out = _cli("b64", "-e", input=b"admin\n")
        self.assertEqual(out.stdout, b"YWRtaW4=\n")
        self.assertEqual(out.returncode, 0)

    def test_b64_encode_from_argv(self):
        self.assertEqual(_cli("b64", "-e", "admin").stdout, b"YWRtaW4=\n")

    def test_b64_decode_is_lenient(self):
        out = _cli("b64", "-d", input=b"YWRtaW4\n")     # no padding
        self.assertEqual(out.stdout, b"admin\n")
        self.assertEqual(out.returncode, 0)

    def test_b64_decode_of_nothing_returns_1(self):
        self.assertEqual(_cli("b64", "-d", input=b"\n").returncode, 1)

    def test_url_encode_and_decode(self):
        self.assertEqual(_cli("url", "-e", "a b&c=d/e").stdout, b"a%20b%26c%3Dd%2Fe\n")
        self.assertEqual(_cli("url", "-d", input=b"a%20b%26c\n").stdout, b"a b&c\n")

    def test_missing_or_unknown_flag_prints_usage(self):
        for args in (("b64",), ("url",), ("b64", "-x")):
            out = _cli(*args, input=b"")
            self.assertEqual(out.returncode, 2, args)
            self.assertIn(b"python -m ctflib", out.stderr)

    def test_usage_documents_the_new_commands(self):
        usage = _cli("--help").stderr
        self.assertIn(b"ctflib b64", usage)
        self.assertIn(b"ctflib url", usage)


if __name__ == "__main__":
    unittest.main(verbosity=2)
