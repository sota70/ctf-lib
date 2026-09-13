"""Async HTTP round trips, concurrency and connection lifecycle."""

import asyncio
import gzip
import json
import os
import threading
import unittest
from unittest.mock import patch

import httpx

from ctflib import App, AsyncSession, Response


class AsyncSessionTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = App(log=False)
        cls.app.route("/echo", lambda req, res: res.json({
            "method": req.method, "body": req.text, "headers": req.headers,
            "cookies": req.cookies, "query": req.query,
            "port": req.raw.client_address[1],
        }))
        cls.app.listen(0, host="127.0.0.1", background=True, quiet=True)
        cls.base = "http://127.0.0.1:%d" % cls.app.port

    @classmethod
    def tearDownClass(cls):
        cls.app.close()

    async def asyncSetUp(self):
        self.s = AsyncSession(base_url=self.base, headers={"X-Default": "yes"})

    async def asyncTearDown(self):
        await self.s.aclose()

    async def test_gather_sends_twenty_requests_concurrently(self):
        # No response is sent until all 20 requests have reached the server.
        # A sequential implementation fails the barrier, irrespective of speed.
        barrier = threading.Barrier(20, timeout=10)

        def parallel(req, res):
            barrier.wait()
            res.cookie("cookie" + req.params["id"], "saved").text(req.params["id"])

        self.app.route("/parallel/:id", parallel)
        responses = await asyncio.wait_for(asyncio.gather(
            *(self.s.get("/parallel/%d" % i) for i in range(20))), timeout=15)
        self.assertTrue(all(isinstance(r, Response) for r in responses))
        self.assertEqual([r.text for r in responses], [str(i) for i in range(20)])
        self.assertCountEqual(self.s.history, responses)
        self.assertEqual(self.s.cookies, {"cookie%d" % i: "saved" for i in range(20)})

    async def test_connections_are_reused_and_context_closes_them(self):
        async with self.s:
            first = (await self.s.get("/echo")).json()
            second = (await self.s.get("/echo")).json()
            self.assertEqual(first["port"], second["port"])
            clients = list(self.s._clients.values())
            self.assertEqual(len(clients), 1)
            self.assertIsInstance(clients[0], httpx.AsyncClient)
        self.assertTrue(all(c.is_closed for c in clients))
        with self.assertRaisesRegex(RuntimeError, "closed"):
            await self.s.get("/echo")
        with self.assertRaisesRegex(RuntimeError, "closed"):
            async with self.s:
                pass

    async def test_payloads_headers_auth_and_query(self):
        cases = [
            ({"data": {"a": [1, 2]}}, "application/x-www-form-urlencoded", "a=1&a=2"),
            ({"json": {"value": "日本語"}}, "application/json",
             json.dumps({"value": "日本語"}, ensure_ascii=False)),
            ({"data": b"<xml/>", "headers": {"Content-Type": None}}, None, "<xml/>"),
        ]
        for kwargs, content_type, body in cases:
            with self.subTest(kwargs=kwargs):
                result = (await self.s.post("/echo?existing=yes", params={"q": "a b"},
                                            auth=("u", "p"), **kwargs)).json()
                self.assertEqual(result["body"], body)
                self.assertEqual(result["headers"].get("content-type"), content_type)
                self.assertEqual(result["headers"]["x-default"], "yes")
                self.assertEqual(result["headers"]["authorization"], "Basic dTpw")
                self.assertEqual(result["query"], {"existing": "yes", "q": "a b"})
        result = (await self.s.post("/echo", form={"file": ("hello.txt", b"hello")},
                                    boundary="BOUNDARY")).json()
        self.assertEqual(result["headers"]["content-type"],
                         "multipart/form-data; boundary=BOUNDARY")
        self.assertIn('filename="hello.txt"', result["body"])
        self.assertIn("hello\r\n--BOUNDARY--", result["body"])
        with self.assertRaises(ValueError):
            await self.s.post("/echo", data="x", json={})

    async def test_all_method_shortcuts_and_error_status(self):
        for method in ("get", "post", "put", "patch", "delete", "options"):
            with self.subTest(method=method):
                result = await getattr(self.s, method)("/echo")
                self.assertEqual(result.json()["method"], method.upper())
        self.assertEqual((await self.s.head("/echo")).content, b"")
        self.assertEqual((await self.s.get("/missing")).status, 404)

    async def test_redirect_cookies_persist_and_can_be_overridden_or_deleted(self):
        self.app.route("/login", lambda req, res:
                       res.cookie("sess", "saved").redirect("/echo"))
        self.app.route("/logout", lambda req, res:
                       res.cookie("sess", "", max_age="0").text("deleted"))
        result = await self.s.get("/login")
        self.assertEqual(result.json()["cookies"], {"sess": "saved"})
        result = await self.s.get("/echo", cookies={"sess": "override", "extra": "1"})
        self.assertEqual(result.json()["cookies"], {"sess": "override", "extra": "1"})
        self.assertEqual(self.s.cookies, {"sess": "saved"})
        await self.s.get("/logout")
        self.assertEqual(self.s.cookies, {})
        self.s.set_cookie("manual", "value")
        self.assertEqual((await self.s.get("/echo")).json()["cookies"], {"manual": "value"})
        self.s.clear_cookies()
        self.assertEqual((await self.s.get("/echo")).json()["cookies"], {})
        self.assertEqual((await self.s.get("/login", allow_redirects=False)).status, 302)

    async def test_redirect_preserves_body_and_compression_is_decoded(self):
        for code in (307, 308):
            with self.subTest(code=code):
                self.app.route("/redirect-body", lambda req, res: res.redirect("/echo", code=code))
                result = await self.s.post("/redirect-body", data=b"payload")
                self.assertEqual(result.json()["method"], "POST")
                self.assertEqual(result.json()["body"], "payload")

        def compressed(req, res):
            res.headers["Content-Encoding"] = "gzip"
            res.cookie("one", "1").cookie("two", "2").send(gzip.compress(b"hello"))

        self.app.route("/compressed", compressed)
        result = await self.s.get("/compressed")
        self.assertEqual(result.content, b"hello")
        self.assertEqual(result.cookies, {"one": "1", "two": "2"})

    async def test_timeout_and_cancellation_leave_session_usable(self):
        loop = asyncio.get_running_loop()
        entered = asyncio.Event()
        release = threading.Event()

        def slow(req, res):
            loop.call_soon_threadsafe(entered.set)
            release.wait(5)
            try:
                res.text("done")
            except (BrokenPipeError, ConnectionResetError):
                pass

        self.app.route("/slow", slow)
        try:
            with self.assertRaises(httpx.ReadTimeout):
                await self.s.get("/slow", timeout=0.1)
            entered.clear()
            task = asyncio.create_task(self.s.get("/slow"))
            try:
                await asyncio.wait_for(entered.wait(), timeout=5)
            finally:
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
        finally:
            release.set()
        self.assertEqual(self.s.history, [])
        self.assertEqual((await self.s.get("/echo")).status, 200)

    async def test_proxy_override_and_all_pools_are_closed(self):
        seen = []
        proxy = App(log=False)
        proxy.default(lambda req, res: (seen.append(req.url), res.text("proxied"))[-1])
        proxy.listen(0, host="127.0.0.1", background=True, quiet=True)
        try:
            async with self.s:
                with patch.dict(os.environ, {"NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}):
                    for config in ("127.0.0.1:%d" % proxy.port,
                                   {"http": "127.0.0.1:%d" % proxy.port}):
                        result = await self.s.get("/echo", proxy=config)
                        self.assertEqual(result.text, "proxied")
                    self.assertEqual((await self.s.get("/echo")).status, 200)
                clients = list(self.s._clients.values())
            self.assertEqual(seen, [self.base + "/echo"] * 2)
            self.assertTrue(all(c.is_closed for c in clients))
        finally:
            await asyncio.get_running_loop().run_in_executor(None, proxy.close)


if __name__ == "__main__":
    unittest.main()
