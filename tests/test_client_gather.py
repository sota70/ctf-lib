"""The session()/gather() shorthand over actual asynchronous HTTP requests."""

import asyncio
import contextlib
import io
import threading
import unittest
from unittest.mock import patch

import httpx

from ctflib import App, Response, Session, gather, session


class GatherTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = App(log=False)
        cls.app.route("/echo", lambda req, res: res.json({
            "method": req.method, "cookies": req.cookies, "body": req.text,
            "query": req.query, "headers": req.headers,
        }))
        cls.app.listen(0, host="127.0.0.1", background=True, quiet=True)
        cls.base = "http://127.0.0.1:%d" % cls.app.port

    @classmethod
    def tearDownClass(cls):
        cls.app.close()

    async def test_exact_star_import_example_runs_setup_then_twenty_parallel_requests(self):
        barrier = threading.Barrier(20, timeout=10)
        received = []
        ports = []

        def setup(req, res):
            received.append("setup")
            ports.append(req.raw.client_address[1])
            res.cookie("login", "ready").text("ready")

        def parallel(req, res):
            received.append(req.cookies.get("login"))
            ports.append(req.raw.client_address[1])
            barrier.wait()
            res.text("ok")

        self.app.route("/setup", setup)
        self.app.route("/parallel", parallel)
        namespace = {"URL": self.base}
        exec('''from ctflib import *
import asyncio

async def main():
    sess = session()
    sess.get(URL + "/setup")
    tasks = [sess.get(URL + "/parallel") for _ in range(20)]
    resps = await gather(*tasks)
    print([r.status_code for r in resps])
    return sess, resps
''', namespace)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            sess, resps = await asyncio.wait_for(namespace["main"](), timeout=15)
        self.assertEqual(output.getvalue(), str([200] * 20) + "\n")
        self.assertEqual(received, ["setup"] + ["ready"] * 20)
        self.assertIn(ports[0], ports[1:])  # The setup connection joins the batch pool.
        self.assertEqual(len(sess.history), 21)
        self.assertEqual(sess.cookies, {"login": "ready"})
        self.assertTrue(all(isinstance(r, Response) for r in resps))

    async def test_deferred_calls_input_order_and_no_resending(self):
        sess = session(base_url=self.base)
        first = sess.get("/echo", params={"id": "first"})
        second = sess.post("/echo", data="second")
        later = sess.get("/echo", params={"id": "later"})
        self.assertEqual(sess.history, [])
        results = await gather(second, first, second)
        self.assertEqual(results[0].json()["body"], "second")
        self.assertEqual(results[1].json()["query"], {"id": "first"})
        self.assertIs(results[0], results[2])
        self.assertEqual(len(sess.history), 2)
        self.assertIs(await first, results[1])
        self.assertEqual(await gather(first, second), [results[1], results[0]])
        self.assertEqual(len(sess.history), 2)
        self.assertEqual((await later).json()["query"], {"id": "later"})
        self.assertEqual(len(sess.history), 3)

    async def test_sequential_prerequisites_and_persistent_cookie_deletion(self):
        self.app.route("/set-cookie", lambda req, res:
                       res.cookie("sess", "saved").text("set"))
        self.app.route("/del-cookie", lambda req, res:
                       res.cookie("sess", "", max_age="0").text("deleted"))
        sess = session(base_url=self.base)
        sess.get("/set-cookie")
        sess.get("/del-cookie")
        result = (await gather(sess.get("/echo")))[0]
        self.assertEqual(result.json()["cookies"], {})
        self.assertEqual([r.text for r in sess.history[:2]], ["set", "deleted"])
        await sess.get("/set-cookie")
        self.assertEqual((await sess.get("/echo")).json()["cookies"], {"sess": "saved"})

    async def test_multiple_sessions_keep_cookies_and_headers_isolated(self):
        left = session(base_url=self.base, headers={"X-Session": "left"})
        right = session(base_url=self.base, headers={"X-Session": "right"})
        left.set_cookie("user", "left")
        right.set_cookie("user", "right")
        responses = await gather(left.get("/echo"), right.get("/echo"))
        for name, result in zip(("left", "right"), responses):
            self.assertEqual(result.json()["cookies"], {"user": name})
            self.assertEqual(result.json()["headers"]["x-session"], name)

    async def test_failure_results_and_no_retry(self):
        sess = session(base_url=self.base)
        bad = sess.post("/echo", data="x", json={})
        good = sess.get("/echo")
        results = await gather(bad, good, return_exceptions=True)
        self.assertIsInstance(results[0], ValueError)
        self.assertEqual(results[1].status, 200)
        with self.assertRaises(ValueError):
            await bad
        self.assertEqual(len(sess.history), 1)

    async def test_failed_prerequisite_prevents_batch(self):
        sess = session(base_url=self.base)
        sess.post("/echo", data="x", json={})
        tasks = [sess.get("/echo") for _ in range(3)]
        results = await gather(*tasks, return_exceptions=True)
        self.assertTrue(all(isinstance(r, ValueError) for r in results))
        self.assertEqual(sess.history, [])
        with self.assertRaises(ValueError):
            await gather(*tasks)
        self.assertEqual((await sess.get("/echo")).status, 200)

    async def test_pools_closed_on_success_failure_and_cancellation(self):
        clients = []
        sess = session(base_url=self.base)
        make_client = sess._async_session

        def capture():
            client = make_client()
            clients.append(client)
            return client

        entered = asyncio.Event()
        release = threading.Event()
        loop = asyncio.get_running_loop()

        def slow(req, res):
            loop.call_soon_threadsafe(entered.set)
            release.wait(5)
            try:
                res.text("done")
            except (BrokenPipeError, ConnectionResetError):
                pass

        self.app.route("/gather-slow", slow)
        with patch.object(sess, "_async_session", side_effect=capture):
            await gather(sess.get("/echo"))
            timeout = sess.get("/gather-slow", timeout=0.1)
            sibling = sess.get("/gather-slow")
            with self.assertRaises(httpx.ReadTimeout):
                await gather(timeout, sibling)
            with self.assertRaises(asyncio.CancelledError):
                await sibling
            entered.clear()
            pending = sess.get("/gather-slow")
            task = asyncio.create_task(gather(pending))
            try:
                await asyncio.wait_for(entered.wait(), timeout=5)
            finally:
                task.cancel()
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            with self.assertRaises(asyncio.CancelledError):
                await pending
            self.assertEqual((await sess.get("/echo")).status, 200)
        self.assertTrue(all(client._closed for client in clients))
        pools = [pool for client in clients for pool in client._clients.values()]
        self.assertTrue(pools)
        self.assertTrue(all(pool.is_closed for pool in pools))
        self.assertEqual(len(sess.history), 2)

    async def test_overlapping_batches_do_not_send_a_handle_twice(self):
        sess = session(base_url=self.base)
        handle = sess.get("/echo")
        first, second = await asyncio.gather(gather(handle), gather(handle))
        self.assertIs(first[0], second[0])
        self.assertEqual(len(sess.history), 1)

    async def test_empty_invalid_and_explicit_sync_api(self):
        self.assertEqual(await gather(), [])
        with self.assertRaises(TypeError):
            await gather(Response(self.base, 200, {}, b"already sent"))
        self.assertIsInstance(Session(base_url=self.base).get("/echo"), Response)


class SyncFactoryTests(unittest.TestCase):
    def test_factory_remains_synchronous_without_an_event_loop(self):
        sess = session()
        result = Response("http://localhost/", 200, {}, b"ok")
        with patch.object(sess, "_request", return_value=result):
            self.assertIs(sess.get("http://localhost/"), result)


if __name__ == "__main__":
    unittest.main()
