"""Background request lifecycle, without external network access."""

import threading
import unittest
from concurrent.futures import CancelledError, Future, TimeoutError
from unittest.mock import patch

from ctflib import Response, Session


class BackgroundRequestTests(unittest.TestCase):
    def test_returns_before_request_finishes_and_runs_on_another_thread(self):
        session = Session()
        entered = threading.Event()
        release = threading.Event()
        caller = threading.get_ident()
        worker = []
        response = Response("http://localhost/status", 200, {}, b"ok")

        def send(*args, **kwargs):
            worker.append(threading.get_ident())
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test did not release worker")
            return response

        with patch.object(session, "_request", side_effect=send) as mocked:
            future = session.get("/status", params={"a": "b"}, background=True)
            try:
                self.assertIsInstance(future, Future)
                self.assertTrue(entered.wait(5))
                self.assertNotEqual(worker, [caller])
                with self.assertRaises(TimeoutError):
                    future.result(timeout=0)
                self.assertFalse(future.cancel())
            finally:
                release.set()
                self.assertIs(future.result(timeout=5), response)
            self.assertEqual(mocked.call_args.args, ("GET", "/status"))
            self.assertEqual(mocked.call_args.kwargs["params"], {"a": "b"})

    def test_exception_is_reraised_by_result_and_session_remains_usable(self):
        session = Session()
        error = OSError("connection failed")
        response = Response("http://localhost/status", 200, {}, b"ok")
        with patch.object(session, "_request", side_effect=[error, response]):
            future = session.get("/status", background=True)
            with self.assertRaises(OSError) as caught:
                future.result(timeout=5)
            self.assertIs(caught.exception, error)
            self.assertIs(session.get("/status", background=True).result(5), response)

    def test_waiting_request_can_be_cancelled_without_sending(self):
        session = Session()
        with patch.object(session, "_request") as send:
            with patch("ctflib.client.threading.Thread") as thread:
                future = session.get("/status", background=True)
                self.assertFalse(future.running())
                send.assert_not_called()
                self.assertTrue(future.cancel())
                thread.call_args.kwargs["target"]()
            with self.assertRaises(CancelledError):
                future.result(timeout=5)
            # A subsequent request still completes after the cancelled worker.
            session.get("/status", background=True).result(timeout=5)
            self.assertEqual(send.call_count, 1)

    def test_synchronous_default_returns_response_in_callers_thread(self):
        session = Session()
        worker = []
        response = Response("http://localhost/status", 200, {}, b"ok")

        def send(*args, **kwargs):
            worker.append(threading.get_ident())
            return response

        with patch.object(session, "_request", side_effect=send):
            self.assertIs(session.get("/status"), response)
        self.assertEqual(worker, [threading.get_ident()])


if __name__ == "__main__":
    unittest.main()
