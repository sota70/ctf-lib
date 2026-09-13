"""HTTP client for CTF web challenges, powered by HTTPX.

The entry point is :func:`request` (plus the ``get`` / ``post`` / ... shortcuts).
Body payloads are passed through one of three mutually exclusive arguments and
the matching ``Content-Type`` header is filled in automatically:

===============  ==========================================================
argument         Content-Type
===============  ==========================================================
``data``         ``application/x-www-form-urlencoded``
``json``         ``application/json``
``form``         ``multipart/form-data; boundary=...`` (files included)
===============  ==========================================================

``data`` takes a dict (url-encoded for you) or a ready-made str/bytes body.
Passing ``headers={"Content-Type": ...}`` overrides the automatic header, and
``headers={"Content-Type": None}`` sends the body with no Content-Type at all.
"""

from __future__ import annotations

import asyncio
import gzip
import json as _json
import mimetypes
import os
import threading
import time
import urllib.parse
import zlib
from contextlib import AsyncExitStack
from http.cookiejar import Cookie, CookieJar
from pathlib import Path

import httpx

from .dom import parse_html as _parse_html
from .flag import find_flg as _find_flg

__all__ = [
    "Headers",
    "Response",
    "Session",
    "AsyncSession",
    "request",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "encode_multipart",
    "session",
    "gather",
    "default_session",
]

DEFAULT_USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:153.0) Gecko/20100101 Firefox/153.0"
DEFAULT_TIMEOUT = 15


class Headers(dict):
    """Case-insensitive header mapping.

    Keys are stored lower-cased, so ``h["Content-Type"]`` and ``h["content-type"]``
    are the same entry.

    Example:
        >>> h = Headers({"Content-Type": "text/html"})
        >>> h["content-type"]
        'text/html'
        >>> "CONTENT-TYPE" in h
        True
    """

    def __init__(self, data=None):
        super().__init__()
        self.update(data or {})

    @staticmethod
    def _key(key):
        return key.lower() if isinstance(key, str) else key

    def __setitem__(self, key, value):
        super().__setitem__(self._key(key), value)

    def __getitem__(self, key):
        return super().__getitem__(self._key(key))

    def __delitem__(self, key):
        super().__delitem__(self._key(key))

    def __contains__(self, key):
        return super().__contains__(self._key(key))

    def get(self, key, default=None):
        return super().get(self._key(key), default)

    def pop(self, key, *default):
        return super().pop(self._key(key), *default)

    def setdefault(self, key, default=None):
        return super().setdefault(self._key(key), default)

    def update(self, data=None, **kwargs):
        items = data.items() if hasattr(data, "items") else (data or ())
        for key, value in items:
            self[key] = value
        for key, value in kwargs.items():
            self[key] = value


class Response:
    """Result of an HTTP request.

    Example:
        >>> r = Response("http://target/x", 200, {"content-type": "text/html"},
        ...              b"<b>sknb{a}</b>")
        >>> r.ok, r.status_code
        (True, 200)
        >>> r.find_flg("sknb{*}")
        'sknb{a}'
        >>> r.query_selector("b").text          # the body is parsed on demand
        'sknb{a}'
    """

    def __init__(self, url, status, headers, content, method="GET", elapsed=0.0, reason=""):
        self.url = url
        self.status = int(status)
        self.reason = reason
        self.headers = Headers(headers)
        self.content = content
        self.method = method
        self.elapsed = elapsed
        self._dom = None               # filled in on the first .dom() call

    # ``status_code`` is the name requests uses -- accept both.
    @property
    def status_code(self):
        return self.status

    @property
    def ok(self):
        return 200 <= self.status < 400

    @property
    def encoding(self):
        ctype = self.headers.get("content-type", "")
        for part in ctype.split(";")[1:]:
            name, _, value = part.strip().partition("=")
            if name.strip().lower() == "charset":
                return value.strip().strip('"\'') or "utf-8"
        return None

    @property
    def text(self):
        for enc in filter(None, (self.encoding, "utf-8")):
            try:
                return self.content.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
        return self.content.decode("latin-1")

    def json(self):
        """Parse the body as JSON."""
        return _json.loads(self.text)

    @property
    def cookies(self):
        """Cookies set by *this* response (name -> value)."""
        out = {}
        for raw in self.headers.get("set-cookie", "").split("\n"):
            if not raw.strip():
                continue
            name, _, value = raw.split(";")[0].partition("=")
            out[name.strip()] = value.strip()
        return out

    def find_flg(self, fmt=None, **kwargs):
        """Search the body for a flag -- see :func:`ctflib.find_flg`."""
        return _find_flg(self.text, fmt, **kwargs)

    def dom(self):
        """Parse the body as HTML -- see :func:`ctflib.dom.parse_html`.

        Parsed once and memoised, so ``r.dom()`` is cheap to call repeatedly.
        """
        if self._dom is None:
            self._dom = _parse_html(self.text)
        return self._dom

    def query_selector(self, selector):
        """First element in the body matching a CSS *selector* (``None`` if none)."""
        return self.dom().query_selector(selector)

    def query_selector_all(self, selector):
        """Every element in the body matching a CSS *selector*, in document order."""
        return self.dom().query_selector_all(selector)

    @property
    def forms(self):
        """The ``<form>`` elements in the body as :class:`~ctflib.dom.Form` objects."""
        return self.dom().forms

    def __contains__(self, needle):
        if isinstance(needle, bytes):
            return needle in self.content
        return needle in self.text

    def __len__(self):
        return len(self.content)

    def __repr__(self):
        return f"<Response [{self.status}] {self.method} {self.url} {len(self.content)}B {self.elapsed:.3f}s>"


# --------------------------------------------------------------------------- #
# body encoders
# --------------------------------------------------------------------------- #

def _items(data):
    """Iterate ``(key, value)`` over a dict or a sequence of pairs."""
    if data is None:
        return []
    if hasattr(data, "items"):
        return list(data.items())
    return list(data)


def _to_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return str(value).encode("utf-8")


def _urlencode(data):
    """``application/x-www-form-urlencoded`` body.

    A dict (or a sequence of pairs) is url-encoded; a str/bytes body is sent
    exactly as given, so hand-crafted payloads survive untouched.
    """
    if isinstance(data, (str, bytes, bytearray)):
        return _to_bytes(data)
    return urllib.parse.urlencode(_items(data), doseq=True).encode("utf-8")


def _quote_field(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\r", "").replace("\n", "")


def _file_part(name, filename, content, ctype):
    if ctype is None:
        ctype = mimetypes.guess_type(filename or "")[0] or "application/octet-stream"
    disposition = f'form-data; name="{_quote_field(name)}"'
    if filename is not None:
        disposition += f'; filename="{_quote_field(filename)}"'
    return (
        f"Content-Disposition: {disposition}\r\n"
        f"Content-Type: {ctype}\r\n\r\n"
    ).encode("utf-8"), _to_bytes(content)


def _read_file_like(value):
    """Return ``(filename, content)`` for a path or an open file object."""
    if isinstance(value, Path):
        return value.name, value.read_bytes()
    if hasattr(value, "read"):
        content = value.read()
        filename = os.path.basename(getattr(value, "name", "") or "") or None
        return filename, content
    raise TypeError(f"not a file: {value!r}")


def _multipart_parts(name, value):
    """Normalise one ``form`` value into a list of encoded parts.

    Accepted shapes::

        "text"                              plain field
        b"bytes"                            plain field
        ["a", "b"]                          the same field sent twice
        Path("/etc/passwd")                 file (name/type derived)
        open("shell.php", "rb")             file (name/type derived)
        ("shell.php", "<?php ...")          file with an explicit filename
        ("shell.php", data, "image/png")    file with an explicit content type
        {"filename": ..., "content": ..., "content_type": ...}
    """
    # tuple -> file spec (a list means "repeat this field", like requests)
    if isinstance(value, tuple):
        if not 2 <= len(value) <= 3:
            raise ValueError(f"form[{name!r}]: file tuple must be (filename, content[, content_type])")
        filename, content = value[0], value[1]
        ctype = value[2] if len(value) == 3 else None
        if isinstance(content, Path) or hasattr(content, "read"):
            _, content = _read_file_like(content)
        return [_file_part(name, filename, content, ctype)]

    if isinstance(value, dict):
        content = value.get("content", value.get("data", b""))
        if isinstance(content, Path) or hasattr(content, "read"):
            derived, content = _read_file_like(content)
            value.setdefault("filename", derived)
        return [_file_part(name, value.get("filename"), content, value.get("content_type"))]

    if isinstance(value, Path) or hasattr(value, "read"):
        filename, content = _read_file_like(value)
        return [_file_part(name, filename, content, None)]

    if isinstance(value, (list, set, frozenset)):
        parts = []
        for item in value:
            parts.extend(_multipart_parts(name, item))
        return parts

    header = f'Content-Disposition: form-data; name="{_quote_field(name)}"\r\n\r\n'.encode("utf-8")
    return [(header, _to_bytes("" if value is None else value))]


def encode_multipart(fields, boundary=None):
    """Encode *fields* as ``multipart/form-data``.

    Returns ``(body, content_type)``.

    Example:
        >>> body, ctype = encode_multipart({"f": ("shell.php", b"<?php ?>")},
        ...                                boundary="B")
        >>> ctype
        'multipart/form-data; boundary=B'
        >>> body.splitlines()[1]
        b'Content-Disposition: form-data; name="f"; filename="shell.php"'
    """
    if boundary is None:
        boundary = "----ctflib" + os.urandom(12).hex()
    marker = f"--{boundary}\r\n".encode("ascii")
    body = bytearray()
    for name, value in _items(fields):
        for header, content in _multipart_parts(name, value):
            body += marker + header + content + b"\r\n"
    body += f"--{boundary}--\r\n".encode("ascii")
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def _build_body(json, form, data, boundary=None):
    """Pick the one payload argument in use and encode it."""
    given = [n for n, v in (("data", data), ("json", json), ("form", form)) if v is not None]
    if len(given) > 1:
        raise ValueError("pass only one of data / json / form, got: " + ", ".join(given))
    if data is not None:
        return _urlencode(data), "application/x-www-form-urlencoded"
    if json is not None:
        return _json.dumps(json, ensure_ascii=False).encode("utf-8"), "application/json"
    if form is not None:
        return encode_multipart(form, boundary)
    return None, None


def _normalise_proxy(proxy):
    """``"127.0.0.1:8080"`` / ``"http://..."`` / ``{"https": ...}`` -> proxy dict."""
    if not proxy:
        return None
    if isinstance(proxy, dict):
        return dict(proxy)
    proxy = str(proxy)
    if "://" not in proxy:
        proxy = "http://" + proxy
    return {"http": proxy, "https": proxy}


def _decompress(body, encoding):
    encoding = (encoding or "").lower().strip()
    try:
        if encoding == "gzip":
            return gzip.decompress(body)
        if encoding == "deflate":
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
    except (OSError, zlib.error):
        return body  # served with a bogus header -- keep the raw bytes
    return body


def _merge_query(url, params):
    if not params:
        return url
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    query += [(k, v) for k, v in _items(params)]
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query, doseq=True)))


class Session:
    """Keeps cookies, proxy and default headers across requests.

    Example:
        >>> s = Session(base_url=URL)           # URL: the doctest echo server
        >>> s.get("/echo").text
        'GET /echo'
        >>> s.set_cookie("session", "abc")
        >>> s.cookies
        {'session': 'abc'}
    """

    def __init__(self, base_url=None, headers=None, proxy=None, verify=False,
                 timeout=DEFAULT_TIMEOUT, user_agent=DEFAULT_USER_AGENT):
        self.base_url = base_url
        self.headers = Headers(headers)
        self.proxy = proxy
        self.verify = verify
        self.timeout = timeout
        self.user_agent = user_agent
        self.jar = CookieJar()
        self.history = []
        self._request_lock = threading.RLock()

    # -- cookies ----------------------------------------------------------- #
    @property
    def cookies(self):
        with self._request_lock:
            return {c.name: c.value for c in self.jar}

    def set_cookie(self, name, value, domain="", path="/"):
        with self._request_lock:
            self.jar.set_cookie(Cookie(
                version=0, name=name, value=value, port=None, port_specified=False,
                domain=domain, domain_specified=bool(domain), domain_initial_dot=domain.startswith("."),
                path=path, path_specified=True, secure=False, expires=None, discard=True,
                comment=None, comment_url=None, rest={}, rfc2109=False,
            ))

    def clear_cookies(self):
        with self._request_lock:
            self.jar.clear()

    def _cookie_header(self, url, extra):
        """Merge jar cookies for *url* with the per-request ``cookies`` dict."""
        probe = httpx.Request("GET", url)
        httpx.Cookies(self.jar).set_cookie_header(probe)
        pairs = []
        for chunk in (probe.headers.get("cookie") or "").split(";"):
            name, sep, value = chunk.strip().partition("=")
            if sep:
                pairs.append((name, value))
        overrides = {str(k): str(v) for k, v in _items(extra)}
        merged = [(k, overrides.pop(k)) if k in overrides else (k, v) for k, v in pairs]
        merged += list(overrides.items())
        return "; ".join(f"{k}={v}" for k, v in merged)

    # -- request ----------------------------------------------------------- #
    def request(self, method, url, *, params=None, data=None, json=None, form=None,
                headers=None, cookies=None, proxy=None, auth=None,
                timeout=None, allow_redirects=True, verify=None, boundary=None):
        """Send a request and return a :class:`Response`.

        ``data`` (url-encoded), ``json`` and ``form`` are mutually
        exclusive and each set their own ``Content-Type``.
        Never raises on 4xx/5xx -- inspect ``response.status``.

        Network errors are HTTPX exceptions.
        """
        kwargs = dict(params=params, data=data, json=json, form=form,
                      headers=headers, cookies=cookies, proxy=proxy, auth=auth,
                      timeout=timeout, allow_redirects=allow_redirects,
                      verify=verify, boundary=boundary)
        return self._request(method, url, **kwargs)

    def _request(self, method, url, *, params=None, data=None, json=None, form=None,
                 headers=None, cookies=None, proxy=None, auth=None,
                 timeout=None, allow_redirects=True, verify=None, boundary=None):
        method, url, body, final = self._prepare_request(
            method, url, params=params, data=data, json=json, form=form,
            headers=headers, cookies=cookies, auth=auth, boundary=boundary,
        )
        proxy = self.proxy if proxy is None else proxy
        verify = self.verify if verify is None else verify
        proxies = _normalise_proxy(proxy)
        # Each request owns its transport and redirect cookies. Only received
        # Set-Cookie headers are merged back, so concurrent updates are not lost.
        with self._request_lock:
            request_cookies = httpx.Cookies()
            for cookie in self.jar:
                request_cookies.jar.set_cookie(cookie)

        def save_cookies(raw):
            with self._request_lock:
                httpx.Cookies(self.jar).extract_cookies(raw)

        with httpx.Client(
            verify=verify, mounts=_proxy_mounts(proxies, verify, httpx.HTTPTransport),
            trust_env=not bool(proxies), cookies=request_cookies,
            follow_redirects=allow_redirects,
            timeout=self.timeout if timeout is None else timeout,
            event_hooks={"response": [save_cookies]},
        ) as client:
            client.headers.clear()
            started = time.monotonic()
            with client.stream(method, url, content=body, headers=final) as raw:
                content = b"".join(raw.iter_raw())
            elapsed = time.monotonic() - started
        return self._record_response(raw, content, method, elapsed)

    def _prepare_request(self, method, url, *, params, data, json, form,
                         headers, cookies, auth, boundary):
        if self.base_url and "://" not in url:
            url = self.base_url.rstrip("/") + "/" + url.lstrip("/")
        url = _merge_query(url, params)
        method = method.upper()

        body, content_type = _build_body(json, form, data, boundary)

        final = Headers({"user-agent": self.user_agent, "accept-encoding": "gzip, deflate"})
        final.update(self.headers)
        final.update(headers)          # per-request headers win over session defaults
        if content_type and "content-type" not in final:
            final["content-type"] = content_type
        if auth:
            import base64
            token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode("utf-8")).decode("ascii")
            final.setdefault("authorization", "Basic " + token)
        with self._request_lock:
            if "cookie" not in final:
                cookie = self._cookie_header(url, cookies)
                if cookie:
                    final["cookie"] = cookie
        # Keep header suppression (including Content-Type=None) intact.
        return method, url, body, {
            name: value for name, value in final.items() if value is not None
        }

    def _record_response(self, raw, content, method, elapsed):
        raw_headers = raw.headers.multi_items()
        merged = Headers()
        for name, value in raw_headers:
            key = name.lower()
            merged[key] = f"{merged[key]}\n{value}" if key in merged else value

        content = _decompress(content, merged.get("content-encoding"))
        response = Response(
            url=str(raw.url), status=raw.status_code, headers=merged, content=content,
            method=method, elapsed=elapsed, reason=raw.reason_phrase,
        )
        with self._request_lock:
            self.history.append(response)
        return response

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def put(self, url, **kw):
        return self.request("PUT", url, **kw)

    def patch(self, url, **kw):
        return self.request("PATCH", url, **kw)

    def delete(self, url, **kw):
        return self.request("DELETE", url, **kw)

    def head(self, url, **kw):
        return self.request("HEAD", url, **kw)

    def options(self, url, **kw):
        return self.request("OPTIONS", url, **kw)

    def __repr__(self):
        return f"<{type(self).__name__} base_url={self.base_url!r} cookies={list(self.cookies)} proxy={self.proxy!r}>"


def _proxy_mounts(proxies, verify, transport):
    if not proxies:
        return None
    return {
        scheme.rstrip(":/") + "://": transport(
            proxy=(value if "://" in value else "http://" + value) if value else None,
            verify=verify,
        )
        for scheme, value in proxies.items()
    }


class AsyncSession(Session):
    """Awaitable HTTP requests with shared cookies and connection pools.

    Use one session within one event loop and close it with ``async with`` or
    ``await session.aclose()`` after all requests finish. HTTP helpers return
    coroutines; pass several to ``asyncio.gather`` to send them concurrently.
    Connections are reused for requests with the same proxy and TLS settings.
    Cookie helpers remain synchronous. Await login responses before sending
    requests that need their cookies; concurrent cookie updates are applied in
    response-header arrival order. Do not mutate settings or upload files while
    requests are in flight.

    Example:
        >>> import asyncio
        >>> async def fetch_many():
        ...     async with AsyncSession(base_url=URL) as s:
        ...         responses = await asyncio.gather(
        ...             *(s.get("/echo") for _ in range(3)))
        ...         return [r.text for r in responses]
        >>> asyncio.run(fetch_many())
        ['GET /echo', 'GET /echo', 'GET /echo']
    """

    def __init__(self, base_url=None, headers=None, proxy=None, verify=False,
                 timeout=DEFAULT_TIMEOUT, user_agent=DEFAULT_USER_AGENT):
        super().__init__(base_url=base_url, headers=headers, proxy=proxy,
                         verify=verify, timeout=timeout, user_agent=user_agent)
        self._clients = {}
        self._closed = False

    async def __aenter__(self):
        if self._closed:
            raise RuntimeError("AsyncSession is closed")
        return self

    async def __aexit__(self, *exc):
        await self.aclose()

    async def aclose(self):
        """Close pooled connections after awaiting all outstanding requests."""
        self._closed = True
        for client in self._clients.values():
            await client.aclose()

    async def request(self, method, url, *, params=None, data=None, json=None,
                      form=None, headers=None, cookies=None, proxy=None, auth=None,
                      timeout=None, allow_redirects=True, verify=None, boundary=None):
        """Send asynchronously and return a :class:`Response`.

        Supports the synchronous session's payload and request options.
        Use ``await`` or ``asyncio.gather`` to receive responses. HTTP errors
        return responses; network failures raise HTTPX exceptions. Cancelling
        the awaiting task cancels the request and closes its response stream.
        """
        if self._closed:
            raise RuntimeError("AsyncSession is closed")
        method, url, body, final = self._prepare_request(
            method, url, params=params, data=data, json=json, form=form,
            headers=headers, cookies=cookies, auth=auth, boundary=boundary,
        )
        proxies = _normalise_proxy(self.proxy if proxy is None else proxy)
        verify = self.verify if verify is None else verify
        key = (verify, tuple(sorted((proxies or {}).items())))
        client = self._clients.get(key)
        if client is None:
            client = httpx.AsyncClient(
                verify=verify,
                mounts=_proxy_mounts(proxies, verify, httpx.AsyncHTTPTransport),
                trust_env=not bool(proxies), cookies=self.jar,
            )
            client.headers.clear()
            self._clients[key] = client

        started = time.monotonic()
        async with client.stream(
            method, url, content=body, headers=final,
            timeout=self.timeout if timeout is None else timeout,
            follow_redirects=allow_redirects,
        ) as raw:
            content = b"".join([chunk async for chunk in raw.aiter_raw()])
        return self._record_response(raw, content, method, time.monotonic() - started)


#: Session used by the module level helpers -- cookies persist between calls.
default_session = Session()


class _PendingRequest:
    """A request description; constructing it does not open a connection."""

    def __init__(self, owner, method, url, kwargs):
        self.owner = owner
        self.method = method
        self.url = url
        self.kwargs = kwargs
        self.done = False
        self.response = None
        self.error = None

    async def _send(self, client):
        if not self.done:
            try:
                self.response = await client.request(self.method, self.url, **self.kwargs)
            except BaseException as exc:
                self.error = exc
            self.done = True
        if self.error is not None:
            raise self.error
        return self.response

    def __await__(self):
        async def receive():
            return (await gather(self))[0]
        return receive().__await__()


class _QueuedSession(Session):
    """Session factory's event-loop mode, with automatically closed batches."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._loop = asyncio.get_running_loop()
        self._pending = []
        self._batch_lock = asyncio.Lock()

    def request(self, method, url, **kwargs):
        pending = _PendingRequest(self, method, url, kwargs)
        self._pending.append(pending)
        return pending

    def _async_session(self):
        client = AsyncSession(base_url=self.base_url, headers=self.headers,
                              proxy=self.proxy, verify=self.verify,
                              timeout=self.timeout, user_agent=self.user_agent)
        client.jar = self.jar
        client.history = self.history
        client._request_lock = self._request_lock
        return client


async def gather(*requests, return_exceptions=False):
    """Send queued session requests concurrently, returning responses in input order.

    Accepts the awaitable request handles returned by ``session()`` created in
    an event loop. For each session, requests queued before the earliest selected
    handle run sequentially first (for login cookies, for example).
    Requests queued after the selected handles are left for a later batch.
    A handle is sent at most once, even if gathered or awaited again.

    Connections are shared within each batch and closed before returning.
    On failure, unfinished batch requests are cancelled before raising. With
    ``return_exceptions=True``, request errors appear in the result list instead.
    A failed prerequisite prevents that session's selected requests from being
    sent. Cancelling gather cancels its in-flight requests. Batches using the
    same session are serialized. Use one session within one event loop.

    Example:
        >>> async def main():
        ...     sess = session(base_url=URL)
        ...     _ = sess.get("/echo")
        ...     tasks = [sess.get("/echo") for _ in range(3)]
        ...     responses = await gather(*tasks)
        ...     return [r.status_code for r in responses], len(sess.history)
        >>> asyncio.run(main())
        ([200, 200, 200], 4)
    """
    if any(not isinstance(req, _PendingRequest) for req in requests):
        raise TypeError("gather expects request handles from session() in an event loop")
    selected = set(requests)
    owners = sorted({req.owner for req in requests}, key=id)
    if any(owner._loop is not asyncio.get_running_loop() for owner in owners):
        raise RuntimeError("use session() and gather() within the same event loop")

    async with AsyncExitStack() as stack:
        for owner in owners:
            await stack.enter_async_context(owner._batch_lock)
        clients = {
            owner: await stack.enter_async_context(owner._async_session())
            for owner in owners
        }
        try:
            for owner in owners:
                # Earlier unselected requests are prerequisites, not discarded
                # coroutine objects. Never replay a completed request.
                batch = [req for req in requests if req.owner is owner and not req.done]
                if not batch:
                    continue
                try:
                    for req in owner._pending:
                        if req in selected:
                            break
                        if not req.done:
                            await req._send(clients[owner])
                except BaseException as exc:
                    for req in batch:
                        req.error, req.done = exc, True
                    if isinstance(exc, asyncio.CancelledError):
                        raise

            tasks = {req: asyncio.create_task(req._send(clients[req.owner]))
                     for req in dict.fromkeys(requests)}
            try:
                return await asyncio.gather(
                    *(tasks[req] for req in requests), return_exceptions=return_exceptions)
            finally:
                for task in tasks.values():
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks.values(), return_exceptions=True)
                for req, task in tasks.items():
                    if task.cancelled() and not req.done:
                        req.error, req.done = asyncio.CancelledError(), True
        finally:
            for owner in owners:
                owner._pending[:] = [req for req in owner._pending if not req.done]


def session(**kwargs):
    """Create a session with cookies isolated from the default session.

    Outside an event loop, requests synchronously return :class:`Response`.
    Inside an event loop, requests are queued: use ``await gather(*tasks)`` for
    parallel sending, or ``await sess.get(url)`` for one response. Earlier queued
    requests are completed before the selected batch. No request is sent until
    awaited or included as a prerequisite by :func:`gather`. Batch connections
    close automatically; cookies and history persist for the next batch.
    Use :class:`Session` explicitly for synchronous calls inside an event loop,
    or :class:`AsyncSession` for direct ``asyncio.gather`` and long-lived pools.

    Example:
        >>> s = session(base_url=URL)
        >>> s.get("/echo").status
        200
        >>> s.cookies                           # its own jar, nothing inherited
        {}
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return Session(**kwargs)
    return _QueuedSession(**kwargs)


def request(method, url, **kwargs):
    """Send an HTTP request using the default session.

    ``data=`` (url-encoded) / ``json=`` / ``form=`` (multipart, files included)
    set ``Content-Type`` automatically, ``proxy=`` routes the request through
    e.g. Burp.

    Example:
        >>> request("POST", URL + "/echo", data={"user": "admin"}).text.splitlines()
        ['POST /echo', 'user=admin']
    """
    return default_session.request(method, url, **kwargs)


def get(url, **kw):
    """GET *url* on the default session -- see :func:`request` for the arguments.

    Example:
        >>> get(URL + "/echo", params={"a": "1 2"}).text
        'GET /echo?a=1+2'
    """
    return default_session.request("GET", url, **kw)


def post(url, **kw):
    """POST *url* on the default session -- see :func:`request` for the arguments.

    Example:
        >>> post(URL + "/echo", data={"user": "admin", "pw": "' OR 1--"}).text.splitlines()
        ['POST /echo', 'user=admin&pw=%27+OR+1--']
    """
    return default_session.request("POST", url, **kw)


def put(url, **kw):
    """PUT *url* on the default session -- see :func:`request`.

    Example:
        >>> put(URL + "/echo", data="raw").text.splitlines()
        ['PUT /echo', 'raw']
    """
    return default_session.request("PUT", url, **kw)


def patch(url, **kw):
    """PATCH *url* on the default session -- see :func:`request`.

    Example:
        >>> patch(URL + "/echo").text
        'PATCH /echo'
    """
    return default_session.request("PATCH", url, **kw)


def delete(url, **kw):
    """DELETE *url* on the default session -- see :func:`request`.

    Example:
        >>> delete(URL + "/echo").text
        'DELETE /echo'
    """
    return default_session.request("DELETE", url, **kw)


def head(url, **kw):
    """HEAD *url* on the default session -- headers only, no body.

    Example:
        >>> r = head(URL + "/echo")
        >>> r.status, r.text
        (200, '')
    """
    return default_session.request("HEAD", url, **kw)


def options(url, **kw):
    """OPTIONS *url* on the default session -- see :func:`request`.

    Example:
        >>> options(URL + "/echo").text
        'OPTIONS /echo'
    """
    return default_session.request("OPTIONS", url, **kw)
