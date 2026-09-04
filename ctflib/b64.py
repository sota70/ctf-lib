"""Forgiving base64 helpers -- string in, string out, like Node's Buffer.

    b64e("admin")                  # -> 'YWRtaW4='
    b64d("YWRtaW4")                # -> b'admin'   (missing padding is fine)
    b64decode_str("aGk_-\n!!")     # -> 'hi?'      (url-safe, mixed, garbage)

``b64decode`` never raises on a blob you pasted out of a burp window: it takes
both alphabets (``+/`` and ``-_``, even mixed), drops whitespace and anything
else outside the alphabet, and re-pads for you. Pass ``strict=True`` when you
actually want the stdlib's "this is malformed" behaviour.
"""

from __future__ import annotations

import base64
import binascii
import re

__all__ = [
    "b64encode",
    "b64decode",
    "b64decode_str",
    "b64e",
    "b64d",
    "atob",
    "btoa",
    "b64url_encode",
    "b64url_decode",
    "is_b64",
    "b64_len",
    "b64decode_all",
]

#: everything outside the two alphabets (padding kept) -- stripped before decoding.
_JUNK_RE = re.compile(r"[^A-Za-z0-9+/\-_=]")

#: a run of payload characters, no padding, nothing else.
_ALPHA_RE = re.compile(r"\A[A-Za-z0-9+/\-_]+\Z")

#: strict alphabets: one or the other, correctly padded, nothing else.
_STD_RE = re.compile(r"\A[A-Za-z0-9+/]*={0,2}\Z")
_URL_RE = re.compile(r"\A[A-Za-z0-9\-_]*={0,2}\Z")

#: is_b64 tolerates MIME line wrapping but not stray spaces.
_WRAP_RE = re.compile(r"[\r\n]+")

#: a base64-looking run -- CR/LF may sit inside it, since MIME wraps long blobs.
_RUN_RE = re.compile(r"[A-Za-z0-9+/\-_][A-Za-z0-9+/\-_\r\n]*={0,2}")

_PRINTABLE = frozenset(b"\t\n\r") | frozenset(range(0x20, 0x7F))


# --------------------------------------------------------------------------- #
# input coercion
# --------------------------------------------------------------------------- #

def _as_bytes(data):
    """Raw bytes of str / bytes / a Response (``.content``, else ``.text``)."""
    if data is None:
        return b""
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    if isinstance(data, str):
        return data.encode("utf-8")
    content = getattr(data, "content", None)  # Response-like
    if isinstance(content, (bytes, bytearray)):
        return bytes(content)
    text = getattr(data, "text", None)
    if isinstance(text, str):
        return text.encode("utf-8")
    return str(data).encode("utf-8")


def _as_text(data):
    """Base64 source as str -- bytes are latin-1'd, so no decode can fail."""
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data).decode("latin-1")
    text = getattr(data, "text", None)  # Response-like
    if isinstance(text, str):
        return text
    return str(data)


# --------------------------------------------------------------------------- #
# encode / decode
# --------------------------------------------------------------------------- #

def b64encode(data, *, urlsafe=False, padding=True, wrap=0):
    """Base64-encode *data* and return a str.

    *data* may be str (utf-8), bytes, or a Response. ``urlsafe=True`` uses the
    ``-_`` alphabet, ``padding=False`` strips the trailing ``=``, and ``wrap=N``
    breaks the output into lines of *N* characters (``wrap=76`` for MIME).

    Example:
        >>> b64encode("admin")
        'YWRtaW4='
        >>> b64encode("~~~?", urlsafe=True, padding=False)
        'fn5-Pw'
    """
    raw = _as_bytes(data)
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    out = encoder(raw).decode("ascii")
    if not padding:
        out = out.rstrip("=")
    if wrap and wrap > 0:
        out = "\n".join(out[i:i + wrap] for i in range(0, len(out), wrap))
    return out


def b64decode(data, *, text=False, encoding="utf-8", errors="replace", strict=False):
    """Decode base64 *data*, repairing whatever needs repairing.

    Accepts str or bytes, both alphabets (even mixed in one blob), ignores
    whitespace and any other character outside the alphabet, stops at the first
    ``=`` (like Node), re-pads when ``=`` is missing, and drops a trailing group
    of a single leftover character.

    ``strict=True`` skips every repair and raises :class:`ValueError` instead --
    the input must be one alphabet, correctly padded, with nothing else in it.
    ``text=True`` returns a str decoded with *encoding* / *errors*.

    Example:
        >>> b64decode("YWRtaW4")                # padding missing, re-padded
        b'admin'
        >>> b64decode("aGk_- !!", text=True)    # url-safe, spaces, junk
        'hi?'
        >>> b64decode("YWRtaW4", strict=True)
        Traceback (most recent call last):
            ...
        ValueError: base64 length is not a multiple of 4 (missing padding?)
    """
    source = _as_text(data)
    if strict:
        raw = _strict_decode(source)
    else:
        cleaned = _JUNK_RE.sub("", source).split("=", 1)[0]  # '=' ends the payload
        cleaned = cleaned.replace("-", "+").replace("_", "/")
        leftover = len(cleaned) % 4
        if leftover == 1:
            cleaned = cleaned[:-1]  # a lone char cannot carry a byte -- drop it
        elif leftover:
            cleaned += "=" * (4 - leftover)
        try:
            raw = base64.b64decode(cleaned)
        except (binascii.Error, ValueError):  # pragma: no cover -- cleaned is valid
            raw = b""
    return raw.decode(encoding, errors) if text else raw


def _strict_decode(source):
    """Decode with no repairs at all -- ValueError on anything unexpected."""
    if len(source) % 4:
        raise ValueError("base64 length is not a multiple of 4 (missing padding?)")
    if _STD_RE.match(source):
        translated = source
    elif _URL_RE.match(source):
        translated = source.replace("-", "+").replace("_", "/")
    else:
        raise ValueError("not strict base64 -- junk, whitespace or mixed alphabets")
    try:
        return base64.b64decode(translated, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64: %s" % exc)


def b64decode_str(data, **kwargs):
    """Same as :func:`b64decode` but always returns a str.

    Example:
        >>> b64decode_str("eyJ1c2VyIjoiYWRtaW4ifQ")
        '{"user":"admin"}'
    """
    kwargs["text"] = True
    return b64decode(data, **kwargs)


def atob(s):
    """Browser ``atob``: base64 in, latin-1 "binary string" out (forgiving).

    Example:
        >>> atob("aGVsbG8=")
        'hello'
    """
    return b64decode(s, text=True, encoding="latin-1", errors="replace")


def btoa(s):
    """Browser ``btoa``: latin-1 "binary string" in, base64 out.

    Raises :class:`ValueError` on a code point above 255, like the browser does.

    Example:
        >>> btoa("hello")
        'aGVsbG8='
        >>> btoa(chr(256))
        Traceback (most recent call last):
            ...
        ValueError: btoa: character out of latin-1 range (code point > 255)
    """
    if isinstance(s, (bytes, bytearray, memoryview)):
        return base64.b64encode(bytes(s)).decode("ascii")
    if not isinstance(s, str):
        s = str(s)
    try:
        raw = s.encode("latin-1")
    except UnicodeEncodeError:
        raise ValueError("btoa: character out of latin-1 range (code point > 255)")
    return base64.b64encode(raw).decode("ascii")


def b64url_encode(data):
    """URL-safe, unpadded base64 -- the flavour used in JWTs and cookies.

    Example:
        >>> b64url_encode('{"alg":"none"}')       # a JWT header
        'eyJhbGciOiJub25lIn0'
    """
    return b64encode(data, urlsafe=True, padding=False)


def b64url_decode(data, **kwargs):
    """Decode URL-safe base64 (padding optional) -- see :func:`b64decode`.

    Example:
        >>> b64url_decode("eyJhbGciOiJub25lIn0", text=True)
        '{"alg":"none"}'
    """
    return b64decode(data, **kwargs)


# --------------------------------------------------------------------------- #
# inspection
# --------------------------------------------------------------------------- #

def is_b64(s, *, urlsafe=None):
    """Cheap "does this look like base64" check.

    ``urlsafe=None`` accepts either alphabet, ``True`` requires ``-_`` only and
    ``False`` requires ``+/`` only. Line wrapping is ignored, other whitespace
    is not.

    Example:
        >>> is_b64("YWRtaW4=")
        True
        >>> is_b64("fn5-Pw", urlsafe=False)     # '-' is not in the '+/' alphabet
        False
        >>> is_b64("hello world")
        False
    """
    text = _WRAP_RE.sub("", _as_text(s).strip())
    if not text or len(text) % 4 == 1:
        return False
    body = text.rstrip("=")
    pad = len(text) - len(body)
    if pad > 2 or (pad and len(text) % 4):
        return False
    if len(body) % 4 == 1:
        return False
    if urlsafe is None:
        return bool(_ALPHA_RE.match(body))
    pattern = _URL_RE if urlsafe else _STD_RE
    return bool(body) and bool(pattern.match(body))


def b64_len(n, *, padding=True):
    """Encoded length, in characters, of *n* raw bytes.

    Example:
        >>> b64_len(10)
        16
        >>> b64_len(10, padding=False)
        14
    """
    if n < 0:
        raise ValueError("b64_len: n must be >= 0")
    if padding:
        return 4 * ((n + 2) // 3)
    return 4 * (n // 3) + (0 if n % 3 == 0 else n % 3 + 1)


def _mostly_printable(raw, ratio=0.9):
    if not raw:
        return False
    good = sum(1 for byte in raw if byte in _PRINTABLE)
    return good >= ratio * len(raw)


def _wrapped_joins(lines):
    """Join each block of lines that looks like one wrapped blob.

    Wrapping means equal-length lines plus a shorter last one, so a run that
    starts with a stray word (``...Encoding: base64\\n<blob>``) still yields the
    blob on its own.
    """
    joins = []
    start = 0
    while start < len(lines):
        width = len(lines[start])
        end = start + 1
        while end < len(lines) and len(lines[end]) == width:
            end += 1
        if end < len(lines) and len(lines[end]) < width:
            end += 1  # the short tail line of a wrapped blob
        if end - start > 1:
            joins.append("".join(lines[start:end]))
        start = end
    return joins


def _run_candidates(run, min_len):
    """Blobs to try for a matched run -- unwrapped first, single lines last.

    A run may span several lines: one MIME-wrapped blob (``wrap=76`` mail bodies,
    PEM-ish dumps, a ``data:`` URI broken by a template) or unrelated blobs
    stacked on top of each other. All of them are cheap to try, so all of them
    are, whole before pieces -- the full flag beats one line of it.
    """
    lines = [line for line in run.splitlines() if line]
    if len(lines) < 2:
        runs = lines
    else:
        runs = ["".join(lines)] + _wrapped_joins(lines) + lines
    out = []
    for item in runs:
        if len(item.rstrip("=")) >= min_len and item not in out:
            out.append(item)
    return out


def b64decode_all(text, *, min_len=8):
    """Find every base64-looking run in *text* and return the clean decodes.

    Only runs that are valid base64 *and* decode to mostly-printable bytes are
    returned, so grepping a whole HTML page does not spew binary noise. Line
    wrapping is undone first (as :func:`is_b64` does), so a MIME-wrapped blob
    decodes whole instead of one truncated piece per line. Results keep their
    order and are de-duplicated.

    Example:
        >>> b64decode_all("user: YWRtaW5pc3RyYXRvcg== flag: c2tuYnt0ZXN0fQ==")
        [b'administrator', b'sknb{test}']
    """
    if min_len < 4:
        min_len = 4
    blob = _as_text(text)
    out = []
    seen = set()
    for match in _RUN_RE.finditer(blob):
        for run in _run_candidates(match.group(0), min_len):
            if not is_b64(run):
                continue
            raw = b64decode(run)
            if len(raw) < 3 or not _mostly_printable(raw):
                continue
            if raw in seen:
                continue
            seen.add(raw)
            out.append(raw)
    return out


# Aliases -- what you actually type at 3am.
b64e = b64encode
b64d = b64decode
