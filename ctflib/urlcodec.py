"""URL encoding with JavaScript semantics, plus a querystring toolbox.

    encode_uri_component("a b&c")   # -> 'a%20b%26c'   (urllib.quote would keep the &)
    encode_uri("a b&c")             # -> 'a%20b&c'     -- reserved chars survive
    decode_uri("%2F%20")            # -> '%2F '        -- reserved escapes stay escaped
    urlencode({"q": "1 2"})         # -> 'q=1+2'
    add_params("/x?a=1", {"b": 2})  # -> '/x?a=1&b=2'

The four JS globals are here under both spellings, so a payload copied out of a
browser console can be pasted straight in: ``encodeURIComponent`` is
:func:`encode_uri_component`, and so on. Hex is UPPERCASE like every JS engine.

Every function takes str, bytes, or a Response (its ``.text``). Broken escapes
(``"%zz"``, ``"%4"``, a trailing ``"%"``) are left as literal text -- JS throws
URIError, which helps nobody mid-challenge -- pass ``strict=True`` to raise
:class:`ValueError` instead. Undecodable UTF-8 becomes U+FFFD by default.
"""

from __future__ import annotations

import string
import urllib.parse

__all__ = [
    "encode_uri_component",
    "decode_uri_component",
    "encode_uri",
    "decode_uri",
    "encodeURIComponent",
    "decodeURIComponent",
    "encodeURI",
    "decodeURI",
    "urlencode",
    "urldecode",
    "parse_qs",
    "parse_qsl",
    "stringify",
    "parse",
    "qs_stringify",
    "qs_parse",
    "form_encode",
    "form_decode",
    "double_encode",
    "decode_all",
    "url_join",
    "url_parse",
    "add_params",
]

#: encodeURIComponent leaves exactly these alone.
_COMPONENT_SAFE = string.ascii_letters + string.digits + "-_.!~*'()"

#: encodeURI additionally leaves the reserved set alone.
_RESERVED = ";/?:@&=+$,#"
_URI_SAFE = _COMPONENT_SAFE + _RESERVED

#: decodeURI refuses to decode an escape that would produce a reserved char --
#: %23 %24 %26 %2B %2C %2F %3A %3B %3D %3F %40 come back out untouched.
_KEEP_ESCAPED = frozenset(_RESERVED.encode("ascii"))

_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")

_COMPONENT_TABLE = tuple(
    chr(b) if chr(b) in _COMPONENT_SAFE else "%%%02X" % b for b in range(256)
)
_URI_TABLE = tuple(
    chr(b) if chr(b) in _URI_SAFE else "%%%02X" % b for b in range(256)
)


# --------------------------------------------------------------------------- #
# input coercion
# --------------------------------------------------------------------------- #

def _as_bytes(value):
    """Raw bytes of str / bytes / a Response (``.text``).

    A str goes through UTF-8; bytes are taken byte for byte, so a hand-built
    payload is never silently re-encoded. Lone surrogates survive instead of
    blowing up.
    """
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8", "surrogatepass")
    text = getattr(value, "text", None)  # Response-like
    if isinstance(text, str):
        return text.encode("utf-8", "surrogatepass")
    return str(value).encode("utf-8", "surrogatepass")


def _as_text(value):
    """str / bytes / Response -> str (never raises)."""
    if isinstance(value, str):
        return value
    return _as_bytes(value).decode("utf-8", "replace")


# --------------------------------------------------------------------------- #
# the four JS globals
# --------------------------------------------------------------------------- #

def _encode(value, table):
    data = _as_bytes(value)
    return "".join([table[b] for b in data])


def _decode(value, keep, strict, errors):
    """Percent-decode *value*, leaving escapes for bytes in *keep* as written."""
    data = _as_bytes(value)
    out = bytearray()
    i = 0
    size = len(data)
    while i < size:
        if data[i] == 0x25:  # '%'
            digits = data[i + 1:i + 3]
            if len(digits) == 2 and digits[0] in _HEX_DIGITS and digits[1] in _HEX_DIGITS:
                byte = int(digits.decode("ascii"), 16)
                if byte in keep:
                    out += data[i:i + 3]  # keep the original spelling, case and all
                else:
                    out.append(byte)
                i += 3
                continue
            if strict:
                raise ValueError("malformed percent escape at offset %d: %r" % (i, data[i:i + 3]))
        out.append(data[i])
        i += 1
    try:
        return bytes(out).decode("utf-8", "strict" if strict else errors)
    except UnicodeDecodeError as exc:
        raise ValueError("undecodable UTF-8 in percent escapes: %s" % exc)


def encode_uri_component(s):
    """JS ``encodeURIComponent`` -- escape everything but ``A-Za-z0-9-_.!~*'()``.

    This is the one you want for a value going into a query string or a cookie.

    Example:
        >>> encode_uri_component("a b&c=d/e")
        'a%20b%26c%3Dd%2Fe'
    """
    return _encode(s, _COMPONENT_TABLE)


def encode_uri(s):
    """JS ``encodeURI`` -- like :func:`encode_uri_component` but ``;/?:@&=+$,#`` survive.

    For escaping a whole URL whose structure you want to keep.

    Example:
        >>> encode_uri("http://x/a b?q=1&r=2")
        'http://x/a%20b?q=1&r=2'
    """
    return _encode(s, _URI_TABLE)


def decode_uri_component(s, *, strict=False, errors="replace"):
    """JS ``decodeURIComponent`` -- decode every percent escape.

    Example:
        >>> decode_uri_component("a%20b%2Fc")
        'a b/c'
        >>> decode_uri_component("100%25 %zz")      # a broken escape stays put
        '100% %zz'
    """
    return _decode(s, frozenset(), strict, errors)


def decode_uri(s, *, strict=False, errors="replace"):
    """JS ``decodeURI`` -- decode everything except the reserved escapes.

    ``%23 %24 %26 %2B %2C %2F %3A %3B %3D %3F %40`` stay escaped, so decoding a
    URL cannot invent a new path segment or parameter.

    Example:
        >>> decode_uri("/a%20b%2Fc")
        '/a b%2Fc'
        >>> decode_uri_component("/a%20b%2Fc")
        '/a b/c'
    """
    return _decode(s, _KEEP_ESCAPED, strict, errors)


# JS spellings -- paste from the browser console without renaming anything.
encodeURIComponent = encode_uri_component
decodeURIComponent = decode_uri_component
encodeURI = encode_uri
decodeURI = decode_uri


# --------------------------------------------------------------------------- #
# querystrings
# --------------------------------------------------------------------------- #

def _items(data):
    """Iterate ``(key, value)`` over a dict or a sequence of pairs."""
    if data is None:
        return []
    if hasattr(data, "items"):
        return list(data.items())
    return list(data)


def _strip_q(s):
    """Drop a leading ``?`` (or ``#``) so a pasted URL tail just works."""
    text = _as_text(s)
    return text[1:] if text[:1] in ("?", "#") else text


def urlencode(data, *, doseq=True, safe="", plus=True):
    """Build an ``application/x-www-form-urlencoded`` string.

    Takes a dict or a sequence of pairs; a str/bytes body is passed through
    untouched so hand-crafted payloads survive -- bytes come back as bytes,
    byte for byte, because a padding-oracle blob is not UTF-8 and must not be
    "repaired". ``plus=True`` (the default, form style) encodes a space as
    ``+``, ``plus=False`` as ``%20``. List values repeat the key while
    ``doseq`` is on.

    Example:
        >>> urlencode({"a": 1, "b": ["x", "y z"]})
        'a=1&b=x&b=y+z'
        >>> urlencode(b"sig=\\xde\\xad")            # bytes pass through untouched
        b'sig=\\xde\\xad'
    """
    if isinstance(data, str):
        return data
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    quote_via = urllib.parse.quote_plus if plus else urllib.parse.quote
    return urllib.parse.urlencode(_items(data), doseq=doseq, safe=safe, quote_via=quote_via)


def parse_qsl(s, *, sep="&", eq="=", plus=True, strip_q=True):
    """Query string -> ``[(key, value), ...]``, in order, blanks kept.

    A leading ``?`` is ignored, ``+`` means space unless ``plus=False``, and a
    key with no ``=`` yields an empty value. Pass ``strip_q=False`` when *s* is
    an already-split ``.query`` -- a URL with ``??`` really does start its first
    name with a ``?``.

    Example:
        >>> parse_qsl("?a=1")                   # pasted tail
        [('a', '1')]
        >>> parse_qsl("?a=1", strip_q=False)    # already-split query
        [('?a', '1')]
    """
    text = _strip_q(s) if strip_q else _as_text(s)
    out = []
    for chunk in text.split(sep):
        if not chunk:
            continue
        key, found, value = chunk.partition(eq)
        out.append((_qs_decode(key, plus), _qs_decode(value, plus) if found else ""))
    return out


def _qs_decode(part, plus):
    return decode_uri_component(part.replace("+", " ") if plus else part)


def parse_qs(s, *, sep="&", eq="=", plus=True, strip_q=True):
    """Query string -> ``{key: [value, ...]}`` keeping every repeat.

    ``strip_q`` is :func:`parse_qsl`'s.

    Example:
        >>> parse_qs("a=1&a=2&b=")
        {'a': ['1', '2'], 'b': ['']}
    """
    out = {}
    for key, value in parse_qsl(s, sep=sep, eq=eq, plus=plus, strip_q=strip_q):
        out.setdefault(key, []).append(value)
    return out


def urldecode(s, *, sep="&", eq="=", plus=True, strip_q=True):
    """Query string -> a flat ``{key: value}`` dict, last repeat wins.

    Example:
        >>> urldecode("a=1&a=2&b=")
        {'a': '2', 'b': ''}
    """
    return dict(parse_qsl(s, sep=sep, eq=eq, plus=plus, strip_q=strip_q))


def _stringify_value(value):
    if value is None:
        return ""
    if value is True:
        return "true"
    if value is False:
        return "false"
    return value if isinstance(value, (str, bytes, bytearray, memoryview)) else str(value)


def stringify(obj, sep="&", eq="="):
    """Node's ``querystring.stringify`` -- component-escaped, so a space is ``%20``.

    ``None`` becomes an empty value, booleans become ``true``/``false``, and a
    list repeats its key. Use :func:`urlencode` instead when you want the ``+``
    form encoding.

    Example:
        >>> stringify({"a": "1 2", "b": [1, 2], "c": None})
        'a=1%202&b=1&b=2&c='
    """
    parts = []
    for key, value in _items(obj):
        name = encode_uri_component(_stringify_value(key))
        values = value if isinstance(value, (list, tuple)) else [value]
        for item in values:
            parts.append(name + eq + encode_uri_component(_stringify_value(item)))
    return sep.join(parts)


def parse(s, sep="&", eq="=", *, strip_q=True):
    """Node's ``querystring.parse`` -- repeated keys collapse into a list.

    Unlike Node a leading ``?`` is ignored -- ``strip_q=False`` for Node's own
    behaviour. Prefer :func:`parse_qs` when you want every value to be a list
    regardless.

    Example:
        >>> parse("a=1&b=2&b=3")
        {'a': '1', 'b': ['2', '3']}
    """
    out = {}
    for key, values in parse_qs(s, sep=sep, eq=eq, strip_q=strip_q).items():
        out[key] = values[0] if len(values) == 1 else values
    return out


qs_stringify = stringify
qs_parse = parse


def form_encode(s, *, plus=False):
    """Node's ``querystring.escape`` (renamed, so it does not shadow the builtin).

    Same safe set as :func:`encode_uri_component`, so a space is ``%20``; pass
    ``plus=True`` for the HTML-form flavour where a space is ``+``.

    Example:
        >>> form_encode("a b")
        'a%20b'
        >>> form_encode("a b", plus=True)
        'a+b'
    """
    out = encode_uri_component(s)
    return out.replace("%20", "+") if plus else out


def form_decode(s, *, plus=False, strict=False, errors="replace"):
    """Node's ``querystring.unescape`` (renamed, see :func:`form_encode`).

    ``plus=True`` also turns ``+`` back into a space, like a form body.

    Example:
        >>> form_decode("a%20b")
        'a b'
        >>> form_decode("a+b", plus=True)
        'a b'
    """
    if plus:
        s = _as_text(s).replace("+", " ")
    return decode_uri_component(s, strict=strict, errors=errors)


# --------------------------------------------------------------------------- #
# CTF conveniences
# --------------------------------------------------------------------------- #

def double_encode(s):
    """:func:`encode_uri_component` applied twice -- the classic filter bypass.

    Example:
        >>> double_encode("../")
        '..%252F'
    """
    return encode_uri_component(encode_uri_component(s))


def decode_all(s, *, max_rounds=5):
    """Percent-decode until the string stops changing (or *max_rounds* is hit).

    Example:
        >>> decode_all("%25252e%25252e%25252f")
        '../'
    """
    text = _as_text(s)
    for _ in range(max(0, max_rounds)):
        nxt = decode_uri_component(text)
        if nxt == text:
            break
        text = nxt
    return text


def url_join(base, url):
    """Resolve *url* against *base*, exactly like a browser follows a link.

    Example:
        >>> url_join("http://x/a/b", "../c?d=1")
        'http://x/c?d=1'
    """
    return urllib.parse.urljoin(_as_text(base), _as_text(url))


def url_parse(url):
    """Split a URL into a named tuple: ``scheme netloc path query fragment``.

    This is :func:`urllib.parse.urlsplit`, so ``.hostname``, ``.port``,
    ``.username`` and ``.password`` are there too, and ``._replace(...)`` plus
    ``.geturl()`` put it back together. ``.query`` has had its ``?`` removed
    already, so pass ``strip_q=False`` to :func:`parse_qs` if the URL might
    contain ``??``.

    Example:
        >>> url_parse("http://a:b@x:8080/p?q=1#f").hostname
        'x'
        >>> parse_qs(url_parse("/p?q=1").query)
        {'q': ['1']}
    """
    return urllib.parse.urlsplit(_as_text(url))


def add_params(url, params):
    """Merge *params* into the query of *url*, keeping what is already there.

    Example:
        >>> add_params("/x?a=1", {"b": "2 3"})
        '/x?a=1&b=2+3'

    Existing parameters are preserved even when a new one repeats the name, so
    this can also be used to smuggle a duplicate key. The query is already
    split, so a first name starting with ``?`` (a URL with ``??``) is kept and
    re-emitted as ``%3F``, the way the browser's URLSearchParams does it.
    """
    if not params:
        return _as_text(url)
    parts = urllib.parse.urlsplit(_as_text(url))
    query = parse_qsl(parts.query, strip_q=False)
    query += [(key, value) for key, value in _items(params)]
    return urllib.parse.urlunsplit(parts._replace(query=urlencode(query)))
