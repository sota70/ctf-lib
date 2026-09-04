"""ctflib -- a small toolbox for CTF web challenges. No external dependencies.

    from ctflib import post, find_flg, route, listen, reverse_shell

    r = post("http://target/login", data={"user": "admin", "pw": "' OR 1--"})
    print(find_flg(r.text, "sknb{*}"))

Contents
    HTTP client   request / get / post / ... , Session, data= json= form= proxy=
    Flags         find_flg, find_flgs (wildcard formats such as ``sknb{*}``)
    Web server    App, @route("/path") annotation, listen(port)  -- express style
    Reverse shell reverse_shell(port)
    HTML / DOM    parse_html, r.dom(), query_selector, Document / Element / Form
    Base64        b64e / b64d, b64decode_str, atob / btoa, b64url_*, b64decode_all
    URL encoding  encode_uri_component / encodeURI, urlencode, qs_parse, add_params
"""

from .b64 import (
    atob,
    b64_len,
    b64d,
    b64decode,
    b64decode_all,
    b64decode_str,
    b64e,
    b64encode,
    b64url_decode,
    b64url_encode,
    btoa,
    is_b64,
)
from .client import (
    DEFAULT_TIMEOUT,
    DEFAULT_USER_AGENT,
    Headers,
    Response,
    Session,
    default_session,
    delete,
    encode_multipart,
    get,
    head,
    options,
    patch,
    post,
    put,
    request,
    session,
)
from .dom import (
    COMMENT_NODE,
    DOCUMENT_NODE,
    ELEMENT_NODE,
    TEXT_NODE,
    Comment,
    Document,
    Element,
    Form,
    Node,
    Text,
    parse_html,
)
from .dom import parse as parse_dom
from .flag import (
    find_flag,
    find_flags,
    find_flg,
    find_flgs,
    format_to_regex,
    get_flag_format,
    set_flag_format,
)
from .server import App
from .server import Request as ServerRequest
from .server import Response as ServerResponse
from .server import app, hits, listen, route, wait_hit
from .shell import UPGRADE_PAYLOADS, reverse_shell, revshell
from .urlcodec import (
    add_params,
    decodeURI,
    decodeURIComponent,
    decode_uri,
    decode_uri_component,
    double_encode,
    encodeURI,
    encodeURIComponent,
    encode_uri,
    encode_uri_component,
    form_decode,
    form_encode,
    parse_qs,
    parse_qsl,
    qs_parse,
    qs_stringify,
    url_join,
    url_parse,
    urldecode,
    urlencode,
)
from .urlcodec import decode_all as url_decode_all

__version__ = "1.0.0"

__all__ = [
    # http client
    "request", "get", "post", "put", "patch", "delete", "head", "options",
    "Session", "session", "default_session", "Response", "Headers",
    "encode_multipart", "DEFAULT_TIMEOUT", "DEFAULT_USER_AGENT",
    # flags
    "find_flg", "find_flgs", "find_flag", "find_flags",
    "set_flag_format", "get_flag_format", "format_to_regex",
    # web server
    "App", "route", "listen", "app", "hits", "wait_hit",
    "ServerRequest", "ServerResponse",
    # reverse shell
    "reverse_shell", "revshell", "UPGRADE_PAYLOADS",
    # html / dom
    "parse_html", "parse_dom", "Document", "Element", "Form",
    "Node", "Text", "Comment",
    "ELEMENT_NODE", "TEXT_NODE", "COMMENT_NODE", "DOCUMENT_NODE",
    # base64
    "b64e", "b64d", "b64encode", "b64decode", "b64decode_str", "b64decode_all",
    "b64url_encode", "b64url_decode", "atob", "btoa", "is_b64", "b64_len",
    # url encoding
    "encode_uri_component", "decode_uri_component", "encode_uri", "decode_uri",
    "encodeURIComponent", "decodeURIComponent", "encodeURI", "decodeURI",
    "urlencode", "urldecode", "parse_qs", "parse_qsl", "qs_stringify", "qs_parse",
    "form_encode", "form_decode", "double_encode", "url_decode_all",
    "url_join", "url_parse", "add_params",
    "__version__",
]
