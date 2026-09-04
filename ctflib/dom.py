"""HTML parsing with a browser-like DOM API (standard library only).

    doc = parse_html(get("http://target/login"))       # str, bytes or a Response
    doc.form().fields                                  # -> {'csrf': 'a1b2', 'user': '', 'pw': ''}
    doc.query_selector('input[name="csrf"]')["value"]  # -> 'a1b2'
    [a["href"] for a in doc.find_all("a.admin, a[href^=/adm]")]
    doc.comments                                       # the dev left the flag in one, again

Tolerant of real-world markup -- unclosed <p>/<li>/<tr>, stray end tags, uppercase
tags, unquoted attributes and void elements without a slash all parse without raising.
"""

from __future__ import annotations

import html as _html
import re
import urllib.parse
from functools import lru_cache
from html.parser import HTMLParser

__all__ = [
    "parse_html",
    "parse",
    "Node",
    "Text",
    "Comment",
    "Element",
    "Document",
    "Form",
    "ELEMENT_NODE",
    "TEXT_NODE",
    "COMMENT_NODE",
    "DOCUMENT_NODE",
]

ELEMENT_NODE = 1
TEXT_NODE = 3
COMMENT_NODE = 8
DOCUMENT_NODE = 9

#: never nest -- an end tag for one of these is meaningless
VOID_ELEMENTS = frozenset(
    "area base br col embed hr img input link meta param source track wbr".split()
)

#: content is raw text, not markup (html.parser puts these in CDATA mode for us)
RAW_TEXT_ELEMENTS = frozenset({"script", "style"})

#: fields collected by :attr:`Form.fields`
_FIELD_TAGS = frozenset({"input", "textarea", "select", "button"})

#: attributes whose *values* selectors match case-insensitively in an HTML document
#: -- so [type=hidden] finds <INPUT TYPE="Hidden">, like a browser does
_CI_ATTRS = frozenset("""
    accept accept-charset align alink axis bgcolor charset checked clear codetype color
    compact declare defer dir direction disabled enctype face frame hreflang http-equiv
    lang language link media method multiple nohref noresize noshade nowrap readonly rel
    rev rules scope scrolling selected shape target text type valign valuetype vlink
""".split())

# a start tag on the left auto-closes an open element on the right
_P_CLOSERS = frozenset("""
    address article aside blockquote details dialog div dl fieldset figcaption figure
    footer form h1 h2 h3 h4 h5 h6 header hgroup hr li main nav ol p pre section table ul
""".split())

_CLOSED_BY = {
    "p": _P_CLOSERS,
    "li": frozenset({"li"}),
    "dt": frozenset({"dt", "dd"}),
    "dd": frozenset({"dt", "dd"}),
    "option": frozenset({"option", "optgroup"}),
    "optgroup": frozenset({"optgroup"}),
    "tr": frozenset({"tr", "thead", "tbody", "tfoot"}),
    "td": frozenset({"td", "th", "tr", "thead", "tbody", "tfoot"}),
    "th": frozenset({"td", "th", "tr", "thead", "tbody", "tfoot"}),
    "thead": frozenset({"thead", "tbody", "tfoot"}),
    "tbody": frozenset({"thead", "tbody", "tfoot"}),
    "tfoot": frozenset({"thead", "tbody", "tfoot"}),
    "head": frozenset({"body"}),
}


def _as_text(source):
    """Accept str, bytes or a Response-like object (anything with ``.text``)."""
    if source is None:
        return ""
    if isinstance(source, str):
        return source
    if isinstance(source, (bytes, bytearray)):
        return bytes(source).decode("utf-8", "replace")
    text = getattr(source, "text", None)  # Response-like
    if isinstance(text, str):
        return text
    return str(source)


# --------------------------------------------------------------------------- #
# nodes
# --------------------------------------------------------------------------- #

class Node:
    """Base class for everything in the tree.

    Example:
        >>> doc = parse_html("<p>a<b>c</b></p>")
        >>> p = doc.query_selector("p")
        >>> p.child_nodes                       # text and comments included
        [<Text 'a'>, <Element b children=0>]
        >>> p.children                          # elements only
        [<Element b children=0>]
        >>> p.children[0].parent_element.tag_name
        'p'
    """

    node_type = None

    def __init__(self):
        self.parent = None
        self.child_nodes = []       # every child, text and comments included
        self._index = None          # cached position in parent.child_nodes
        self._element_cache = None  # cached element-child positions (parents only)

    @property
    def children(self):
        """Element children only (what a browser calls ``children``)."""
        return [n for n in self.child_nodes if isinstance(n, Element)]

    @property
    def parent_element(self):
        return self.parent if isinstance(self.parent, Element) else None

    @property
    def next_sibling(self):
        return _sibling(self, 1)

    @property
    def previous_sibling(self):
        return _sibling(self, -1)

    @property
    def next_element_sibling(self):
        return _element_sibling(self, 1)

    @property
    def previous_element_sibling(self):
        return _element_sibling(self, -1)


def _child_index(node):
    """Position of *node* in ``node.parent.child_nodes`` -- ``-1`` when detached.

    Cached: a whole row of siblings is stamped in one pass, so walking n siblings
    costs O(n) instead of O(n^2). The cache is checked by identity, so a tree that
    is edited afterwards just falls back to another scan.
    """
    parent = node.parent
    if parent is None:
        return -1
    siblings = parent.child_nodes
    index = node._index
    if index is None or index >= len(siblings) or siblings[index] is not node:
        for i, sibling in enumerate(siblings):      # stamp the whole row at once
            sibling._index = i
        index = node._index
        if index is None or index >= len(siblings) or siblings[index] is not node:
            return -1
    return index


def _sibling(node, step):
    parent = node.parent
    if parent is None:
        return None
    index = _child_index(node)
    if index < 0:
        return None
    siblings = parent.child_nodes
    index += step
    if 0 <= index < len(siblings):
        return siblings[index]
    return None


def _element_sibling(node, step):
    parent = node.parent
    if parent is None:
        return None
    index = _child_index(node)
    if index < 0:
        return None
    siblings = parent.child_nodes
    index += step
    while 0 <= index < len(siblings):
        if isinstance(siblings[index], Element):
            return siblings[index]
        index += step
    return None


class Text(Node):
    """A run of character data.

    Example:
        >>> doc = parse_html("<p>1 &lt; 2</p>")
        >>> node = doc.query_selector("p").child_nodes[0]
        >>> node.text
        '1 < 2'
        >>> node.outer_html                     # re-escaped on the way out
        '1 &lt; 2'
    """

    node_type = TEXT_NODE

    def __init__(self, data=""):
        Node.__init__(self)
        self.data = data

    @property
    def text(self):
        return self.data

    text_content = text
    textContent = text

    @property
    def outer_html(self):
        parent_tag = getattr(self.parent, "tag", None)
        if parent_tag in RAW_TEXT_ELEMENTS:
            return self.data          # script/style bodies are not escaped
        return _html.escape(self.data, quote=False)

    outerHTML = outer_html

    def __str__(self):
        return self.data

    def __repr__(self):
        preview = self.data if len(self.data) <= 40 else self.data[:37] + "..."
        return f"<Text {preview!r}>"


class Comment(Node):
    """An ``<!-- ... -->`` node -- CTF flags live here more often than anywhere else.

    Example:
        >>> doc = parse_html("<div><!-- sknb{in_comment} --></div>")
        >>> node = doc.query_selector("div").child_nodes[0]
        >>> node.text
        ' sknb{in_comment} '
        >>> node.outer_html
        '<!-- sknb{in_comment} -->'
    """

    node_type = COMMENT_NODE

    def __init__(self, data=""):
        Node.__init__(self)
        self.data = data

    @property
    def text(self):
        return self.data

    text_content = text
    textContent = text

    @property
    def outer_html(self):
        return f"<!--{self.data}-->"

    outerHTML = outer_html

    def __str__(self):
        return self.data

    def __repr__(self):
        preview = self.data.strip()
        if len(preview) > 40:
            preview = preview[:37] + "..."
        return f"<Comment {preview!r}>"


class Element(Node):
    """An HTML element: tag name, attributes and children.

    Example:
        >>> doc = parse_html('<a class="admin" href="/adm">panel</a>')
        >>> a = doc.query_selector("a.admin")
        >>> a.get_attribute("href"), a.text
        ('/adm', 'panel')
        >>> a["href"] = "/x"                    # __setitem__ writes an attribute
        >>> a.outer_html
        '<a class="admin" href="/x">panel</a>'
    """

    node_type = ELEMENT_NODE

    def __init__(self, tag, attrs=None):
        Node.__init__(self)
        self.tag = tag.lower()
        self.attrs = _norm_attrs(attrs)

    # -- names ------------------------------------------------------------- #
    @property
    def tag_name(self):
        return self.tag

    tagName = tag_name

    # -- attributes -------------------------------------------------------- #
    def get_attribute(self, name, default=None):
        """Attribute value (names are case-insensitive), *default* when absent."""
        return self.attrs.get(str(name).lower(), default)

    def set_attribute(self, name, value):
        self.attrs[str(name).lower()] = "" if value is None else str(value)
        return self

    def has_attribute(self, name):
        return str(name).lower() in self.attrs

    getAttribute = get_attribute
    setAttribute = set_attribute
    hasAttribute = has_attribute

    @property
    def id(self):
        return self.attrs.get("id", "")

    @property
    def class_name(self):
        return self.attrs.get("class", "")

    @property
    def class_list(self):
        return self.class_name.split()

    className = class_name
    classList = class_list

    # -- text -------------------------------------------------------------- #
    @property
    def text(self):
        """Visible text: every descendant text node, concatenated.

        Comments are skipped, and so are nested <script>/<style> bodies -- what
        you want when scraping. ``doc.scripts[0].text`` still returns the source,
        because only *descendant* raw-text elements are skipped.
        """
        return _collect_text(self, skip=RAW_TEXT_ELEMENTS)

    text_content = text
    textContent = text

    @property
    def inner_html(self):
        return _serialize(self.child_nodes)

    @property
    def outer_html(self):
        return _serialize([self])

    innerHTML = inner_html
    outerHTML = outer_html

    # -- traversal --------------------------------------------------------- #
    @property
    def first_child_element(self):
        children = self.children
        return children[0] if children else None

    @property
    def last_child_element(self):
        children = self.children
        return children[-1] if children else None

    firstElementChild = first_child_element
    lastElementChild = last_child_element

    @property
    def descendants(self):
        """Every descendant element, in document order."""
        return list(_iter_elements(self))

    def iter_nodes(self):
        """Every descendant node (text and comments included), in document order."""
        return _iter_nodes(self)

    # -- queries ----------------------------------------------------------- #
    def query_selector(self, selector):
        """First descendant matching the CSS *selector*, or ``None``."""
        groups = _compile(selector)
        for element in _iter_elements(self):
            if _matches_any(element, groups):
                return element
        return None

    def query_selector_all(self, selector):
        """Every descendant matching the CSS *selector*, in document order."""
        groups = _compile(selector)
        return [el for el in _iter_elements(self) if _matches_any(el, groups)]

    querySelector = query_selector
    querySelectorAll = query_selector_all
    find = query_selector
    find_all = query_selector_all

    def matches(self, selector):
        """True when this element itself matches *selector*."""
        return _matches_any(self, _compile(selector))

    def closest(self, selector):
        """This element or the nearest ancestor matching *selector*."""
        groups = _compile(selector)
        node = self
        while isinstance(node, Element):
            if _matches_any(node, groups):
                return node
            node = node.parent
        return None

    def get_element_by_id(self, value):
        value = str(value)
        for element in _iter_elements(self):
            if element.attrs.get("id") == value:
                return element
        return None

    def get_elements_by_tag_name(self, name):
        name = str(name).lower()
        if name == "*":
            return list(_iter_elements(self))
        return [el for el in _iter_elements(self) if el.tag == name]

    def get_elements_by_class_name(self, names):
        wanted = str(names).split()
        return [el for el in _iter_elements(self)
                if all(name in el.class_list for name in wanted)]

    def get_elements_by_name(self, value):
        """Elements with ``name="value"`` -- the way to grab one form field."""
        value = str(value)
        return [el for el in _iter_elements(self) if el.attrs.get("name") == value]

    getElementById = get_element_by_id
    getElementsByTagName = get_elements_by_tag_name
    getElementsByClassName = get_elements_by_class_name
    getElementsByName = get_elements_by_name

    # -- dunders ----------------------------------------------------------- #
    def __getitem__(self, key):
        """``el["href"]`` -> attribute (``None`` when absent), ``el[0]`` -> child element."""
        if isinstance(key, int):
            return self.children[key]
        return self.attrs.get(str(key).lower())

    def __setitem__(self, key, value):
        self.set_attribute(key, value)

    def __contains__(self, item):
        """``"href" in el`` -> attribute present, ``other in el`` -> node is a descendant."""
        if isinstance(item, Node):
            node = item.parent
            while node is not None:
                if node is self:
                    return True
                node = node.parent
            return False
        return str(item).lower() in self.attrs

    def __iter__(self):
        return iter(self.children)

    def __len__(self):
        return len(self.children)

    def __bool__(self):
        """Always true -- an element you are holding was found, like in a browser.

        Without this, ``__len__`` would make every leaf element (``<input>``,
        ``<img>``, ``<a>text</a>``) falsy and break ``if doc.find("input"):``.
        """
        return True

    def __repr__(self):
        label = self.tag
        if self.id:
            label += "#" + self.id
        for name in self.class_list[:2]:
            label += "." + name
        return f"<Element {label} children={len(self.children)}>"


def _norm_attrs(attrs):
    """``[("HREF", "/x"), ("checked", None)]`` -> ``{"href": "/x", "checked": ""}``."""
    out = {}
    for name, value in (attrs or ()):
        key = str(name).lower()
        if key not in out:                 # duplicate attributes: the first one wins
            out[key] = "" if value is None else value
    return out


def _iter_nodes(node):
    """Depth-first, document order, every node type, *node* itself excluded."""
    stack = list(reversed(node.child_nodes))
    while stack:
        current = stack.pop()
        yield current
        if current.child_nodes:
            stack.extend(reversed(current.child_nodes))


def _iter_elements(node):
    for current in _iter_nodes(node):
        if isinstance(current, Element):
            yield current


def _open_tag(element):
    parts = ["<", element.tag]
    for name, value in element.attrs.items():
        parts.append(f' {name}="{_html.escape(str(value), True)}"')
    parts.append("/>" if element.tag in VOID_ELEMENTS else ">")
    return "".join(parts)


def _serialize(nodes):
    """Markup for *nodes* and their subtrees -- iterative, so nesting has no limit."""
    out = []
    stack = list(reversed(nodes))
    while stack:
        current = stack.pop()
        if isinstance(current, str):            # a pending end tag
            out.append(current)
        elif isinstance(current, Element):
            out.append(_open_tag(current))
            if current.tag not in VOID_ELEMENTS:
                stack.append(f"</{current.tag}>")
                stack.extend(reversed(current.child_nodes))
        else:
            out.append(current.outer_html)      # text and comments are leaves
    return "".join(out)


def _collect_text(node, skip=()):
    out = []
    stack = list(reversed(node.child_nodes))
    while stack:
        current = stack.pop()
        if isinstance(current, Text):
            out.append(current.data)
        elif isinstance(current, Element) and current.tag not in skip:
            stack.extend(reversed(current.child_nodes))
    return "".join(out)


# --------------------------------------------------------------------------- #
# forms
# --------------------------------------------------------------------------- #

class Form:
    """A ``<form>``, with its current field values ready to POST back.

    Example:
        >>> doc = parse_html('<form action="/login" method="post">'
        ...                  '<input name="user" value="admin">'
        ...                  '<input type="hidden" name="csrf" value="a1b2"></form>')
        >>> form = doc.form()
        >>> form.action, form.method
        ('/login', 'POST')
        >>> form.data                           # hidden fields kept
        {'user': 'admin', 'csrf': 'a1b2'}
        >>> form.fill(user="' OR 1--")          # a copy; the form is untouched
        {'user': "' OR 1--", 'csrf': 'a1b2'}
    """

    def __init__(self, element):
        self.element = element

    @property
    def action(self):
        return self.element.attrs.get("action", "")

    @property
    def method(self):
        return (self.element.attrs.get("method") or "GET").strip().upper() or "GET"

    @property
    def enctype(self):
        return self.element.attrs.get("enctype", "application/x-www-form-urlencoded")

    @property
    def name(self):
        return self.element.attrs.get("name", "")

    @property
    def id(self):
        return self.element.attrs.get("id", "")

    @property
    def inputs(self):
        """Every input/textarea/select/button element, named or not."""
        return [el for el in _iter_elements(self.element) if el.tag in _FIELD_TAGS]

    @property
    def fields(self):
        """``name -> current value`` for everything the browser would submit.

        Hidden inputs are included (that is the CSRF-token case). Unchecked
        checkboxes and radios are dropped, a ``<select>`` reports its selected
        option -- or its first one -- and buttons only count when they are named.
        Disabled controls are dropped too, including everything inside a
        ``<fieldset disabled>`` -- a browser never sends those.
        """
        out = {}
        for el in self.inputs:
            name = el.attrs.get("name")
            if not name or _is_disabled(el):
                continue
            kind = (el.attrs.get("type") or "").strip().lower()
            if el.tag == "input":
                if kind in ("checkbox", "radio"):
                    if "checked" not in el.attrs:
                        continue
                    out[name] = el.attrs.get("value", "on")
                elif kind == "reset":
                    continue                       # never submitted
                else:
                    out[name] = el.attrs.get("value", "")
            elif el.tag == "button":
                if kind in ("button", "reset"):
                    continue
                out[name] = el.attrs.get("value", "")
            elif el.tag == "textarea":
                value = el.text
                out[name] = value[1:] if value.startswith("\n") else value
            elif el.tag == "select":
                out[name] = _select_value(el)
        return out

    @property
    def data(self):
        """Alias for :attr:`fields` -- the name ``request(data=...)`` wants."""
        return self.fields

    def fill(self, values=None, **kwargs):
        """Return :attr:`fields` merged with *values* / keyword overrides."""
        out = self.fields
        if values:
            out.update(values)
        out.update(kwargs)
        return out

    def url(self, base=None):
        """The action resolved against *base* -- an empty action means *base*."""
        action = self.action
        if not action:
            return base or ""
        if base:
            return urllib.parse.urljoin(base, action)
        return action

    def __getitem__(self, name):
        return self.fields[name]

    def __contains__(self, name):
        return name in self.fields

    def __repr__(self):
        return f"<Form {self.method} {self.action!r} fields={list(self.fields)}>"


def _is_disabled(element):
    """True when a control is disabled -- directly, or by an ancestor ``<fieldset>``.

    A disabled ``<fieldset>`` disables every descendant control except the ones in
    its first ``<legend>``, exactly like the HTML standard says.
    """
    if "disabled" in element.attrs:
        return True
    child, node = element, element.parent
    while isinstance(node, Element):
        if node.tag == "fieldset" and "disabled" in node.attrs:
            legend = next((c for c in node.children if c.tag == "legend"), None)
            if child is not legend:
                return True
        child, node = node, node.parent
    return False


def _select_value(select):
    """Value of the selected ``<option>``, falling back to the first one."""
    options = [el for el in _iter_elements(select) if el.tag == "option"]
    if not options:
        return ""
    chosen = next((o for o in options if "selected" in o.attrs), options[0])
    if "value" in chosen.attrs:
        return chosen.attrs["value"]
    return chosen.text.strip()


# --------------------------------------------------------------------------- #
# document
# --------------------------------------------------------------------------- #

class Document(Element):
    """The root of a parsed page -- an :class:`Element` with page-level shortcuts.

    Example:
        >>> doc = parse_html("<html><head><title>Login</title></head>"
        ...                  "<body><!-- sknb{x} --><a href='/adm'>panel</a></body></html>")
        >>> doc.title
        'Login'
        >>> doc.links
        ['/adm']
        >>> doc.comments
        ['sknb{x}']
    """

    node_type = DOCUMENT_NODE

    def __init__(self):
        Element.__init__(self, "#document")

    @property
    def outer_html(self):
        return self.inner_html

    outerHTML = outer_html

    @property
    def html(self):
        return self._first("html")

    @property
    def head(self):
        return self._first("head")

    @property
    def body(self):
        """The ``<body>`` element -- the document itself when there is none."""
        return self._first("body") or self

    @property
    def title(self):
        node = self._first("title")
        return node.text.strip() if node is not None else ""

    @property
    def links(self):
        """Every ``<a href>`` value, in document order."""
        return [el.attrs["href"] for el in _iter_elements(self)
                if el.tag == "a" and "href" in el.attrs]

    @property
    def images(self):
        return [el.attrs["src"] for el in _iter_elements(self)
                if el.tag == "img" and "src" in el.attrs]

    @property
    def scripts(self):
        return self.get_elements_by_tag_name("script")

    @property
    def comments(self):
        """Every ``<!-- ... -->`` body, stripped."""
        return [n.data.strip() for n in _iter_nodes(self) if isinstance(n, Comment)]

    @property
    def forms(self):
        return [Form(el) for el in self.get_elements_by_tag_name("form")]

    def form(self, name_or_index=0):
        """A single form, by index or by ``name``/``id``."""
        forms = self.forms
        if isinstance(name_or_index, int):
            try:
                return forms[name_or_index]
            except IndexError:
                raise IndexError(
                    f"no form at index {name_or_index} -- the document has {len(forms)}"
                )
        wanted = str(name_or_index)
        for candidate in forms:
            if wanted in (candidate.name, candidate.id):
                return candidate
        raise ValueError(f"no <form> named {wanted!r} -- have {[f.name or f.id for f in forms]}")

    def _first(self, tag):
        for element in _iter_elements(self):
            if element.tag == tag:
                return element
        return None

    def __repr__(self):
        return f"<Document title={self.title!r} children={len(self.children)}>"


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #

class _DOMBuilder(HTMLParser):
    """Turns a byte-soup page into a :class:`Document`, never raising."""

    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.document = Document()
        self.stack = [self.document]

    def _append(self, node):
        node.parent = self.stack[-1]
        self.stack[-1].child_nodes.append(node)

    def _auto_close(self, tag):
        """Pop elements that this start tag implicitly closes (<p>, <li>, <td>, ...)."""
        while len(self.stack) > 1:
            open_tag = self.stack[-1].tag
            if tag in _CLOSED_BY.get(open_tag, ()):
                self.stack.pop()
            else:
                break

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        self._auto_close(tag)
        element = Element(tag, attrs)
        self._append(element)
        if tag not in VOID_ELEMENTS:
            self.stack.append(element)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in VOID_ELEMENTS:
            return
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]      # also closes anything left open inside
                return
        # stray end tag for something that was never opened -- ignore it

    def handle_data(self, data):
        if data:
            self._append(Text(data))

    def handle_comment(self, data):
        self._append(Comment(data))

    # convert_charrefs=True means these normally never fire -- keep the text anyway
    def handle_entityref(self, name):
        self._append(Text(_html.unescape(f"&{name};")))

    def handle_charref(self, name):
        self._append(Text(_html.unescape(f"&#{name};")))


def parse_html(source):
    """Parse *source* into a :class:`Document`.

    *source* may be a str, bytes, or a Response-like object with a ``.text``
    attribute. Broken markup is fixed up rather than rejected -- this never raises.

    Example:
        >>> doc = parse_html("<p>hi<p>there")   # unclosed tags are fixed up
        >>> [p.text for p in doc.get_elements_by_tag_name("p")]
        ['hi', 'there']
    """
    if isinstance(source, Document):
        return source
    builder = _DOMBuilder()
    try:
        builder.feed(_as_text(source))
        builder.close()
    except Exception:                    # a page is never worth an exception mid-exploit
        pass
    return builder.document


#: short alias
parse = parse_html


# --------------------------------------------------------------------------- #
# css selectors
# --------------------------------------------------------------------------- #
#
# a selector list is a tuple of complex selectors; a complex selector is a tuple
# of (combinator, compound) pairs -- the first combinator is None -- and a
# compound is (tag_or_None, (condition, ...)).

_IDENT_RE = re.compile(r"-?[_a-zA-Z\u00a0-\uffff][-_a-zA-Z0-9\u00a0-\uffff]*")
# ids and classes in the wild start with digits often enough to be forgiving here
_NAME_RE = re.compile(r"[-_a-zA-Z0-9\u00a0-\uffff]+")
_UNQUOTED_RE = re.compile(r"[^\]\s\"']+")
_NTH_RE = re.compile(r"^([-+]?\d*)n\s*(?:([-+])\s*(\d+))?$|^([-+]?\d+)$")
_ATTR_OPS = ("^=", "$=", "*=", "~=", "|=", "=")
_COMBINATORS = ">+~"
_WS = " \t\r\n\f"
_NO_ARG_PSEUDOS = frozenset({
    "first-child", "last-child", "only-child", "first-of-type", "last-of-type",
    "only-of-type", "empty", "root",
})
_NTH_PSEUDOS = {
    "nth-child": (False, False),
    "nth-last-child": (False, True),
    "nth-of-type": (True, False),
    "nth-last-of-type": (True, True),
}


class _SelectorParser:
    def __init__(self, text):
        self.text = text
        self.pos = 0

    def fail(self, why):
        raise ValueError(f"cannot parse selector {self.text!r} -- {why}")

    def ws(self):
        start = self.pos
        while self.pos < len(self.text) and self.text[self.pos] in _WS:
            self.pos += 1
        return self.pos > start

    def at(self):
        return self.text[self.pos] if self.pos < len(self.text) else ""

    # -- selector list ----------------------------------------------------- #
    def parse_list(self):
        groups = [self.parse_complex()]
        while True:
            self.ws()
            if self.at() != ",":
                break
            self.pos += 1
            groups.append(self.parse_complex())
        self.ws()
        if self.pos != len(self.text):
            self.fail(f"unexpected {self.at()!r} at offset {self.pos}")
        return tuple(groups)

    def parse_complex(self):
        self.ws()
        sequence = [(None, self.parse_compound())]
        while True:
            spaced = self.ws()
            char = self.at()
            if not char or char == ",":
                break
            if char in _COMBINATORS:
                self.pos += 1
                self.ws()
                combinator = char
            elif spaced:
                combinator = " "
            else:
                break                       # junk -- parse_list reports the position
            if not self.at() or self.at() == ",":
                self.fail("trailing combinator")
            sequence.append((combinator, self.parse_compound()))
        return tuple(sequence)

    # -- compound ---------------------------------------------------------- #
    def parse_compound(self):
        tag = None
        conditions = []
        if self.at() == "*":
            tag = "*"
            self.pos += 1
        else:
            match = _IDENT_RE.match(self.text, self.pos)
            if match:
                tag = match.group(0).lower()
                self.pos = match.end()
        while True:
            char = self.at()
            if char == "#":
                self.pos += 1
                conditions.append(("id", self.name("id")))
            elif char == ".":
                self.pos += 1
                conditions.append(("class", self.name("class")))
            elif char == "[":
                conditions.append(self.parse_attr())
            elif char == ":":
                conditions.append(self.parse_pseudo())
            else:
                break
        if tag is None and not conditions:
            self.fail(f"empty compound at offset {self.pos}")
        return (tag, tuple(conditions))

    def name(self, kind):
        match = _NAME_RE.match(self.text, self.pos)
        if not match:
            self.fail(f"expected a {kind} name at offset {self.pos}")
        self.pos = match.end()
        return match.group(0)

    # -- [attr op value] --------------------------------------------------- #
    def parse_attr(self):
        self.pos += 1                        # [
        self.ws()
        name = self.name("attribute").lower()
        self.ws()
        if self.at() == "]":
            self.pos += 1
            return ("attr", name, None, None, None)
        operator = next((op for op in _ATTR_OPS if self.text.startswith(op, self.pos)), None)
        if operator is None:
            self.fail(f"bad attribute operator at offset {self.pos}")
        self.pos += len(operator)
        self.ws()
        value = self.parse_value()
        self.ws()
        fold = None                          # None -- no flag written, decide per attribute
        if self.at() in ("i", "I", "s", "S"):
            fold = self.at() in ("i", "I")
            self.pos += 1
            self.ws()
        if self.at() != "]":
            self.fail("unterminated attribute selector")
        self.pos += 1
        return ("attr", name, operator, value, fold)

    def parse_value(self):
        quote = self.at()
        if quote in ("'", '"'):
            self.pos += 1
            out = []
            while self.pos < len(self.text):
                char = self.text[self.pos]
                if char == "\\" and self.pos + 1 < len(self.text):
                    out.append(self.text[self.pos + 1])
                    self.pos += 2
                    continue
                if char == quote:
                    self.pos += 1
                    return "".join(out)
                out.append(char)
                self.pos += 1
            self.fail("unterminated string")
        match = _UNQUOTED_RE.match(self.text, self.pos)
        if not match:
            self.fail(f"expected an attribute value at offset {self.pos}")
        self.pos = match.end()
        return match.group(0)

    # -- :pseudo-classes --------------------------------------------------- #
    def parse_pseudo(self):
        self.pos += 1                        # :
        if self.at() == ":":
            self.fail("pseudo-elements are not supported")
        match = _IDENT_RE.match(self.text, self.pos)
        if not match:
            self.fail(f"expected a pseudo-class name at offset {self.pos}")
        name = match.group(0).lower()
        self.pos = match.end()
        arg = self.parse_arg() if self.at() == "(" else None
        if arg is None:
            if name not in _NO_ARG_PSEUDOS:
                self.fail(f":{name} needs an argument or is not supported")
            return ("pseudo", name, None)
        if name in _NTH_PSEUDOS:
            of_type, from_end = _NTH_PSEUDOS[name]
            a, b = self.parse_nth(arg)
            return ("pseudo", "nth", (a, b, of_type, from_end))
        if name == "not":
            return ("pseudo", "not", _SelectorParser(arg).parse_list())
        if name == "has":
            stripped = arg.strip()
            combinator = None
            if stripped[:1] in _COMBINATORS:
                combinator = stripped[0]
                stripped = stripped[1:]
            if not stripped.strip():
                self.fail(":has() needs a selector")
            return ("pseudo", "has", (combinator, _SelectorParser(stripped).parse_list()))
        if name == "contains":
            text = arg.strip()
            if text[:1] in ("'", '"') and text[-1:] == text[:1]:
                text = text[1:-1]
            return ("pseudo", "contains", text)
        self.fail(f":{name}() is not supported")

    def parse_arg(self):
        """Consume a balanced ``( ... )`` and return what is inside it."""
        depth = 0
        start = self.pos + 1
        quote = ""
        while self.pos < len(self.text):
            char = self.text[self.pos]
            if quote:
                if char == "\\":
                    self.pos += 1
                elif char == quote:
                    quote = ""
            elif char in ("'", '"'):
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    inner = self.text[start:self.pos]
                    self.pos += 1
                    return inner
            self.pos += 1
        self.fail("unbalanced parentheses")

    def parse_nth(self, arg):
        arg = arg.strip().lower().replace(" ", "")
        if arg == "odd":
            return (2, 1)
        if arg == "even":
            return (2, 0)
        match = _NTH_RE.match(arg)
        if not match:
            self.fail(f"bad nth argument {arg!r}")
        if match.group(4) is not None:
            return (0, int(match.group(4)))
        coefficient = match.group(1)
        if coefficient in ("", "+"):
            a = 1
        elif coefficient == "-":
            a = -1
        else:
            a = int(coefficient)
        b = 0
        if match.group(3) is not None:
            b = int(match.group(3))
            if match.group(2) == "-":
                b = -b
        return (a, b)


@lru_cache(maxsize=512)
def _compile_cached(selector):
    return _SelectorParser(selector).parse_list()


def _compile(selector):
    if not isinstance(selector, str):
        raise ValueError(f"selector must be a string, got {type(selector).__name__}")
    if not selector.strip():
        raise ValueError("empty selector")
    return _compile_cached(selector)


# -- matching --------------------------------------------------------------- #

def _matches_any(element, groups):
    return any(_match_complex(element, group) for group in groups)


def _match_complex(element, sequence, index=None):
    if index is None:
        index = len(sequence) - 1
    combinator, compound = sequence[index]
    if not _match_compound(element, compound):
        return False
    if index == 0:
        return True
    if combinator == " ":
        node = element.parent
        while node is not None:
            if _match_complex(node, sequence, index - 1):
                return True
            node = node.parent
        return False
    if combinator == ">":
        parent = element.parent
        return parent is not None and _match_complex(parent, sequence, index - 1)
    if combinator == "+":
        previous = element.previous_element_sibling
        return previous is not None and _match_complex(previous, sequence, index - 1)
    # "~" -- walk the parent's children backwards directly, no per-step lookups
    parent = element.parent
    position = _child_index(element) if parent is not None else -1
    if position < 0:
        return False
    siblings = parent.child_nodes
    for i in range(position - 1, -1, -1):
        previous = siblings[i]
        if isinstance(previous, Element) and _match_complex(previous, sequence, index - 1):
            return True
    return False


def _match_compound(element, compound):
    if not isinstance(element, Element) or isinstance(element, Document):
        return False                        # the document root matches nothing
    tag, conditions = compound
    if tag not in (None, "*") and element.tag != tag:
        return False
    return all(_match_condition(element, condition) for condition in conditions)


def _match_condition(element, condition):
    kind = condition[0]
    if kind == "id":
        return element.attrs.get("id") == condition[1]
    if kind == "class":
        return condition[1] in element.class_list
    if kind == "attr":
        return _match_attr(element, *condition[1:])
    return _match_pseudo(element, condition[1], condition[2])


def _match_attr(element, name, operator, wanted, fold):
    if name not in element.attrs:
        return False
    if operator is None:
        return True
    value = str(element.attrs[name])
    if fold is None:                        # no i/s flag -- html says these fold, href/id do not
        fold = name in _CI_ATTRS
    if fold:
        value, wanted = value.lower(), wanted.lower()
    if operator == "=":
        return value == wanted
    if not wanted:
        return False                        # [a^=""] and friends never match
    if operator == "^=":
        return value.startswith(wanted)
    if operator == "$=":
        return value.endswith(wanted)
    if operator == "*=":
        return wanted in value
    if operator == "~=":
        return not any(c in wanted for c in _WS) and wanted in value.split()
    # "|="
    return value == wanted or value.startswith(wanted + "-")


def _match_pseudo(element, name, arg):
    if name == "nth":
        return _match_nth(element, *arg)
    if name == "first-child":
        return _match_nth(element, 0, 1, False, False)
    if name == "last-child":
        return _match_nth(element, 0, 1, False, True)
    if name == "only-child":
        return _element_position(element, False)[1] == 1
    if name == "first-of-type":
        return _match_nth(element, 0, 1, True, False)
    if name == "last-of-type":
        return _match_nth(element, 0, 1, True, True)
    if name == "only-of-type":
        return _element_position(element, True)[1] == 1
    if name == "empty":
        return not element.children and not element.text.strip()
    if name == "root":
        return element.parent is None or isinstance(element.parent, Document)
    if name == "not":
        return not _matches_any(element, arg)
    if name == "has":
        return _match_has(element, arg[0], arg[1])
    # "contains"
    return arg in element.text


def _element_position(element, of_type):
    """``(index, total)`` among the element siblings -- ``(-1, 0)`` when detached.

    The parent's element children are counted once and cached, so :func:`_match_nth`
    stays O(1) per element instead of rebuilding the sibling list every time. The
    cache is rebuilt whenever the child count changes, and each entry keeps the node
    it describes, so a stale hit is rejected by identity.
    """
    parent = element.parent
    if parent is None:
        return (0, 1)
    children = parent.child_nodes
    cache = parent._element_cache
    if cache is None or cache[0] != len(children):
        positions = {}
        per_tag = {}
        total = 0
        for node in children:
            if isinstance(node, Element):
                count = per_tag.get(node.tag, 0)
                per_tag[node.tag] = count + 1
                positions[id(node)] = (node, total, count)
                total += 1
        cache = (len(children), total, positions, per_tag)
        parent._element_cache = cache
    entry = cache[2].get(id(element))
    if entry is None or entry[0] is not element:
        return (-1, 0)
    if of_type:
        return (entry[2], cache[3][element.tag])
    return (entry[1], cache[1])


def _match_nth(element, a, b, of_type, from_end):
    position, total = _element_position(element, of_type)
    if position < 0:
        return False
    index = total - position if from_end else position + 1
    if a == 0:
        return index == b
    offset = index - b
    return offset % a == 0 and offset // a >= 0


def _match_has(element, combinator, groups):
    if combinator == ">":
        candidates = element.children
    elif combinator == "+":
        sibling = element.next_element_sibling
        candidates = [sibling] if sibling is not None else []
    elif combinator == "~":
        candidates = []
        sibling = element.next_element_sibling
        while sibling is not None:
            candidates.append(sibling)
            sibling = sibling.next_element_sibling
    else:
        candidates = _iter_elements(element)
    return any(_matches_any(candidate, groups) for candidate in candidates)
