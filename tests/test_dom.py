"""DOM tests: the selector engine, broken markup, and pulling fields out of forms."""

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ctflib.dom import Comment, Document, Element, Form, Text, parse, parse_html


PAGE = """
<!DOCTYPE html>
<HTML>
<head>
  <title>  Admin &amp; Co  </title>
  <style>body { color: red }</style>
</head>
<body class="page dark">
  <!-- TODO: remove before the ctf -- sknb{comment_flag} -->
  <div id="main" class="wrap">
    <ul class="nav">
      <li class="item first">Home</li>
      <li class="item">Docs</li>
      <li class="item last"><a href="/adm/panel" class="btn admin" data-role="x y">Panel</a></li>
    </ul>
    <p>first &lt;para&gt;</p>
    <p class="lead">second</p>
    <span>tail</span>
  </div>
  <img src="/static/logo.png" alt="logo">
  <script>var flag = "sknb{script_flag}";</script>
</body>
</HTML>
"""

LOGIN = """
<html><body>
<h1>Sign in</h1>
<form id="loginform" name="login" action="/auth/login" method="post" enctype="multipart/form-data">
  <input type="hidden" name="csrf_token" value="9f8e7d6c">
  <input type="text" name="username" value="guest">
  <input type="password" name="password">
  <input type="checkbox" name="remember" value="yes" checked>
  <input type="checkbox" name="newsletter" value="1">
  <input type="radio" name="tier" value="free">
  <input type="radio" name="tier" value="pro" checked>
  <select name="role">
    <option value="user">User</option>
    <option value="admin" selected>Admin</option>
  </select>
  <select name="lang">
    <option value="en">English</option>
    <option value="ja">Japanese</option>
  </select>
  <select name="plain"><option>Bare</option></select>
  <textarea name="note">hello
world</textarea>
  <input type="reset" name="clear" value="Clear">
  <input type="submit" name="do" value="Sign in">
  <input type="submit" value="unnamed">
</form>
<form name="search" action=""><input name="q" value="x"></form>
</body></html>
"""


class _FakeResponse:
    """Stands in for ctflib.client.Response -- only ``.text`` matters here."""

    def __init__(self, text):
        self.text = text


class ParsingTests(unittest.TestCase):
    def setUp(self):
        self.doc = parse_html(PAGE)

    def test_parse_returns_a_document(self):
        self.assertIsInstance(self.doc, Document)
        self.assertIs(parse, parse_html)

    def test_accepts_str_bytes_and_response_like(self):
        for source in ("<p>hi</p>", b"<p>hi</p>", _FakeResponse("<p>hi</p>")):
            self.assertEqual(parse_html(source).find("p").text, "hi")

    def test_parsing_a_document_returns_it_unchanged(self):
        self.assertIs(parse_html(self.doc), self.doc)

    def test_tags_and_attribute_names_are_lowercased(self):
        doc = parse_html("<DIV ID=x><SPAN>y</SPAN></DIV>")
        self.assertEqual([e.tag for e in doc.find_all("*")], ["div", "span"])
        self.assertEqual(parse_html("<a HREF=/x>y</a>").find("a").attrs, {"href": "/x"})

    def test_unquoted_and_bare_attributes(self):
        el = parse_html("<input type=checkbox name=a checked>").find("input")
        self.assertEqual(el.attrs, {"type": "checkbox", "name": "a", "checked": ""})

    def test_void_elements_never_nest(self):
        doc = parse_html("<div><br><img src=x><hr>after</div>")
        div = doc.find("div")
        self.assertEqual([e.tag for e in div.children], ["br", "img", "hr"])
        self.assertEqual(div.text, "after")

    def test_unclosed_p_and_li_are_auto_closed(self):
        doc = parse_html("<ul><li>a<li>b<li>c</ul><p>one<p>two")
        self.assertEqual([e.text for e in doc.find_all("li")], ["a", "b", "c"])
        self.assertEqual([e.text for e in doc.find_all("p")], ["one", "two"])

    def test_unclosed_table_cells_are_auto_closed(self):
        doc = parse_html("<table><tr><td>a<td>b<tr><td>c<td>d</table>")
        self.assertEqual([e.text for e in doc.find_all("td")], ["a", "b", "c", "d"])
        self.assertEqual(len(doc.find_all("tr")), 2)
        self.assertEqual([e.text for e in doc.find_all("tr")], ["ab", "cd"])

    def test_stray_end_tag_is_ignored(self):
        doc = parse_html("<div>a</span></p>b</div></div>c")
        self.assertEqual(doc.find("div").text, "ab")
        self.assertEqual(doc.text, "abc")

    def test_end_tag_closes_everything_left_open_inside(self):
        doc = parse_html("<div><span><b>x</div><i>y</i>")
        self.assertEqual(doc.find("div").text, "x")
        self.assertNotIn(doc.find("i"), doc.find("div"))     # </div> ended span and b too
        self.assertIs(doc.find("i").parent, doc)

    def test_entities_are_decoded(self):
        doc = parse_html("<p>a &amp; b &lt;c&gt; &#65; &nbsp;</p>")
        self.assertEqual(doc.find("p").text, "a & b <c> A \xa0")
        self.assertEqual(self.doc.title, "Admin & Co")

    def test_malformed_soup_never_raises(self):
        for junk in ("<<<>>>", "<a href=", "<!-- unterminated", "<p<div>", "</>", "<a b='c"):
            self.assertIsInstance(parse_html(junk), Document)

    def test_node_types_and_child_nodes(self):
        doc = parse_html("<div>text<!--c--><b>x</b></div>")
        kinds = [type(n) for n in doc.find("div").child_nodes]
        self.assertEqual(kinds, [Text, Comment, Element])
        self.assertEqual([n.node_type for n in doc.find("div").child_nodes], [3, 8, 1])
        self.assertEqual(doc.node_type, 9)
        self.assertEqual([e.tag for e in doc.find("div").children], ["b"])


class SelectorTests(unittest.TestCase):
    def setUp(self):
        self.doc = parse_html(PAGE)

    def sel(self, selector):
        return self.doc.query_selector_all(selector)

    def test_tag_id_class_and_universal(self):
        self.assertEqual(len(self.sel("li")), 3)
        self.assertEqual(self.sel("#main")[0].tag, "div")
        self.assertEqual(len(self.sel(".item")), 3)
        self.assertGreater(len(self.sel("*")), 10)

    def test_selectors_are_case_insensitive_for_tags(self):
        self.assertEqual(len(self.sel("LI")), 3)
        self.assertEqual(len(self.sel("A[HREF]")), 1)

    def test_class_names_and_attribute_values_are_case_sensitive(self):
        self.assertEqual(self.sel(".ITEM"), [])
        self.assertEqual(self.sel('a[href="/ADM/PANEL"]'), [])

    def test_compound_selector(self):
        found = self.sel('a.btn#nope[href^="/adm"]')
        self.assertEqual(found, [])
        found = self.sel('a.btn.admin[href^="/adm"]')
        self.assertEqual([e.text for e in found], ["Panel"])

    def test_attribute_operators(self):
        self.assertEqual(len(self.sel("[data-role]")), 1)
        self.assertEqual(len(self.sel('a[href="/adm/panel"]')), 1)
        self.assertEqual(len(self.sel('a[href^="/adm"]')), 1)
        self.assertEqual(len(self.sel('a[href$="panel"]')), 1)
        self.assertEqual(len(self.sel('a[href*="dm/pa"]')), 1)
        self.assertEqual(len(self.sel('a[data-role~="y"]')), 1)
        self.assertEqual(len(self.sel('a[data-role~="x y"]')), 0)
        self.assertEqual(len(self.sel('a[href^=""]')), 0)

    def test_unquoted_attribute_value_in_selector(self):
        self.assertEqual(len(self.sel("a[href^=/adm]")), 1)
        self.assertEqual(len(self.sel("[class=lead]")), 1)

    def test_attribute_case_insensitive_flag(self):
        self.assertEqual(len(self.sel('a[href="/ADM/PANEL" i]')), 1)

    def test_dash_operator(self):
        doc = parse_html('<p lang="en-GB">x</p><p lang="fr">y</p>')
        self.assertEqual(len(doc.find_all('[lang|="en"]')), 1)

    def test_descendant_and_child_combinators(self):
        self.assertEqual(len(self.sel("#main li")), 3)
        self.assertEqual(len(self.sel("#main > li")), 0)
        self.assertEqual(len(self.sel("ul > li")), 3)
        self.assertEqual(len(self.sel("body div ul li a")), 1)

    def test_adjacent_and_general_sibling_combinators(self):
        self.assertEqual([e.text for e in self.sel("li + li")], ["Docs", "Panel"])
        self.assertEqual([e.text for e in self.sel("li.first ~ li")], ["Docs", "Panel"])
        self.assertEqual([e.text for e in self.sel("p + span")], ["tail"])
        self.assertEqual(self.sel("span + p"), [])

    def test_selector_list(self):
        found = self.sel("p.lead, span")
        self.assertEqual([e.text for e in found], ["second", "tail"])

    def test_results_are_in_document_order(self):
        self.assertEqual([e.tag for e in self.sel("span, ul, p")], ["ul", "p", "p", "span"])

    def test_first_last_and_only_child(self):
        self.assertEqual([e.text for e in self.sel("li:first-child")], ["Home"])
        self.assertEqual([e.text for e in self.sel("li:last-child")], ["Panel"])
        self.assertEqual([e.tag for e in self.sel("ul:only-child")], [])
        self.assertEqual([e.text for e in self.sel("li:last-child > a:only-child")], ["Panel"])

    def test_nth_child(self):
        self.assertEqual([e.text for e in self.sel("li:nth-child(2)")], ["Docs"])
        self.assertEqual([e.text for e in self.sel("li:nth-child(odd)")], ["Home", "Panel"])
        self.assertEqual([e.text for e in self.sel("li:nth-child(even)")], ["Docs"])
        self.assertEqual([e.text for e in self.sel("li:nth-child(2n+1)")], ["Home", "Panel"])
        self.assertEqual([e.text for e in self.sel("li:nth-child(-n+2)")], ["Home", "Docs"])
        self.assertEqual([e.text for e in self.sel("li:nth-last-child(1)")], ["Panel"])

    def test_of_type_pseudos(self):
        doc = parse_html("<div><span>s1</span><p>p1</p><p>p2</p><span>s2</span></div>")
        self.assertEqual([e.text for e in doc.find_all("p:first-of-type")], ["p1"])
        self.assertEqual([e.text for e in doc.find_all("p:last-of-type")], ["p2"])
        self.assertEqual([e.text for e in doc.find_all("p:nth-of-type(2)")], ["p2"])

    def test_not_pseudo(self):
        self.assertEqual([e.text for e in self.sel("li:not(.first)")], ["Docs", "Panel"])
        self.assertEqual([e.text for e in self.sel("p:not([class])")], ["first <para>"])
        self.assertEqual(len(self.sel("li:not(li)")), 0)

    def test_has_pseudo(self):
        self.assertEqual([e.get_attribute("class") for e in self.sel("li:has(a)")], ["item last"])
        self.assertEqual([e.tag for e in self.sel("div:has(> ul)")], ["div"])
        self.assertEqual(self.sel("p:has(a)"), [])

    def test_empty_pseudo(self):
        doc = parse_html("<div><p></p><p>x</p><p>   </p></div>")
        self.assertEqual(len(doc.find_all("p:empty")), 2)

    def test_query_selector_returns_first_or_none(self):
        self.assertEqual(self.doc.query_selector("li").text, "Home")
        self.assertIsNone(self.doc.query_selector("blockquote"))

    def test_matches_and_closest(self):
        link = self.doc.find("a")
        self.assertTrue(link.matches("a.btn"))
        self.assertTrue(link.matches("li > a"))
        self.assertFalse(link.matches("p a"))
        self.assertEqual(link.closest("ul").get_attribute("class"), "nav")
        self.assertIs(link.closest("a"), link)
        self.assertIsNone(link.closest("table"))

    def test_scoped_query_only_sees_descendants(self):
        nav = self.doc.find("ul.nav")
        self.assertEqual(len(nav.find_all("li")), 3)
        self.assertEqual(nav.find_all("p"), [])
        self.assertEqual(len(nav.find_all("a")), 1)

    def test_bad_selectors_raise_value_error(self):
        for bad in ("", "   ", ">", "a >", "a ~", "div[", "div[href=", "a::before",
                    ":bogus(1)", "a:nth-child(q)", "!", "a, ", "()"):
            with self.assertRaises(ValueError, msg=bad):
                self.doc.find_all(bad)

    def test_non_string_selector_raises(self):
        with self.assertRaises(ValueError):
            self.doc.find_all(42)

    def test_aliases_point_at_the_same_engine(self):
        self.assertEqual(self.doc.querySelectorAll("li"), self.doc.find_all("li"))
        self.assertIs(self.doc.querySelector("li"), self.doc.find("li"))


class ElementApiTests(unittest.TestCase):
    def setUp(self):
        self.doc = parse_html(PAGE)
        self.link = self.doc.find("a")

    def test_tag_name_aliases(self):
        self.assertEqual((self.link.tag, self.link.tag_name, self.link.tagName), ("a",) * 3)

    def test_attribute_helpers(self):
        self.assertEqual(self.link.get_attribute("HREF"), "/adm/panel")
        self.assertIsNone(self.link.get_attribute("missing"))
        self.assertEqual(self.link.get_attribute("missing", "-"), "-")
        self.assertTrue(self.link.has_attribute("class"))
        self.assertFalse(self.link.has_attribute("nope"))
        self.link.set_attribute("Href", "/pwn")
        self.assertEqual(self.link["href"], "/pwn")

    def test_getitem_and_contains(self):
        self.assertEqual(self.link["class"], "btn admin")
        self.assertIsNone(self.link["nope"])
        self.assertIn("href", self.link)
        self.assertNotIn("action", self.link)
        self.assertIn(self.link, self.doc.find("ul"))
        self.assertNotIn(self.link, self.doc.find("p"))

    def test_id_and_class_helpers(self):
        body = self.doc.find("body")
        self.assertEqual(body.class_name, "page dark")
        self.assertEqual(body.class_list, ["page", "dark"])
        self.assertEqual(self.doc.find("#main").id, "main")
        self.assertEqual(self.doc.find("p").id, "")

    def test_iteration_and_len(self):
        nav = self.doc.find("ul.nav")
        self.assertEqual(len(nav), 3)
        self.assertEqual([child.tag for child in nav], ["li", "li", "li"])
        self.assertEqual(nav[0].text, "Home")

    def test_traversal(self):
        items = self.doc.find_all("li")
        self.assertIs(items[1].parent_element, self.doc.find("ul"))
        self.assertIs(items[0].next_element_sibling, items[1])
        self.assertIs(items[1].previous_element_sibling, items[0])
        self.assertIsNone(items[0].previous_element_sibling)
        self.assertIsNone(items[2].next_element_sibling)
        nav = self.doc.find("ul")
        self.assertIs(nav.first_child_element, items[0])
        self.assertIs(nav.last_child_element, items[2])
        self.assertIsNone(items[0].first_child_element)

    def test_text_content_aliases(self):
        item = self.doc.find("li.last")
        self.assertEqual(item.text, "Panel")
        self.assertEqual(item.text_content, "Panel")
        self.assertEqual(item.textContent, "Panel")

    def test_text_skips_comments_and_nested_scripts(self):
        doc = parse_html("<div>a<!--hidden-->b<script>var c=1;</script>c</div>")
        self.assertEqual(doc.find("div").text, "abc")
        self.assertEqual(doc.find("script").text, "var c=1;")

    def test_document_text_excludes_script_and_style(self):
        text = self.doc.text
        self.assertIn("Home", text)
        self.assertNotIn("sknb{script_flag}", text)
        self.assertNotIn("color: red", text)

    def test_get_elements_by_helpers(self):
        self.assertEqual(len(self.doc.get_elements_by_tag_name("li")), 3)
        self.assertEqual(len(self.doc.getElementsByTagName("*")), len(self.doc.descendants))
        self.assertEqual(len(self.doc.get_elements_by_class_name("item")), 3)
        self.assertEqual(len(self.doc.get_elements_by_class_name("item last")), 1)
        self.assertEqual(self.doc.get_element_by_id("main").tag, "div")
        self.assertIsNone(self.doc.get_element_by_id("nope"))

    def test_get_elements_by_name(self):
        doc = parse_html(LOGIN)
        found = doc.get_elements_by_name("tier")
        self.assertEqual([e.get_attribute("value") for e in found], ["free", "pro"])

    def test_inner_and_outer_html(self):
        item = self.doc.find("li.first")
        self.assertEqual(item.inner_html, "Home")
        self.assertEqual(item.outer_html, '<li class="item first">Home</li>')
        self.assertEqual(item.innerHTML, item.inner_html)
        self.assertEqual(item.outerHTML, item.outer_html)

    def test_outer_html_escapes_and_self_terminates(self):
        doc = parse_html('<p title=\'a"b\'>x &amp; &lt;y&gt; z</p><br><img src="/a?b=1&amp;c=2">')
        self.assertEqual(doc.find("p").outer_html, '<p title="a&quot;b">x &amp; &lt;y&gt; z</p>')
        self.assertEqual(doc.find("br").outer_html, "<br/>")
        self.assertEqual(doc.find("img").outer_html, '<img src="/a?b=1&amp;c=2"/>')

    def test_outer_html_round_trips(self):
        once = self.doc.outer_html
        twice = parse_html(once).outer_html
        self.assertEqual(once, twice)
        again = parse_html(once)
        self.assertEqual(again.title, self.doc.title)
        self.assertEqual([e.text for e in again.find_all("li")],
                         [e.text for e in self.doc.find_all("li")])
        self.assertEqual(again.links, self.doc.links)

    def test_script_body_is_not_escaped_on_round_trip(self):
        doc = parse_html('<script>if (a < b && c) { x("<b>"); }</script>')
        self.assertIn("a < b && c", doc.outer_html)
        self.assertEqual(parse_html(doc.outer_html).scripts[0].text, doc.scripts[0].text)

    def test_repr_is_informative(self):
        self.assertIn("li", repr(self.doc.find("li.first")))
        self.assertIn("Admin", repr(self.doc))
        self.assertIn("Text", repr(self.doc.find("p").child_nodes[0]))
        self.assertIn("Comment", repr(parse_html("<!--x-->").child_nodes[0]))


class DocumentTests(unittest.TestCase):
    def setUp(self):
        self.doc = parse_html(PAGE)

    def test_structural_shortcuts(self):
        self.assertEqual(self.doc.html.tag, "html")
        self.assertEqual(self.doc.head.tag, "head")
        self.assertEqual(self.doc.body.tag, "body")
        self.assertEqual(self.doc.title, "Admin & Co")

    def test_body_falls_back_to_the_document(self):
        fragment = parse_html("<p>just a fragment</p>")
        self.assertIs(fragment.body, fragment)
        self.assertIsNone(fragment.head)
        self.assertEqual(fragment.title, "")

    def test_links_and_images(self):
        self.assertEqual(self.doc.links, ["/adm/panel"])
        self.assertEqual(self.doc.images, ["/static/logo.png"])
        self.assertEqual(parse_html("<a>no href</a>").links, [])

    def test_scripts(self):
        self.assertEqual(len(self.doc.scripts), 1)
        self.assertIn("sknb{script_flag}", self.doc.scripts[0].text)

    def test_comments_are_collected_and_stripped(self):
        self.assertEqual(self.doc.comments,
                         ["TODO: remove before the ctf -- sknb{comment_flag}"])
        doc = parse_html("<div><!--a--><p><!--b--></p></div>")
        self.assertEqual(doc.comments, ["a", "b"])


class FormTests(unittest.TestCase):
    def setUp(self):
        self.doc = parse_html(LOGIN)
        self.form = self.doc.form()

    def test_forms_and_lookup(self):
        self.assertEqual(len(self.doc.forms), 2)
        self.assertIsInstance(self.form, Form)
        self.assertEqual(self.doc.form(1).name, "search")
        self.assertEqual(self.doc.form("search").name, "search")
        self.assertEqual(self.doc.form("loginform").name, "login")

    def test_missing_form_raises(self):
        with self.assertRaises(ValueError):
            self.doc.form("nope")
        with self.assertRaises(IndexError):
            self.doc.form(9)

    def test_form_metadata(self):
        self.assertEqual(self.form.action, "/auth/login")
        self.assertEqual(self.form.method, "POST")
        self.assertEqual(self.form.enctype, "multipart/form-data")
        self.assertEqual((self.form.name, self.form.id), ("login", "loginform"))
        self.assertEqual(self.form.element.tag, "form")

    def test_method_defaults_to_get(self):
        self.assertEqual(parse_html("<form></form>").form().method, "GET")
        self.assertEqual(parse_html("<form method=post>").form().method, "POST")

    def test_fields_include_hidden_inputs(self):
        self.assertEqual(self.form.fields["csrf_token"], "9f8e7d6c")
        self.assertEqual(self.form.data["csrf_token"], "9f8e7d6c")

    def test_checkbox_semantics(self):
        fields = self.form.fields
        self.assertEqual(fields["remember"], "yes")
        self.assertNotIn("newsletter", fields)

    def test_radio_semantics(self):
        self.assertEqual(self.form.fields["tier"], "pro")

    def test_select_uses_the_selected_option(self):
        self.assertEqual(self.form.fields["role"], "admin")

    def test_select_falls_back_to_the_first_option(self):
        self.assertEqual(self.form.fields["lang"], "en")

    def test_option_without_a_value_uses_its_text(self):
        self.assertEqual(self.form.fields["plain"], "Bare")

    def test_textarea_value(self):
        self.assertEqual(self.form.fields["note"], "hello\nworld")

    def test_empty_and_valueless_inputs(self):
        fields = self.form.fields
        self.assertEqual(fields["username"], "guest")
        self.assertEqual(fields["password"], "")

    def test_submit_buttons_need_a_name(self):
        fields = self.form.fields
        self.assertEqual(fields["do"], "Sign in")
        self.assertNotIn("unnamed", fields.values())
        self.assertNotIn("clear", fields)      # reset buttons are never submitted

    def test_button_element_is_included_when_named(self):
        doc = parse_html('<form><button name="act" value="del">x</button>'
                         '<button type="button" name="ui">y</button></form>')
        self.assertEqual(doc.form().fields, {"act": "del"})

    def test_inputs_lists_every_field_element(self):
        tags = [e.tag for e in self.form.inputs]
        self.assertEqual(tags.count("select"), 3)
        self.assertEqual(tags.count("textarea"), 1)
        self.assertGreater(tags.count("input"), 5)

    def test_fill_merges_without_touching_the_dom(self):
        filled = self.form.fill(username="admin", password="' OR 1--")
        self.assertEqual(filled["username"], "admin")
        self.assertEqual(filled["csrf_token"], "9f8e7d6c")
        self.assertEqual(self.form.fields["username"], "guest")
        self.assertEqual(self.form.fill({"username": "root"})["username"], "root")

    def test_url_resolution(self):
        self.assertEqual(self.form.url(), "/auth/login")
        self.assertEqual(self.form.url("http://target/x/y"), "http://target/auth/login")
        empty = self.doc.form("search")
        self.assertEqual(empty.url("http://target/login"), "http://target/login")
        self.assertEqual(empty.url(), "")

    def test_form_mapping_helpers(self):
        self.assertIn("csrf_token", self.form)
        self.assertEqual(self.form["csrf_token"], "9f8e7d6c")
        self.assertIn("POST", repr(self.form))

    def test_grab_the_csrf_token_from_a_login_page(self):
        """The whole point of the module, end to end."""
        doc = parse_html(_FakeResponse(LOGIN))
        form = doc.form()
        token = doc.query_selector('input[name="csrf_token"]')["value"]
        self.assertEqual(token, "9f8e7d6c")
        payload = form.fill(username="admin", password="admin")
        self.assertEqual(payload["csrf_token"], token)
        self.assertEqual((form.method, form.url("http://target/login")),
                         ("POST", "http://target/auth/login"))

    def test_fields_survive_a_form_with_broken_markup(self):
        doc = parse_html("""
            <form action=/x><table>
              <tr><td>User<td><input name=user value=a
              <tr><td>Pass<td><input name=pw value=b>
            </table><input type=hidden name=token value=t0k3n>
        """)
        self.assertEqual(doc.form().fields, {"user": "a", "pw": "b", "token": "t0k3n"})


class TruthinessTests(unittest.TestCase):
    """A found element is truthy -- ``__len__`` must not decide ``if el:``."""

    def setUp(self):
        self.doc = parse_html(
            '<form><input name="csrf" value="a1b2"><a href="/admin">Admin</a>'
            "<p>text</p><br></form>"
        )

    def test_leaf_elements_are_truthy(self):
        for selector in ("input[name=csrf]", "a", "p", "br", "form"):
            el = self.doc.query_selector(selector)
            self.assertTrue(el, msg=selector)
            self.assertTrue(bool(el), msg=selector)

    def test_the_found_branch_is_taken(self):
        el = self.doc.query_selector("input[name=csrf]")
        token = el["value"] if el else "missing"
        self.assertEqual(token, "a1b2")
        self.assertIs(el or "fallback", el)
        self.assertFalse(not el)

    def test_missing_elements_are_still_falsy(self):
        el = self.doc.query_selector("table")
        self.assertIsNone(el)
        self.assertFalse(el)
        self.assertEqual(el or "fallback", "fallback")

    def test_documents_are_truthy_even_when_empty(self):
        self.assertTrue(parse_html(""))
        self.assertTrue(parse_html("just text"))
        self.assertTrue(parse_html(PAGE))

    def test_len_still_counts_element_children(self):
        self.assertEqual(len(self.doc.find("form")), 4)
        self.assertEqual(len(self.doc.find("br")), 0)
        self.assertTrue(self.doc.find("br"))


class DeepNestingTests(unittest.TestCase):
    """Serialization is iterative -- markup the parser accepts must render."""

    def test_unclosed_inline_tags_serialize(self):
        doc = parse_html("<span>" * 400 + "FLAG{x}")
        self.assertEqual(doc.text, "FLAG{x}")
        self.assertEqual(len(doc.descendants), 400)
        self.assertEqual(doc.outer_html, "<span>" * 400 + "FLAG{x}" + "</span>" * 400)

    def test_deeply_nested_elements_round_trip(self):
        markup = "<div>" * 1000 + "x" + "</div>" * 1000
        doc = parse_html(markup)
        self.assertEqual(doc.outer_html, markup)
        self.assertEqual(parse_html(doc.outer_html).outer_html, doc.outer_html)
        self.assertEqual(doc.text, "x")

    def test_inner_html_of_a_deep_element(self):
        doc = parse_html("<p>" + "<b>" * 800 + "deep")
        para = doc.find("p")
        self.assertEqual(para.inner_html, "<b>" * 800 + "deep" + "</b>" * 800)
        self.assertEqual(para.find("b").outer_html.count("<b>"), 800)

    def test_deep_void_and_comment_nodes_survive(self):
        doc = parse_html("<div>" * 500 + "<img src=x><!--sknb{deep}-->")
        self.assertIn('<img src="x"/>', doc.outer_html)
        self.assertIn("<!--sknb{deep}-->", doc.outer_html)
        self.assertEqual(doc.comments, ["sknb{deep}"])


class DisabledFieldTests(unittest.TestCase):
    """A browser never submits a disabled control."""

    def test_disabled_controls_are_not_submitted(self):
        doc = parse_html(
            "<form><input name=user value=alice>"
            "<input name=role value=admin disabled>"
            "<select name=tier disabled><option value=gold>g</option></select>"
            "<textarea name=note disabled>x</textarea>"
            "<button name=act value=del disabled>d</button></form>"
        )
        self.assertEqual(doc.form().fields, {"user": "alice"})

    def test_fieldset_disables_every_descendant(self):
        doc = parse_html(
            "<form><input name=user value=alice>"
            "<fieldset disabled><input name=internal value=1>"
            "<div><input name=deeper value=2></div></fieldset></form>"
        )
        self.assertEqual(doc.form().fields, {"user": "alice"})

    def test_the_first_legend_of_a_disabled_fieldset_stays_enabled(self):
        doc = parse_html(
            "<form><fieldset disabled>"
            "<legend><input name=keep value=k></legend>"
            "<legend><input name=second value=s></legend>"
            "<input name=off value=o></fieldset></form>"
        )
        self.assertEqual(doc.form().fields, {"keep": "k"})

    def test_an_enabled_fieldset_changes_nothing(self):
        doc = parse_html("<form><fieldset><input name=a value=1></fieldset></form>")
        self.assertEqual(doc.form().fields, {"a": "1"})

    def test_disabled_still_shows_up_in_inputs_and_the_dom(self):
        doc = parse_html("<form><input name=role value=admin disabled></form>")
        form = doc.form()
        self.assertEqual([e.tag for e in form.inputs], ["input"])
        self.assertEqual(form.inputs[0]["value"], "admin")
        self.assertEqual(form.fields, {})
        self.assertNotIn("role", form)

    def test_disabled_checkbox_is_dropped_even_when_checked(self):
        doc = parse_html("<form><input type=checkbox name=adm value=1 checked disabled></form>")
        self.assertEqual(doc.form().fields, {})


class AttributeCaseTests(unittest.TestCase):
    """Legacy pages shout their attribute values -- selectors still have to match."""

    def test_uppercase_type_is_found(self):
        doc = parse_html('<!doctype html><form><INPUT TYPE="Hidden" NAME=csrf VALUE=tok></form>')
        self.assertIsNotNone(doc.query_selector("input[type=hidden]"))
        self.assertEqual(len(doc.query_selector_all("input[type=hidden]")), 1)
        self.assertEqual(doc.query_selector("input[type=hidden]")["value"], "tok")

    def test_other_case_insensitive_attributes(self):
        self.assertEqual(len(parse_html("<form method=POST></form>")
                             .find_all("form[method=post]")), 1)
        self.assertEqual(len(parse_html("<a rel=NOFOLLOW>x</a>").find_all("a[rel=nofollow]")), 1)
        self.assertEqual(len(parse_html("<p LANG=EN>x</p>").find_all('[lang|="en"]')), 1)
        self.assertEqual(len(parse_html("<form enctype=Multipart/Form-Data>").find_all(
            '[enctype^="multipart"]')), 1)

    def test_matching_folds_in_both_directions(self):
        doc = parse_html("<input type=text><input type=checkbox>")
        self.assertEqual(len(doc.find_all("[type=TEXT]")), 1)
        self.assertEqual(len(doc.find_all("[type=CheckBox]")), 1)

    def test_the_s_flag_asks_for_case_sensitivity_back(self):
        doc = parse_html('<INPUT TYPE="Hidden" name=csrf>')
        self.assertEqual(doc.find_all("input[type=hidden s]"), [])
        self.assertEqual(len(doc.find_all("input[type=Hidden s]")), 1)
        self.assertEqual(len(doc.find_all("input[type=hidden i]")), 1)

    def test_href_id_class_and_data_stay_case_sensitive(self):
        doc = parse_html('<a href="/ADM" id="Main" class="Btn" data-role="X">x</a>')
        self.assertEqual(doc.find_all('[href="/adm"]'), [])
        self.assertEqual(doc.find_all("#main"), [])
        self.assertEqual(doc.find_all(".btn"), [])
        self.assertEqual(doc.find_all('[data-role="x"]'), [])
        self.assertEqual(doc.find_all('[name=CSRF]'), [])
        self.assertEqual(len(doc.find_all('[href="/ADM"][data-role="X"]')), 1)


class SelectorPerformanceTests(unittest.TestCase):
    """Sibling and :nth-* matching must not rescan the parent for every node."""

    def timed(self, doc, selector):
        start = time.monotonic()
        found = doc.query_selector_all(selector)
        return found, time.monotonic() - start

    def test_general_sibling_over_a_long_row(self):
        doc = parse_html("<div><a></a>" + "<p>x</p>" * 2000 + "</div>")
        found, taken = self.timed(doc, "a ~ p")
        self.assertEqual(len(found), 2000)
        self.assertLess(taken, 4.0)          # ~17s before the index cache

    def test_sibling_combinator_over_a_long_table(self):
        doc = parse_html("<table><thead></thead>" + "<tr><td>x</td></tr>" * 1500 + "</table>")
        found, taken = self.timed(doc, "thead ~ tr")
        self.assertEqual(len(found), 1500)
        self.assertLess(taken, 4.0)          # ~7s before the index cache

    def test_nth_child_over_a_long_list(self):
        doc = parse_html("<ul>" + "<li>x</li>" * 4000 + "</ul>")
        found, taken = self.timed(doc, "li:nth-child(odd)")
        self.assertEqual(len(found), 2000)
        self.assertLess(taken, 0.5)          # ~1.3s before the position cache

    def test_adjacent_sibling_over_a_long_row(self):
        doc = parse_html("<div>" + "<p>x</p>" * 2000 + "</div>")
        found, taken = self.timed(doc, "p + p")
        self.assertEqual(len(found), 1999)
        self.assertLess(taken, 0.5)


class SiblingCacheTests(unittest.TestCase):
    """The cached indexes must not go stale when the tree is edited."""

    def test_traversal_of_a_long_row_is_correct(self):
        doc = parse_html("<div>" + "".join(f"<p>{i}</p>" for i in range(50)) + "</div>")
        kids = doc.find("div").children
        self.assertEqual([k.next_element_sibling for k in kids[:-1]], kids[1:])
        self.assertEqual([k.previous_element_sibling for k in kids[1:]], kids[:-1])
        self.assertIsNone(kids[-1].next_element_sibling)
        self.assertIs(kids[7].previous_sibling, kids[6])
        self.assertIs(kids[7].previous_sibling.previous_sibling, kids[5])

    def test_edits_invalidate_the_cached_positions(self):
        doc = parse_html("<ul><li>a</li><li>b</li></ul>")
        ul = doc.find("ul")
        first = ul.children[0]
        self.assertEqual([e.text for e in doc.find_all("li:first-child")], ["a"])
        self.assertIs(first.next_element_sibling, ul.children[1])

        extra = Element("li")
        extra.child_nodes.append(Text("z"))
        extra.parent = ul
        ul.child_nodes.insert(0, extra)

        self.assertEqual([e.text for e in doc.find_all("li:first-child")], ["z"])
        self.assertEqual([e.text for e in doc.find_all("li:nth-child(2)")], ["a"])
        self.assertIs(extra.next_element_sibling, first)
        self.assertIs(first.previous_element_sibling, extra)
        self.assertEqual(len(doc.find_all("li:last-child")), 1)

    def test_text_nodes_between_elements_are_skipped(self):
        doc = parse_html("<div>  <p>a</p> <!--c--> <p>b</p>  </div>")
        paras = doc.find_all("p")
        self.assertIs(paras[0].next_element_sibling, paras[1])
        self.assertIs(paras[1].previous_element_sibling, paras[0])
        self.assertIsInstance(paras[0].next_sibling, Text)
        self.assertEqual([e.text for e in doc.find_all("p:nth-child(1)")], ["a"])
        self.assertEqual([e.text for e in doc.find_all("p + p")], ["b"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
