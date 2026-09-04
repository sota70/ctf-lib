"""URL codec tests -- every expectation is what node/the browser actually prints."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ctflib.urlcodec import (
    add_params,
    decode_all,
    decode_uri,
    decode_uri_component,
    decodeURI,
    decodeURIComponent,
    double_encode,
    encode_uri,
    encode_uri_component,
    encodeURI,
    encodeURIComponent,
    form_decode,
    form_encode,
    parse,
    parse_qs,
    parse_qsl,
    qs_parse,
    qs_stringify,
    stringify,
    url_join,
    url_parse,
    urldecode,
    urlencode,
)

#: the string every JS reference uses -- exercises the whole reserved set at once.
MIXED = "a b&c=d/e?f#g!~*'()"


class EncodeTests(unittest.TestCase):
    def test_unreserved_set_is_never_escaped(self):
        safe = "abcXYZ012-_.!~*'()"
        self.assertEqual(encode_uri_component(safe), safe)
        self.assertEqual(encode_uri(safe), safe)

    def test_component_matches_the_browser(self):
        self.assertEqual(encode_uri_component(MIXED), "a%20b%26c%3Dd%2Fe%3Ff%23g!~*'()")

    def test_encode_uri_matches_the_browser(self):
        self.assertEqual(encode_uri(MIXED), "a%20b&c=d/e?f#g!~*'()")

    def test_the_two_differ_exactly_on_the_reserved_set(self):
        reserved = ";/?:@&=+$,#"
        self.assertEqual(encode_uri(reserved), reserved)
        self.assertEqual(
            encode_uri_component(reserved),
            "%3B%2F%3F%3A%40%26%3D%2B%24%2C%23",
        )
        # everything outside the reserved set is treated identically by both
        for char in "\"'`\\| {}[]^<>%":
            self.assertEqual(encode_uri(char), encode_uri_component(char), char)

    def test_hex_digits_are_uppercase(self):
        self.assertEqual(encode_uri_component("/"), "%2F")
        self.assertEqual(encode_uri_component("<script>"), "%3Cscript%3E")
        self.assertNotIn("%2f", encode_uri_component("/"))

    def test_space_is_percent_twenty_not_plus(self):
        self.assertEqual(encode_uri_component("a b"), "a%20b")
        self.assertEqual(encode_uri_component("a+b"), "a%2Bb")

    def test_multibyte_utf8(self):
        self.assertEqual(encode_uri_component("日本語"), "%E6%97%A5%E6%9C%AC%E8%AA%9E")
        self.assertEqual(encode_uri("日本語"), "%E6%97%A5%E6%9C%AC%E8%AA%9E")

    def test_emoji_is_four_bytes(self):
        self.assertEqual(encode_uri_component("😀"), "%F0%9F%98%80")

    def test_bytes_are_encoded_byte_for_byte(self):
        self.assertEqual(encode_uri_component(b"\xff\x00"), "%FF%00")
        # already utf-8 bytes -> same answer as the str, no double encoding
        self.assertEqual(encode_uri_component("日".encode("utf-8")), encode_uri_component("日"))

    def test_lone_surrogate_does_not_crash(self):
        out = encode_uri_component("\ud800")  # JS would throw URIError here
        self.assertEqual(out, "%ED%A0%80")

    def test_response_like_objects_are_accepted(self):
        class FakeResponse:
            text = "a b"

        self.assertEqual(encode_uri_component(FakeResponse()), "a%20b")


class DecodeTests(unittest.TestCase):
    def test_decode_uri_component_decodes_everything(self):
        self.assertEqual(decode_uri_component("a%20b%26c%3Dd%2Fe%3Ff%23g"), "a b&c=d/e?f#g")

    def test_decode_uri_keeps_the_reserved_escapes(self):
        self.assertEqual(decode_uri("a%20b%26c%3Dd%2Fe%3Ff%23g"), "a b%26c%3Dd%2Fe%3Ff%23g")

    def test_every_reserved_escape_survives_decode_uri(self):
        for escape in ("%23", "%24", "%26", "%2B", "%2C", "%2F", "%3A", "%3B", "%3D", "%3F", "%40"):
            self.assertEqual(decode_uri(escape), escape)
            self.assertEqual(len(decode_uri_component(escape)), 1)

    def test_decode_uri_preserves_the_original_escape_spelling(self):
        self.assertEqual(decode_uri("%2f%2F"), "%2f%2F")
        self.assertEqual(decode_uri_component("%2f%2F"), "//")

    def test_decode_uri_still_decodes_the_unreserved_ones(self):
        self.assertEqual(decode_uri("%3Cscript%3E"), "<script>")
        self.assertEqual(decode_uri("%25"), "%")

    def test_decode_multibyte(self):
        self.assertEqual(decode_uri_component("%E6%97%A5%E6%9C%AC%E8%AA%9E"), "日本語")
        self.assertEqual(decode_uri("%F0%9F%98%80"), "😀")

    def test_literal_non_ascii_passes_through(self):
        self.assertEqual(decode_uri_component("日%41"), "日A")

    def test_decode_accepts_bytes(self):
        self.assertEqual(decode_uri_component(b"%E6%97%A5"), "日")
        self.assertEqual(decode_uri_component("日".encode("utf-8")), "日")

    def test_round_trip_component(self):
        for original in (MIXED, "日本語 😀", "' OR 1=1--", "\x00\x7f"):
            self.assertEqual(decode_uri_component(encode_uri_component(original)), original)

    def test_round_trip_uri(self):
        url = "http://x/a b?q=1&r=2#f"
        self.assertEqual(encode_uri(url), "http://x/a%20b?q=1&r=2#f")
        self.assertEqual(decode_uri(encode_uri(url)), url)


class BadEscapeTests(unittest.TestCase):
    def test_lenient_leaves_broken_escapes_alone(self):
        self.assertEqual(decode_uri_component("%zz"), "%zz")
        self.assertEqual(decode_uri_component("%4"), "%4")
        self.assertEqual(decode_uri_component("100%"), "100%")
        self.assertEqual(decode_uri_component("a%%20b"), "a% b")

    def test_lenient_applies_to_decode_uri_too(self):
        self.assertEqual(decode_uri("%g1%2F"), "%g1%2F")

    def test_strict_raises_on_broken_escapes(self):
        for bad in ("%zz", "%4", "100%"):
            with self.assertRaises(ValueError):
                decode_uri_component(bad, strict=True)
            with self.assertRaises(ValueError):
                decode_uri(bad, strict=True)

    def test_strict_accepts_a_valid_string(self):
        self.assertEqual(decode_uri_component("%41%20b", strict=True), "A b")

    def test_undecodable_utf8_is_replaced_not_fatal(self):
        self.assertEqual(decode_uri_component("%FF%FE"), "��")
        self.assertEqual(decode_uri_component("%E6%97"), "�")

    def test_undecodable_utf8_raises_when_strict(self):
        with self.assertRaises(ValueError):
            decode_uri_component("%FF", strict=True)


class AliasTests(unittest.TestCase):
    def test_js_spellings_are_the_same_functions(self):
        self.assertIs(encodeURIComponent, encode_uri_component)
        self.assertIs(decodeURIComponent, decode_uri_component)
        self.assertIs(encodeURI, encode_uri)
        self.assertIs(decodeURI, decode_uri)
        self.assertIs(qs_stringify, stringify)
        self.assertIs(qs_parse, parse)


class QueryStringTests(unittest.TestCase):
    def test_urlencode_uses_plus_by_default(self):
        self.assertEqual(urlencode({"q": "1 2"}), "q=1+2")

    def test_urlencode_plus_false_uses_percent_twenty(self):
        self.assertEqual(urlencode({"q": "1 2"}, plus=False), "q=1%202")

    def test_urlencode_repeats_list_values(self):
        self.assertEqual(urlencode({"a": 1, "b": ["x", "y z"]}), "a=1&b=x&b=y+z")

    def test_urlencode_takes_pairs_and_honours_safe(self):
        self.assertEqual(urlencode([("a", "1"), ("a", "2")]), "a=1&a=2")
        self.assertEqual(urlencode({"p": "/etc/passwd"}, safe="/"), "p=/etc/passwd")

    def test_urlencode_passes_a_ready_made_body_through(self):
        self.assertEqual(urlencode("id=1' UNION SELECT--"), "id=1' UNION SELECT--")

    def test_urlencode_passes_raw_bytes_through_byte_for_byte(self):
        # a padding-oracle / shellcode body is not utf-8 and must survive verbatim
        body = b"user=admin&sig=\xde\xad\xbe\xef"
        self.assertEqual(urlencode(body), body)
        self.assertIsInstance(urlencode(body), bytes)
        self.assertEqual(len(urlencode(body)), len(body))  # content-length must not move
        self.assertNotIn("�", urlencode(body).decode("latin-1"))

    def test_urlencode_bytes_passthrough_covers_every_buffer_type(self):
        body = b"\x00\xff\x80"
        self.assertEqual(urlencode(bytearray(body)), body)
        self.assertEqual(urlencode(memoryview(body)), body)

    def test_urlencode_str_body_stays_a_str(self):
        self.assertIsInstance(urlencode("a=1"), str)

    def test_urldecode_last_value_wins_and_blanks_are_kept(self):
        self.assertEqual(urldecode("a=1&a=2&b="), {"a": "2", "b": ""})
        self.assertEqual(urldecode("a"), {"a": ""})

    def test_parse_qs_keeps_every_value(self):
        self.assertEqual(parse_qs("a=1&a=2&b="), {"a": ["1", "2"], "b": [""]})

    def test_parse_qsl_keeps_order(self):
        self.assertEqual(parse_qsl("b=2&a=1&b=3"), [("b", "2"), ("a", "1"), ("b", "3")])

    def test_parse_decodes_plus_and_escapes(self):
        self.assertEqual(parse_qsl("q=1+2%263"), [("q", "1 2&3")])
        self.assertEqual(parse_qsl("q=1+2", plus=False), [("q", "1+2")])

    def test_a_leading_question_mark_is_ignored(self):
        self.assertEqual(parse_qs("?a=1"), {"a": ["1"]})
        self.assertEqual(urldecode("?a=1"), {"a": "1"})

    def test_strip_q_false_keeps_a_leading_question_mark_in_the_first_name(self):
        # url_parse("http://h/p??a=1").query is literally "?a=1" -- the '?' is a name char
        self.assertEqual(parse_qsl("?a=1", strip_q=False), [("?a", "1")])
        self.assertEqual(parse_qs("?a=1", strip_q=False), {"?a": ["1"]})
        self.assertEqual(urldecode("?a=1", strip_q=False), {"?a": "1"})
        self.assertEqual(parse("?a=1", strip_q=False), {"?a": "1"})

    def test_strip_q_false_is_a_no_op_without_a_leading_question_mark(self):
        self.assertEqual(parse_qsl("a=1&b=2", strip_q=False), [("a", "1"), ("b", "2")])

    def test_a_split_query_round_trips_through_url_parse(self):
        query = url_parse("http://h/p??a=1").query
        self.assertEqual(parse_qsl(query, strip_q=False), [("?a", "1")])

    def test_parse_qs_round_trips_repeated_keys(self):
        pairs = [("a", "1"), ("a", "2 3"), ("b", "&=")]
        self.assertEqual(parse_qsl(urlencode(pairs)), pairs)
        self.assertEqual(parse_qs(urlencode(pairs)), {"a": ["1", "2 3"], "b": ["&="]})

    def test_stringify_matches_node(self):
        self.assertEqual(
            stringify({"a": "1 2", "b": [1, 2], "c": None, "d": True}),
            "a=1%202&b=1&b=2&c=&d=true",
        )

    def test_stringify_custom_separators(self):
        self.assertEqual(stringify({"a": "1", "b": "2"}, sep=";", eq=":"), "a:1;b:2")
        self.assertEqual(parse("a:1;b:2", sep=";", eq=":"), {"a": "1", "b": "2"})

    def test_parse_collapses_single_values_like_node(self):
        self.assertEqual(parse("a=1&b=2&b=3&c"), {"a": "1", "b": ["2", "3"], "c": ""})

    def test_form_encode_decode_pair(self):
        self.assertEqual(form_encode("a b&c"), "a%20b%26c")
        self.assertEqual(form_encode("a b&c", plus=True), "a+b%26c")
        self.assertEqual(form_decode("a%20b%26c"), "a b&c")
        self.assertEqual(form_decode("a+b", plus=True), "a b")
        self.assertEqual(form_decode("a+b"), "a+b")


class CtfHelperTests(unittest.TestCase):
    def test_double_encode(self):
        self.assertEqual(double_encode("../"), "..%252F")
        self.assertEqual(double_encode("<"), "%253C")

    def test_decode_all_unwraps_every_layer(self):
        self.assertEqual(decode_all("%25252e%25252e%25252f"), "../")
        self.assertEqual(decode_all(double_encode("../")), "../")

    def test_decode_all_stops_and_never_chokes(self):
        self.assertEqual(decode_all("plain"), "plain")
        self.assertEqual(decode_all("100%"), "100%")
        # one round short of fully decoded, and no exception either way
        self.assertEqual(decode_all("%2525252F", max_rounds=2), "%252F")

    def test_add_params_preserves_existing_query(self):
        self.assertEqual(add_params("/x?a=1", {"b": "2 3"}), "/x?a=1&b=2+3")
        self.assertEqual(
            add_params("http://h/p?a=1&a=2", [("b", "3")]),
            "http://h/p?a=1&a=2&b=3",
        )

    def test_add_params_can_duplicate_an_existing_key(self):
        self.assertEqual(add_params("/x?id=1", {"id": "2"}), "/x?id=1&id=2")

    def test_add_params_keeps_the_fragment_and_no_op_on_empty(self):
        self.assertEqual(add_params("/x?a=1#frag", {"b": "2"}), "/x?a=1&b=2#frag")
        self.assertEqual(add_params("/x?a=1", None), "/x?a=1")
        self.assertEqual(add_params("/x", {}), "/x")

    def test_add_params_keeps_a_question_mark_that_starts_the_first_name(self):
        # node: new URL("http://h/p??a=1") -> [["?a","1"]], append z -> ?%3Fa=1&z=1
        self.assertEqual(add_params("http://h/p??a=1", {"z": "1"}), "http://h/p?%3Fa=1&z=1")
        # the merging path and the no-op path must agree on what the params are
        merged = url_parse(add_params("http://h/p??a=1", {"z": "1"})).query
        untouched = url_parse(add_params("http://h/p??a=1", None)).query
        self.assertEqual(parse_qs(merged, strip_q=False), {"?a": ["1"], "z": ["1"]})
        self.assertEqual(parse_qs(untouched, strip_q=False), {"?a": ["1"]})

    def test_add_params_keeps_a_hash_that_starts_the_first_name(self):
        self.assertEqual(add_params("/p?%23a=1", {"z": "1"}), "/p?%23a=1&z=1")

    def test_add_params_on_a_url_with_no_query(self):
        self.assertEqual(add_params("http://h/p", {"a": "1"}), "http://h/p?a=1")

    def test_url_join(self):
        self.assertEqual(url_join("http://x/a/b", "../c?d=1"), "http://x/c?d=1")
        self.assertEqual(url_join("http://x/a/b", "/root"), "http://x/root")

    def test_url_parse_exposes_the_pieces(self):
        parts = url_parse("http://user:pw@x:8080/p/q?a=1&a=2#frag")
        self.assertEqual(parts.scheme, "http")
        self.assertEqual(parts.hostname, "x")
        self.assertEqual(parts.port, 8080)
        self.assertEqual(parts.path, "/p/q")
        self.assertEqual(parts.fragment, "frag")
        self.assertEqual(parse_qs(parts.query), {"a": ["1", "2"]})
        self.assertEqual(parts.geturl(), "http://user:pw@x:8080/p/q?a=1&a=2#frag")


if __name__ == "__main__":
    unittest.main(verbosity=2)
