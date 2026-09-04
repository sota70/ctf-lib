"""Tests for ctflib.b64 -- the Node-flavoured, forgiving base64 helpers."""

import base64
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ctflib.b64 import (
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


class _FakeResponse:
    """Minimal Response stand-in -- .content wins over .text."""

    def __init__(self, content=None, text=None):
        if content is not None:
            self.content = content
        self.text = text


def _random_blobs(seed=1337, count=40):
    rng = random.Random(seed)
    return [bytes(rng.randrange(256) for _ in range(rng.randrange(0, 65))) for _ in range(count)]


class EncodeTests(unittest.TestCase):
    def test_str_is_utf8_encoded(self):
        self.assertEqual(b64encode("admin"), "YWRtaW4=")
        self.assertEqual(b64encode("café"), base64.b64encode("café".encode()).decode())

    def test_bytes_and_bytearray(self):
        self.assertEqual(b64encode(b"admin"), "YWRtaW4=")
        self.assertEqual(b64encode(bytearray(b"admin")), "YWRtaW4=")

    def test_response_prefers_content(self):
        self.assertEqual(b64encode(_FakeResponse(b"admin", "ignored")), "YWRtaW4=")

    def test_response_falls_back_to_text(self):
        self.assertEqual(b64encode(_FakeResponse(text="admin")), "YWRtaW4=")

    def test_urlsafe_alphabet(self):
        raw = b"\xfb\xef\xbe"
        self.assertEqual(b64encode(raw), "++++")
        self.assertEqual(b64encode(b"\xff\xef\xbe"), "/+++")
        self.assertEqual(b64encode(b"\xff\xef\xbe", urlsafe=True), "_---")

    def test_padding_can_be_stripped(self):
        self.assertEqual(b64encode("a"), "YQ==")
        self.assertEqual(b64encode("a", padding=False), "YQ")
        self.assertEqual(b64encode("abc", padding=False), "YWJj")

    def test_wrap_inserts_newlines(self):
        wrapped = b64encode(b"A" * 100, wrap=76)
        lines = wrapped.split("\n")
        self.assertEqual(max(len(line) for line in lines), 76)
        self.assertEqual(wrapped.replace("\n", ""), b64encode(b"A" * 100))

    def test_wrap_smaller_than_output(self):
        self.assertEqual(b64encode("admin", wrap=4), "YWRt\naW4=")

    def test_empty_input(self):
        self.assertEqual(b64encode(b""), "")
        self.assertEqual(b64encode(None), "")


class RoundTripTests(unittest.TestCase):
    def test_round_trip_standard_padded(self):
        for raw in _random_blobs():
            self.assertEqual(b64decode(b64encode(raw)), raw)

    def test_round_trip_standard_unpadded(self):
        for raw in _random_blobs(seed=7):
            self.assertEqual(b64decode(b64encode(raw, padding=False)), raw)

    def test_round_trip_urlsafe_both_paddings(self):
        for raw in _random_blobs(seed=99):
            self.assertEqual(b64decode(b64encode(raw, urlsafe=True)), raw)
            self.assertEqual(b64decode(b64encode(raw, urlsafe=True, padding=False)), raw)

    def test_round_trip_every_byte_value(self):
        raw = bytes(range(256))
        self.assertEqual(b64decode(b64encode(raw)), raw)
        self.assertEqual(b64url_decode(b64url_encode(raw)), raw)

    def test_round_trip_survives_wrapping(self):
        for raw in _random_blobs(seed=5, count=10):
            self.assertEqual(b64decode(b64encode(raw, wrap=8)), raw)


class LenientDecodeTests(unittest.TestCase):
    def test_missing_padding(self):
        self.assertEqual(b64decode("aGk"), b"hi")
        self.assertEqual(b64decode("YQ"), b"a")
        self.assertEqual(b64decode("YWRtaW4"), b"admin")

    def test_urlsafe_input(self):
        raw = b"\xff\xef\xbe\x00"
        self.assertEqual(b64decode(b64encode(raw, urlsafe=True)), raw)
        self.assertEqual(b64decode("_---AA=="), raw)

    def test_mixed_alphabets(self):
        self.assertEqual(b64decode("_+-/AA=="), b64decode("/++/AA=="))
        self.assertEqual(b64decode("_+-/AA=="), b"\xff\xef\xbf\x00")

    def test_whitespace_and_newlines_ignored(self):
        self.assertEqual(b64decode("YWRt\n aW4=\r\n"), b"admin")
        self.assertEqual(b64decode("  Y W R t a W 4  "), b"admin")

    def test_garbage_characters_ignored(self):
        self.assertEqual(b64decode("!!YWRt<>aW4=!!"), b"admin")
        self.assertEqual(b64decode('"YWRtaW4="'), b"admin")

    def test_trailing_single_char_dropped(self):
        self.assertEqual(b64decode("YWRtaW4x1"), b"admin1")  # 9 chars -- last one dropped
        self.assertEqual(b64decode("A"), b"")

    def test_padding_terminates_the_payload(self):
        self.assertEqual(b64decode("YWRtaW4=X"), b"admin")
        self.assertEqual(b64decode("YWRtaW4=\ntrailing junk"), b"admin")

    def test_bytes_input(self):
        self.assertEqual(b64decode(b"YWRtaW4="), b"admin")
        self.assertEqual(b64decode(bytearray(b"YWRtaW4")), b"admin")

    def test_response_like_input(self):
        self.assertEqual(b64decode(_FakeResponse(text="YWRtaW4=")), b"admin")

    def test_empty_and_junk_only(self):
        self.assertEqual(b64decode(""), b"")
        self.assertEqual(b64decode("!!!!"), b"")
        self.assertEqual(b64decode(None), b"")


class StrictDecodeTests(unittest.TestCase):
    def test_strict_accepts_clean_input(self):
        self.assertEqual(b64decode("YWRtaW4=", strict=True), b"admin")
        self.assertEqual(b64decode("_---AA==", strict=True), b"\xff\xef\xbe\x00")

    def test_strict_rejects_missing_padding(self):
        with self.assertRaises(ValueError):
            b64decode("YWRtaW4", strict=True)

    def test_strict_rejects_whitespace_and_garbage(self):
        with self.assertRaises(ValueError):
            b64decode("YWRt aW4=", strict=True)
        with self.assertRaises(ValueError):
            b64decode("YWR!aW4=", strict=True)

    def test_strict_rejects_mixed_alphabets(self):
        with self.assertRaises(ValueError):
            b64decode("_+-/AA==", strict=True)

    def test_strict_rejects_lone_trailing_char(self):
        with self.assertRaises(ValueError):
            b64decode("YWRtaW4=X", strict=True)


class TextDecodeTests(unittest.TestCase):
    def test_text_true_returns_str(self):
        self.assertEqual(b64decode("YWRtaW4=", text=True), "admin")
        self.assertIsInstance(b64decode("YWRtaW4=", text=True), str)

    def test_text_replaces_invalid_utf8(self):
        blob = b64encode(b"ok\xff\xfe")
        self.assertEqual(b64decode(blob, text=True), "ok��")

    def test_text_honours_encoding_and_errors(self):
        blob = b64encode(b"caf\xe9")
        self.assertEqual(b64decode(blob, text=True, encoding="latin-1"), "café")
        with self.assertRaises(UnicodeDecodeError):
            b64decode(blob, text=True, errors="strict")

    def test_b64decode_str(self):
        self.assertEqual(b64decode_str("aGk"), "hi")
        self.assertEqual(b64decode_str(b64encode(b"\xff"), encoding="latin-1"), "\xff")


class BrowserApiTests(unittest.TestCase):
    def test_atob_basic(self):
        self.assertEqual(atob("YWRtaW4="), "admin")
        self.assertEqual(atob("YWRtaW4"), "admin")

    def test_atob_is_latin1(self):
        self.assertEqual(atob(base64.b64encode(b"caf\xe9").decode()), "café")

    def test_btoa_basic(self):
        self.assertEqual(btoa("admin"), "YWRtaW4=")
        self.assertEqual(btoa("café"), base64.b64encode(b"caf\xe9").decode())

    def test_btoa_rejects_code_point_above_255(self):
        with self.assertRaises(ValueError):
            btoa("日本")
        with self.assertRaises(ValueError):
            btoa("cafĀ")

    def test_atob_btoa_round_trip(self):
        for raw in _random_blobs(seed=42, count=15):
            binary = raw.decode("latin-1")
            self.assertEqual(atob(btoa(binary)), binary)


class UrlSafeHelperTests(unittest.TestCase):
    def test_b64url_encode_is_unpadded(self):
        self.assertEqual(b64url_encode("a"), "YQ")
        self.assertNotIn("=", b64url_encode(b"\xff\xef\xbe\x00"))
        self.assertEqual(b64url_encode(b"\xff\xef\xbe"), "_---")

    def test_b64url_round_trip_jwt_style(self):
        header = b64url_encode('{"alg":"none"}')
        self.assertEqual(b64url_decode(header), b'{"alg":"none"}')
        self.assertEqual(b64url_decode(header, text=True), '{"alg":"none"}')


class IsB64Tests(unittest.TestCase):
    def test_true_cases(self):
        self.assertTrue(is_b64("YWRtaW4="))
        self.assertTrue(is_b64("YWRtaW4"))
        self.assertTrue(is_b64(b"YWRtaW4="))
        self.assertTrue(is_b64(b64encode(b"A" * 100, wrap=76)))

    def test_false_cases(self):
        self.assertFalse(is_b64(""))
        self.assertFalse(is_b64("   "))
        self.assertFalse(is_b64("hello world!"))
        self.assertFalse(is_b64("YWRtaW4=extra"))
        self.assertFalse(is_b64("YWRtaW4=="))  # too much padding for the length
        self.assertFalse(is_b64("YWRtaW4x1"))  # length % 4 == 1

    def test_urlsafe_flag(self):
        self.assertTrue(is_b64("_---", urlsafe=True))
        self.assertFalse(is_b64("_---", urlsafe=False))
        self.assertTrue(is_b64("/+++", urlsafe=False))
        self.assertFalse(is_b64("/+++", urlsafe=True))
        self.assertTrue(is_b64("_+-/"))  # either alphabet accepted by default


class LenTests(unittest.TestCase):
    def test_padded_length_matches_encoder(self):
        for n in range(0, 40):
            self.assertEqual(b64_len(n), len(b64encode(b"x" * n)))

    def test_unpadded_length_matches_encoder(self):
        for n in range(0, 40):
            self.assertEqual(b64_len(n, padding=False), len(b64encode(b"x" * n, padding=False)))

    def test_negative_raises(self):
        with self.assertRaises(ValueError):
            b64_len(-1)


class DecodeAllTests(unittest.TestCase):
    HTML = (
        "<html><head><title>challenge</title></head><body>\n"
        "<p>nothing to see here, move along</p>\n"
        "<!-- backup: {blob} -->\n"
        "<img src=\"data:image/gif;base64,R0lGODlhAQABAAAAACw=\">\n"
        "</body></html>\n"
    )

    def test_finds_encoded_flag_in_a_page(self):
        flag = b"sknb{b64_is_fun}"
        page = self.HTML.format(blob=b64encode(flag))
        self.assertIn(flag, b64decode_all(page))

    def test_finds_unpadded_urlsafe_flag(self):
        flag = b"sknb{url_safe_flag_here}"
        page = self.HTML.format(blob=b64url_encode(flag))
        self.assertIn(flag, b64decode_all(page))

    def test_results_are_printable_and_deduplicated(self):
        flag = b"sknb{dupe}!!"
        blob = b64encode(flag)
        page = "%s\n%s\n" % (blob, blob)
        found = b64decode_all(page)
        self.assertEqual(found.count(flag), 1)
        for raw in found:
            self.assertTrue(all(0x20 <= c < 0x7F or c in b"\t\r\n" for c in raw))

    def test_min_len_filters_short_runs(self):
        page = self.HTML.format(blob=b64encode(b"sknb{tiny}"))
        self.assertEqual(b64decode_all(page, min_len=200), [])

    def test_plain_prose_yields_nothing(self):
        prose = "The quick brown fox jumps over the lazy dog, repeatedly and loudly."
        self.assertEqual(b64decode_all(prose), [])

    # -- line wrapping: the extractor must undo it, like is_b64 does ---------- #

    WRAPPED_FLAG = b"sknb{a_flag_that_is_long_enough_to_get_wrapped_by_mime}"

    def test_finds_flag_wrapped_by_the_modules_own_encoder(self):
        # every wrap width the encoder can emit, including the MIME ones
        for wrap in (4, 10, 16, 20, 64, 76, 0):
            page = self.HTML.format(blob="\n" + b64encode(self.WRAPPED_FLAG, wrap=wrap) + "\n")
            found = b64decode_all(page)
            self.assertIn(self.WRAPPED_FLAG, found, "wrap=%d lost the flag: %r" % (wrap, found))

    def test_wrapped_flag_comes_before_its_fragments(self):
        # wrap=64 splits cleanly on a 4-char boundary, so each fragment decodes
        # to plausible ASCII -- the whole flag still has to be the first result.
        page = "<!-- backup:\n%s\n-->" % b64encode(self.WRAPPED_FLAG, wrap=64)
        self.assertEqual(b64decode_all(page)[0], self.WRAPPED_FLAG)

    def test_crlf_wrapped_blob_decodes_whole(self):
        blob = b64encode(self.WRAPPED_FLAG, wrap=64).replace("\n", "\r\n")
        body = "Content-Transfer-Encoding: base64\r\n\r\n%s\r\n" % blob
        self.assertIn(self.WRAPPED_FLAG, b64decode_all(body))

    def test_wrapped_urlsafe_unpadded_blob_decodes_whole(self):
        blob = b64url_encode(self.WRAPPED_FLAG)
        wrapped = "\n".join(blob[i:i + 20] for i in range(0, len(blob), 20))
        self.assertIn(self.WRAPPED_FLAG, b64decode_all("<pre>\n%s\n</pre>" % wrapped))

    def test_separate_blobs_on_separate_lines_are_still_found(self):
        first, second = b64encode(b"sknb{line_one}"), b64encode(b"sknb{line_two}")
        found = b64decode_all("%s\n%s\n" % (first, second))
        self.assertIn(b"sknb{line_one}", found)
        self.assertIn(b"sknb{line_two}", found)


class AliasTests(unittest.TestCase):
    def test_short_aliases(self):
        self.assertIs(b64e, b64encode)
        self.assertIs(b64d, b64decode)
        self.assertEqual(b64d(b64e("admin")), b"admin")


if __name__ == "__main__":
    unittest.main()
