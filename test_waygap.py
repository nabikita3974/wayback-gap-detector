#!/usr/bin/env python3
"""
Wayback Gap Detector - Unit Tests
Tests for each feature of waygap.py.

Key expectations are pinned literal strings verified against surt 0.3.1
with the DNS-free canonicalizer chain (canonicalize_nodns + IA tips).
Numeric-shaped hosts are covered explicitly (they are the only place
where our keys intentionally diverge from surt's gethostbyname_ex path).
"""

import contextlib
import io
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import pytest
import requests
from surt import surt as upstream_surt

import waygap
from waygap import (
    CDX_COLLAPSE,
    CDX_COLLAPSE_STRICT,
    CDX_FILTER,
    CDX_FL,
    DB_SCHEMA_VERSION,
    DEFAULT_WORKERS,
    RESUMEKEY_FETCH_VERSION,
    USER_AGENT,
    CacheError,
    CDXAPIError,
    InputFileError,
    __version__,
    _cdx_params,
    _get_with_retries,
    _RateLimiter,
    _split_resume_key,
    archived_columns,
    build_key_opts,
    count_archived,
    detect_not_archived,
    ensure_archived_db,
    expected_meta,
    extract_archived_urls,
    fetch_page_rows,
    fetch_resumekey_rows,
    get_num_pages,
    insert_urls,
    key_profile,
    main,
    normalize_key,
    open_db,
    read_meta,
    scan_input_against_db,
    write_meta,
)


def _json_response(payload):
    """Build a mocked requests.Response returning `payload` as JSON."""
    m = MagicMock()
    body = json.dumps(payload).encode("utf-8")
    m.content = body
    m.text = json.dumps(payload) if not isinstance(payload, int) else str(payload)
    m.headers = {"Content-Type": "application/json"}
    m.status_code = 200
    m.json.return_value = payload
    m.raise_for_status.return_value = None
    return m


@pytest.fixture(autouse=True)
def _no_cdx_throttle(monkeypatch):
    """Disable the CDX request interval so tests do not sleep."""
    monkeypatch.setattr(waygap, "_CDX_LIMITER", _RateLimiter(0))


class TestBuildKeyOpts(unittest.TestCase):
    """Tests for the lenient/strict flag mapping into surt options."""

    def test_default_is_lenient(self):
        self.assertEqual(build_key_opts(True, True), {})

    def test_no_ignore_protocol_keeps_scheme(self):
        self.assertEqual(build_key_opts(False, True), {"with_scheme": True})

    def test_no_ignore_www_keeps_www(self):
        self.assertEqual(build_key_opts(True, False), {"host_massage": False})

    def test_no_ignore_both(self):
        self.assertEqual(
            build_key_opts(False, False),
            {"host_massage": False, "with_scheme": True},
        )

    def test_key_profile_stable(self):
        self.assertEqual(key_profile({}), "surt-default")
        self.assertEqual(
            key_profile({"host_massage": False}), "surt:host_massage=False"
        )
        self.assertEqual(
            key_profile({"host_massage": False, "with_scheme": True}),
            "surt:host_massage=False,with_scheme=True",
        )


class TestNormalizeKey(unittest.TestCase):
    """Tests for surt-key normalization (lenient mode: surt defaults)."""

    def test_blank_inputs_map_to_sentinel(self):
        self.assertEqual(normalize_key(""), "-")
        self.assertEqual(normalize_key("   "), "-")

    def test_readme_example(self):
        self.assertEqual(
            normalize_key("http://archive.org/goo/?a=2&b&a=1"),
            "org,archive)/goo?a=1&a=2&b",
        )

    def test_whitespace_and_case(self):
        self.assertEqual(
            normalize_key("  HTTPS://Example.com/Path  "), "com,example)/path"
        )

    def test_multipart_host_target(self):
        self.assertEqual(
            normalize_key("https://blog.example.net/articles/2024/hello/"),
            "net,example,blog)/articles/2024/hello",
        )

    def test_fragment_removed(self):
        self.assertEqual(normalize_key("http://a/b#frag"), "a)/b")

    def test_userinfo_removed(self):
        self.assertEqual(normalize_key("http://u:p@a/b"), "a)/b")

    def test_default_port_removed(self):
        self.assertEqual(normalize_key("http://example.com:80/x"), "com,example)/x")

    def test_non_default_port_kept(self):
        self.assertEqual(
            normalize_key("http://example.com:8080/x"), "com,example:8080)/x"
        )

    def test_www_massaged(self):
        self.assertEqual(normalize_key("http://www.example.com/"), "com,example)/")

    def test_wwwN_massaged(self):
        self.assertEqual(
            normalize_key("https://www2.example.com/Deep/Path"),
            "com,example)/deep/path",
        )

    def test_query_sorted_and_lowercased(self):
        self.assertEqual(
            normalize_key("https://example.com/page?Z=3&A=1"),
            "com,example)/page?a=1&z=3",
        )

    def test_query_valueless_and_duplicate_preserved(self):
        self.assertEqual(
            normalize_key("http://a.com/p?b=2&a=1&foo&foo=1"),
            "com,a)/p?a=1&b=2&foo&foo=1",
        )

    def test_query_blank_removed(self):
        self.assertEqual(
            normalize_key("https://example.com/page?"), "com,example)/page"
        )

    def test_percent_decoding(self):
        self.assertEqual(
            normalize_key("https://example.com/%7Euser/test"), "com,example)/~user/test"
        )
        # %2F is decoded to "/" by surt (documented, non-reversible).
        self.assertEqual(normalize_key("https://example.com/x%2fY"), "com,example)/x/y")

    def test_root_query_kept(self):
        self.assertEqual(normalize_key("http://a/?x=1"), "a)/?x=1")

    def test_dot_segments(self):
        self.assertEqual(normalize_key("http://a/x/../y"), "a)/y")

    def test_repeated_slash_collapsed(self):
        self.assertEqual(normalize_key("http://a.example.com//"), "com,example,a)/")

    def test_session_id_query_stripped(self):
        # Upstream wart: the leading "&" is kept verbatim after the strip.
        self.assertEqual(
            normalize_key("http://a/p?y=2&jsessionid=ABCDEF0123456789ABCDEF0123456789"),
            "a)/p?&y=2",
        )

    def test_asp_session_id_query_stripped(self):
        self.assertEqual(
            normalize_key(
                "http://a/p?x=1&ASPSESSIONIDABCDEFGH=AAAAAAAAAAAAAAAAAAAAHHHH"
            ),
            "a)/p?&x=1",
        )

    def test_cfid_cftoken_stripped(self):
        self.assertEqual(normalize_key("http://a/p?cfid=1&cftoken=2"), "a)/p")

    def test_idn_host_punycoded(self):
        self.assertEqual(
            normalize_key("http://日本.example.com/テスト"),
            "com,example,xn--wgv71a)/%e3%83%86%e3%82%b9%e3%83%88",
        )

    def test_valid_ipv4_reversed(self):
        self.assertEqual(normalize_key("http://1.2.3.4/x"), "4,3,2,1)/x")

    def test_all_digit_host_masked(self):
        self.assertEqual(normalize_key("http://989137925/x"), "5,12,245,58)/x")

    def test_invalid_numeric_dotted_host_no_dns(self):
        """Numerically shaped non-IPs pass through without any DNS query."""
        with patch(
            "socket.gethostbyname_ex",
            side_effect=AssertionError("DNS lookup attempted"),
        ):
            self.assertEqual(normalize_key("http://123.456.78.9/x"), "9,78,456,123)/x")
            self.assertEqual(normalize_key("http://07.0.0.1/x"), "1,0,0,07)/x")

    def test_parity_with_upstream_surt(self):
        """Lenient keys must equal upstream surt (default canonicalizer).

        The corpus is restricted to ordinary hosts because upstream fires
        socket.gethostbyname_ex() on numeric-shaped ones.
        """
        corpus = [
            "http://archive.org/goo/?a=2&b&a=1",
            "  HTTPS://Example.com/Path  ",
            "https://blog.example.net/articles/2024/hello/",
            "http://www.example.com/",
            "https://www2.example.com/Deep/Path",
            "https://example.com/page?name=John&Doe",
            "https://example.com/%7Euser/test",
            "http://a.com/p?b=2&a=1&foo&foo=1",
            "http://日本.example.com/テスト",
            "http://a/x/../y",
            "http://example.com:8080/x",
        ]
        for u in corpus:
            with self.subTest(url=u):
                self.assertEqual(normalize_key(u), upstream_surt(u))


class TestNormalizeKeyStrict(unittest.TestCase):
    """Tests for strict-mode keys (non-default surt flags)."""

    def test_strict_www_kept(self):
        opts = build_key_opts(True, False)
        self.assertEqual(normalize_key("http://www.a.com/p", opts), "com,a,www)/p")
        self.assertEqual(
            normalize_key("HTTP://WWW.EXAMPLE.COM/Path?a=1", opts),
            "com,example,www)/path?a=1",
        )

    def test_strict_scheme_kept(self):
        opts = build_key_opts(False, True)
        self.assertEqual(normalize_key("HTTPS://a/x", opts), "https://(a)/x")
        self.assertEqual(
            normalize_key("https://help.example.org/", opts),
            "https://(org,example,help)/",
        )
        self.assertEqual(normalize_key("HTTP://a/p", opts), "http://(a)/p")

    def test_strict_both(self):
        opts = build_key_opts(False, False)
        self.assertEqual(
            normalize_key("http://www.a.com/p", opts), "http://(com,a,www)/p"
        )

    def test_lenient_merges_what_strict_keeps(self):
        lenient = normalize_key("http://www.a.com/p")
        strict = normalize_key("http://www.a.com/p", build_key_opts(True, False))
        self.assertEqual(lenient, "com,a)/p")
        self.assertEqual(strict, "com,a,www)/p")
        self.assertNotEqual(lenient, strict)


class TestCdxParams(unittest.TestCase):
    """Tests for CDX request parameter construction."""

    def test_page_params_lenient(self):
        p = _cdx_params(
            "http://example.com/*", page=0, page_size=None, collapse=CDX_COLLAPSE
        )
        self.assertEqual(
            p,
            {
                "url": "http://example.com/*",
                "output": "json",
                "filter": CDX_FILTER,
                "fl": CDX_FL,
                "showResumeKey": "true",
                "page": 0,
                "collapse": "urlkey",
            },
        )
        self.assertNotIn("limit", p)
        self.assertNotIn("pageSize", p)
        self.assertNotIn("resumeKey", p)

    def test_page_params_strict_uses_original_collapse(self):
        p = _cdx_params(
            "http://example.com/*", page=3, page_size=500, collapse=CDX_COLLAPSE_STRICT
        )
        self.assertEqual(p["collapse"], "original")
        self.assertEqual(p["page"], 3)
        self.assertEqual(p["pageSize"], 500)

    def test_resume_params_limit_optional(self):
        p = _cdx_params("http://example.com/*", limit=None, collapse=CDX_COLLAPSE)
        self.assertNotIn("limit", p)
        p2 = _cdx_params("http://example.com/*", limit=100, collapse=None)
        self.assertEqual(p2["limit"], 100)
        self.assertNotIn("collapse", p2)

    def test_fetch_page_rows_uses_params(self):
        with patch("requests.Session") as mock_session_cls:
            mock_session = mock_session_cls.return_value
            resp = _json_response([["original"], ["http://a.example/"]])
            mock_session.get.return_value = resp
            fetch_page_rows(
                "http://example.com/*", 0, None, CDX_COLLAPSE, mock_session, {}
            )
            params = mock_session.get.call_args.kwargs["params"]
            self.assertEqual(params["collapse"], "urlkey")
            self.assertNotIn("limit", params)
            self.assertEqual(params["showResumeKey"], "true")

            fetch_page_rows(
                "http://example.com/*", 1, None, CDX_COLLAPSE_STRICT, mock_session, {}
            )
            params = mock_session.get.call_args.kwargs["params"]
            self.assertEqual(params["collapse"], "original")

    def test_get_num_pages_params_lenient(self):
        with patch("requests.Session") as mock_session_cls:
            mock_session = mock_session_cls.return_value
            mock_session.get.return_value = _json_response(5)
            n = get_num_pages(
                "http://example.com/*", None, CDX_COLLAPSE, mock_session, {}
            )
            self.assertEqual(n, 5)
            params = mock_session.get.call_args.kwargs["params"]
            self.assertEqual(
                params,
                {
                    "url": "http://example.com/*",
                    "filter": CDX_FILTER,
                    "showNumPages": "true",
                    "collapse": "urlkey",
                },
            )

    def test_get_num_pages_params_page_size_and_strict(self):
        with patch("requests.Session") as mock_session_cls:
            mock_session = mock_session_cls.return_value
            mock_session.get.return_value = _json_response(9)
            n = get_num_pages(
                "http://example.com/*", 3, CDX_COLLAPSE_STRICT, mock_session, {}
            )
            self.assertEqual(n, 9)
            params = mock_session.get.call_args.kwargs["params"]
            self.assertEqual(params["collapse"], "original")
            self.assertEqual(params["pageSize"], 3)

    def test_get_num_pages_none_on_request_error(self):
        with patch("requests.Session") as mock_session_cls:
            mock_session = mock_session_cls.return_value
            r = MagicMock()
            r.raise_for_status.side_effect = requests.exceptions.HTTPError("400")
            mock_session.get.return_value = r
            self.assertIsNone(
                get_num_pages(
                    "http://example.com/*", None, CDX_COLLAPSE, mock_session, {}
                )
            )


class TestExtractArchivedUrls(unittest.TestCase):
    """Tests for the surt-key extraction from CDX data."""

    def test_basic_extraction(self):
        cdx_data = [
            ["https://example.com/page1"],
            ["http://example.com/page2"],
        ]
        result = extract_archived_urls(cdx_data)
        self.assertEqual(
            result,
            {
                normalize_key("https://example.com/page1"),
                normalize_key("http://example.com/page2"),
            },
        )

    def test_lenient_merges_scheme(self):
        cdx_data = [["https://example.com/page1"], ["http://example.com/page1"]]
        result = extract_archived_urls(cdx_data)
        # Scheme-less keys: one single key.
        self.assertEqual(len(result), 1)

    def test_strict_keys_differ_per_scheme(self):
        cdx_data = [["https://example.com/page1"], ["http://example.com/page1"]]
        result = extract_archived_urls(cdx_data, build_key_opts(False, True))
        self.assertEqual(len(result), 2)

    def test_multi_column_header_uses_original_column(self):
        cdx_data = [
            ["urlkey", "timestamp", "original", "mimetype"],
            ["k1", "20230101000000", "https://example.com/page1"],
        ]
        result = extract_archived_urls(cdx_data)
        self.assertEqual(result, {normalize_key("https://example.com/page1")})

    def test_empty_data(self):
        self.assertEqual(extract_archived_urls([]), set())

    def test_none_or_dict_or_string(self):
        self.assertEqual(extract_archived_urls(None), set())
        self.assertEqual(extract_archived_urls({"error": "x"}), set())
        self.assertEqual(extract_archived_urls("invalid"), set())

    def test_invalid_header_row(self):
        cdx_data = [
            "invalid_header",
            ["k1", "t", "https://example.com/page1"],
        ]
        self.assertEqual(extract_archived_urls(cdx_data), set())

    def test_string_data_rows_skipped(self):
        cdx_data = [
            ["urlkey", "timestamp", "original"],
            ["k1", "t", "https://example.com/page1"],
            "invalid row",
            ["k2", "t", "https://example.com/page2"],
        ]
        result = extract_archived_urls(cdx_data)
        self.assertEqual(len(result), 2)

    def test_empty_rows_skipped(self):
        cdx_data = [
            ["original", "timestamp"],
            [],
            ["http://valid.example/"],
            [],
        ]
        result = extract_archived_urls(cdx_data)
        self.assertEqual(result, {normalize_key("http://valid.example/")})


class TestExceptions(unittest.TestCase):
    """Tests for exception handling."""

    def test_input_file_not_found(self):
        with self.assertRaises(InputFileError) as cm:
            detect_not_archived("nonexistent_file.txt", set())
        self.assertIn("Input file not found", str(cm.exception))


class TestDetectNotArchived(unittest.TestCase):
    """Tests for the in-memory unarchived-URL detection."""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(
            mode="w", delete=False, encoding="utf-8"
        )
        self.temp_file.write("https://example.com/page1\n")
        self.temp_file.write("https://example.com/page2\n")
        self.temp_file.write("https://example.com/page3\n")
        self.temp_file.close()

    def tearDown(self):
        os.unlink(self.temp_file.name)

    def test_all_archived(self):
        archived_keys = {
            normalize_key("https://example.com/page1"),
            normalize_key("https://example.com/page2"),
            normalize_key("https://example.com/page3"),
        }
        result, _, _ = detect_not_archived(self.temp_file.name, archived_keys)
        self.assertEqual(len(result), 0)

    def test_some_not_archived(self):
        archived_keys = {normalize_key("https://example.com/page1")}
        result, _, _ = detect_not_archived(self.temp_file.name, archived_keys)
        self.assertEqual(len(result), 2)
        self.assertIn("https://example.com/page2", result)
        self.assertIn("https://example.com/page3", result)

    def test_protocol_independent_by_default(self):
        """Lenient keys are scheme-less: http-archived matches https input."""
        archived_keys = {normalize_key("http://example.com/page1")}
        result, _, _ = detect_not_archived(self.temp_file.name, archived_keys)
        self.assertEqual(len(result), 2)
        self.assertNotIn("https://example.com/page1", result)

    def test_strict_mode_distinguishes_scheme(self):
        archived_keys = {
            normalize_key("http://example.com/page1", build_key_opts(False, True))
        }
        result, _, _ = detect_not_archived(
            self.temp_file.name, archived_keys, key_opts=build_key_opts(False, True)
        )
        self.assertEqual(len(result), 3)

    def test_collect_archived(self):
        archived_keys = {normalize_key("https://example.com/page1")}
        not_archived, archived, total_count = detect_not_archived(
            self.temp_file.name, archived_keys, collect_archived=True
        )
        self.assertEqual(total_count, 3)
        assert archived is not None
        self.assertEqual(len(archived), 1)
        self.assertIn("https://example.com/page1", archived)
        self.assertEqual(len(not_archived), 2)

    def test_collect_archived_disabled(self):
        archived_keys = {normalize_key("https://example.com/page1")}
        not_archived, archived, total_count = detect_not_archived(
            self.temp_file.name, archived_keys, collect_archived=False
        )
        self.assertIsNone(archived)
        self.assertEqual(total_count, 3)
        self.assertEqual(len(not_archived), 2)


class TestIntegration(unittest.TestCase):
    """Integration test: extract keys then detect unarchived URLs."""

    def test_end_to_end_workflow(self):
        cdx_data = [
            ["https://example.com/path1"],
            ["http://example.com/path2"],
        ]
        archived = extract_archived_urls(cdx_data)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8") as f:
            f.write("https://example.com/path1\n")
            f.write("https://example.com/path2\n")
            f.write("https://example.com/path3\n")
            temp_input = f.name

        try:
            not_archived, _, _ = detect_not_archived(temp_input, archived)
            self.assertEqual(len(not_archived), 1)
            self.assertEqual(not_archived[0], "https://example.com/path3")
        finally:
            os.unlink(temp_input)


class TestAdditionalFeatures(unittest.TestCase):
    """Additional edge-case tests."""

    def test_extract_mixed_row_types(self):
        cdx = [
            ["original", "timestamp"],  # header
            {"bad": "row"},  # malformed row
            ["http://a.example/"],  # valid row
            "invalid_string",  # malformed row
            ["https://b/"],  # valid row
        ]
        res = extract_archived_urls(cdx)
        self.assertEqual(
            res,
            {
                normalize_key("http://a.example/"),
                normalize_key("https://b/"),
            },
        )

    def test_extract_header_without_original_uses_index0(self):
        cdx = [
            ["url", "timestamp"],  # header, no 'original' column
            ["http://test.example/"],
        ]
        res = extract_archived_urls(cdx)
        self.assertEqual(res, {normalize_key("http://test.example/")})


class TestSplitResumeKey(unittest.TestCase):
    """Tests for resumeKey detection with fl=original (single-column rows)."""

    def test_separator_pattern_extracts_key(self):
        data = [["original"], ["http://a.example/"], [], ["RESUME123"]]
        rows, key = _split_resume_key(data)
        self.assertEqual(key, "RESUME123")
        self.assertEqual(rows, [["original"], ["http://a.example/"]])

    def test_trailing_url_row_is_not_a_key(self):
        data = [["original"], ["http://a.example/"], ["http://b.example/"]]
        rows, key = _split_resume_key(data)
        self.assertIsNone(key)
        self.assertEqual(len(rows), 3)

    def test_non_url_singleton_without_separator_is_not_a_key(self):
        data = [["original"], ["http://a.example/"], ["SOMEKEY"]]
        rows, key = _split_resume_key(data)
        self.assertIsNone(key)
        self.assertEqual(rows, data)

    def test_trailing_non_url_data_row_is_kept(self):
        data = [["original"], ["http://a.example/"], ["dns:a.example"]]
        rows, key = _split_resume_key(data)
        self.assertIsNone(key)
        self.assertEqual(rows, data)

    def test_header_only_response_has_no_key(self):
        rows, key = _split_resume_key([["original"]])
        self.assertIsNone(key)
        self.assertEqual(rows, [["original"]])


class TestSQLiteCache(unittest.TestCase):
    """Tests for the SQLite cache layer (keys only)."""

    def test_open_db_schema(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            path = f.name
        try:
            os.unlink(path)
            conn = open_db(path)
            try:
                tables = {
                    r[0]: r[1]
                    for r in conn.execute(
                        "SELECT name, sql FROM sqlite_master WHERE type='table';"
                    )
                }
                self.assertIn("archived", tables)
                self.assertIn("meta", tables)
                self.assertIn("WITHOUT ROWID", tables["archived"])
                self.assertIn("WITHOUT ROWID", tables["meta"])
                self.assertEqual(archived_columns(conn), {"key"})
            finally:
                conn.close()
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_insert_keys_dedup(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            path = f.name
        try:
            os.unlink(path)
            conn = open_db(path)
            try:
                key_a = normalize_key("https://example.com/a")
                key_b = normalize_key("https://example.com/b")
                insert_urls(conn, [key_a, key_a, key_b])
                rows = conn.execute("SELECT key FROM archived ORDER BY key;").fetchall()
                self.assertEqual(rows, [(key_a,), (key_b,)])
            finally:
                conn.close()
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_scan_streams_to_disk(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            db_path = f.name
        try:
            os.unlink(db_path)
            conn = open_db(db_path)
            try:
                insert_urls(conn, [normalize_key("https://example.com/a")])
            finally:
                conn.close()

            with tempfile.NamedTemporaryFile(
                mode="w", delete=False, encoding="utf-8"
            ) as f:
                f.write("https://example.com/a\nhttps://example.com/b\n")
                input_path = f.name
            out_fd, out_path = tempfile.mkstemp()
            os.close(out_fd)
            arch_fd, arch_path = tempfile.mkstemp()
            os.close(arch_fd)
            try:
                total, not_count, arch_count = scan_input_against_db(
                    input_path,
                    db_path,
                    output_file=out_path,
                    output_archived=arch_path,
                    batch_size=1,
                )
                self.assertEqual((total, not_count, arch_count), (2, 1, 1))
                with open(out_path, encoding="utf-8") as fh:
                    self.assertIn("https://example.com/b", fh.read())
                with open(arch_path, encoding="utf-8") as fh:
                    self.assertIn("https://example.com/a", fh.read())
            finally:
                for p in (input_path, out_path, arch_path):
                    if os.path.exists(p):
                        os.unlink(p)
        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)


class TestCdxRateLimiter(unittest.TestCase):
    """Tests for the CDX request interval shared by all threads."""

    @patch("waygap.time.sleep")
    @patch("waygap.time.monotonic")
    def test_wait_spaces_calls_by_interval(self, mock_monotonic, mock_sleep):
        limiter = _RateLimiter(3.0)
        mock_monotonic.return_value = 100.0

        limiter.wait()
        mock_sleep.assert_not_called()

        limiter.wait()
        mock_sleep.assert_called_once_with(3.0)

    @patch("waygap.time.sleep")
    @patch("waygap.time.monotonic")
    def test_wait_does_not_sleep_after_reserved_time(self, mock_monotonic, mock_sleep):
        limiter = _RateLimiter(3.0)
        mock_monotonic.return_value = 100.0
        limiter.wait()

        mock_monotonic.return_value = 104.0
        limiter.wait()

        mock_sleep.assert_not_called()

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_get_with_retries_waits_before_each_attempt(self, mock_session_cls, _sleep):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            requests.exceptions.ConnectionError("reset"),
            _json_response([["original"]]),
        ]
        with patch("waygap._CDX_LIMITER") as mock_limiter:
            _get_with_retries(mock_session, "https://example.invalid/", {}, {})

        self.assertEqual(mock_session.get.call_count, 2)
        self.assertEqual(mock_limiter.wait.call_count, 2)

    @patch("requests.Session")
    def test_get_num_pages_waits_before_request(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.get.return_value = _json_response(5)
        with patch("waygap._CDX_LIMITER") as mock_limiter:
            get_num_pages("http://example.com/*", None, CDX_COLLAPSE, mock_session, {})

        mock_limiter.wait.assert_called_once_with()


class TestFetchPageRowsChaining(unittest.TestCase):
    """Tests for in-page resumeKey chaining without a hard iteration cap."""

    @patch("requests.Session")
    def test_chain_beyond_1000_iterations_not_truncated(self, mock_session_cls):
        responses = []
        for i in range(1000):
            responses.append(
                _json_response(
                    [["original"], [f"http://page{i}.example/"], [], [f"KEY_{i}"]]
                )
            )
        responses.append(_json_response([["original"], ["http://page1000.example/"]]))
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = responses

        rows = fetch_page_rows("http://example.com/*", 0, None, None, mock_session, {})

        self.assertEqual(mock_session.get.call_count, 1001)
        self.assertEqual(len(rows), 1001)
        self.assertTrue(
            any("page1000" in str(r) for r in rows),
            "tail row lost: chaining was truncated",
        )

    @patch("requests.Session")
    def test_cycle_detection_breaks_without_hang(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.get.return_value = _json_response(
            [["original"], ["http://a.example/"], [], ["SAME_KEY"]]
        )

        rows = fetch_page_rows("http://example.com/*", 0, None, None, mock_session, {})

        self.assertEqual(mock_session.get.call_count, 2)
        self.assertEqual(len(rows), 2)

    @patch("requests.Session")
    def test_trailing_non_url_row_is_kept(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.get.return_value = _json_response(
            [["original"], ["http://a.example/"], ["dns:a.example"]]
        )

        rows = fetch_page_rows("http://example.com/*", 0, None, None, mock_session, {})

        self.assertEqual(mock_session.get.call_count, 1)
        self.assertEqual(rows, [["http://a.example/"], ["dns:a.example"]])

    @patch("requests.Session")
    def test_header_only_page_makes_no_extra_request(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.get.return_value = _json_response([["original"]])

        rows = fetch_page_rows("http://example.com/*", 0, None, None, mock_session, {})

        self.assertEqual(mock_session.get.call_count, 1)
        self.assertEqual(rows, [])


def _drain(gen):
    """Collect a generator's yielded items and its return value."""
    items = []
    while True:
        try:
            items.append(next(gen))
        except StopIteration as stop:
            return items, stop.value


class TestFetchResumeKeyRows(unittest.TestCase):
    """Tests for resumeKey detection in the sequential fallback fetch."""

    @patch("requests.Session")
    def test_separator_key_is_followed(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _json_response([["original"], ["http://a.example/"], [], ["KEY1"]]),
            _json_response([["original"], ["http://b.example/"]]),
        ]

        rows, last_key = _drain(
            fetch_resumekey_rows(
                "http://example.com/*", None, None, None, mock_session, {}
            )
        )

        self.assertEqual(rows, [["http://a.example/"], ["http://b.example/"]])
        self.assertIsNone(last_key)
        self.assertEqual(mock_session.get.call_count, 2)
        second_params = mock_session.get.call_args_list[1].kwargs["params"]
        self.assertEqual(second_params.get("resumeKey"), "KEY1")

    @patch("requests.Session")
    def test_trailing_non_url_row_is_kept(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.get.return_value = _json_response(
            [["original"], ["http://a.example/"], ["dns:a.example"]]
        )

        rows, last_key = _drain(
            fetch_resumekey_rows(
                "http://example.com/*", None, None, None, mock_session, {}
            )
        )

        self.assertEqual(rows, [["http://a.example/"], ["dns:a.example"]])
        self.assertIsNone(last_key)
        self.assertEqual(mock_session.get.call_count, 1)

    @patch("requests.Session")
    def test_header_only_response_is_a_normal_end(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.get.return_value = _json_response([["original"]])

        rows, last_key = _drain(
            fetch_resumekey_rows(
                "http://example.com/*", None, None, None, mock_session, {}
            )
        )

        self.assertEqual(rows, [])
        self.assertIsNone(last_key)
        self.assertEqual(mock_session.get.call_count, 1)

    @patch("requests.Session")
    def test_repeated_response_key_raises(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _json_response([["original"], ["http://a.example/"], [], ["KEY1"]]),
            _json_response([["original"], ["http://b.example/"], [], ["KEY1"]]),
        ]

        with self.assertRaises(CDXAPIError):
            _drain(
                fetch_resumekey_rows(
                    "http://example.com/*", None, None, None, mock_session, {}
                )
            )

    @patch("requests.Session")
    def test_request_side_cycle_raises(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.get.return_value = _json_response(
            [["original"], ["http://a.example/"], [], ["KEY0"]]
        )

        with self.assertRaises(CDXAPIError):
            _drain(
                fetch_resumekey_rows(
                    "http://example.com/*", "KEY0", None, None, mock_session, {}
                )
            )
        self.assertEqual(mock_session.get.call_count, 1)

    @patch("requests.Session")
    def test_key_without_rows_is_followed(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _json_response([["original"], ["http://a.example/"], [], ["KEY1"]]),
            _json_response([["original"], [], ["KEY2"]]),
            _json_response([["original"], ["http://c.example/"]]),
        ]

        rows, _ = _drain(
            fetch_resumekey_rows(
                "http://example.com/*", None, None, None, mock_session, {}
            )
        )

        self.assertEqual(rows, [["http://a.example/"], ["http://c.example/"]])
        self.assertEqual(mock_session.get.call_count, 3)


TARGET = "http://example.com/*"


def _no_pagination_response():
    """A showNumPages response that makes the fetch fall back to resumeKey."""
    r = MagicMock()
    r.raise_for_status.side_effect = requests.exceptions.HTTPError("400")
    r.status_code = 400
    return r


def _no_network(url, params=None, headers=None, timeout=None):
    raise AssertionError(f"unexpected request: {params}")


class TestResumeKeyCache(unittest.TestCase):
    """Tests that the resumeKey paths mark the cache complete only when done."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cache = os.path.join(self.tmpdir, "cache.db")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_cache(
        self,
        target: str = TARGET,
        completed: str = "0",
        mode: str | None = "resumekey",
        urls: tuple[str, ...] | list[str] = (),
        marked: bool = False,
        resume_key: str | None = None,
    ):
        conn = open_db(self.cache)
        try:
            meta = {**expected_meta(target, {}, None), "completed": completed}
            if mode is not None:
                meta["mode"] = mode
            if resume_key is not None:
                meta["resume_key"] = resume_key
            if marked:
                meta["resumekey_v"] = RESUMEKEY_FETCH_VERSION
            write_meta(conn, meta)
            insert_urls(conn, [normalize_key(u) for u in urls])
        finally:
            conn.close()

    def _state(self):
        conn = sqlite3.connect(self.cache)
        try:
            keys = {r[0] for r in conn.execute("SELECT key FROM archived;")}
            return keys, read_meta(conn)
        finally:
            conn.close()

    @patch("requests.Session")
    def test_fallback_repeated_key_leaves_cache_incomplete(self, mock_session_cls):
        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _no_pagination_response()
            if params.get("resumeKey") is None:
                return _json_response(
                    [["original"], ["http://a.example/"], [], ["KEY1"]]
                )
            return _json_response([["original"], ["http://b.example/"], [], ["KEY1"]])

        mock_session_cls.return_value.get.side_effect = _route

        with self.assertRaises(CDXAPIError):
            ensure_archived_db(TARGET, self.cache, workers=1)

        keys, meta = self._state()
        self.assertEqual(meta.get("completed"), "0")
        self.assertEqual(meta.get("mode"), "resumekey")
        self.assertIn(normalize_key("http://a.example/"), keys)

    @patch("requests.Session")
    def test_fallback_key_without_rows_continues(self, mock_session_cls):
        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _no_pagination_response()
            key = params.get("resumeKey")
            if key is None:
                return _json_response(
                    [["original"], ["http://a.example/"], [], ["KEY1"]]
                )
            if key == "KEY1":
                return _json_response([["original"], [], ["KEY2"]])
            if key == "KEY2":
                return _json_response([["original"], ["http://c.example/"]])
            raise AssertionError(f"unexpected params: {params}")

        mock_session_cls.return_value.get.side_effect = _route

        ensure_archived_db(TARGET, self.cache, workers=1)

        keys, meta = self._state()
        self.assertEqual(meta.get("completed"), "1")
        self.assertEqual(
            keys,
            {normalize_key("http://a.example/"), normalize_key("http://c.example/")},
        )

    @patch("requests.Session")
    def test_resume_key_cycle_leaves_cache_incomplete(self, mock_session_cls):
        self._make_cache(urls=["http://a.example/"], resume_key="KEY1", marked=True)
        mock_session_cls.return_value.get.return_value = _json_response(
            [["original"], ["http://b.example/"], [], ["KEY1"]]
        )

        with self.assertRaises(CDXAPIError):
            ensure_archived_db(TARGET, self.cache, initial_resume_key="KEY1")

        keys, meta = self._state()
        self.assertEqual(meta.get("completed"), "0")
        self.assertIn(normalize_key("http://b.example/"), keys)

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_rows_before_a_failure_survive_resume(self, mock_session_cls, _sleep):
        def _route_fail(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _no_pagination_response()
            if params.get("resumeKey") is None:
                return _json_response(
                    [["original"], ["http://a.example/"], [], ["KEY1"]]
                )
            raise requests.exceptions.ConnectionError("down")

        mock_session_cls.return_value.get.side_effect = _route_fail
        with self.assertRaises(CDXAPIError):
            ensure_archived_db(TARGET, self.cache, workers=1)

        keys, meta = self._state()
        self.assertEqual(keys, {normalize_key("http://a.example/")})
        self.assertEqual(meta.get("completed"), "0")
        self.assertEqual(meta.get("resumekey_v"), RESUMEKEY_FETCH_VERSION)
        self.assertEqual(meta.get("resume_key"), "KEY1")

        def _route_resume(url, params=None, headers=None, timeout=None):
            params = params or {}
            if params.get("resumeKey") == "KEY1":
                return _json_response([["original"], ["http://b.example/"]])
            raise AssertionError(f"unexpected params: {params}")

        mock_session_cls.return_value.get.side_effect = _route_resume
        ensure_archived_db(TARGET, self.cache, initial_resume_key="KEY1")

        keys, meta = self._state()
        self.assertEqual(
            keys,
            {normalize_key("http://a.example/"), normalize_key("http://b.example/")},
        )
        self.assertEqual(meta.get("completed"), "1")
        self.assertEqual(meta.get("resumekey_v"), RESUMEKEY_FETCH_VERSION)

    @staticmethod
    def _route_fail_after_one_row(url, params=None, headers=None, timeout=None):
        params = params or {}
        if "showNumPages" in params:
            return _no_pagination_response()
        if params.get("resumeKey") is None:
            return _json_response([["original"], ["http://a.example/"], [], ["KEY1"]])
        raise requests.exceptions.ConnectionError("down")

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_resume_hint_logged_after_rows_are_saved(self, mock_session_cls, _sleep):
        mock_session_cls.return_value.get.side_effect = self._route_fail_after_one_row

        with (
            self.assertLogs("waygap", level="INFO") as logs,
            patch(
                "sys.argv",
                ["waygap.py", TARGET, "--cache", self.cache, "--workers", "1"],
            ),
        ):
            self.assertEqual(main(), 1)

        messages = [r.getMessage() for r in logs.records]
        saved = messages.index("Fetched rows stored (1 records).")
        hint = messages.index("  --resume-key KEY1")
        self.assertLess(saved, hint)

    @patch("waygap.insert_urls", side_effect=sqlite3.OperationalError("disk full"))
    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_no_resume_hint_when_saving_rows_fails(
        self, mock_session_cls, _sleep, _insert
    ):
        # The rows before KEY1 are not stored, so resuming from KEY1 would
        # leave them missing from a cache that is later marked complete.
        mock_session_cls.return_value.get.side_effect = self._route_fail_after_one_row

        with (
            self.assertLogs("waygap", level="INFO") as logs,
            patch(
                "sys.argv",
                ["waygap.py", TARGET, "--cache", self.cache, "--workers", "1"],
            ),
        ):
            self.assertEqual(main(), 1)

        _insert.assert_called_once()
        self.assertEqual(
            _insert.call_args.args[1], [normalize_key("http://a.example/")]
        )
        messages = [r.getMessage() for r in logs.records]
        self.assertIn("Unexpected error: disk full", messages)
        self.assertFalse(any("--resume-key" in m for m in messages), messages)
        self.assertFalse(any("Fetched rows stored" in m for m in messages), messages)
        keys, meta = self._state()
        self.assertEqual(keys, set())
        self.assertEqual(meta.get("completed"), "0")
        self.assertNotIn("resume_key", meta)

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_no_resume_hint_when_checkpoint_cannot_be_saved(
        self, mock_session_cls, _sleep
    ):
        mock_session_cls.return_value.get.side_effect = self._route_fail_after_one_row
        original_write = write_meta

        def write(conn, values):
            if "resume_key" in values:
                raise sqlite3.OperationalError("checkpoint full")
            original_write(conn, values)

        with (
            patch("waygap.write_meta", side_effect=write),
            self.assertLogs("waygap", level="INFO") as logs,
            patch("sys.argv", ["waygap.py", TARGET, "--cache", self.cache]),
        ):
            self.assertEqual(main(), 1)
        keys, meta = self._state()
        self.assertEqual(keys, {normalize_key("http://a.example/")})
        self.assertEqual(meta.get("completed"), "0")
        self.assertNotIn("resume_key", meta)
        messages = [record.getMessage() for record in logs.records]
        self.assertIn("Unexpected error: checkpoint full", messages)
        self.assertFalse(any("--resume-key" in message for message in messages))

    @patch("requests.Session")
    def test_pre_checkpoint_completed_cache_is_fetched_again(self, mock_session_cls):
        self._make_cache(completed="1", urls=["http://a.example/"])
        conn = open_db(self.cache)
        try:
            write_meta(conn, {"resumekey_v": "2"})
        finally:
            conn.close()
        mock_session_cls.return_value.get.side_effect = (
            lambda url, params=None, **kwargs: (
                _no_pagination_response()
                if "showNumPages" in (params or {})
                else _json_response([["original"], ["http://b.example/"]])
            )
        )
        ensure_archived_db(TARGET, self.cache)
        keys, meta = self._state()
        self.assertEqual(
            keys, {normalize_key(u) for u in ["http://a.example/", "http://b.example/"]}
        )
        self.assertEqual(meta.get("completed"), "1")
        self.assertEqual(meta.get("resumekey_v"), RESUMEKEY_FETCH_VERSION)

    @patch("requests.Session")
    def test_rows_before_an_interrupt_survive(self, mock_session_cls):
        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _no_pagination_response()
            if params.get("resumeKey") is None:
                return _json_response(
                    [["original"], ["http://a.example/"], [], ["KEY1"]]
                )
            raise KeyboardInterrupt

        mock_session_cls.return_value.get.side_effect = _route
        with self.assertRaises(KeyboardInterrupt):
            ensure_archived_db(TARGET, self.cache, workers=1)

        keys, meta = self._state()
        self.assertEqual(keys, {normalize_key("http://a.example/")})
        self.assertEqual(meta.get("completed"), "0")

    @patch("requests.Session")
    def test_legacy_completed_resumekey_cache_is_fetched_again(self, mock_session_cls):
        self._make_cache(completed="1", urls=["http://a.example/"])

        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _no_pagination_response()
            if params.get("resumeKey") is None:
                return _json_response([["original"], ["http://b.example/"]])
            raise AssertionError(f"unexpected params: {params}")

        mock_session_cls.return_value.get.side_effect = _route
        ensure_archived_db(TARGET, self.cache, workers=1)

        keys, meta = self._state()
        self.assertEqual(
            keys,
            {normalize_key("http://a.example/"), normalize_key("http://b.example/")},
        )
        self.assertEqual(meta.get("completed"), "1")
        self.assertEqual(meta.get("resumekey_v"), RESUMEKEY_FETCH_VERSION)

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_legacy_completed_resumekey_cache_stays_incomplete_on_failure(
        self, mock_session_cls, _sleep
    ):
        self._make_cache(completed="1", urls=["http://a.example/"])

        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _no_pagination_response()
            raise requests.exceptions.ConnectionError("down")

        mock_session_cls.return_value.get.side_effect = _route
        with self.assertRaises(CDXAPIError):
            ensure_archived_db(TARGET, self.cache, workers=1)

        keys, meta = self._state()
        self.assertEqual(keys, {normalize_key("http://a.example/")})
        self.assertEqual(meta.get("completed"), "0")

    @patch("requests.Session")
    def test_marked_completed_resumekey_cache_is_reused(self, mock_session_cls):
        self._make_cache(completed="1", urls=["http://a.example/"], marked=True)
        mock_session_cls.return_value.get.side_effect = _no_network

        ensure_archived_db(TARGET, self.cache)

        keys, meta = self._state()
        self.assertEqual(keys, {normalize_key("http://a.example/")})
        self.assertEqual(meta.get("completed"), "1")

    @patch("requests.Session")
    def test_resume_key_without_cache_is_rejected(self, mock_session_cls):
        mock_session_cls.return_value.get.side_effect = _no_network

        with self.assertRaises(CacheError):
            ensure_archived_db(TARGET, self.cache, initial_resume_key="KEY1")

        self.assertFalse(os.path.exists(self.cache))

    @patch("requests.Session")
    def test_resume_key_with_other_settings_is_rejected(self, mock_session_cls):
        self._make_cache(target="http://other.example/*", urls=["http://o.example/"])
        mock_session_cls.return_value.get.side_effect = _no_network

        with self.assertRaises(CacheError):
            ensure_archived_db(TARGET, self.cache, initial_resume_key="KEY1")

        keys, meta = self._state()
        self.assertEqual(keys, {normalize_key("http://o.example/")})
        self.assertEqual(meta.get("target_url"), "http://other.example/*")

    @patch("requests.Session")
    def test_resume_key_on_completed_cache_is_rejected(self, mock_session_cls):
        self._make_cache(completed="1", urls=["http://a.example/"])
        mock_session_cls.return_value.get.side_effect = _no_network

        with self.assertRaises(CacheError):
            ensure_archived_db(TARGET, self.cache, initial_resume_key="KEY1")

        _, meta = self._state()
        self.assertEqual(meta.get("completed"), "1")

    @patch("requests.Session")
    def test_resume_key_on_pagination_cache_is_rejected(self, mock_session_cls):
        self._make_cache(mode="pagination")
        mock_session_cls.return_value.get.side_effect = _no_network

        with self.assertRaises(CacheError):
            ensure_archived_db(TARGET, self.cache, initial_resume_key="KEY1")

    @patch("requests.Session")
    def test_resume_key_without_checkpoint_is_rejected(self, mock_session_cls):
        for mode in (None, "resumekey"):
            with self.subTest(mode=mode):
                self._make_cache(mode=mode, urls=["http://a.example/"])
                before = self._state()
                mock_session_cls.return_value.get.side_effect = _no_network
                with self.assertRaisesRegex(CacheError, "run without --resume-key"):
                    ensure_archived_db(TARGET, self.cache, initial_resume_key="KEY1")
                self.assertEqual(self._state(), before)
        mock_session_cls.assert_not_called()

    @patch("requests.Session")
    def test_resume_key_must_match_saved_checkpoint(self, mock_session_cls):
        self._make_cache(urls=["http://a.example/"], resume_key="KEY2", marked=True)
        before = self._state()
        mock_session_cls.return_value.get.side_effect = _no_network
        with self.assertRaisesRegex(CacheError, "saved resume key"):
            ensure_archived_db(TARGET, self.cache, initial_resume_key="KEY5")
        self.assertEqual(self._state(), before)
        mock_session_cls.assert_not_called()

    @patch("requests.Session")
    def test_old_fetch_version_checkpoint_is_rejected(self, mock_session_cls):
        self._make_cache(resume_key="KEY1")
        conn = open_db(self.cache)
        try:
            write_meta(conn, {"resumekey_v": "2"})
        finally:
            conn.close()
        before = self._state()
        mock_session_cls.return_value.get.side_effect = _no_network
        with self.assertRaisesRegex(CacheError, "run without --resume-key"):
            ensure_archived_db(TARGET, self.cache, initial_resume_key="KEY1")
        self.assertEqual(self._state(), before)
        mock_session_cls.assert_not_called()

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_resumed_failure_advances_checkpoint_after_saving_rows(
        self, mock_session_cls, _sleep
    ):
        self._make_cache(urls=["http://a.example/"], resume_key="KEY1", marked=True)

        def route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if params.get("resumeKey") == "KEY1":
                return _json_response(
                    [["original"], ["http://b.example/"], [], ["KEY2"]]
                )
            raise requests.exceptions.ConnectionError("down")

        mock_session_cls.return_value.get.side_effect = route
        with self.assertRaises(CDXAPIError):
            ensure_archived_db(TARGET, self.cache, initial_resume_key="KEY1")
        keys, meta = self._state()
        self.assertEqual(
            keys, {normalize_key(u) for u in ["http://a.example/", "http://b.example/"]}
        )
        self.assertEqual(meta.get("resume_key"), "KEY2")
        self.assertEqual(meta.get("completed"), "0")

    @patch("requests.Session")
    def test_legacy_cache_can_restart_without_resume_key(self, mock_session_cls):
        self._make_cache(urls=["http://a.example/"])
        mock_session_cls.return_value.get.side_effect = (
            lambda url, params=None, **kwargs: (
                _no_pagination_response()
                if "showNumPages" in (params or {})
                else _json_response(
                    [["original"], ["http://a.example/"], ["http://b.example/"]]
                )
            )
        )
        ensure_archived_db(TARGET, self.cache)
        keys, meta = self._state()
        self.assertEqual(
            keys, {normalize_key(u) for u in ["http://a.example/", "http://b.example/"]}
        )
        self.assertEqual(meta.get("completed"), "1")
        self.assertEqual(meta.get("resumekey_v"), RESUMEKEY_FETCH_VERSION)


class TestMainResumeKeyOptions(unittest.TestCase):
    """Tests for CLI option combinations with --resume-key."""

    def _run_main(self, *args):
        with (
            patch("sys.argv", ["waygap.py", TARGET, *args]),
            patch("waygap.ensure_archived_db") as mock_ensure,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as cm:
                main()
        mock_ensure.assert_not_called()
        return cm.exception.code

    @patch("waygap.ensure_archived_db")
    def test_failed_fetch_hint_matches_retained_progress(self, mock_ensure):
        from waygap import ResumeKeyRequestError

        cases = [
            (None, [], False),
            ("KEY1", [], True),
            ("KEY1", ["--refresh"], True),
            (None, ["--no-cache"], False),
            ("KEY1", ["--no-cache"], False),
        ]
        for key, args, can_resume in cases:
            with self.subTest(key=key, args=args):
                mock_ensure.side_effect = ResumeKeyRequestError("request failed", key)
                with (
                    patch("sys.argv", ["waygap.py", TARGET, *args]),
                    self.assertLogs("waygap", level="INFO") as logs,
                ):
                    self.assertEqual(main(), 1)
                text = "\n".join(logs.output)
                if can_resume:
                    self.assertIn("--resume-key KEY1", text)
                    if "--refresh" in args:
                        self.assertIn("remove --refresh", text.lower())
                else:
                    self.assertNotIn("--resume-key", text)
                    self.assertIn("re-run the same command", text.lower())
                self.assertNotIn("(initial)", text)

    def test_resume_key_with_no_cache_is_rejected(self):
        self.assertEqual(self._run_main("--resume-key", "KEY1", "--no-cache"), 2)

    def test_resume_key_with_refresh_is_rejected(self):
        self.assertEqual(self._run_main("--resume-key", "KEY1", "--refresh"), 2)


class TestMainWorkersDefault(unittest.TestCase):
    """Tests for the default --workers value passed to ensure_archived_db."""

    def test_default_workers_is_two(self):
        with (
            patch("sys.argv", ["waygap.py", TARGET]),
            patch(
                "waygap.ensure_archived_db", side_effect=CacheError("stop")
            ) as mock_ensure,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            main()

        self.assertEqual(DEFAULT_WORKERS, 2)
        self.assertEqual(mock_ensure.call_args.kwargs["workers"], 2)


class TestCDXPaginationDB(unittest.TestCase):
    """Tests for pagination fetch into SQLite (mocked API)."""

    @patch("requests.Session")
    def test_pagination_build_and_reuse(self, mock_session_cls):
        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                self.assertEqual(params.get("collapse"), "urlkey")
                return _json_response(2)
            self.assertEqual(params.get("collapse"), "urlkey")
            self.assertNotIn("limit", params)
            if params.get("page") == 0:
                return _json_response(
                    [["original"], ["http://a.example/"], ["https://b.example/"]]
                )
            if params.get("page") == 1:
                return _json_response([["original"], ["http://c.example/"]])
            raise AssertionError(f"unexpected params: {params}")

        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = _route

        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            cache_path = f.name
        try:
            os.unlink(cache_path)
            db_path = ensure_archived_db("http://example.com/*", cache_path, workers=1)
            conn = sqlite3.connect(db_path)
            try:
                self.assertEqual(count_archived(conn), 3)
                meta = read_meta(conn)
                self.assertEqual(meta.get("completed"), "1")
                self.assertEqual(meta.get("mode"), "pagination")
                self.assertEqual(meta.get("key_profile"), "surt-default")
                self.assertEqual(meta.get("schema_v"), DB_SCHEMA_VERSION)
                done = {r[0] for r in conn.execute("SELECT page FROM pages_done;")}
                self.assertEqual(done, {0, 1})
            finally:
                conn.close()

            # Second run with identical params must not touch the network.
            with patch("requests.Session") as mock_session_cls2:
                ensure_archived_db("http://example.com/*", cache_path, workers=1)
                mock_session_cls2.assert_not_called()
        finally:
            if os.path.exists(cache_path):
                os.unlink(cache_path)

    @patch(
        "waygap.concurrent.futures.as_completed",
        side_effect=lambda futures: iter(futures),
    )
    @patch("requests.Session")
    def test_pagination_progress_counts_unique_rows_without_per_page_counts(
        self, mock_session_cls, _as_completed
    ):
        pages = [
            [["original"], ["http://a.example/"], ["http://a.example/"]],
            [["original"], ["http://a.example/"], ["http://b.example/"]],
            [["original"]],
        ]

        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _json_response(len(pages))
            return _json_response(pages[params["page"]])

        mock_session_cls.return_value.get.side_effect = _route
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as tmp:
                cache_path = os.path.join(tmp, "cache.db")
                if existing:
                    conn = open_db(cache_path)
                    try:
                        write_meta(
                            conn,
                            {
                                **expected_meta(TARGET, {}, None),
                                "completed": "0",
                                "mode": "pagination",
                            },
                        )
                        insert_urls(conn, [normalize_key("http://a.example/")])
                    finally:
                        conn.close()

                with (
                    patch("waygap.count_archived", wraps=count_archived) as count,
                    patch("waygap.tqdm") as progress,
                    self.assertLogs("waygap", level="INFO") as logs,
                ):
                    ensure_archived_db(TARGET, cache_path, workers=1)

                bar = progress.return_value.__enter__.return_value
                self.assertEqual(
                    [call.kwargs["records"] for call in bar.set_postfix.call_args_list],
                    [1, 2, 2],
                )
                self.assertEqual(count.call_count, 2)
                self.assertIn(
                    "All pages fetched successfully (2 unique URLs)",
                    [record.getMessage() for record in logs.records],
                )

    @patch(
        "waygap.concurrent.futures.as_completed",
        side_effect=lambda futures: iter(futures),
    )
    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_pagination_progress_resumes_after_failed_page(
        self, mock_session_cls, _sleep, _as_completed
    ):
        # Consume futures in page order so page 0 is persisted before page 1 fails.
        fail = True
        requested_pages = []

        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _json_response(2)
            page = params["page"]
            requested_pages.append(page)
            if page == 0:
                return _json_response([["original"], ["http://a.example/"]])
            if fail:
                raise requests.exceptions.ConnectionError("down")
            return _json_response(
                [["original"], ["http://a.example/"], ["http://b.example/"]]
            )

        mock_session_cls.return_value.get.side_effect = _route
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = os.path.join(tmp, "cache.db")
            with self.assertRaises(CDXAPIError):
                ensure_archived_db(TARGET, cache_path, workers=1)
            fail = False
            requested_pages.clear()
            with (
                patch("waygap.count_archived", wraps=count_archived) as count,
                patch("waygap.tqdm") as progress,
            ):
                ensure_archived_db(TARGET, cache_path, workers=1)
            self.assertEqual(requested_pages, [1])
            bar = progress.return_value.__enter__.return_value
            bar.set_postfix.assert_called_once_with(records=2)
            self.assertEqual(count.call_count, 2)

    @patch("requests.Session")
    def test_pagination_strict_uses_original_collapse(self, mock_session_cls):
        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            self.assertEqual(params.get("collapse"), "original")
            if "showNumPages" in params:
                self.assertEqual(params.get("pageSize"), 2)
                return _json_response(1)
            self.assertEqual(params.get("pageSize"), 2)
            self.assertNotIn("limit", params)
            return _json_response(
                [["original"], ["http://www.a.example/p"], ["https://a.example/p"]]
            )

        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = _route

        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            cache_path = f.name
        try:
            os.unlink(cache_path)
            db_path = ensure_archived_db(
                "http://example.com/*",
                cache_path,
                key_opts=build_key_opts(False, False),
                page_size=2,
                workers=1,
            )
            conn = sqlite3.connect(db_path)
            try:
                meta = read_meta(conn)
                self.assertEqual(meta.get("completed"), "1")
                self.assertEqual(
                    meta.get("key_profile"), "surt:host_massage=False,with_scheme=True"
                )
                # strict keys keep both scheme and www
                self.assertEqual(count_archived(conn), 2)
            finally:
                conn.close()
        finally:
            if os.path.exists(cache_path):
                os.unlink(cache_path)

    @patch("requests.Session")
    def test_resumekey_fallback_when_no_pagination(self, mock_session_cls):
        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                r = MagicMock()
                r.raise_for_status.side_effect = requests.exceptions.HTTPError("400")
                r.status_code = 400
                return r
            if params.get("resumeKey") is None:
                return _json_response(
                    [["original"], ["http://x.example/"], [], ["KEY1"]]
                )
            if params.get("resumeKey") == "KEY1":
                return _json_response([["original"], ["http://y.example/"]])
            raise AssertionError(f"unexpected params: {params}")

        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = _route

        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            cache_path = f.name
        try:
            os.unlink(cache_path)
            db_path = ensure_archived_db("http://example.com/*", cache_path, workers=1)
            conn = sqlite3.connect(db_path)
            try:
                self.assertEqual(count_archived(conn), 2)
                meta = read_meta(conn)
                self.assertEqual(meta.get("mode"), "resumekey")
                self.assertEqual(meta.get("completed"), "1")
            finally:
                conn.close()
        finally:
            if os.path.exists(cache_path):
                os.unlink(cache_path)

    @patch("requests.Session")
    def test_stale_cache_rebuilds(self, mock_session_cls):
        def _route_a(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _json_response(1)
            return _json_response([["original"], ["http://a.example/"]])

        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = _route_a

        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            cache_path = f.name
        try:
            os.unlink(cache_path)
            ensure_archived_db("http://a.example/*", cache_path, workers=1)

            def _route_b(url, params=None, headers=None, timeout=None):
                params = params or {}
                if "showNumPages" in params:
                    return _json_response(1)
                return _json_response([["original"], ["http://b.example/"]])

            mock_session.get.side_effect = _route_b
            ensure_archived_db("http://b.example/*", cache_path, workers=1)

            conn = sqlite3.connect(cache_path)
            try:
                keys = {r[0] for r in conn.execute("SELECT key FROM archived;")}
            finally:
                conn.close()
            self.assertEqual(keys, {normalize_key("http://b.example/")})
        finally:
            if os.path.exists(cache_path):
                os.unlink(cache_path)

    @patch("requests.Session")
    def test_strict_profile_switch_rebuilds(self, mock_session_cls):
        """Changing the key profile must rebuild the cache, not mix keys."""

        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _json_response(1)
            return _json_response([["original"], ["http://a.example/"]])

        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = _route

        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            cache_path = f.name
        try:
            os.unlink(cache_path)
            lenient_db = ensure_archived_db(
                "http://example.com/*", cache_path, workers=1
            )
            conn = sqlite3.connect(lenient_db)
            try:
                self.assertEqual(read_meta(conn).get("key_profile"), "surt-default")
            finally:
                conn.close()

            strict_db = ensure_archived_db(
                "http://example.com/*",
                cache_path,
                workers=1,
                key_opts=build_key_opts(True, False),
            )
            conn = sqlite3.connect(strict_db)
            try:
                meta = read_meta(conn)
                self.assertEqual(meta.get("key_profile"), "surt:host_massage=False")
                keys = {r[0] for r in conn.execute("SELECT key FROM archived;")}
                self.assertEqual(
                    keys,
                    {normalize_key("http://a.example/", {"host_massage": False})},
                )
            finally:
                conn.close()
        finally:
            if os.path.exists(cache_path):
                os.unlink(cache_path)

    @patch("requests.Session")
    def test_incompatible_shape_db_rebuilds(self, mock_session_cls):
        """A cache file whose archived table has an unexpected layout is
        rebuilt automatically instead of failing on mismatched columns."""

        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _json_response(1)
            return _json_response([["original"], ["http://a.example/"]])

        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = _route

        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            cache_path = f.name
        try:
            os.unlink(cache_path)
            # Create a cache with an incompatible archived layout manually.
            conn = sqlite3.connect(cache_path)
            conn.execute("CREATE TABLE archived(url TEXT PRIMARY KEY);")
            conn.execute("CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);")
            conn.execute("CREATE TABLE pages_done(page INTEGER PRIMARY KEY);")
            conn.execute(
                "INSERT INTO meta VALUES ('schema_v', ?);", (DB_SCHEMA_VERSION,)
            )
            conn.execute("INSERT INTO meta VALUES ('completed', '1');")
            conn.execute("INSERT INTO archived VALUES ('http://old.example/');")
            conn.commit()
            conn.close()

            db_path = ensure_archived_db("http://example.com/*", cache_path, workers=1)
            conn = sqlite3.connect(db_path)
            try:
                self.assertEqual(archived_columns(conn), {"key"})
                self.assertEqual(count_archived(conn), 1)
                keys = {r[0] for r in conn.execute("SELECT key FROM archived;")}
                self.assertEqual(keys, {normalize_key("http://a.example/")})
                self.assertEqual(read_meta(conn).get("schema_v"), DB_SCHEMA_VERSION)
            finally:
                conn.close()
        finally:
            if os.path.exists(cache_path):
                os.unlink(cache_path)


class TestVersion(unittest.TestCase):
    """Tests for the version string and User-Agent."""

    def test_version_is_semver(self):
        parts = __version__.split(".")
        self.assertEqual(len(parts), 3)
        self.assertTrue(all(p.isdigit() for p in parts))

    def test_user_agent_contains_version(self):
        self.assertIn(f"Wayback-Gap-Detector/{__version__}", USER_AGENT)


def run_tests():
    """Discover and run all test cases."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestBuildKeyOpts))
    suite.addTests(loader.loadTestsFromTestCase(TestNormalizeKey))
    suite.addTests(loader.loadTestsFromTestCase(TestNormalizeKeyStrict))
    suite.addTests(loader.loadTestsFromTestCase(TestCdxParams))
    suite.addTests(loader.loadTestsFromTestCase(TestExtractArchivedUrls))
    suite.addTests(loader.loadTestsFromTestCase(TestExceptions))
    suite.addTests(loader.loadTestsFromTestCase(TestDetectNotArchived))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestAdditionalFeatures))
    suite.addTests(loader.loadTestsFromTestCase(TestSplitResumeKey))
    suite.addTests(loader.loadTestsFromTestCase(TestSQLiteCache))
    suite.addTests(loader.loadTestsFromTestCase(TestFetchPageRowsChaining))
    suite.addTests(loader.loadTestsFromTestCase(TestFetchResumeKeyRows))
    suite.addTests(loader.loadTestsFromTestCase(TestResumeKeyCache))
    suite.addTests(loader.loadTestsFromTestCase(TestMainResumeKeyOptions))
    suite.addTests(loader.loadTestsFromTestCase(TestCDXPaginationDB))
    suite.addTests(loader.loadTestsFromTestCase(TestVersion))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result


if __name__ == "__main__":
    result = run_tests()

    print("\n" + "=" * 70)
    print("Test Result Summary")
    print("=" * 70)
    print(f"Tests run:  {result.testsRun}")
    print(f"Passed:     {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failed:     {len(result.failures)}")
    print(f"Errors:     {len(result.errors)}")
    print("=" * 70)

    exit(0 if result.wasSuccessful() else 1)
