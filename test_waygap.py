#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wayback Gap Detector - Unit Tests
Tests for each feature of waygap.py.

Key expectations are pinned literal strings verified against surt 0.3.1
with the DNS-free canonicalizer chain (canonicalize_nodns + IA tips).
Numeric-shaped hosts are covered explicitly (they are the only place
where our keys intentionally diverge from surt's gethostbyname_ex path).
"""

import unittest
import os
import json
import sqlite3
import tempfile
from unittest.mock import patch, MagicMock

from waygap import (
    normalize_key,
    build_key_opts,
    key_profile,
    KEY_CANONICALIZER,
    __version__,
    USER_AGENT,
    extract_archived_urls,
    detect_not_archived,
    ensure_archived_db,
    scan_input_against_db,
    open_db,
    insert_urls,
    count_archived,
    read_meta,
    archived_columns,
    fetch_page_rows,
    get_num_pages,
    _cdx_params,
    _split_resume_key,
    CDX_FILTER,
    CDX_FL,
    CDX_COLLAPSE,
    CDX_COLLAPSE_STRICT,
    DB_SCHEMA_VERSION,
    CDXAPIError,
    InputFileError,
)
from surt import surt as upstream_surt
import requests


def _json_response(payload):
    """Build a mocked requests.Response returning `payload` as JSON."""
    m = MagicMock()
    body = json.dumps(payload).encode('utf-8')
    m.content = body
    m.text = json.dumps(payload) if not isinstance(payload, int) else str(payload)
    m.headers = {'Content-Type': 'application/json'}
    m.status_code = 200
    m.json.return_value = payload
    m.raise_for_status.return_value = None
    return m


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
        self.assertEqual(key_profile({"host_massage": False}),
                         "surt:host_massage=False")
        self.assertEqual(key_profile({"host_massage": False, "with_scheme": True}),
                         "surt:host_massage=False,with_scheme=True")


class TestNormalizeKey(unittest.TestCase):
    """Tests for surt-key normalization (lenient mode: surt defaults)."""

    def test_blank_inputs_map_to_sentinel(self):
        self.assertEqual(normalize_key(""), "-")
        self.assertEqual(normalize_key("   "), "-")

    def test_readme_example(self):
        self.assertEqual(normalize_key("http://archive.org/goo/?a=2&b&a=1"),
                         "org,archive)/goo?a=1&a=2&b")

    def test_whitespace_and_case(self):
        self.assertEqual(normalize_key("  HTTPS://Example.com/Path  "),
                         "com,example)/path")

    def test_multipart_host_target(self):
        self.assertEqual(
            normalize_key("https://blog.example.net/articles/2024/hello/"),
            "net,example,blog)/articles/2024/hello")

    def test_fragment_removed(self):
        self.assertEqual(normalize_key("http://a/b#frag"), "a)/b")

    def test_userinfo_removed(self):
        self.assertEqual(normalize_key("http://u:p@a/b"), "a)/b")

    def test_default_port_removed(self):
        self.assertEqual(normalize_key("http://example.com:80/x"),
                         "com,example)/x")

    def test_non_default_port_kept(self):
        self.assertEqual(normalize_key("http://example.com:8080/x"),
                         "com,example:8080)/x")

    def test_www_massaged(self):
        self.assertEqual(normalize_key("http://www.example.com/"), "com,example)/")

    def test_wwwN_massaged(self):
        self.assertEqual(normalize_key("https://www2.example.com/Deep/Path"),
                         "com,example)/deep/path")

    def test_query_sorted_and_lowercased(self):
        self.assertEqual(normalize_key("https://example.com/page?Z=3&A=1"),
                         "com,example)/page?a=1&z=3")

    def test_query_valueless_and_duplicate_preserved(self):
        self.assertEqual(normalize_key("http://a.com/p?b=2&a=1&foo&foo=1"),
                         "com,a)/p?a=1&b=2&foo&foo=1")

    def test_query_blank_removed(self):
        self.assertEqual(normalize_key("https://example.com/page?"),
                         "com,example)/page")

    def test_percent_decoding(self):
        self.assertEqual(normalize_key("https://example.com/%7Euser/test"),
                         "com,example)/~user/test")
        # %2F is decoded to "/" by surt (documented, non-reversible).
        self.assertEqual(normalize_key("https://example.com/x%2fY"),
                         "com,example)/x/y")

    def test_root_query_kept(self):
        self.assertEqual(normalize_key("http://a/?x=1"), "a)/?x=1")

    def test_dot_segments(self):
        self.assertEqual(normalize_key("http://a/x/../y"), "a)/y")

    def test_repeated_slash_collapsed(self):
        self.assertEqual(normalize_key("http://a.example.com//"),
                         "com,example,a)/")

    def test_session_id_query_stripped(self):
        # Upstream wart: the leading "&" is kept verbatim after the strip.
        self.assertEqual(
            normalize_key("http://a/p?y=2&jsessionid=ABCDEF0123456789ABCDEF0123456789"),
            "a)/p?&y=2")

    def test_asp_session_id_query_stripped(self):
        self.assertEqual(
            normalize_key("http://a/p?x=1&ASPSESSIONIDABCDEFGH=AAAAAAAAAAAAAAAAAAAAHHHH"),
            "a)/p?&x=1")

    def test_cfid_cftoken_stripped(self):
        self.assertEqual(normalize_key("http://a/p?cfid=1&cftoken=2"),
                         "a)/p")

    def test_idn_host_punycoded(self):
        self.assertEqual(normalize_key("http://日本.example.com/テスト"),
                         "com,example,xn--wgv71a)/%e3%83%86%e3%82%b9%e3%83%88")

    def test_valid_ipv4_reversed(self):
        self.assertEqual(normalize_key("http://1.2.3.4/x"), "4,3,2,1)/x")

    def test_all_digit_host_masked(self):
        self.assertEqual(normalize_key("http://989137925/x"), "5,12,245,58)/x")

    def test_invalid_numeric_dotted_host_no_dns(self):
        """Numerically shaped non-IPs pass through without any DNS query."""
        with patch('socket.gethostbyname_ex',
                   side_effect=AssertionError("DNS lookup attempted")):
            self.assertEqual(normalize_key("http://123.456.78.9/x"),
                             "9,78,456,123)/x")
            self.assertEqual(normalize_key("http://07.0.0.1/x"),
                             "1,0,0,07)/x")

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
        self.assertEqual(normalize_key("http://www.a.com/p", opts),
                         "com,a,www)/p")
        self.assertEqual(normalize_key("HTTP://WWW.EXAMPLE.COM/Path?a=1", opts),
                         "com,example,www)/path?a=1")

    def test_strict_scheme_kept(self):
        opts = build_key_opts(False, True)
        self.assertEqual(normalize_key("HTTPS://a/x", opts),
                         "https://(a)/x")
        self.assertEqual(normalize_key("https://help.example.org/", opts),
                         "https://(org,example,help)/")
        self.assertEqual(normalize_key("HTTP://a/p", opts),
                         "http://(a)/p")

    def test_strict_both(self):
        opts = build_key_opts(False, False)
        self.assertEqual(normalize_key("http://www.a.com/p", opts),
                         "http://(com,a,www)/p")

    def test_lenient_merges_what_strict_keeps(self):
        lenient = normalize_key("http://www.a.com/p")
        strict = normalize_key("http://www.a.com/p", build_key_opts(True, False))
        self.assertEqual(lenient, "com,a)/p")
        self.assertEqual(strict, "com,a,www)/p")
        self.assertNotEqual(lenient, strict)


class TestCdxParams(unittest.TestCase):
    """Tests for CDX request parameter construction."""

    def test_page_params_lenient(self):
        p = _cdx_params("http://example.com/*", page=0,
                        page_size=None, collapse=CDX_COLLAPSE)
        self.assertEqual(p, {
            "url": "http://example.com/*",
            "output": "json",
            "filter": CDX_FILTER,
            "fl": CDX_FL,
            "showResumeKey": "true",
            "page": 0,
            "collapse": "urlkey",
        })
        self.assertNotIn("limit", p)
        self.assertNotIn("pageSize", p)
        self.assertNotIn("resumeKey", p)

    def test_page_params_strict_uses_original_collapse(self):
        p = _cdx_params("http://example.com/*", page=3, page_size=500,
                        collapse=CDX_COLLAPSE_STRICT)
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
        with patch('requests.Session') as mock_session_cls:
            mock_session = mock_session_cls.return_value
            resp = _json_response([["original"], ["http://a.example/"]])
            mock_session.get.return_value = resp
            fetch_page_rows("http://example.com/*", 0, None,
                            CDX_COLLAPSE, mock_session, {})
            params = mock_session.get.call_args.kwargs["params"]
            self.assertEqual(params["collapse"], "urlkey")
            self.assertNotIn("limit", params)
            self.assertEqual(params["showResumeKey"], "true")

            fetch_page_rows("http://example.com/*", 1, None,
                            CDX_COLLAPSE_STRICT, mock_session, {})
            params = mock_session.get.call_args.kwargs["params"]
            self.assertEqual(params["collapse"], "original")

    def test_get_num_pages_params_lenient(self):
        with patch('requests.Session') as mock_session_cls:
            mock_session = mock_session_cls.return_value
            mock_session.get.return_value = _json_response(5)
            n = get_num_pages("http://example.com/*", None, CDX_COLLAPSE,
                              mock_session, {})
            self.assertEqual(n, 5)
            params = mock_session.get.call_args.kwargs["params"]
            self.assertEqual(params, {
                "url": "http://example.com/*",
                "filter": CDX_FILTER,
                "showNumPages": "true",
                "collapse": "urlkey",
            })

    def test_get_num_pages_params_page_size_and_strict(self):
        with patch('requests.Session') as mock_session_cls:
            mock_session = mock_session_cls.return_value
            mock_session.get.return_value = _json_response(9)
            n = get_num_pages("http://example.com/*", 3, CDX_COLLAPSE_STRICT,
                              mock_session, {})
            self.assertEqual(n, 9)
            params = mock_session.get.call_args.kwargs["params"]
            self.assertEqual(params["collapse"], "original")
            self.assertEqual(params["pageSize"], 3)

    def test_get_num_pages_none_on_request_error(self):
        with patch('requests.Session') as mock_session_cls:
            mock_session = mock_session_cls.return_value
            r = MagicMock()
            r.raise_for_status.side_effect = requests.exceptions.HTTPError("400")
            mock_session.get.return_value = r
            self.assertIsNone(get_num_pages("http://example.com/*", None,
                                            CDX_COLLAPSE, mock_session, {}))


class TestExtractArchivedUrls(unittest.TestCase):
    """Tests for the surt-key extraction from CDX data."""

    def test_basic_extraction(self):
        cdx_data = [
            ["https://example.com/page1"],
            ["http://example.com/page2"],
        ]
        result = extract_archived_urls(cdx_data)
        self.assertEqual(result, {
            normalize_key("https://example.com/page1"),
            normalize_key("http://example.com/page2"),
        })

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
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False,
                                                     encoding='utf-8')
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
            self.temp_file.name, archived_keys,
            key_opts=build_key_opts(False, True))
        self.assertEqual(len(result), 3)

    def test_collect_archived(self):
        archived_keys = {normalize_key("https://example.com/page1")}
        not_archived, archived, total_count = detect_not_archived(
            self.temp_file.name, archived_keys, collect_archived=True)
        self.assertEqual(total_count, 3)
        self.assertEqual(len(archived), 1)
        self.assertIn("https://example.com/page1", archived)
        self.assertEqual(len(not_archived), 2)

    def test_collect_archived_disabled(self):
        archived_keys = {normalize_key("https://example.com/page1")}
        not_archived, archived, total_count = detect_not_archived(
            self.temp_file.name, archived_keys, collect_archived=False)
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

        with tempfile.NamedTemporaryFile(mode='w', delete=False,
                                         encoding='utf-8') as f:
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
            ["original", "timestamp"],      # header
            {"bad": "row"},                 # malformed row
            ["http://a.example/"],          # valid row
            "invalid_string",               # malformed row
            ["https://b/"],                 # valid row
        ]
        res = extract_archived_urls(cdx)
        self.assertEqual(res, {
            normalize_key("http://a.example/"),
            normalize_key("https://b/"),
        })

    def test_extract_header_without_original_uses_index0(self):
        cdx = [
            ["url", "timestamp"],           # header, no 'original' column
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

    def test_non_url_singleton_is_a_key(self):
        data = [["original"], ["http://a.example/"], ["SOMEKEY"]]
        rows, key = _split_resume_key(data)
        self.assertEqual(key, "SOMEKEY")
        self.assertEqual(len(rows), 2)


class TestSQLiteCache(unittest.TestCase):
    """Tests for the SQLite cache layer (keys only)."""

    def test_open_db_schema(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            path = f.name
        try:
            os.unlink(path)
            conn = open_db(path)
            try:
                tables = {r[0]: r[1] for r in
                          conn.execute("SELECT name, sql FROM sqlite_master WHERE type='table';")}
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

            with tempfile.NamedTemporaryFile(mode='w', delete=False,
                                             encoding='utf-8') as f:
                f.write("https://example.com/a\nhttps://example.com/b\n")
                input_path = f.name
            out_fd, out_path = tempfile.mkstemp()
            os.close(out_fd)
            arch_fd, arch_path = tempfile.mkstemp()
            os.close(arch_fd)
            try:
                total, not_count, arch_count = scan_input_against_db(
                    input_path, db_path,
                    output_file=out_path, output_archived=arch_path,
                    batch_size=1)
                self.assertEqual((total, not_count, arch_count), (2, 1, 1))
                with open(out_path, encoding='utf-8') as fh:
                    self.assertIn("https://example.com/b", fh.read())
                with open(arch_path, encoding='utf-8') as fh:
                    self.assertIn("https://example.com/a", fh.read())
            finally:
                for p in (input_path, out_path, arch_path):
                    if os.path.exists(p):
                        os.unlink(p)
        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)


class TestFetchPageRowsChaining(unittest.TestCase):
    """Tests for in-page resumeKey chaining without a hard iteration cap."""

    @patch('requests.Session')
    def test_chain_beyond_1000_iterations_not_truncated(self, mock_session_cls):
        responses = []
        for i in range(1000):
            responses.append(_json_response(
                [["original"], [f"http://page{i}.example/"], [], [f"KEY_{i}"]]))
        responses.append(_json_response(
            [["original"], ["http://page1000.example/"]]))
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = responses

        rows = fetch_page_rows("http://example.com/*", 0, None,
                               None, mock_session, {})

        self.assertEqual(mock_session.get.call_count, 1001)
        self.assertEqual(len(rows), 1001)
        self.assertTrue(any("page1000" in str(r) for r in rows),
                        "tail row lost: chaining was truncated")

    @patch('requests.Session')
    def test_cycle_detection_breaks_without_hang(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.get.return_value = _json_response(
            [["original"], ["http://a.example/"], [], ["SAME_KEY"]])

        rows = fetch_page_rows("http://example.com/*", 0, None,
                               None, mock_session, {})

        self.assertEqual(mock_session.get.call_count, 2)
        self.assertEqual(len(rows), 2)


class TestCDXPaginationDB(unittest.TestCase):
    """Tests for pagination fetch into SQLite (mocked API)."""

    @patch('requests.Session')
    def test_pagination_build_and_reuse(self, mock_session_cls):
        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if 'showNumPages' in params:
                self.assertEqual(params.get("collapse"), "urlkey")
                return _json_response(2)
            self.assertEqual(params.get("collapse"), "urlkey")
            self.assertNotIn("limit", params)
            if params.get('page') == 0:
                return _json_response(
                    [["original"], ["http://a.example/"],
                     ["https://b.example/"]])
            if params.get('page') == 1:
                return _json_response([["original"], ["http://c.example/"]])
            raise AssertionError(f"unexpected params: {params}")

        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = _route

        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            cache_path = f.name
        try:
            os.unlink(cache_path)
            db_path = ensure_archived_db("http://example.com/*", cache_path,
                                         workers=1)
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
            with patch('requests.Session') as mock_session_cls2:
                ensure_archived_db("http://example.com/*", cache_path, workers=1)
                mock_session_cls2.assert_not_called()
        finally:
            if os.path.exists(cache_path):
                os.unlink(cache_path)

    @patch('requests.Session')
    def test_pagination_strict_uses_original_collapse(self, mock_session_cls):
        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            self.assertEqual(params.get("collapse"), "original")
            if 'showNumPages' in params:
                self.assertEqual(params.get("pageSize"), 2)
                return _json_response(1)
            self.assertEqual(params.get("pageSize"), 2)
            self.assertNotIn("limit", params)
            return _json_response(
                [["original"], ["http://www.a.example/p"],
                 ["https://a.example/p"]])

        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = _route

        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            cache_path = f.name
        try:
            os.unlink(cache_path)
            db_path = ensure_archived_db(
                "http://example.com/*", cache_path,
                key_opts=build_key_opts(False, False),
                page_size=2, workers=1)
            conn = sqlite3.connect(db_path)
            try:
                meta = read_meta(conn)
                self.assertEqual(meta.get("completed"), "1")
                self.assertEqual(meta.get("key_profile"),
                                 "surt:host_massage=False,with_scheme=True")
                # strict keys keep both scheme and www
                self.assertEqual(count_archived(conn), 2)
            finally:
                conn.close()
        finally:
            if os.path.exists(cache_path):
                os.unlink(cache_path)

    @patch('requests.Session')
    def test_resumekey_fallback_when_no_pagination(self, mock_session_cls):
        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if 'showNumPages' in params:
                r = MagicMock()
                r.raise_for_status.side_effect = requests.exceptions.HTTPError("400")
                r.status_code = 400
                return r
            if params.get('resumeKey') is None:
                return _json_response(
                    [["original"], ["http://x.example/"], [], ["KEY1"]])
            if params.get('resumeKey') == 'KEY1':
                return _json_response([["original"], ["http://y.example/"]])
            raise AssertionError(f"unexpected params: {params}")

        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = _route

        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            cache_path = f.name
        try:
            os.unlink(cache_path)
            db_path = ensure_archived_db("http://example.com/*", cache_path,
                                         workers=1)
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

    @patch('requests.Session')
    def test_stale_cache_rebuilds(self, mock_session_cls):
        def _route_a(url, params=None, headers=None, timeout=None):
            params = params or {}
            if 'showNumPages' in params:
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
                if 'showNumPages' in params:
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

    @patch('requests.Session')
    def test_strict_profile_switch_rebuilds(self, mock_session_cls):
        """Changing the key profile must rebuild the cache, not mix keys."""
        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if 'showNumPages' in params:
                return _json_response(1)
            return _json_response([["original"], ["http://a.example/"]])

        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = _route

        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            cache_path = f.name
        try:
            os.unlink(cache_path)
            lenient_db = ensure_archived_db("http://example.com/*", cache_path,
                                            workers=1)
            conn = sqlite3.connect(lenient_db)
            try:
                self.assertEqual(read_meta(conn).get("key_profile"),
                                 "surt-default")
            finally:
                conn.close()

            strict_db = ensure_archived_db(
                "http://example.com/*", cache_path, workers=1,
                key_opts=build_key_opts(True, False))
            conn = sqlite3.connect(strict_db)
            try:
                meta = read_meta(conn)
                self.assertEqual(meta.get("key_profile"),
                                 "surt:host_massage=False")
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

    @patch('requests.Session')
    def test_incompatible_shape_db_rebuilds(self, mock_session_cls):
        """A cache file whose archived table has an unexpected layout is
        rebuilt automatically instead of failing on mismatched columns."""
        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if 'showNumPages' in params:
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
            conn.execute("INSERT INTO meta VALUES ('schema_v', ?);",
                         (DB_SCHEMA_VERSION,))
            conn.execute("INSERT INTO meta VALUES ('completed', '1');")
            conn.execute("INSERT INTO archived VALUES ('http://old.example/');")
            conn.commit()
            conn.close()

            db_path = ensure_archived_db("http://example.com/*", cache_path,
                                         workers=1)
            conn = sqlite3.connect(db_path)
            try:
                self.assertEqual(archived_columns(conn), {"key"})
                self.assertEqual(count_archived(conn), 1)
                keys = {r[0] for r in conn.execute("SELECT key FROM archived;")}
                self.assertEqual(keys, {normalize_key("http://a.example/")})
                self.assertEqual(read_meta(conn).get("schema_v"),
                                 DB_SCHEMA_VERSION)
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
    suite.addTests(loader.loadTestsFromTestCase(TestCDXPaginationDB))
    suite.addTests(loader.loadTestsFromTestCase(TestVersion))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result


if __name__ == '__main__':
    result = run_tests()

    print("\n" + "="*70)
    print("Test Result Summary")
    print("="*70)
    print(f"Tests run:  {result.testsRun}")
    print(f"Passed:     {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failed:     {len(result.failures)}")
    print(f"Errors:     {len(result.errors)}")
    print("="*70)

    exit(0 if result.wasSuccessful() else 1)
