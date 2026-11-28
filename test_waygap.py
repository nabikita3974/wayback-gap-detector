"""
Wayback Gap Detector - Unit Tests
Tests for each feature of waygap.py.

Key expectations are pinned literal strings verified against surt 0.3.1
with the DNS-free canonicalizer chain (canonicalize_nodns + IA tips).
Numeric-shaped hosts are covered explicitly (they are the only place
where our keys intentionally diverge from surt's gethostbyname_ex path).
"""

import _thread
import concurrent.futures
import contextlib
import gc
import io
import json
import os
import shutil
import sqlite3
import tempfile
import threading
import time
import unittest
import weakref
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests
from requests.adapters import HTTPAdapter
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


def _status_response(status, headers=None):
    """Build a mocked requests.Response with an empty body and `status`."""
    m = MagicMock()
    m.status_code = status
    m.headers = dict(headers or {})
    m.content = b""
    m.text = ""
    m.raise_for_status.side_effect = requests.exceptions.HTTPError(
        f"{status} Client Error", response=m
    )
    return m


@pytest.fixture(autouse=True)
def _no_cdx_throttle(monkeypatch):
    """Disable the CDX request interval so tests do not sleep."""
    monkeypatch.setattr(waygap, "_CDX_LIMITER", _RateLimiter(0))


@contextlib.contextmanager
def _join_new_threads(timeout: float = 10.0):
    """Wait for the non-daemon threads started inside the block to finish.

    Page fetch workers may outlive the call that started them, so a test
    must wait for them before leaving its mock patches (a late worker would
    run the real fetch) or starting the next run.
    """
    before = set(threading.enumerate())
    try:
        yield
    finally:
        new = [t for t in threading.enumerate() if t not in before and not t.daemon]
        for t in new:
            t.join(timeout)
        alive = [t.name for t in new if t.is_alive()]
        if alive:
            raise AssertionError(f"threads still running: {alive}")


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

    def test_get_num_pages_none_on_http_400(self):
        with patch("requests.Session") as mock_session_cls:
            mock_session = mock_session_cls.return_value
            mock_session.get.return_value = _status_response(400)
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

    def test_utf8_bom_is_not_part_of_first_url(self):
        with tempfile.TemporaryDirectory() as directory:
            input_file = Path(directory) / "urls.txt"
            input_file.write_bytes(
                b"\xef\xbb\xbfhttps://example.com/page1\nhttps://example.com/page2\n"
            )
            archived_keys = {
                normalize_key("https://example.com/page1"),
                normalize_key("https://example.com/page2"),
            }
            not_archived, archived, total_count = detect_not_archived(
                str(input_file), archived_keys, collect_archived=True
            )
        self.assertEqual(not_archived, [])
        self.assertEqual(
            archived, ["https://example.com/page1", "https://example.com/page2"]
        )
        self.assertEqual(total_count, 2)


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

    def test_scan_strips_utf8_bom_from_input(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = os.path.join(directory, "cache.db")
            conn = open_db(db_path)
            try:
                insert_urls(
                    conn,
                    [
                        normalize_key("https://example.com/a"),
                        normalize_key("https://example.com/b"),
                    ],
                )
            finally:
                conn.close()

            input_file = Path(directory) / "urls.txt"
            input_file.write_bytes(
                b"\xef\xbb\xbfhttps://example.com/a\nhttps://example.com/b\n"
            )
            out_file = Path(directory) / "not_archived.txt"
            arch_file = Path(directory) / "archived.txt"
            result = scan_input_against_db(
                str(input_file),
                db_path,
                output_file=str(out_file),
                output_archived=str(arch_file),
            )
            self.assertEqual(result, (2, 0, 2))
            self.assertEqual(out_file.read_bytes(), b"")
            self.assertEqual(
                arch_file.read_text(encoding="utf-8").splitlines(),
                ["https://example.com/a", "https://example.com/b"],
            )


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
    @patch("waygap.time.monotonic", return_value=100.0)
    def test_wait_after_pause_waits_for_the_pause(self, _monotonic, mock_sleep):
        limiter = _RateLimiter(3.0)
        limiter.pause(60.0)
        limiter.wait()
        mock_sleep.assert_called_once_with(60.0)

        mock_sleep.reset_mock()
        limiter = _RateLimiter(3.0)
        limiter.pause(120.0)
        limiter.pause(60.0)  # must not shorten the longer pause
        limiter.wait()
        mock_sleep.assert_called_once_with(120.0)

    @patch("waygap.time.sleep")
    @patch("waygap.time.monotonic")
    def test_pause_during_wait_makes_wait_retake_a_slot(
        self, mock_monotonic, mock_sleep
    ):
        limiter = _RateLimiter(3.0)
        mock_monotonic.return_value = 100.0
        limiter.wait()  # the next slot is at 103

        def _sleep(seconds):
            if mock_sleep.call_count == 1:
                limiter.pause(60.0)  # another worker got a 429 at 100
            mock_monotonic.return_value += seconds

        mock_sleep.side_effect = _sleep
        limiter.wait()

        self.assertEqual([c.args[0] for c in mock_sleep.call_args_list], [3.0, 57.0])

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

        mock_limiter.wait.assert_called_once_with(None)


class TestFetchCancellation(unittest.TestCase):
    """Tests for the stop event that cancels page fetch workers."""

    @staticmethod
    def _set_stop() -> threading.Event:
        stop = threading.Event()
        stop.set()
        return stop

    @patch("waygap.time.sleep")
    def test_pause_without_stop_sleeps(self, mock_sleep):
        waygap._pause(2.0, None)

        mock_sleep.assert_called_once_with(2.0)

    @patch("waygap.time.sleep")
    def test_pause_raises_at_once_when_stop_is_set(self, mock_sleep):
        start = time.monotonic()
        with self.assertRaises(waygap._FetchCancelled):
            waygap._pause(5.0, self._set_stop())

        self.assertLess(time.monotonic() - start, 1.0)
        mock_sleep.assert_not_called()

    @patch("waygap.time.sleep")
    @patch("waygap.time.monotonic", return_value=100.0)
    def test_rate_limiter_raises_without_sleeping_when_stop_is_set(
        self, _monotonic, mock_sleep
    ):
        limiter = _RateLimiter(3.0)
        limiter.wait()  # the next call has a reserved 3 s wait

        with self.assertRaises(waygap._FetchCancelled):
            limiter.wait(self._set_stop())

        mock_sleep.assert_not_called()

    @patch("requests.Session")
    def test_get_with_retries_skips_request_when_stopped(self, mock_session_cls):
        mock_session = mock_session_cls.return_value

        with self.assertRaises(waygap._FetchCancelled):
            _get_with_retries(
                mock_session, "https://example.invalid/", {}, {}, stop=self._set_stop()
            )

        mock_session.get.assert_not_called()

    @patch("requests.Session")
    def test_get_with_retries_error_after_stop_cancels_without_warning(
        self, mock_session_cls
    ):
        stop = threading.Event()

        def _get(*args, **kwargs):
            stop.set()
            raise requests.exceptions.ConnectionError("reset")

        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = _get

        with (
            self.assertNoLogs("waygap", level="WARNING"),
            self.assertRaises(waygap._FetchCancelled),
        ):
            _get_with_retries(
                mock_session, "https://example.invalid/", {}, {}, stop=stop
            )

        self.assertEqual(mock_session.get.call_count, 1)

    @patch("requests.Session")
    def test_fetch_page_rows_skips_request_when_stopped(self, mock_session_cls):
        mock_session = mock_session_cls.return_value

        with self.assertRaises(waygap._FetchCancelled):
            fetch_page_rows(
                TARGET, 0, None, None, mock_session, {}, stop=self._set_stop()
            )

        mock_session.get.assert_not_called()


class TestCdxRateLimit429(unittest.TestCase):
    """Tests for pausing every CDX request after HTTP 429."""

    URL = "https://example.invalid/"

    @staticmethod
    def _pauses(mock_limiter) -> list:
        return [c.args[0] for c in mock_limiter.pause.call_args_list]

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_one_429_pauses_60_s_then_retries(self, mock_session_cls, mock_sleep):
        ok = _json_response([["original"]])
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [_status_response(429), ok]

        with patch("waygap._CDX_LIMITER") as mock_limiter:
            response = _get_with_retries(mock_session, self.URL, {}, {})

        self.assertIs(response, ok)
        self.assertEqual(self._pauses(mock_limiter), [60.0])
        self.assertEqual(mock_session.get.call_count, 2)
        mock_sleep.assert_not_called()

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_consecutive_429s_pause_60_120_240_s(self, mock_session_cls, mock_sleep):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [_status_response(429)] * 3 + [
            _json_response([["original"]])
        ]

        with patch("waygap._CDX_LIMITER") as mock_limiter:
            _get_with_retries(mock_session, self.URL, {}, {})

        self.assertEqual(self._pauses(mock_limiter), [60.0, 120.0, 240.0])
        self.assertEqual(mock_session.get.call_count, 4)
        mock_sleep.assert_not_called()

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_fourth_429_fails_without_more_requests(self, mock_session_cls, mock_sleep):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [_status_response(429)] * 4 + [
            _json_response([["original"]])
        ]

        with (
            patch("waygap._CDX_LIMITER"),
            self.assertRaises(CDXAPIError) as cm,
        ):
            _get_with_retries(mock_session, self.URL, {}, {})

        self.assertIn("429", str(cm.exception))
        self.assertEqual(mock_session.get.call_count, 4)
        mock_sleep.assert_not_called()

    @patch("requests.Session")
    def test_stop_during_pause_cancels_at_once(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _status_response(429),
            _json_response([["original"]]),
        ]
        stop = threading.Event()
        timer = threading.Timer(0.2, stop.set)

        with patch("waygap._CDX_LIMITER", _RateLimiter(0)):
            start = time.monotonic()
            timer.start()
            try:
                with self.assertRaises(waygap._FetchCancelled):
                    _get_with_retries(mock_session, self.URL, {}, {}, stop=stop)
            finally:
                timer.cancel()

        self.assertLess(time.monotonic() - start, 2.0)
        self.assertEqual(mock_session.get.call_count, 1)

    def test_session_does_not_retry_status_codes(self):
        adapter = waygap.make_session().get_adapter("https://web.archive.org/")
        assert isinstance(adapter, HTTPAdapter)
        retry = adapter.max_retries

        for code in (429, 500, 502, 503, 504):
            with self.subTest(status=code):
                self.assertFalse(retry.is_retry("GET", code))
        self.assertFalse(retry.is_retry("GET", 429, has_retry_after=True))
        self.assertFalse(retry.is_retry("GET", 503, has_retry_after=True))

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_retry_after_raises_the_first_pause(self, mock_session_cls, mock_sleep):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _status_response(429, {"Retry-After": "200"}),
            _json_response([["original"]]),
        ]

        with (
            patch("waygap._CDX_LIMITER") as mock_limiter,
            self.assertLogs("waygap", level="WARNING") as logs,
        ):
            _get_with_retries(mock_session, self.URL, {}, {})

        self.assertEqual(self._pauses(mock_limiter), [200.0])
        self.assertTrue(any("200" in line for line in logs.output))
        mock_sleep.assert_not_called()

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_retry_after_over_last_pause_fails_at_once(
        self, mock_session_cls, mock_sleep
    ):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _status_response(429, {"Retry-After": "241"}),
            _json_response([["original"]]),
        ]

        with (
            patch("waygap._CDX_LIMITER") as mock_limiter,
            self.assertRaises(CDXAPIError) as cm,
        ):
            _get_with_retries(mock_session, self.URL, {}, {})

        self.assertIn("241", str(cm.exception))
        mock_limiter.pause.assert_not_called()
        self.assertEqual(mock_session.get.call_count, 1)
        mock_sleep.assert_not_called()

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_retry_after_equal_to_last_pause_is_waited(
        self, mock_session_cls, mock_sleep
    ):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _status_response(429, {"Retry-After": "240"}),
            _json_response([["original"]]),
        ]

        with patch("waygap._CDX_LIMITER") as mock_limiter:
            _get_with_retries(mock_session, self.URL, {}, {})

        self.assertEqual(self._pauses(mock_limiter), [240.0])
        mock_sleep.assert_not_called()

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_short_retry_after_does_not_shorten_the_pause(
        self, mock_session_cls, mock_sleep
    ):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _status_response(429, {"Retry-After": "10"}),
            _json_response([["original"]]),
        ]

        with patch("waygap._CDX_LIMITER") as mock_limiter:
            _get_with_retries(mock_session, self.URL, {}, {})

        self.assertEqual(self._pauses(mock_limiter), [60.0])
        mock_sleep.assert_not_called()

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_invalid_retry_after_is_ignored(self, mock_session_cls, mock_sleep):
        for value in ("soon", "-5"):
            with self.subTest(retry_after=value):
                mock_session = mock_session_cls.return_value
                mock_session.get.reset_mock()
                mock_session.get.side_effect = [
                    _status_response(429, {"Retry-After": value}),
                    _json_response([["original"]]),
                ]

                with patch("waygap._CDX_LIMITER") as mock_limiter:
                    _get_with_retries(mock_session, self.URL, {}, {})

                self.assertEqual(self._pauses(mock_limiter), [60.0])
        mock_sleep.assert_not_called()

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_resumekey_fetch_keeps_key_after_persistent_429(
        self, mock_session_cls, mock_sleep
    ):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _json_response([["original"], ["http://a.example/"], [], ["KEY1"]])
        ] + [_status_response(429)] * 4

        with (
            patch("waygap._CDX_LIMITER"),
            self.assertRaises(waygap.ResumeKeyRequestError) as cm,
        ):
            _drain(fetch_resumekey_rows(TARGET, None, None, None, mock_session, {}))

        self.assertEqual(cm.exception.resume_key, "KEY1")
        self.assertIn("429", str(cm.exception))
        mock_sleep.assert_not_called()

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_get_num_pages_429_pauses_then_returns_count(
        self, mock_session_cls, mock_sleep
    ):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [_status_response(429), _json_response(5)]

        with patch("waygap._CDX_LIMITER") as mock_limiter:
            n = get_num_pages(TARGET, None, CDX_COLLAPSE, mock_session, {})

        self.assertEqual(n, 5)
        self.assertEqual(self._pauses(mock_limiter), [60.0])
        self.assertEqual(mock_session.get.call_count, 2)
        mock_sleep.assert_not_called()

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_get_num_pages_persistent_429_fails_without_more_requests(
        self, mock_session_cls, mock_sleep
    ):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [_status_response(429)] * 4 + [_json_response(5)]

        with (
            patch("waygap._CDX_LIMITER"),
            self.assertRaises(CDXAPIError) as cm,
        ):
            get_num_pages(TARGET, None, CDX_COLLAPSE, mock_session, {})

        self.assertIn("429", str(cm.exception))
        self.assertEqual(mock_session.get.call_count, 4)
        mock_sleep.assert_not_called()


class TestCdx5xxRetry(unittest.TestCase):
    """Tests for retrying HTTP 500/502/503/504 in one place."""

    URL = "https://example.invalid/"

    @staticmethod
    def _pauses(mock_limiter) -> list:
        return [c.args[0] for c in mock_limiter.pause.call_args_list]

    @staticmethod
    def _sleeps(mock_sleep) -> list:
        return [c.args[0] for c in mock_sleep.call_args_list]

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_persistent_5xx_waits_10_20_s(self, mock_session_cls, mock_sleep):
        for status in (500, 502, 503, 504):
            with self.subTest(status=status):
                mock_sleep.reset_mock()
                mock_session = mock_session_cls.return_value
                mock_session.get.reset_mock()
                mock_session.get.side_effect = [_status_response(status)] * 3 + [
                    _json_response([["original"]])
                ]

                with (
                    patch("waygap._CDX_LIMITER") as mock_limiter,
                    self.assertLogs("waygap", level="WARNING") as logs,
                    self.assertRaises(CDXAPIError),
                ):
                    _get_with_retries(mock_session, self.URL, {}, {})

                self.assertEqual(self._sleeps(mock_sleep), [10.0, 20.0])
                self.assertEqual(mock_session.get.call_count, 3)
                self.assertEqual(mock_limiter.wait.call_count, 3)
                mock_limiter.pause.assert_not_called()
                request_errors = [
                    line for line in logs.output if "Request error (attempt" in line
                ]
                self.assertEqual(len(request_errors), 3)

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_request_error_waits_1_2_s(self, mock_session_cls, mock_sleep):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            requests.exceptions.ConnectionError("reset")
        ] * 3 + [_json_response([["original"]])]

        with patch("waygap._CDX_LIMITER"), self.assertRaises(CDXAPIError):
            _get_with_retries(mock_session, self.URL, {}, {})

        self.assertEqual(self._sleeps(mock_sleep), [1, 2])
        self.assertEqual(mock_session.get.call_count, 3)

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_501_keeps_1_2_s_waits(self, mock_session_cls, mock_sleep):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [_status_response(501)] * 3

        with (
            patch("waygap._CDX_LIMITER") as mock_limiter,
            self.assertRaises(CDXAPIError),
        ):
            _get_with_retries(mock_session, self.URL, {}, {})

        self.assertEqual(self._sleeps(mock_sleep), [1, 2])
        mock_limiter.pause.assert_not_called()

    @patch("requests.Session")
    def test_stop_during_5xx_wait_cancels_at_once(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _status_response(503),
            _json_response([["original"]]),
        ]
        stop = threading.Event()
        timer = threading.Timer(0.2, stop.set)

        with (
            patch("waygap._CDX_LIMITER", _RateLimiter(0)),
            patch("waygap._pause", wraps=waygap._pause) as spy_pause,
        ):
            start = time.monotonic()
            timer.start()
            try:
                with self.assertRaises(waygap._FetchCancelled):
                    _get_with_retries(mock_session, self.URL, {}, {}, stop=stop)
            finally:
                timer.cancel()

        self.assertLess(time.monotonic() - start, 2.0)
        self.assertEqual(mock_session.get.call_count, 1)
        spy_pause.assert_called_once_with(10.0, stop)

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_5xx_retry_after_pauses_all_requests(self, mock_session_cls, mock_sleep):
        ok = _json_response([["original"]])
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _status_response(503, {"Retry-After": "30"}),
            ok,
        ]

        with (
            patch("waygap._CDX_LIMITER") as mock_limiter,
            self.assertLogs("waygap", level="WARNING") as logs,
        ):
            response = _get_with_retries(mock_session, self.URL, {}, {})

        self.assertIs(response, ok)
        self.assertEqual(self._pauses(mock_limiter), [30.0])
        self.assertEqual(self._sleeps(mock_sleep), [10.0])
        self.assertEqual(mock_session.get.call_count, 2)
        self.assertTrue(
            any(
                "CDX API returned HTTP 503 with Retry-After: 30; "
                "pausing all CDX requests for 30 s" in line
                for line in logs.output
            )
        )

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_5xx_retry_after_pauses_all_but_keeps_normal_wait(
        self, mock_session_cls, mock_sleep
    ):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _status_response(503, {"Retry-After": "5"}),
            _json_response([["original"]]),
        ]

        with patch("waygap._CDX_LIMITER") as mock_limiter:
            _get_with_retries(mock_session, self.URL, {}, {})

        self.assertEqual(self._pauses(mock_limiter), [5.0])
        self.assertEqual(self._sleeps(mock_sleep), [10.0])

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_5xx_retry_after_too_long_fails_at_once(self, mock_session_cls, mock_sleep):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _status_response(503, {"Retry-After": "241"}),
            _json_response([["original"]]),
        ]

        with (
            patch("waygap._CDX_LIMITER") as mock_limiter,
            self.assertRaises(CDXAPIError) as cm,
        ):
            _get_with_retries(mock_session, self.URL, {}, {})

        self.assertIn("Retry-After", str(cm.exception))
        self.assertIn("241", str(cm.exception))
        self.assertEqual(mock_session.get.call_count, 1)
        mock_limiter.pause.assert_not_called()
        mock_sleep.assert_not_called()

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_5xx_invalid_retry_after_uses_normal_wait(
        self, mock_session_cls, mock_sleep
    ):
        for value in ("soon", "0"):
            with self.subTest(retry_after=value):
                mock_sleep.reset_mock()
                mock_session = mock_session_cls.return_value
                mock_session.get.reset_mock()
                mock_session.get.side_effect = [
                    _status_response(503, {"Retry-After": value}),
                    _json_response([["original"]]),
                ]

                with patch("waygap._CDX_LIMITER") as mock_limiter:
                    _get_with_retries(mock_session, self.URL, {}, {})

                mock_limiter.pause.assert_not_called()
                self.assertEqual(self._sleeps(mock_sleep), [10.0])

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_get_with_retries_last_5xx_with_long_retry_after_raises(
        self, mock_session_cls, mock_sleep
    ):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _status_response(503),
            _status_response(503),
            _status_response(503, {"Retry-After": "241"}),
        ]

        with (
            patch("waygap._CDX_LIMITER") as mock_limiter,
            self.assertRaises(CDXAPIError) as cm,
        ):
            _get_with_retries(mock_session, self.URL, {}, {})

        self.assertIn("241", str(cm.exception))
        self.assertEqual(mock_session.get.call_count, 3)
        mock_limiter.pause.assert_not_called()

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_get_num_pages_retries_5xx_then_returns_count(
        self, mock_session_cls, mock_sleep
    ):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [_status_response(503), _json_response(5)]

        with (
            patch("waygap._CDX_LIMITER"),
            self.assertLogs("waygap", level="WARNING") as logs,
        ):
            n = get_num_pages(TARGET, None, CDX_COLLAPSE, mock_session, {})

        self.assertEqual(n, 5)
        self.assertEqual(mock_session.get.call_count, 2)
        self.assertEqual(self._sleeps(mock_sleep), [10.0])
        self.assertTrue(
            any(
                "showNumPages request error (attempt 1/3)" in line
                for line in logs.output
            )
        )

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_get_num_pages_persistent_5xx_raises(self, mock_session_cls, mock_sleep):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [_status_response(503)] * 3 + [_json_response(5)]

        with patch("waygap._CDX_LIMITER"), self.assertRaises(CDXAPIError) as cm:
            get_num_pages(TARGET, None, CDX_COLLAPSE, mock_session, {})

        self.assertIn(
            "showNumPages request failed (max retries reached)", str(cm.exception)
        )
        self.assertEqual(mock_session.get.call_count, 3)
        self.assertEqual(self._sleeps(mock_sleep), [10.0, 20.0])

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_get_num_pages_400_falls_back_at_once(self, mock_session_cls, mock_sleep):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [_status_response(400), _json_response(5)]

        with (
            patch("waygap._CDX_LIMITER"),
            self.assertLogs("waygap", level="INFO") as logs,
        ):
            n = get_num_pages(TARGET, None, CDX_COLLAPSE, mock_session, {})

        self.assertIsNone(n)
        self.assertEqual(mock_session.get.call_count, 1)
        mock_sleep.assert_not_called()
        self.assertEqual(
            [(r.levelname, r.getMessage()) for r in logs.records],
            [
                (
                    "INFO",
                    "showNumPages returned HTTP 400 (pagination unsupported), "
                    "falling back to resumeKey mode",
                )
            ],
        )

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_get_num_pages_5xx_retry_after_too_long_raises(
        self, mock_session_cls, mock_sleep
    ):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _status_response(503, {"Retry-After": "241"}),
            _json_response(5),
        ]

        with (
            patch("waygap._CDX_LIMITER") as mock_limiter,
            self.assertRaises(CDXAPIError) as cm,
        ):
            get_num_pages(TARGET, None, CDX_COLLAPSE, mock_session, {})

        self.assertIn("241", str(cm.exception))
        self.assertEqual(mock_session.get.call_count, 1)
        mock_limiter.pause.assert_not_called()
        mock_sleep.assert_not_called()

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_get_num_pages_last_5xx_with_long_retry_after_raises(
        self, mock_session_cls, mock_sleep
    ):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _status_response(503),
            _status_response(503),
            _status_response(503, {"Retry-After": "241"}),
        ]

        with patch("waygap._CDX_LIMITER"), self.assertRaises(CDXAPIError) as cm:
            get_num_pages(TARGET, None, CDX_COLLAPSE, mock_session, {})

        self.assertIn("241", str(cm.exception))
        self.assertEqual(mock_session.get.call_count, 3)

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_get_num_pages_last_5xx_retry_after_raises_without_pause(
        self, mock_session_cls, mock_sleep
    ):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _status_response(503),
            _status_response(503),
            _status_response(503, {"Retry-After": "120"}),
        ]

        with (
            patch("waygap._CDX_LIMITER") as mock_limiter,
            self.assertLogs("waygap", level="WARNING") as logs,
            self.assertRaises(CDXAPIError),
        ):
            get_num_pages(TARGET, None, CDX_COLLAPSE, mock_session, {})

        self.assertEqual(mock_session.get.call_count, 3)
        mock_limiter.pause.assert_not_called()
        self.assertEqual(self._sleeps(mock_sleep), [10.0, 20.0])
        self.assertFalse(
            any("pausing all CDX requests" in line for line in logs.output)
        )

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_get_with_retries_last_5xx_retry_after_pauses_then_fails(
        self, mock_session_cls, mock_sleep
    ):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _status_response(503),
            _status_response(503),
            _status_response(503, {"Retry-After": "120"}),
        ]

        with (
            patch("waygap._CDX_LIMITER") as mock_limiter,
            self.assertRaises(CDXAPIError),
        ):
            _get_with_retries(mock_session, self.URL, {}, {})

        self.assertEqual(mock_session.get.call_count, 3)
        self.assertEqual(self._pauses(mock_limiter), [120.0])
        self.assertEqual(self._sleeps(mock_sleep), [10.0, 20.0])

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_resumekey_fetch_keeps_key_after_5xx_long_retry_after(
        self, mock_session_cls, mock_sleep
    ):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _json_response([["original"], ["http://a.example/"], [], ["KEY1"]]),
            _status_response(503, {"Retry-After": "241"}),
            _json_response([["original"]]),
        ]

        with (
            patch("waygap._CDX_LIMITER"),
            self.assertRaises(waygap.ResumeKeyRequestError) as cm,
        ):
            _drain(fetch_resumekey_rows(TARGET, None, None, None, mock_session, {}))

        self.assertEqual(cm.exception.resume_key, "KEY1")
        self.assertIn("241", str(cm.exception))
        self.assertEqual(mock_session.get.call_count, 2)


def _html_response():
    """A 200 response whose body is not a page count."""
    m = MagicMock()
    m.status_code = 200
    m.headers = {"Content-Type": "text/html"}
    m.content = b"<html>"
    m.text = "<html>"
    m.json.side_effect = ValueError("not JSON")
    m.raise_for_status.return_value = None
    return m


class TestShowNumPagesErrors(unittest.TestCase):
    """Tests that only HTTP 400 makes the page count request give up at once."""

    @staticmethod
    def _sleeps(mock_sleep) -> list:
        return [c.args[0] for c in mock_sleep.call_args_list]

    def _assert_retried_then_raised(self, responses, mock_session_cls, mock_sleep):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = responses

        with (
            patch("waygap._CDX_LIMITER"),
            self.assertLogs("waygap", level="WARNING") as logs,
            self.assertRaises(CDXAPIError) as cm,
        ):
            get_num_pages(TARGET, None, CDX_COLLAPSE, mock_session, {})

        self.assertIn(
            "showNumPages request failed (max retries reached)", str(cm.exception)
        )
        self.assertEqual(mock_session.get.call_count, 3)
        self.assertEqual(self._sleeps(mock_sleep), [1, 2])
        warnings = [
            r.getMessage()
            for r in logs.records
            if r.getMessage().startswith("showNumPages request error (attempt ")
        ]
        self.assertEqual(
            [w.split(")")[0] for w in warnings],
            [f"showNumPages request error (attempt {n}/3" for n in (1, 2, 3)],
        )
        return warnings

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_get_num_pages_404_retries_then_raises(self, mock_session_cls, mock_sleep):
        self._assert_retried_then_raised(
            [_status_response(404)] * 3 + [_json_response(5)],
            mock_session_cls,
            mock_sleep,
        )

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_get_num_pages_connection_error_retries_then_raises(
        self, mock_session_cls, mock_sleep
    ):
        self._assert_retried_then_raised(
            [requests.exceptions.ConnectionError("reset")] * 3 + [_json_response(5)],
            mock_session_cls,
            mock_sleep,
        )

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_get_num_pages_404_then_returns_count(self, mock_session_cls, mock_sleep):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [_status_response(404), _json_response(5)]

        with patch("waygap._CDX_LIMITER"):
            n = get_num_pages(TARGET, None, CDX_COLLAPSE, mock_session, {})

        self.assertEqual(n, 5)
        self.assertEqual(mock_session.get.call_count, 2)
        self.assertEqual(self._sleeps(mock_sleep), [1])

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_get_num_pages_404_then_400_falls_back(self, mock_session_cls, mock_sleep):
        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = [
            _status_response(404),
            _status_response(400),
            _json_response(5),
        ]

        with patch("waygap._CDX_LIMITER"):
            n = get_num_pages(TARGET, None, CDX_COLLAPSE, mock_session, {})

        self.assertIsNone(n)
        self.assertEqual(mock_session.get.call_count, 2)
        self.assertEqual(self._sleeps(mock_sleep), [1])

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_get_num_pages_non_numeric_retries_then_raises(
        self, mock_session_cls, mock_sleep
    ):
        warnings = self._assert_retried_then_raised(
            [_html_response() for _ in range(3)] + [_json_response(5)],
            mock_session_cls,
            mock_sleep,
        )

        self.assertEqual(
            warnings[0],
            "showNumPages request error (attempt 1/3): non-numeric response: "
            "status=200, Content-Type=text/html, content-length=6",
        )


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
        input_file = Path(self.enterContext(tempfile.TemporaryDirectory())) / "urls.txt"
        input_file.touch()
        mock_session_cls.return_value.get.side_effect = self._route_fail_after_one_row

        with (
            self.assertLogs("waygap", level="INFO") as logs,
            patch(
                "sys.argv",
                [
                    "waygap.py",
                    TARGET,
                    "--input",
                    str(input_file),
                    "--cache",
                    self.cache,
                    "--workers",
                    "1",
                ],
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
        input_file = Path(self.enterContext(tempfile.TemporaryDirectory())) / "urls.txt"
        input_file.touch()
        # The rows before KEY1 are not stored, so resuming from KEY1 would
        # leave them missing from a cache that is later marked complete.
        mock_session_cls.return_value.get.side_effect = self._route_fail_after_one_row

        with (
            self.assertLogs("waygap", level="INFO") as logs,
            patch(
                "sys.argv",
                [
                    "waygap.py",
                    TARGET,
                    "--input",
                    str(input_file),
                    "--cache",
                    self.cache,
                    "--workers",
                    "1",
                ],
            ),
        ):
            self.assertEqual(main(), 1)

        _insert.assert_called_once()
        self.assertEqual(
            _insert.call_args.args[1], [normalize_key("http://a.example/")]
        )
        messages = [r.getMessage() for r in logs.records]
        self.assertTrue(
            any(f"{self.cache}: disk full" in message for message in messages)
        )
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
        input_file = Path(self.enterContext(tempfile.TemporaryDirectory())) / "urls.txt"
        input_file.touch()
        mock_session_cls.return_value.get.side_effect = self._route_fail_after_one_row
        original_write = write_meta

        def write(conn, values):
            if "resume_key" in values:
                raise sqlite3.OperationalError("checkpoint full")
            original_write(conn, values)

        with (
            patch("waygap.write_meta", side_effect=write),
            self.assertLogs("waygap", level="INFO") as logs,
            patch(
                "sys.argv",
                [
                    "waygap.py",
                    TARGET,
                    "--input",
                    str(input_file),
                    "--cache",
                    self.cache,
                ],
            ),
        ):
            self.assertEqual(main(), 1)
        keys, meta = self._state()
        self.assertEqual(keys, {normalize_key("http://a.example/")})
        self.assertEqual(meta.get("completed"), "0")
        self.assertNotIn("resume_key", meta)
        messages = [record.getMessage() for record in logs.records]
        self.assertTrue(
            any(f"{self.cache}: checkpoint full" in message for message in messages)
        )
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
                if os.path.exists(self.cache):
                    os.remove(self.cache)
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

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_restart_invalidates_old_checkpoint_before_first_request(
        self, mock_session_cls, _sleep
    ):
        self._make_cache(urls=["http://a.example/"], resume_key="KEY1")
        conn = open_db(self.cache)
        try:
            write_meta(conn, {"resumekey_v": "2"})
        finally:
            conn.close()

        def route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _no_pagination_response()
            self.assertNotIn("resumeKey", params)
            raise requests.exceptions.ConnectionError("down")

        mock_session_cls.return_value.get.side_effect = route
        with self.assertRaises(CDXAPIError):
            ensure_archived_db(TARGET, self.cache)

        keys, meta = self._state()
        self.assertEqual(keys, {normalize_key("http://a.example/")})
        self.assertEqual(meta.get("completed"), "0")
        self.assertEqual(meta.get("resumekey_v"), RESUMEKEY_FETCH_VERSION)
        self.assertNotIn("resume_key", meta)

        mock_session_cls.reset_mock()
        mock_session_cls.return_value.get.side_effect = _no_network
        with self.assertRaisesRegex(CacheError, "no verified saved resume key"):
            ensure_archived_db(TARGET, self.cache, initial_resume_key="KEY1")
        self.assertEqual(self._state(), (keys, meta))
        mock_session_cls.assert_not_called()

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


class TestMainInputValidation(unittest.TestCase):
    """Invalid input must fail before any CDX fetch or temporary cache setup."""

    def test_missing_input_is_rejected_before_fetch(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = os.path.join(directory, "missing.txt")
            for options in ([], ["--no-cache"]):
                with (
                    self.subTest(options=options),
                    patch(
                        "sys.argv", ["waygap.py", TARGET, "--input", missing, *options]
                    ),
                    patch(
                        "waygap.ensure_archived_db", side_effect=CacheError("stop")
                    ) as mock_ensure,
                    patch("waygap.tempfile.mkstemp") as mock_mkstemp,
                    self.assertLogs("waygap", level="ERROR") as logs,
                ):
                    self.assertEqual(main(), 1)
                mock_ensure.assert_not_called()
                mock_mkstemp.assert_not_called()
                self.assertIn(
                    f"Input file not found: {missing}", "\n".join(logs.output)
                )

    def test_non_utf8_input_is_rejected_before_fetch(self):
        with tempfile.TemporaryDirectory() as directory:
            input_file = Path(directory) / "urls.txt"
            cases = {
                "utf16": "https://example.com/\n".encode("utf-16"),
                "bom_first_byte_only": b"\xef",
                "bom_first_two_bytes_only": b"\xef\xbb",
                "invalid_after_first_chunk": (
                    b"https://example.com/\n" * 100_000 + b"https://example.com/\x82\n"
                ),
            }
            for name, data in cases.items():
                input_file.write_bytes(data)
                with (
                    self.subTest(name=name),
                    patch(
                        "sys.argv",
                        ["waygap.py", TARGET, "--input", str(input_file), "--no-cache"],
                    ),
                    patch(
                        "waygap.ensure_archived_db", side_effect=CacheError("stop")
                    ) as mock_ensure,
                    patch(
                        "waygap.tempfile.mkstemp", wraps=tempfile.mkstemp
                    ) as mock_mkstemp,
                    self.assertLogs("waygap", level="ERROR") as logs,
                ):
                    self.assertEqual(main(), 1)
                    mock_ensure.assert_not_called()
                    mock_mkstemp.assert_not_called()
                    self.assertIn(
                        f"Input file is not valid UTF-8: {input_file}",
                        "\n".join(logs.output),
                    )

    def test_valid_utf8_split_across_chunks_reaches_fetch(self):
        # "あ" starts 1 byte before 1 MiB, so every chunk size up to 1 MiB splits it.
        head = b"https://example.com/"
        boundary = 1024 * 1024
        data = head + b"a" * (boundary - 1 - len(head)) + "あ\n".encode()
        with tempfile.TemporaryDirectory() as directory:
            input_file = Path(directory) / "urls.txt"
            input_file.write_bytes(data)
            with (
                patch("sys.argv", ["waygap.py", TARGET, "--input", str(input_file)]),
                patch(
                    "waygap.ensure_archived_db", side_effect=CacheError("stop")
                ) as mock_ensure,
                self.assertLogs("waygap", level="ERROR") as logs,
            ):
                self.assertEqual(main(), 1)
            mock_ensure.assert_called_once()
            self.assertNotIn("not valid UTF-8", "\n".join(logs.output))

    def test_input_directory_is_rejected_before_fetch(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("sys.argv", ["waygap.py", TARGET, "--input", directory]),
            patch(
                "waygap.ensure_archived_db", side_effect=CacheError("stop")
            ) as mock_ensure,
            self.assertLogs("waygap", level="ERROR") as logs,
        ):
            self.assertEqual(main(), 1)
        mock_ensure.assert_not_called()
        self.assertIn(f"Cannot read input file: {directory}", "\n".join(logs.output))

    def test_unreadable_input_is_rejected_before_fetch(self):
        with (
            patch("sys.argv", ["waygap.py", TARGET, "--input", "private.txt"]),
            patch("builtins.open", side_effect=PermissionError("Permission denied")),
            patch(
                "waygap.ensure_archived_db", side_effect=CacheError("stop")
            ) as mock_ensure,
            self.assertLogs("waygap", level="ERROR") as logs,
        ):
            self.assertEqual(main(), 1)
        mock_ensure.assert_not_called()
        self.assertIn("Cannot read input file: private.txt", "\n".join(logs.output))
        self.assertIn("Permission denied", "\n".join(logs.output))


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

        input_file = Path(self.enterContext(tempfile.TemporaryDirectory())) / "urls.txt"
        input_file.touch()

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
                    patch(
                        "sys.argv",
                        ["waygap.py", TARGET, "--input", str(input_file), *args],
                    ),
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
        input_file = Path(self.enterContext(tempfile.TemporaryDirectory())) / "urls.txt"
        input_file.touch()
        with (
            patch("sys.argv", ["waygap.py", TARGET, "--input", str(input_file)]),
            patch(
                "waygap.ensure_archived_db", side_effect=CacheError("stop")
            ) as mock_ensure,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            main()

        self.assertEqual(DEFAULT_WORKERS, 2)
        self.assertEqual(mock_ensure.call_args.kwargs["workers"], 2)


class TestMainInterrupt(unittest.TestCase):
    """Tests for Ctrl+C handling in main()."""

    @patch("waygap.ensure_archived_db", side_effect=KeyboardInterrupt)
    def test_ctrl_c_exits_with_130_and_rerun_hint(self, _ensure):
        input_file = Path(self.enterContext(tempfile.TemporaryDirectory())) / "urls.txt"
        input_file.touch()
        cases = [
            ([], "Interrupted. Re-run the same command to resume."),
            (
                ["--no-cache"],
                "Interrupted. Re-run the same command to start from the beginning. "
                "Omit --no-cache on future runs to retain progress.",
            ),
            (
                ["--refresh"],
                "Interrupted. Remove --refresh and re-run the command to resume.",
            ),
            (
                ["--refresh", "--no-cache"],
                "Interrupted. Re-run the same command to start from the beginning. "
                "Omit --no-cache on future runs to retain progress.",
            ),
        ]
        for args, message in cases:
            with self.subTest(args=args):
                with (
                    patch(
                        "sys.argv",
                        ["waygap.py", TARGET, "--input", str(input_file), *args],
                    ),
                    self.assertLogs("waygap", level="ERROR") as logs,
                ):
                    try:
                        code = main()
                    except KeyboardInterrupt:
                        self.fail("KeyboardInterrupt escaped main()")
                self.assertEqual(code, 130)
                self.assertEqual([r.getMessage() for r in logs.records], [message])


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

    @patch("requests.Session")
    def test_pagination_progress_counts_unique_rows_without_per_page_counts(
        self, mock_session_cls
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

    @patch("waygap._pause")
    @patch("requests.Session")
    def test_pagination_progress_resumes_after_failed_page(
        self, mock_session_cls, _pause
    ):
        # With one worker, page 0 completes first, and _fetch_pages_parallel
        # yields completed pages before raising a failed page, so page 0 is
        # stored before the failure.
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
    def test_pagination_interrupt_keeps_stored_pages(self, mock_session_cls):
        requested_pages = []

        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _json_response(3)
            page = params["page"]
            requested_pages.append(page)
            return _json_response([["original"], [f"http://p{page}.example/"]])

        mock_session_cls.return_value.get.side_effect = _route
        inserts = 0

        def _insert_then_interrupt(conn, keys):
            nonlocal inserts
            inserts += 1
            if inserts == 2:
                raise KeyboardInterrupt
            return insert_urls(conn, keys)

        with tempfile.TemporaryDirectory() as tmp:
            cache_path = os.path.join(tmp, "cache.db")
            with (
                _join_new_threads(),
                patch("waygap.insert_urls", side_effect=_insert_then_interrupt),
                self.assertRaises(KeyboardInterrupt),
            ):
                ensure_archived_db(TARGET, cache_path, workers=1)

            conn = sqlite3.connect(cache_path)
            try:
                done = {r[0] for r in conn.execute("SELECT page FROM pages_done;")}
                keys = {r[0] for r in conn.execute("SELECT key FROM archived;")}
                completed = read_meta(conn).get("completed")
            finally:
                conn.close()
            self.assertEqual(done, {0})
            self.assertEqual(keys, {normalize_key("http://p0.example/")})
            self.assertEqual(completed, "0")

            requested_pages.clear()
            with _join_new_threads():
                ensure_archived_db(TARGET, cache_path, workers=1)
            self.assertEqual(requested_pages, [1, 2])

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
    def test_num_pages_429_keeps_pagination(self, mock_session_cls):
        num_pages_responses = [_status_response(429), _json_response(1)]

        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return num_pages_responses.pop(0)
            if params.get("page") == 0:
                return _json_response([["original"], ["http://a.example/"]])
            raise AssertionError(f"unexpected params: {params}")

        mock_session_cls.return_value.get.side_effect = _route
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = os.path.join(tmp, "cache.db")
            with patch("waygap._CDX_LIMITER"):
                ensure_archived_db(TARGET, cache_path, workers=1)

            conn = sqlite3.connect(cache_path)
            try:
                meta = read_meta(conn)
                self.assertEqual(meta.get("mode"), "pagination")
                self.assertEqual(meta.get("completed"), "1")
                self.assertEqual(count_archived(conn), 1)
            finally:
                conn.close()
        self.assertEqual(num_pages_responses, [])

    @patch("requests.Session")
    def test_num_pages_persistent_429_stops_before_resumekey(self, mock_session_cls):
        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _status_response(429)
            raise AssertionError(f"unexpected params: {params}")

        mock_session = mock_session_cls.return_value
        mock_session.get.side_effect = _route
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = os.path.join(tmp, "cache.db")
            with (
                patch("waygap._CDX_LIMITER"),
                self.assertRaises(CDXAPIError) as cm,
            ):
                ensure_archived_db(TARGET, cache_path, workers=1)

            conn = sqlite3.connect(cache_path)
            try:
                meta = read_meta(conn)
            finally:
                conn.close()
        self.assertIn("429", str(cm.exception))
        self.assertEqual(mock_session.get.call_count, 4)
        self.assertNotEqual(meta.get("mode"), "resumekey")
        self.assertEqual(meta.get("completed"), "0")

    @staticmethod
    def _read_cache(cache_path):
        conn = sqlite3.connect(cache_path)
        try:
            meta = read_meta(conn)
            keys = {r[0] for r in conn.execute("SELECT key FROM archived;")}
            done = {r[0] for r in conn.execute("SELECT page FROM pages_done;")}
        finally:
            conn.close()
        return meta, keys, done

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_num_pages_persistent_404_exits_1_before_resumekey(
        self, mock_session_cls, mock_sleep
    ):
        sent = []

        def _route(url, params=None, headers=None, timeout=None):
            params = dict(params or {})
            sent.append(params)
            if "showNumPages" in params:
                return _status_response(404)
            # Recorded and checked below: an AssertionError raised here
            # would make main() return 1 for the wrong reason.
            return _json_response([["original"]])

        mock_session_cls.return_value.get.side_effect = _route
        with tempfile.TemporaryDirectory() as tmp:
            input_file = Path(tmp) / "urls.txt"
            input_file.write_text("https://example.com/\n", encoding="utf-8")
            cache_path = os.path.join(tmp, "cache.db")
            argv = ["waygap.py", TARGET, "--input", str(input_file)]
            argv += ["--cache", cache_path]
            with (
                patch("sys.argv", argv),
                self.assertLogs("waygap", level="INFO") as logs,
            ):
                self.assertEqual(main(), 1)

            meta, _, _ = self._read_cache(cache_path)

        errors = [r.getMessage() for r in logs.records if r.levelname == "ERROR"]
        self.assertTrue(
            any(
                "showNumPages request failed (max retries reached)" in e for e in errors
            )
        )
        self.assertFalse(any("Unexpected error" in e for e in errors))
        self.assertEqual(len(sent), 3)
        self.assertTrue(all("showNumPages" in p for p in sent))
        self.assertEqual([c.args[0] for c in mock_sleep.call_args_list], [1, 2])
        self.assertNotIn("mode", meta)
        self.assertEqual(meta.get("completed"), "0")

    @patch("requests.Session")
    def test_num_pages_zero_falls_back_to_resumekey(self, mock_session_cls):
        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _json_response(0)
            if "page" not in params and params.get("resumeKey") is None:
                return _json_response([["original"], ["http://a.example/"]])
            raise AssertionError(f"unexpected params: {params}")

        mock_session_cls.return_value.get.side_effect = _route
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = os.path.join(tmp, "cache.db")
            ensure_archived_db(TARGET, cache_path, workers=1)
            meta, keys, _ = self._read_cache(cache_path)

        self.assertEqual(meta.get("mode"), "resumekey")
        self.assertEqual(meta.get("completed"), "1")
        self.assertEqual(keys, {normalize_key("http://a.example/")})

    def _assert_page_400_stops(self, num_pages, mock_session_cls, mock_pause):
        """Page `num_pages - 1` keeps returning 400; earlier pages succeed."""
        failing = num_pages - 1
        requested_pages = []
        resumekey_requests = []

        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _json_response(num_pages)
            if "page" not in params:
                resumekey_requests.append(dict(params))
                return _json_response([["original"]])
            page = params["page"]
            requested_pages.append(page)
            if page == failing:
                return _status_response(400)
            return _json_response([["original"], [f"http://p{page}.example/"]])

        mock_session_cls.return_value.get.side_effect = _route
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = os.path.join(tmp, "cache.db")
            with _join_new_threads(), self.assertRaises(CDXAPIError):
                ensure_archived_db(TARGET, cache_path, workers=1)
            meta, keys, done = self._read_cache(cache_path)

        self.assertEqual(requested_pages.count(failing), 3)
        self.assertEqual([c.args[0] for c in mock_pause.call_args_list], [1, 2])
        self.assertEqual(resumekey_requests, [])
        self.assertEqual(meta.get("mode"), "pagination")
        self.assertEqual(meta.get("completed"), "0")
        return keys, done

    @patch("waygap._pause")
    @patch("requests.Session")
    def test_page_400_on_only_page_stops_with_error(self, mock_session_cls, mock_pause):
        keys, done = self._assert_page_400_stops(1, mock_session_cls, mock_pause)

        self.assertEqual(keys, set())
        self.assertEqual(done, set())

    @patch("waygap._pause")
    @patch("requests.Session")
    def test_page_400_after_stored_page_stops_with_error(
        self, mock_session_cls, mock_pause
    ):
        keys, done = self._assert_page_400_stops(2, mock_session_cls, mock_pause)

        self.assertEqual(keys, {normalize_key("http://p0.example/")})
        self.assertEqual(done, {0})

    @patch("waygap.time.sleep")
    @patch("requests.Session")
    def test_resumekey_400_stops_with_error(self, mock_session_cls, _sleep):
        resumekey_requests = []

        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _no_pagination_response()
            resumekey_requests.append(dict(params))
            return _status_response(400)

        mock_session_cls.return_value.get.side_effect = _route
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = os.path.join(tmp, "cache.db")
            with self.assertRaises(CDXAPIError):
                ensure_archived_db(TARGET, cache_path, workers=1)
            meta, _, _ = self._read_cache(cache_path)

        self.assertEqual(len(resumekey_requests), 3)
        self.assertEqual(meta.get("mode"), "resumekey")
        self.assertEqual(meta.get("completed"), "0")

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


class TestParallelFetchMemory(unittest.TestCase):
    """Slow consumers must not retain every fetched page in memory."""

    def test_slow_consumer_bounds_submitted_pages(self):
        submitted: list[int] = []

        class TrackingExecutor(concurrent.futures.ThreadPoolExecutor):
            def submit(self, fn, /, *args, **kwargs):
                submitted.append(args[0])
                return super().submit(fn, *args, **kwargs)

        with (
            patch("waygap.concurrent.futures.ThreadPoolExecutor", TrackingExecutor),
            patch("waygap.fetch_page_rows", return_value=[]),
            _join_new_threads(),
        ):
            gen = TestParallelFetchStops._pages(100, 2)
            try:
                next(gen)
                # The caller is paused here, as during a slow SQLite insert.
                self.assertLessEqual(len(submitted), 4)
            finally:
                gen.close()

    def test_consumed_page_results_are_released(self):
        class Keys(list):
            pass

        def keys(rows, key_opts):
            return Keys(["a.example)/"])

        with (
            patch("waygap.fetch_page_rows", return_value=[]),
            patch("waygap._rows_to_keys", side_effect=keys),
            _join_new_threads(),
        ):
            gen = TestParallelFetchStops._pages(100, 2)
            try:
                consumed = []
                for _ in range(99):
                    _, result = next(gen)
                    consumed.append(weakref.ref(result))
                    del result
                next(gen)
                gc.collect()
                self.assertTrue(all(ref() is None for ref in consumed))
            finally:
                gen.close()

    def test_yields_completed_page_without_waiting_for_earlier_page(self):
        release = threading.Event()

        def fetch(target_url, page, *args, **kwargs):
            if page == 0:
                self.assertTrue(release.wait(3))
            return [[f"https://example.com/{page}"]]

        with patch("waygap.fetch_page_rows", fetch), _join_new_threads():
            gen = TestParallelFetchStops._pages(2, 2)
            try:
                self.assertEqual(
                    next(gen), (1, [normalize_key("https://example.com/1")])
                )
                release.set()
                self.assertEqual(
                    list(gen), [(0, [normalize_key("https://example.com/0")])]
                )
            finally:
                release.set()
                gen.close()

    def test_failed_batch_preserves_successes_without_submitting_more(self):
        wait = concurrent.futures.wait
        stops = []
        fetched = []

        def fetch(target_url, page, *args, **kwargs):
            fetched.append(page)
            stops.append(kwargs["stop"])
            if page in (1, 2):
                raise CDXAPIError(f"page {page} failed")
            return []

        def whole_batch(fs, **kwargs):
            return wait(fs, timeout=3)

        with (
            patch("waygap.fetch_page_rows", fetch),
            patch("waygap.concurrent.futures.wait", whole_batch),
            _join_new_threads(),
        ):
            gen = TestParallelFetchStops._pages(100, 2)
            try:
                self.assertEqual(next(gen), (0, []))
                self.assertTrue(all(stop.is_set() for stop in stops))
                self.assertEqual(next(gen), (3, []))
                with self.assertRaisesRegex(CDXAPIError, "page 1 failed"):
                    next(gen)
                self.assertEqual(sorted(fetched), [0, 1, 2, 3])
            finally:
                gen.close()

    def test_empty_and_small_inputs(self):
        with patch("waygap.fetch_page_rows", return_value=[]) as fetch:
            for workers in (-1, 0, 1, 3):
                for pages in ([], [8], [8, 3, 11]):
                    with self.subTest(workers=workers, pages=pages):
                        result = list(
                            waygap._fetch_pages_parallel(
                                TARGET, pages, None, None, workers, {}, None
                            )
                        )
                        self.assertEqual(
                            sorted(result), [(p, []) for p in sorted(pages)]
                        )
            self.assertEqual(fetch.call_count, 16)


class TestParallelFetchStops(unittest.TestCase):
    """A failed page, close() or Ctrl+C stops the remaining page fetches."""

    def setUp(self):
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.started: list[int] = []
        self.stops: list[object] = []

    def _fake_fetch(self, page0: str):
        """Stand-in for fetch_page_rows that does not use `stop`.

        Page 0 fails ("fail"), returns one row ("ok") or blocks ("block");
        the other pages block until self.release is set (at most 3 s).
        """

        def fake(target_url, page, *args, **kwargs):
            with self.lock:
                self.started.append(page)
                self.stops.append(kwargs.get("stop"))
            if page == 0 and page0 == "fail":
                raise CDXAPIError("page 0 failed")
            if page == 0 and page0 == "ok":
                return [["http://a.example/"]]
            self.release.wait(3)
            return []

        return fake

    @staticmethod
    def _pages(count: int, workers: int):
        return waygap._fetch_pages_parallel(
            TARGET, list(range(count)), None, None, workers, {}, None
        )

    def _run_in_thread(self, consume):
        """Run consume() in a thread and wait for it for 1 s.

        Returns the outcome ({"result": ...} or {"error": ...}), or None if
        it did not finish in time, and whether each stop event seen by the
        fake fetch was set at that moment.
        """
        outcome: dict[str, object] = {}

        def target():
            try:
                outcome["result"] = consume()
            except BaseException as e:
                outcome["error"] = e

        thread = threading.Thread(target=target)
        thread.start()
        thread.join(1)
        finished = None if thread.is_alive() else dict(outcome)
        with self.lock:
            stops_set = [
                isinstance(s, threading.Event) and s.is_set() for s in self.stops
            ]
        return finished, stops_set

    def _fail_page_0(self):
        with (
            patch("waygap.fetch_page_rows", self._fake_fetch("fail")),
            _join_new_threads(),
        ):
            try:
                gen = self._pages(200, 4)
                return self._run_in_thread(lambda: list(gen))
            finally:
                self.release.set()

    def _close_after_first_page(self):
        with (
            patch("waygap.fetch_page_rows", self._fake_fetch("ok")),
            _join_new_threads(),
        ):
            try:
                gen = self._pages(200, 4)

                def consume():
                    first = next(gen)
                    gen.close()
                    return first

                return self._run_in_thread(consume)
            finally:
                self.release.set()

    def test_failed_page_stops_remaining_pages(self):
        finished, _ = self._fail_page_0()

        if finished is None:
            self.fail(
                f"error not reported within 1 s; pages started: {len(self.started)}"
            )
        self.assertIsInstance(finished.get("error"), CDXAPIError)
        self.assertLessEqual(len(self.started), 5)

    def test_close_stops_remaining_pages(self):
        finished, _ = self._close_after_first_page()

        if finished is None:
            self.fail(
                f"close() did not return within 1 s; pages started: {len(self.started)}"
            )
        self.assertEqual(
            finished.get("result"), (0, [normalize_key("http://a.example/")])
        )
        self.assertLessEqual(len(self.started), 5)

    def test_ctrl_c_stops_waiting_and_remaining_pages(self):
        with (
            patch("waygap.fetch_page_rows", self._fake_fetch("block")),
            _join_new_threads(),
        ):
            timer = threading.Timer(0.2, _thread.interrupt_main)
            try:
                gen = self._pages(8, 4)
                start = time.monotonic()
                with self.assertRaises(KeyboardInterrupt):
                    timer.start()
                    for _ in gen:
                        pass
                elapsed = time.monotonic() - start
            finally:
                timer.cancel()
                self.release.set()

        self.assertLess(
            elapsed, 2.0, f"interrupt took {elapsed:.1f} s; started: {self.started}"
        )
        self.assertLessEqual(len(self.started), 4)

    def test_failed_page_sets_stop(self):
        _, stops_set = self._fail_page_0()

        self.assertTrue(stops_set)
        self.assertTrue(all(stops_set), stops_set)

    def test_close_sets_stop(self):
        _, stops_set = self._close_after_first_page()

        self.assertTrue(stops_set)
        self.assertTrue(all(stops_set), stops_set)

    def test_failed_page_stops_workers_before_yielding_its_batch(self):
        """A failed page and a successful page that complete in the same
        wait: workers are stopped before the successful page is yielded."""
        go = threading.Event()
        changed = threading.Condition()

        def fake(target_url, page, *args, **kwargs):
            with changed:
                self.started.append(page)
                self.stops.append(kwargs.get("stop"))
                changed.notify_all()
            if page == 0:
                return [["http://a.example/"]]
            if page in (1, 2):
                go.wait(3)
                if page == 1:
                    raise CDXAPIError("page 1 failed")
                return [["http://c.example/"]]
            self.release.wait(3)
            return []

        with patch("waygap.fetch_page_rows", fake), _join_new_threads():
            try:
                gen = self._pages(10, 3)
                self.assertEqual(next(gen)[0], 0)
                # While the generator is suspended, let pages 1 and 2 finish.
                # A worker starts its next page (4 or 5) only after storing
                # the result of the previous one, so once both have started,
                # pages 1 and 2 are complete and land in the same wait.
                go.set()
                with changed:
                    both_done = changed.wait_for(
                        lambda: {4, 5} <= set(self.started), timeout=3
                    )
                self.assertTrue(both_done, self.started)

                page, _ = next(gen)
                with changed:
                    stops_set = [
                        isinstance(s, threading.Event) and s.is_set()
                        for s in self.stops
                    ]
                with self.assertRaises(CDXAPIError):
                    next(gen)
            finally:
                self.release.set()

        self.assertEqual(page, 2)
        self.assertTrue(stops_set)
        self.assertTrue(all(stops_set), stops_set)


BAD_PORT_URL = "http://example.com:99999/"
# A lone surrogate can come from a JSON escape in a CDX response; a UTF-8
# input file cannot contain one.
LONE_SURROGATE_URL = "http://a\udc80b.example/"


class TestUnparsableUrls(unittest.TestCase):
    """A URL that surt cannot parse must not stop the run (issue #14)."""

    def test_try_normalize_key_returns_none_for_unparsable_urls(self):
        for url in (BAD_PORT_URL, "http://example.com:abc/", LONE_SURROGATE_URL):
            with (
                self.subTest(url=url),
                self.assertLogs("waygap", level="WARNING") as logs,
            ):
                self.assertIsNone(waygap._try_normalize_key(url, None, "in a test"))
            self.assertIn(repr(url), "\n".join(logs.output))
        self.assertEqual(
            waygap._try_normalize_key("http://a.example/", None, "in a test"),
            normalize_key("http://a.example/"),
        )

    def test_extract_skips_unparsable_rows(self):
        cdx_data = [
            ["http://a.example/"],
            [BAD_PORT_URL],
            [LONE_SURROGATE_URL],
            ["http://b.example/"],
        ]
        with self.assertLogs("waygap", level="WARNING") as logs:
            result = extract_archived_urls(cdx_data)
        self.assertEqual(
            result,
            {normalize_key("http://a.example/"), normalize_key("http://b.example/")},
        )
        self.assertIn(repr(BAD_PORT_URL), "\n".join(logs.output))

    @patch("requests.Session")
    def test_pagination_completes_past_unparsable_rows(self, mock_session_cls):
        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _json_response(2)
            if params["page"] == 0:
                return _json_response([["original"], ["http://a.example/"]])
            return _json_response(
                [
                    ["original"],
                    [BAD_PORT_URL],
                    [LONE_SURROGATE_URL],
                    ["http://b.example/"],
                ]
            )

        mock_session_cls.return_value.get.side_effect = _route
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = os.path.join(tmp, "cache.db")
            with (
                _join_new_threads(),
                self.assertLogs("waygap", level="WARNING") as logs,
            ):
                ensure_archived_db(TARGET, cache_path, workers=1)
            conn = sqlite3.connect(cache_path)
            try:
                done = {r[0] for r in conn.execute("SELECT page FROM pages_done;")}
                keys = {r[0] for r in conn.execute("SELECT key FROM archived;")}
                completed = read_meta(conn).get("completed")
            finally:
                conn.close()
        self.assertEqual(done, {0, 1})
        self.assertEqual(
            keys,
            {normalize_key("http://a.example/"), normalize_key("http://b.example/")},
        )
        self.assertEqual(completed, "1")
        self.assertIn(repr(BAD_PORT_URL), "\n".join(logs.output))

    @patch("requests.Session")
    def test_resumekey_fetch_completes_past_unparsable_rows(self, mock_session_cls):
        def _route(url, params=None, headers=None, timeout=None):
            params = params or {}
            if "showNumPages" in params:
                return _no_pagination_response()
            if params.get("resumeKey") is None:
                return _json_response(
                    [["original"], ["http://a.example/"], [BAD_PORT_URL], [], ["KEY1"]]
                )
            return _json_response(
                [["original"], [LONE_SURROGATE_URL], ["http://b.example/"]]
            )

        mock_session_cls.return_value.get.side_effect = _route
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = os.path.join(tmp, "cache.db")
            with self.assertLogs("waygap", level="WARNING") as logs:
                ensure_archived_db(TARGET, cache_path, workers=1)
            conn = sqlite3.connect(cache_path)
            try:
                keys = {r[0] for r in conn.execute("SELECT key FROM archived;")}
                completed = read_meta(conn).get("completed")
            finally:
                conn.close()
        self.assertEqual(
            keys,
            {normalize_key("http://a.example/"), normalize_key("http://b.example/")},
        )
        self.assertEqual(completed, "1")
        self.assertIn(repr(BAD_PORT_URL), "\n".join(logs.output))

    def _write_input(self, directory: str) -> str:
        input_file = Path(directory) / "urls.txt"
        input_file.write_text(
            f"http://a.example/\n{BAD_PORT_URL}\nhttp://b.example/\n", encoding="utf-8"
        )
        return str(input_file)

    def _make_db(self, directory: str) -> str:
        db_path = os.path.join(directory, "cache.db")
        conn = open_db(db_path)
        try:
            insert_urls(conn, [normalize_key("http://a.example/")])
        finally:
            conn.close()
        return db_path

    def test_scan_reports_unparsable_line_as_unarchived(self):
        with tempfile.TemporaryDirectory() as directory:
            input_file = self._write_input(directory)
            db_path = self._make_db(directory)
            out_file = Path(directory) / "not_archived.txt"
            arch_file = Path(directory) / "archived.txt"
            with self.assertLogs("waygap", level="WARNING") as logs:
                result = scan_input_against_db(
                    input_file,
                    db_path,
                    output_file=str(out_file),
                    output_archived=str(arch_file),
                )
            not_archived = out_file.read_text(encoding="utf-8").splitlines()
            archived = arch_file.read_text(encoding="utf-8").splitlines()
        self.assertEqual(result, (3, 2, 1))
        self.assertEqual(not_archived, [BAD_PORT_URL, "http://b.example/"])
        self.assertEqual(archived, ["http://a.example/"])
        text = "\n".join(logs.output)
        self.assertIn("line 2", text)
        self.assertIn(repr(BAD_PORT_URL), text)

    def test_detect_reports_unparsable_line_as_unarchived(self):
        with tempfile.TemporaryDirectory() as directory:
            input_file = self._write_input(directory)
            with self.assertLogs("waygap", level="WARNING") as logs:
                not_archived, archived, total = detect_not_archived(
                    input_file,
                    {normalize_key("http://a.example/")},
                    collect_archived=True,
                )
        self.assertEqual(not_archived, [BAD_PORT_URL, "http://b.example/"])
        self.assertEqual(archived, ["http://a.example/"])
        self.assertEqual(total, 3)
        self.assertIn("line 2", "\n".join(logs.output))

    def test_main_finishes_with_unparsable_input_line(self):
        with tempfile.TemporaryDirectory() as directory:
            input_file = self._write_input(directory)
            db_path = self._make_db(directory)
            out_file = Path(directory) / "not_archived.txt"
            with (
                patch(
                    "sys.argv",
                    [
                        "waygap.py",
                        TARGET,
                        "--input",
                        input_file,
                        "--output",
                        str(out_file),
                    ],
                ),
                patch("waygap.ensure_archived_db", return_value=db_path),
                self.assertLogs("waygap", level="INFO"),
            ):
                self.assertEqual(main(), 0)
            not_archived = out_file.read_text(encoding="utf-8").splitlines()
        self.assertEqual(not_archived, [BAD_PORT_URL, "http://b.example/"])


class TestVersion(unittest.TestCase):
    """Tests for the version string and User-Agent."""

    def test_version_is_semver(self):
        parts = __version__.split(".")
        self.assertEqual(len(parts), 3)
        self.assertTrue(all(p.isdigit() for p in parts))

    def test_user_agent_contains_version(self):
        self.assertIn(f"Wayback-Gap-Detector/{__version__}", USER_AGENT)


@pytest.mark.parametrize("mode", ["pagination", "fallback", "manual_resume"])
def test_cache_completion_records_utc_build_time(tmp_path, mode):
    cache = str(tmp_path / "cache.db")
    if mode == "manual_resume":
        conn = open_db(cache)
        write_meta(
            conn,
            {
                **expected_meta(TARGET, {}, None),
                "completed": "0",
                "mode": "resumekey",
                "resumekey_v": RESUMEKEY_FETCH_VERSION,
                "resume_key": "KEY1",
            },
        )
        conn.close()

    def route(url, params=None, headers=None, timeout=None):
        params = params or {}
        if "showNumPages" in params:
            return (
                _json_response(1) if mode == "pagination" else _no_pagination_response()
            )
        return _json_response([["original"], ["http://a.example/"]])

    before = datetime.now(UTC)
    with patch("requests.Session") as session:
        session.return_value.get.side_effect = route
        ensure_archived_db(
            TARGET,
            cache,
            workers=1,
            initial_resume_key="KEY1" if mode == "manual_resume" else None,
        )
    after = datetime.now(UTC)
    with sqlite3.connect(cache) as conn:
        meta = read_meta(conn)
    assert meta["completed"] == "1"
    built_at = datetime.fromisoformat(meta["built_at"])
    assert built_at.utcoffset() == timedelta(0)
    assert before <= built_at <= after


@pytest.mark.parametrize(
    ("built_at", "display_time", "refresh_hint"),
    [
        (None, "unknown", True),
        ("", "unknown", True),
        ("not-a-date", "unknown", True),
        ("2026-11-19", "unknown", True),
        ("2026-11-19T12:00:00", "unknown", True),
        ("2026-11-19T12:00:00+00:00", "2026-11-19T12:00:00+00:00", True),
        ("2026-11-19T11:59:59.999999+00:00", "2026-11-19T11:59:59.999999+00:00", True),
        ("2026-11-19T12:00:00.000001+00:00", "2026-11-19T12:00:00.000001+00:00", False),
        ("2026-11-26T11:00:00+00:00", "2026-11-26T11:00:00+00:00", False),
        ("2026-11-27T12:00:00+00:00", "2026-11-27T12:00:00+00:00", False),
        ("2026-11-19T17:30:00+05:30", "2026-11-19T12:00:00+00:00", True),
    ],
)
def test_cache_reuse_reports_build_time_and_refresh_hint(
    tmp_path, caplog, built_at, display_time, refresh_hint
):
    cache = str(tmp_path / "cache.db")
    conn = open_db(cache)
    meta = {**expected_meta(TARGET, {}, None), "completed": "1", "mode": "pagination"}
    if built_at is not None:
        meta["built_at"] = built_at
    write_meta(conn, meta)
    conn.close()
    with (
        patch("requests.Session") as session,
        patch("waygap.datetime", wraps=datetime) as clock,
        caplog.at_level("INFO", logger="waygap"),
    ):
        clock.now.return_value = datetime(2026, 11, 26, 12, tzinfo=UTC)
        session.return_value.get.side_effect = _no_network
        assert ensure_archived_db(TARGET, cache) == cache
    reuse = next(
        r.message for r in caplog.records if "Reusing completed cache" in r.message
    )
    assert f"built at: {display_time}" in reuse
    assert ("--refresh" in reuse) == refresh_hint
    with sqlite3.connect(cache) as conn:
        assert read_meta(conn) == meta


def test_cache_reuse_with_null_build_time(tmp_path, caplog):
    cache = str(tmp_path / "cache.db")
    conn = open_db(cache)
    write_meta(conn, {**expected_meta(TARGET, {}, None), "completed": "1"})
    with conn:
        conn.execute("INSERT INTO meta(k, v) VALUES ('built_at', NULL)")
    conn.close()
    with patch("requests.Session") as session, caplog.at_level("INFO", logger="waygap"):
        session.return_value.get.side_effect = _no_network
        assert ensure_archived_db(TARGET, cache) == cache
    reuse = next(
        r.message for r in caplog.records if "Reusing completed cache" in r.message
    )
    assert "built at: unknown" in reuse
    assert "--refresh" in reuse
    with sqlite3.connect(cache) as conn:
        assert read_meta(conn)["built_at"] is None


def test_cache_completion_timestamp_failure_rolls_back_completion(tmp_path):
    conn = open_db(str(tmp_path / "cache.db"))
    try:
        write_meta(conn, {"completed": "0"})
        conn.execute("""CREATE TRIGGER reject_built_at BEFORE INSERT ON meta
                        WHEN NEW.k = 'built_at'
                        BEGIN SELECT RAISE(ABORT, 'disk failure'); END;""")
        with pytest.raises(sqlite3.IntegrityError, match="disk failure"):
            waygap.set_completed(conn)
        assert read_meta(conn) == {"completed": "0"}
    finally:
        conn.close()


def test_cache_marked_incomplete_clears_build_time(tmp_path):
    conn = open_db(str(tmp_path / "cache.db"))
    try:
        write_meta(conn, {"completed": "1", "built_at": "2020-01-02T03:04:05+00:00"})
        waygap.set_completed(conn, False)
        assert read_meta(conn) == {"completed": "0"}
    finally:
        conn.close()


@pytest.mark.parametrize("mode", ["pagination", "fallback", "manual_resume"])
def test_interrupted_cache_has_no_build_time(tmp_path, mode):
    cache = str(tmp_path / "cache.db")
    if mode == "manual_resume":
        conn = open_db(cache)
        write_meta(
            conn,
            {
                **expected_meta(TARGET, {}, None),
                "completed": "0",
                "mode": "resumekey",
                "resumekey_v": RESUMEKEY_FETCH_VERSION,
                "resume_key": "KEY1",
            },
        )
        conn.close()

    def route(url, params=None, headers=None, timeout=None):
        params = params or {}
        if "showNumPages" in params:
            return (
                _json_response(1) if mode == "pagination" else _no_pagination_response()
            )
        raise KeyboardInterrupt

    with patch("requests.Session") as session:
        session.return_value.get.side_effect = route
        with pytest.raises(KeyboardInterrupt):
            ensure_archived_db(
                TARGET,
                cache,
                workers=1,
                initial_resume_key="KEY1" if mode == "manual_resume" else None,
            )
    with sqlite3.connect(cache) as conn:
        meta = read_meta(conn)
    assert meta["completed"] == "0"
    assert "built_at" not in meta


def test_corrupt_cache_raises_contextual_cache_error(tmp_path):
    cache = tmp_path / "corrupt.db"
    original = b"this is not a SQLite database" * 10
    cache.write_bytes(original)
    with pytest.raises(CacheError) as caught:
        open_db(str(cache))
    assert str(cache) in str(caught.value)
    assert "--refresh" in str(caught.value)
    assert isinstance(caught.value.__cause__, sqlite3.Error)
    assert cache.read_bytes() == original


@pytest.mark.parametrize("stage", ["fetch", "count", "scan"])
def test_cli_sqlite_errors_name_cache_and_recovery(tmp_path, caplog, stage):
    cache = tmp_path / "cache.db"
    input_file = tmp_path / "urls.txt"
    input_file.write_text("https://example.com/\n", encoding="utf-8")
    conn = open_db(str(cache))
    conn.close()
    failure = sqlite3.OperationalError("database is locked")
    with (
        patch(
            "sys.argv",
            ["waygap.py", TARGET, "--input", str(input_file), "--cache", str(cache)],
        ),
        patch("waygap.ensure_archived_db", return_value=str(cache)) as fetch,
        patch("waygap.count_archived", return_value=0) as count,
        patch("waygap.scan_input_against_db", return_value=(1, 1, 0)) as scan,
        caplog.at_level("ERROR", logger="waygap"),
    ):
        {"fetch": fetch, "count": count, "scan": scan}[stage].side_effect = failure
        assert main() == 1
    assert str(cache) in caplog.text
    assert "database is locked" in caplog.text
    assert "--refresh" in caplog.text
    assert "Unexpected error" not in caplog.text


@pytest.mark.parametrize("verbose", [False, True])
def test_unexpected_error_traceback_requires_verbose(tmp_path, caplog, verbose):
    input_file = tmp_path / "urls.txt"
    input_file.touch()
    with (
        patch(
            "sys.argv",
            [
                "waygap.py",
                TARGET,
                "--input",
                str(input_file),
                *(["-v"] if verbose else []),
            ],
        ),
        patch(
            "waygap.ensure_archived_db", side_effect=RuntimeError("unexpected failure")
        ),
        caplog.at_level("ERROR", logger="waygap"),
    ):
        assert main() == 1
    assert "Unexpected error: unexpected failure" in caplog.text
    assert ("Traceback (most recent call last)" in caplog.text) is verbose


def test_cli_corrupt_cache_fails_before_network_and_preserves_file(tmp_path, caplog):
    cache = tmp_path / "cache.db"
    original = b"not a database" * 32
    cache.write_bytes(original)
    input_file = tmp_path / "urls.txt"
    input_file.write_text("https://example.com/\n", encoding="utf-8")
    with (
        patch(
            "sys.argv",
            ["waygap.py", TARGET, "--input", str(input_file), "--cache", str(cache)],
        ),
        patch("requests.Session") as session,
        caplog.at_level("ERROR", logger="waygap"),
    ):
        assert main() == 1
    session.assert_not_called()
    assert str(cache) in caplog.text
    assert "--refresh" in caplog.text
    assert "Unexpected error" not in caplog.text
    assert "Traceback" not in caplog.text
    assert cache.read_bytes() == original


def test_cache_connection_failure_is_contextual(tmp_path):
    with pytest.raises(CacheError) as caught:
        open_db(str(tmp_path))
    assert str(tmp_path) in str(caught.value)
    assert isinstance(caught.value.__cause__, sqlite3.Error)
