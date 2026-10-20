#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wayback Gap Detector
Compares a local URL list against the Wayback Machine CDX API
to identify URLs that have not been archived.

URL keys: `surt` canonicalization applied identically to the CDX
`original` rows and the local input URLs, so matching does not
depend on CDX-side urlkey strings.

Cache backend: SQLite (single .db file).
Fetch strategy: pagination API (page=i) in parallel, with
resumeKey sequential fetch as fallback.
"""

import argparse
import concurrent.futures
import logging
import os
import re
import socket
import sqlite3
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Set, List, Optional, Generator, Iterable, Tuple, Dict

import requests
from requests.adapters import HTTPAdapter
from tqdm import tqdm
from urllib3.util import Retry

from surt import surt
from surt.surt import CompositeCanonicalizer
from surt.GoogleURLCanonicalizer import (
    DECIMAL_IP,
    escapeOnce,
    minimalEscape,
    normalizePath,
    unescapeRepeatedly,
)
from surt.IAURLCanonicalizer import canonicalize as ia_canonicalize

# Logger setup
logger = logging.getLogger(__name__)


# ========================================
# Default settings
# ========================================
# Lenient defaults mirror surt's own defaults == the CDX urlkey world:
# www/wwwN host massage is ON, the scheme disappears from keys, and
# query params are sorted and lowercased.
IGNORE_PROTOCOL = True
IGNORE_WWW = True
TARGET_URL_FILE = "urls.txt"
OUTPUT_FILE = "not_archived.txt"
CACHE_FILE = "archived_cdx.db"
ARCHIVED_FILE = "archived.txt"

__version__ = "0.1.0"
USER_AGENT = f"Wayback-Gap-Detector/{__version__} (https://github.com/nabikita3974/wayback-gap-detector)"

DB_SCHEMA_VERSION = "1"
LOOKUP_BATCH_SIZE = 500
INSERT_CHUNK_SIZE = 10000

CDX_FILTER = "statuscode:200"
# Lenient (default) mode collapses variants server-side with collapse=urlkey.
# Strict mode collapses only repeated captures of the same original spelling
# (collapse=original); the set of distinct original spellings is unaffected.
CDX_COLLAPSE = "urlkey"
CDX_COLLAPSE_STRICT = "original"
# NOTE: timestamp is intentionally NOT fetched (fl=original only).
# The `timestamp` column may be added in a future schema version
# if time-based features are ever needed.
CDX_FL = "original"


# ========================================
# Custom Exceptions
# ========================================
class WaybackGapDetectorError(Exception):
    """Base exception for Wayback Gap Detector"""
    pass


class CDXAPIError(WaybackGapDetectorError):
    """CDX API related errors (network, response parsing, etc.)"""
    pass


class InputFileError(WaybackGapDetectorError):
    """Input file related errors (not found, encoding issues, etc.)"""
    pass


class CacheError(WaybackGapDetectorError):
    """Local cache (SQLite) related errors"""
    pass


# ========================================
# URL key normalization (surt)
# ========================================
# CDX-comparable keys are produced with the `surt` package, whose default
# canonicalizer is the same family the CDX server itself uses for `urlkey`.
# Lenient mode (both of --ignore-protocol/--ignore-www enabled) therefore
# passes surt's own defaults. Both sides (CDX `original` rows and local
# input URLs) are normalized with the exact same settings, so matching
# never depends on CDX-side urlkey strings.
#
# DNS-free: surt.GoogleURLCanonicalizer calls socket.gethostbyname_ex()
# for numerically shaped hosts (e.g. "123.456.78.9"), which issues real
# DNS queries. canonicalize_nodns() below is a copy of that canonicalizer
# with the IP handling replaced by a local-only variant. For ordinary
# alphanumeric hosts it is byte-identical to surt's default.
# Adapted from internetarchive/surt (c)2012-2013 Internet Archive,
# licensed AGPL-3.0-or-later.


def attemptIPFormats_nodns(host):
    """DNS-free variant of surt.GoogleURLCanonicalizer.attemptIPFormats.

    - all-digit hosts: same local struct conversion as surt (no network).
    - valid dotted quads: returned verbatim; surt's gethostbyname_ex()
      would resolve those locally to the same literal (no network).
    - OCTAL / invalid numeric-dotted hosts: passed through, which equals
      surt's behaviour when gethostbyname_ex() fails, minus the DNS query.
    """
    if host is None:
        return None
    if host.isdigit():
        # Mask to lower four bytes (same workaround as surt for liveweb arcs).
        return socket.inet_ntoa(
            struct.pack('>L', int(host) & 0xffffffff)).encode('ascii')
    if DECIMAL_IP.match(host):
        parts = host.split(b'.')
        if len(parts) == 4 and all(
            p.isdigit() and 0 <= int(p) <= 255
            and (p == b'0' or not p.startswith(b'0'))
            for p in parts
        ):
            return host
        return None
    return None


def canonicalize_nodns(url, **_ignored):
    """Copy of surt.GoogleURLCanonicalizer.canonicalize (module-level fn).

    Everything is identical to the original except that attemptIPFormats()
    is replaced by attemptIPFormats_nodns(). Like the default canonicalizer
    does for its Google stage, **options are accepted here for the
    CompositeCanonicalizer flow but take effect only in the following
    IAURLCanonicalizer stage.
    """
    url.hash = None
    if url.authUser:
        url.authUser = minimalEscape(url.authUser)
    if url.authPass:
        url.authPass = minimalEscape(url.authPass)
    if url.query:
        url.query = minimalEscape(url.query)

    if url.host:
        host = unescapeRepeatedly(url.host)
        try:
            host.decode('ascii')
        except UnicodeDecodeError:
            try:
                host = host.decode('utf-8', 'ignore').encode('idna')
            except ValueError:
                pass

        host = host.replace(b'..', b'.').strip(b'.')

        ip = attemptIPFormats_nodns(host)
        if ip:
            host = ip
        else:
            host = escapeOnce(host.lower())

        url.host = host

    path = unescapeRepeatedly(url.path)
    if url.host:
        path = normalizePath(path)
    # else path is free-form sort of thing, not /directory/thing
    url.path = escapeOnce(path)

    return url


# Canonicalizer chain: [nodns Google stage] -> [IA stage (its flags apply here)].
KEY_CANONICALIZER = CompositeCanonicalizer([canonicalize_nodns, ia_canonicalize])


def build_key_opts(ignore_protocol: bool, ignore_www: bool) -> Dict[str, Any]:
    """Build the surt() options for one run.

    With both defaults (True/True) this is empty == surt defaults ==
    CDX urlkey semantics. --no-ignore-www keeps www/wwwN variants
    (host_massage=False); --no-ignore-protocol keeps the scheme in the
    key (with_scheme=True). Any non-empty opts activates strict mode
    (collapse=original instead of urlkey).
    """
    opts: Dict[str, Any] = {}
    if not ignore_www:
        opts['host_massage'] = False
    if not ignore_protocol:
        opts['with_scheme'] = True
    return opts


def key_profile(opts: Dict[str, Any]) -> str:
    """Stable fingerprint of key options for cache identity."""
    if not opts:
        return "surt-default"
    return "surt:" + ",".join(f"{k}={opts[k]}" for k in sorted(opts))


_SCHEME_RE = re.compile(r'\A([a-zA-Z][a-zA-Z0-9+.\-]*):')


def normalize_key(url: str, key_opts: Optional[Dict[str, Any]] = None) -> str:
    """Produce the CDX-comparable surt key for a URL.

    A deterministic, stable key (inverted host + canonicalized path/query).
    Callers must not pass blank-only URLs; blank-only input is mapped to
    surt's own empty-input sentinel "-" as a defensive fallback.
    """
    opts = key_opts or {}
    text = (url or "").strip()
    if not text:
        return "-"
    if opts.get('with_scheme'):
        # surt reproduces the input scheme verbatim; lower it so that
        # scheme-preserving (strict) matching does not depend on how the
        # scheme was spelled in the input file or in the CDX data.
        m = _SCHEME_RE.match(text)
        if m:
            # m.group(0) spans "scheme:"; lower it while keeping the colon
            # and everything after it intact.
            text = m.group(0).lower() + text[m.end():]
    return surt(text, canonicalizer=KEY_CANONICALIZER, **opts)


# ========================================
# SQLite cache layer
# ========================================
def open_db(path: str) -> sqlite3.Connection:
    """Open (and create if needed) the cache database.

    Uses a single-file layout (journal_mode=DELETE, no -wal/-shm sidecars)
    with WITHOUT ROWID tables for compact point-lookup storage.
    """
    is_new = not os.path.exists(path) or os.path.getsize(path) == 0
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30.0)
    try:
        if is_new:
            # page_size only takes effect for a new database before any tables exist.
            conn.execute("PRAGMA page_size=4096;")
        conn.execute("PRAGMA journal_mode=DELETE;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("PRAGMA cache_size=-64000;")  # ~64 MB page cache
        conn.execute("PRAGMA busy_timeout=30000;")
        # meta: build parameters + completion flag (cache validation).
        conn.execute(
            "CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID;"
        )
        # archived: the surt-key set of archived URLs. Original
        # spellings are intentionally NOT stored: --output-archived reports
        # the local input lines, so only the compact keys need to be cached.
        # WITHOUT ROWID keeps this to a single B-tree (no separate rowid
        # table + PK index).
        conn.execute(
            "CREATE TABLE IF NOT EXISTS archived("
            "key TEXT PRIMARY KEY) WITHOUT ROWID;"
        )
        # pages_done: integer PK uses the rowid alias, which is the most
        # compact/fastest option for integers (deliberately NOT WITHOUT ROWID).
        conn.execute(
            "CREATE TABLE IF NOT EXISTS pages_done(page INTEGER PRIMARY KEY);"
        )
        conn.commit()
    except Exception:
        conn.close()
        raise
    return conn


def archived_columns(conn: sqlite3.Connection) -> Set[str]:
    """Column names of the archived table (empty set when it does not exist)."""
    try:
        return {r[1] for r in conn.execute("PRAGMA table_info(archived);")}
    except sqlite3.Error:
        return set()


def expected_meta(target_url: str, key_opts: Dict[str, Any],
                  page_size: Optional[int]) -> Dict[str, str]:
    """Build parameters that define cache identity."""
    return {
        "schema_v": DB_SCHEMA_VERSION,
        "target_url": target_url,
        "filter": CDX_FILTER,
        "fl": CDX_FL,
        "key_profile": key_profile(key_opts),
        "page_size": str(page_size) if page_size is not None else "",
    }


def read_meta(conn: sqlite3.Connection) -> Dict[str, str]:
    try:
        return {k: v for k, v in conn.execute("SELECT k, v FROM meta;")}
    except sqlite3.Error:
        return {}


def write_meta(conn: sqlite3.Connection, values: Dict[str, str]) -> None:
    with conn:
        conn.executemany(
            "INSERT OR REPLACE INTO meta(k, v) VALUES (?, ?);", list(values.items())
        )


def is_completed(conn: sqlite3.Connection) -> bool:
    row = conn.execute("SELECT v FROM meta WHERE k='completed';").fetchone()
    return row is not None and row[0] == "1"


def set_completed(conn: sqlite3.Connection, done: bool = True) -> None:
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO meta(k, v) VALUES ('completed', ?);",
            ("1" if done else "0",),
        )


def get_done_pages(conn: sqlite3.Connection) -> Set[int]:
    try:
        return {r[0] for r in conn.execute("SELECT page FROM pages_done;")}
    except sqlite3.Error:
        return set()


def mark_page_done(conn: sqlite3.Connection, page: int) -> None:
    with conn:
        conn.execute("INSERT OR IGNORE INTO pages_done(page) VALUES (?);", (page,))


def insert_urls(conn: sqlite3.Connection, keys: Iterable[str]) -> int:
    """Bulk-insert surt keys (deduplicated by PK). Returns rows attempted."""
    batch: List[Tuple[str]] = []
    total = 0
    with conn:
        for k in keys:
            batch.append((k,))
            if len(batch) >= INSERT_CHUNK_SIZE:
                conn.executemany(
                    "INSERT OR IGNORE INTO archived(key) VALUES (?);",
                    batch,
                )
                total += len(batch)
                batch.clear()
        if batch:
            conn.executemany(
                "INSERT OR IGNORE INTO archived(key) VALUES (?);",
                batch,
            )
            total += len(batch)
    return total


def count_archived(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COUNT(*) FROM archived;").fetchone()
    return int(row[0]) if row else 0


def batch_lookup_found(conn: sqlite3.Connection, keys: List[str]) -> Set[str]:
    """Return the subset of surt `keys` present in the archived table."""
    found: Set[str] = set()
    for i in range(0, len(keys), 999):
        chunk = keys[i:i + 999]
        placeholders = ",".join("?" * len(chunk))
        rows = conn.execute(
            f"SELECT key FROM archived WHERE key IN ({placeholders});", chunk
        ).fetchall()
        found.update(r[0] for r in rows)
    return found


# ========================================
# CDX API
# ========================================
def make_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def _split_resume_key(data: List) -> Tuple[List, Optional[str]]:
    """Split a trailing resumeKey off a CDX JSON response.

    Robust against fl=original (single-column data rows): a trailing
    single-element row is only treated as a resumeKey if it does not look
    like a data URL (documented separator `[]` pattern, or a non-URL string
    when a full page was returned).
    """
    if not data:
        return data, None
    last = data[-1]
    if not (isinstance(last, list) and len(last) == 1 and isinstance(last[0], str)):
        return data, None
    candidate = last[0]
    # Documented JSON pattern: [..., [], ["<resumeKey>"]]
    if len(data) >= 2 and data[-2] == []:
        return data[:-2], candidate
    # Fallback heuristic for single-column rows: data rows (original URLs)
    # always contain '://', resumeKeys never do.
    if "://" not in candidate:
        return data[:-1], candidate
    return data, None


def _strip_header(data: List) -> List:
    if data and isinstance(data[0], list) and data[0]:
        if data[0][0] in ('urlkey', 'original'):
            return data[1:]
    return data


def _get_with_retries(session: requests.Session, api_url: str, params: dict,
                      headers: dict, timeout: int = 60) -> requests.Response:
    """GET with retries for transport errors and non-JSON/empty 200 responses."""
    last_error: Optional[Exception] = None
    for attempt in range(3):
        try:
            response = session.get(api_url, params=params, headers=headers, timeout=timeout)
            response.raise_for_status()
            content_type = response.headers.get('Content-Type', '')
            body = response.content
            if len(body) == 0 or not response.text.strip() or 'application/json' not in content_type:
                logger.warning(
                    f"Non-JSON or empty response (attempt {attempt + 1}/3): "
                    f"status={response.status_code}, Content-Type={content_type}, "
                    f"content-length={len(body)}"
                )
                if attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                raise CDXAPIError("Non-JSON or empty response (max retries reached)")
            return response
        except CDXAPIError:
            raise
        except requests.exceptions.RequestException as e:
            last_error = e
            logger.warning(f"Request error (attempt {attempt + 1}/3): {e}")
            if attempt < 2:
                time.sleep(2 ** attempt)
                continue
    raise CDXAPIError(f"CDX API fetch error (max retries reached): {last_error}") from last_error


def get_num_pages(target_url: str, page_size: Optional[int],
                  collapse: Optional[str], session: requests.Session,
                  headers: dict) -> Optional[int]:
    """Ask the CDX server for the page count. Returns None if unsupported.

    Sends the same pageSize/collapse as the paged queries: the page count
    is only valid against the same query shape that will fetch the pages
    (the CDX contract pairs the two; a mismatched pageSize would silently
    truncate the fetch at the tail).
    """
    api_url = "https://web.archive.org/cdx/search/cdx"
    params = {
        'url': target_url,
        'filter': CDX_FILTER,
        'showNumPages': 'true',
    }
    if page_size is not None:
        params['pageSize'] = page_size
    if collapse:
        params['collapse'] = collapse
    try:
        response = session.get(api_url, params=params, headers=headers, timeout=60)
        response.raise_for_status()
        text = response.text.strip()
        # Server returns a bare number (plain text or JSON int).
        try:
            return int(text)
        except ValueError:
            data = response.json()
            return int(data) if isinstance(data, int) else None
    except (requests.exceptions.RequestException, ValueError) as e:
        logger.info(f"showNumPages unavailable, falling back to resumeKey mode: {e}")
        return None


def _cdx_params(target_url: str, *,
                page: Optional[int] = None,
                page_size: Optional[int] = None,
                resume_key: Optional[str] = None,
                limit: Optional[int] = None,
                collapse: Optional[str] = None) -> Dict[str, Any]:
    """CDX request parameters shared by both fetch paths.

    `collapse` carries the run's collapse mode: `urlkey` for lenient,
    `original` for strict. Callers may pass None to omit the parameter.
    """
    params: Dict[str, Any] = {
        'url': target_url,
        'output': 'json',
        'filter': CDX_FILTER,
        'fl': CDX_FL,
        'showResumeKey': 'true',
    }
    if page is not None:
        params['page'] = page
    if page_size is not None:
        params['pageSize'] = page_size
    # Omit `limit` when unset so the CDX server applies its own default.
    if limit is not None:
        params['limit'] = limit
    if collapse:
        params['collapse'] = collapse
    if resume_key:
        params['resumeKey'] = resume_key
    return params


def fetch_page_rows(target_url: str, page: int, page_size: Optional[int],
                    collapse: Optional[str], session: requests.Session,
                    headers: dict) -> List[List]:
    """Fetch one page (following in-page resumeKey chaining). Returns data rows.

    NOTE: `limit` is intentionally NOT sent here. In pagination mode the
    server defines page boundaries, so `limit` would only truncate each page
    (extra round-trips at best, lost data at worst). If a single page exceeds
    the server-side per-response maximum, the response carries a resumeKey
    which is followed below ("in-page" chaining). A complete page carries no
    resumeKey, so the normal case costs nothing.
    """
    api_url = "https://web.archive.org/cdx/search/cdx"
    params = _cdx_params(target_url, page=page, page_size=page_size,
                         collapse=collapse)

    rows: List[List] = []
    resume_key: Optional[str] = None
    seen_keys: Set[str] = set()
    # No hard cap on chaining: safety rests on the cycle detection below
    # (a repeated resumeKey breaks the loop) and on terminating when a
    # response carries no resumeKey.
    while True:
        if resume_key:
            if resume_key in seen_keys:
                logger.warning(f"resumeKey cycle detected within page {page}, stopping")
                break
            seen_keys.add(resume_key)
            params['resumeKey'] = resume_key
        response = _get_with_retries(session, api_url, params, headers)
        data = response.json()
        if not isinstance(data, list):
            raise CDXAPIError(f"CDX API returned unexpected type: {type(data).__name__}")
        data = [row for row in data if row != []]
        data, new_key = _split_resume_key(data)
        data = _strip_header(data)
        rows.extend([r for r in data if isinstance(r, list) and r])
        if new_key:
            resume_key = new_key
        else:
            break
    return rows


def fetch_resumekey_rows(target_url: str, initial_resume_key: Optional[str],
                         limit: Optional[int], collapse: Optional[str],
                         session: requests.Session,
                         headers: dict) -> Generator[List, None, Optional[str]]:
    """Sequential resumeKey fetch (fallback path). Yields data rows.

    Returns the last resumeKey via the generator return value (PEP 380),
    so an interrupted run can be resumed with --resume-key.
    """
    api_url = "https://web.archive.org/cdx/search/cdx"
    params = _cdx_params(target_url, limit=limit, collapse=collapse)
    resume_key = initial_resume_key
    seen_request_keys: Set[str] = set()
    seen_response_keys: Set[str] = set()
    if initial_resume_key:
        logger.info(f"Resuming from resumeKey: {initial_resume_key}")

    while True:
        if resume_key:
            if resume_key in seen_request_keys:
                logger.warning(f"resumeKey cycle detected (request side): {resume_key}")
                break
            seen_request_keys.add(resume_key)
            params['resumeKey'] = resume_key

        try:
            response = _get_with_retries(session, api_url, params, headers, timeout=60)
            data = response.json()
        except CDXAPIError as e:
            failed_key = resume_key if resume_key else "(initial)"
            logger.error(f"Failed at resumeKey={failed_key}. To resume, add:")
            logger.error(f"  --resume-key {failed_key}")
            raise CDXAPIError(f"CDX API fetch error: {e}") from e

        if not isinstance(data, list):
            raise CDXAPIError(f"CDX API returned unexpected type: {type(data).__name__}")

        data = [row for row in data if row != []]
        data, new_key = _split_resume_key(data)
        if new_key and new_key in seen_response_keys:
            logger.warning(f"Previously seen resumeKey returned again: {new_key} -> stopping")
            break
        if new_key:
            seen_response_keys.add(new_key)
        data = _strip_header(data)

        valid = [r for r in data if isinstance(r, list) and r]
        if new_key and not valid:
            logger.warning("No valid data rows in this chunk, stopping pagination")
            resume_key = new_key
            break
        for row in valid:
            yield row
        if new_key:
            resume_key = new_key
        else:
            resume_key = None
            break
    return resume_key


def _rows_to_keys(rows: Iterable[List],
                  key_opts: Optional[Dict[str, Any]]) -> List[str]:
    """Convert CDX data rows (fl=original) into surt keys.

    Original spellings are intentionally not returned (and not stored):
    the key set is the only thing the scan needs, and --output-archived
    reports the matched local input lines instead.
    """
    out: List[str] = []
    for row in rows:
        if not isinstance(row, list) or not row:
            continue
        original = row[0]
        if isinstance(original, str) and original and original.strip():
            out.append(normalize_key(original, key_opts))
    return out


def _fetch_pages_parallel(target_url: str, pages: List[int], page_size: Optional[int],
                          key_opts: Optional[Dict[str, Any]],
                          workers: int, headers: dict,
                          collapse: Optional[str]) -> Generator[
        Tuple[int, List[str]], None, None]:
    """Fetch pages concurrently; yields (page, surt_keys) as they complete."""
    thread_state = threading.local()

    def _get_session() -> requests.Session:
        sess = getattr(thread_state, "session", None)
        if sess is None:
            sess = make_session()
            thread_state.session = sess
        return sess

    def _work(page: int) -> Tuple[int, List[str]]:
        sess = _get_session()
        rows = fetch_page_rows(target_url, page, page_size, collapse, sess, headers)
        return page, _rows_to_keys(rows, key_opts)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futures = {ex.submit(_work, p): p for p in pages}
        for fut in concurrent.futures.as_completed(futures):
            yield fut.result()


def ensure_archived_db(target_url: str, cache_file: str,
                       key_opts: Optional[Dict[str, Any]] = None,
                       initial_resume_key: Optional[str] = None,
                       limit: Optional[int] = None,
                       page_size: Optional[int] = None,
                       workers: int = 4,
                       refresh: bool = False) -> str:
    """Build (or reuse/resume) the SQLite archived-URL cache. Returns db path.

    Lenient mode (empty key_opts == surt defaults) adds collapse=urlkey to
    the CDX queries; strict mode (any non-default flags) adds
    collapse=original, which only folds repeated captures of identical
    original spellings. The key profile is part of the cache identity.
    """
    headers = {'User-Agent': USER_AGENT}
    collapse = CDX_COLLAPSE if not key_opts else CDX_COLLAPSE_STRICT
    logger.info(f"URL key profile: {key_profile(key_opts or {})}")

    if refresh and initial_resume_key is None and os.path.exists(cache_file):
        logger.info(f"Removing existing cache (--refresh): {cache_file}")
        os.remove(cache_file)

    expected = expected_meta(target_url, key_opts or {}, page_size)
    conn = open_db(cache_file)
    try:
        meta = read_meta(conn)
        columns_ok = archived_columns(conn) == {"key"}
        params_match = columns_ok and all(meta.get(k) == v for k, v in expected.items())

        if initial_resume_key is None and params_match and is_completed(conn):
            logger.info(f"Reusing completed cache: {cache_file} ({count_archived(conn)} URLs)")
            return cache_file

        if not params_match and (meta or not columns_ok):
            # Stale cache (other schema/flags/target): rebuild instead of mixing.
            logger.info("Cache parameters changed, rebuilding cache")
            conn.close()
            os.remove(cache_file)
            conn = open_db(cache_file)
            meta = {}
            params_match = False

        if not params_match:
            write_meta(conn, {**expected, "completed": "0"})
            set_completed(conn, False)
        elif is_completed(conn) and initial_resume_key is not None:
            # Explicit resume requested against a completed db: allow append.
            set_completed(conn, False)

        # ResumeKey manual-resume path takes precedence when explicitly requested.
        if initial_resume_key is not None:
            logger.info(f"Fetching data from CDX API (resumeKey mode): {target_url}")
            session = make_session()
            gen = fetch_resumekey_rows(target_url, initial_resume_key, limit,
                                       collapse, session, headers)
            inserted = 0
            batch: List[str] = []
            with tqdm(desc="Fetching (resumeKey)", unit="rec") as bar:
                try:
                    while True:
                        try:
                            row = next(gen)
                        except StopIteration as stop:
                            last_key = stop.value
                            if last_key:
                                write_meta(conn, {"last_resume_key": str(last_key)})
                            break
                        if not isinstance(row, list) or not row:
                            continue
                        if isinstance(row[0], str) and row[0] and row[0].strip():
                            batch.append(normalize_key(row[0], key_opts))
                        if len(batch) >= INSERT_CHUNK_SIZE:
                            insert_urls(conn, batch)
                            inserted += len(batch)
                            bar.update(len(batch))
                            batch.clear()
                    if batch:
                        insert_urls(conn, batch)
                        inserted += len(batch)
                        bar.update(len(batch))
                except CDXAPIError:
                    logger.error(f"Progress saved ({inserted} records). Resume with --resume-key.")
                    raise
            set_completed(conn, True)
            write_meta(conn, {"mode": "resumekey"})
            # Finalize single-file layout.
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            logger.info(f"All chunks fetched successfully ({inserted} records total)")
            return cache_file

        # Pagination path (primary).
        session = make_session()
        num_pages = get_num_pages(target_url, page_size, collapse, session, headers)
        if num_pages is None or num_pages <= 0:
            logger.info("Falling back to resumeKey sequential fetch")
            gen = fetch_resumekey_rows(target_url, None, limit, collapse, session, headers)
            inserted = 0
            batch = []
            with tqdm(desc="Fetching (resumeKey)", unit="rec") as bar:
                for row in gen:
                    if not isinstance(row, list) or not row:
                        continue
                    if isinstance(row[0], str) and row[0] and row[0].strip():
                        batch.append(normalize_key(row[0], key_opts))
                    if len(batch) >= INSERT_CHUNK_SIZE:
                        insert_urls(conn, batch)
                        inserted += len(batch)
                        bar.update(len(batch))
                        batch.clear()
                if batch:
                    insert_urls(conn, batch)
                    inserted += len(batch)
                    bar.update(len(batch))
            set_completed(conn, True)
            write_meta(conn, {"mode": "resumekey", "num_pages": "0"})
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            logger.info(f"All chunks fetched successfully ({inserted} records total)")
            return cache_file

        done = get_done_pages(conn)
        pending = [p for p in range(num_pages) if p not in done]
        logger.info(f"Fetching data from CDX API: {target_url} ({num_pages} pages, {len(pending)} pending)")
        write_meta(conn, {"mode": "pagination", "num_pages": str(num_pages)})
        total_inserted = 0
        with tqdm(total=len(pending), desc="Fetching pages", unit="page") as bar:
            for page, keys in _fetch_pages_parallel(
                target_url, pending, page_size, key_opts, workers, headers, collapse,
            ):
                if keys:
                    insert_urls(conn, keys)
                    total_inserted += len(keys)
                mark_page_done(conn, page)
                bar.update(1)
                bar.set_postfix(records=count_archived(conn))
        set_completed(conn, True)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        logger.info(f"All pages fetched successfully ({count_archived(conn)} unique URLs)")
        return cache_file
    finally:
        conn.close()


def extract_archived_urls(cdx_data: Iterable[List],
                          key_opts: Optional[Dict[str, Any]] = None) -> Set[str]:
    """
    Extract a set of surt keys from CDX data.

    Kept for small-scale/test use. Production flow stores directly into
    SQLite via ensure_archived_db() to avoid holding everything in RAM.

    Args:
        cdx_data: Iterable of CDX API records (fl=original style rows).
        key_opts: surt() options; None means lenient (surt defaults).

    Returns:
        A set of surt keys.
    """
    # Return early if cdx_data is not iterable
    try:
        iter(cdx_data)  # type: ignore[arg-type]
    except TypeError:
        logger.warning(f"cdx_data is not iterable: {type(cdx_data).__name__}")
        return set()

    archived_keys = set()
    header_processed = False
    col_idx = 0

    for row in cdx_data:
        # Skip non-list rows (treat as malformed and ignore).
        # A non-list row *before* any list row means a malformed header:
        # the whole response is untrustworthy, so return an empty set.
        if not isinstance(row, list):
            if not header_processed:
                logger.debug(f"Malformed header row: {type(row).__name__}")
                return set()
            logger.debug(f"Skipping non-list row: {type(row).__name__}")
            continue

        # Skip empty rows
        if not row:
            continue

        if not header_processed:
            header_processed = True
            lowered = [c.lower() for c in row if isinstance(c, str)]
            if 'original' in lowered:
                col_idx = next(
                    i for i, c in enumerate(row)
                    if isinstance(c, str) and c.lower() == 'original'
                )
                continue  # skip the header row itself
            if any(h in lowered for h in ('urlkey', 'url', 'timestamp')):
                col_idx = 0
                continue  # header without an 'original' column; data starts at index 0
            # No recognizable header: treat this row as data (fall through).

        if col_idx >= len(row):
            continue
        original_url = row[col_idx]

        # Ensure the URL value is a string
        if isinstance(original_url, str) and original_url and original_url.strip():
            archived_keys.add(normalize_key(original_url, key_opts))

    return archived_keys


# ========================================
# Main logic
# ========================================
def detect_not_archived(input_file: str, archived_keys: Set[str],
                        key_opts: Optional[Dict[str, Any]] = None,
                        collect_archived: bool = False) -> Tuple[List[str], Optional[List[str]], int]:
    """
    Detect URLs in the input file that have not been archived (in-memory set version).

    Kept for small-scale/test use. Production flow uses scan_input_against_db()
    for streaming operation on tens of millions of URLs.

    Args:
        input_file: Path to the input URL file.
        archived_keys: Set of surt keys of already-archived URLs.
        key_opts: surt() options for the comparison (None = lenient defaults).
        collect_archived: If True, also collect the list of archived URLs (default: False).

    Returns:
        tuple: (list of unarchived URL lines, list of archived URL lines or None,
        total input URL count)
    """
    if not os.path.exists(input_file):
        raise InputFileError(f"Input file not found: {input_file}")

    not_archived = []
    archived = [] if collect_archived else None
    total_count = 0

    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            original_url = line.strip()

            if not original_url:
                continue

            total_count += 1

            key = normalize_key(original_url, key_opts)

            if key not in archived_keys:
                not_archived.append(original_url)
            elif collect_archived:
                archived.append(original_url)

    return not_archived, archived, total_count


def count_input_lines(input_file: str) -> Optional[int]:
    """Fast line count for progress bars. Returns None on failure."""
    try:
        count = 0
        with open(input_file, 'rb') as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                count += chunk.count(b'\n')
        return count
    except OSError:
        return None


def scan_input_against_db(input_file: str, db_path: str,
                          key_opts: Optional[Dict[str, Any]] = None,
                          output_file: Optional[str] = None,
                          output_archived: Optional[str] = None,
                          batch_size: int = LOOKUP_BATCH_SIZE) -> Tuple[int, int, int]:
    """Stream the input file against SQLite and write results incrementally.

    Never accumulates URL lists in RAM: results go straight to disk.
    Matching is done on surt keys computed identically for the input and
    the cached CDX rows.

    Returns:
        tuple: (total input count, unarchived count, archived count)
    """
    if not os.path.exists(input_file):
        raise InputFileError(f"Input file not found: {input_file}")

    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute("PRAGMA query_only=ON;")
    try:
        total_lines = count_input_lines(input_file)

        out_f = None
        arch_f = None
        try:
            if output_file:
                Path(output_file).parent.mkdir(parents=True, exist_ok=True)
                out_f = open(output_file, 'w', encoding='utf-8')
            if output_archived:
                Path(output_archived).parent.mkdir(parents=True, exist_ok=True)
                arch_f = open(output_archived, 'w', encoding='utf-8')

            total_count = 0
            not_count = 0
            arch_count = 0
            batch: List[Tuple[str, str]] = []  # (original line, surt key)

            def _flush() -> None:
                nonlocal not_count, arch_count
                if not batch:
                    return
                key_list = [k for _, k in batch]
                found = batch_lookup_found(conn, key_list)
                for original, key in batch:
                    if key in found:
                        arch_count += 1
                        if arch_f is not None:
                            arch_f.write(original + '\n')
                    else:
                        not_count += 1
                        if out_f is not None:
                            out_f.write(original + '\n')
                batch.clear()

            with open(input_file, 'r', encoding='utf-8') as f:
                with tqdm(total=total_lines, desc="Checking URLs", unit="url") as bar:
                    for line in f:
                        original_url = line.strip()
                        if not original_url:
                            continue
                        total_count += 1
                        key = normalize_key(original_url, key_opts)
                        batch.append((original_url, key))
                        if len(batch) >= batch_size:
                            _flush()
                        bar.update(1)
                    _flush()
        finally:
            if out_f is not None:
                out_f.close()
            if arch_f is not None:
                arch_f.close()

        return total_count, not_count, arch_count
    finally:
        conn.close()


def main() -> int:
    """Entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description='Wayback Gap Detector - Find URLs that have not been archived',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
examples:
  python waygap.py "https://example.com/blog/*"
  python waygap.py "https://example.com/blog/*" --no-ignore-www --output result.txt
        '''
    )

    parser.add_argument(
        'target_url',
        help='Wildcard URL to search in the CDX API (e.g. https://example.com/path/*)'
    )

    parser.add_argument(
        '--ignore-protocol',
        dest='ignore_protocol',
        action='store_true',
        default=IGNORE_PROTOCOL,
        help='treat http and https as equivalent (default: enabled)'
    )
    parser.add_argument(
        '--no-ignore-protocol',
        dest='ignore_protocol',
        action='store_false',
        help='distinguish between http and https'
    )
    parser.add_argument(
        '--ignore-www',
        dest='ignore_www',
        action='store_true',
        default=IGNORE_WWW,
        help='treat www.example.com / www2.example.com etc. as equivalent '
             '(default: enabled, matches CDX urlkey normalization)'
    )
    parser.add_argument(
        '--no-ignore-www',
        dest='ignore_www',
        action='store_false',
        help='distinguish www.example.com and example.com (strict key matching)'
    )

    parser.add_argument(
        '--input',
        dest='input_file',
        default=TARGET_URL_FILE,
        help=f'path to the input URL file (default: {TARGET_URL_FILE})'
    )

    parser.add_argument(
        '--output',
        dest='output_file',
        default=OUTPUT_FILE,
        help=f'path to the output file (default: {OUTPUT_FILE})'
    )

    parser.add_argument(
        '--cache',
        dest='cache_file',
        default=CACHE_FILE,
        help=f'path to the CDX cache file (default: {CACHE_FILE})'
    )
    parser.add_argument(
        '--refresh',
        dest='refresh',
        action='store_true',
        default=False,
        help='ignore and rebuild the existing cache file'
    )
    parser.add_argument(
        '--no-cache',
        dest='no_cache',
        action='store_true',
        default=False,
        help='do not reuse or keep the cache (uses a temporary database)'
    )

    parser.add_argument(
        '--output-archived',
        dest='output_archived',
        nargs='?',
        const=ARCHIVED_FILE,
        default=None,
        help=f'path to write archived URLs to (default: {ARCHIVED_FILE})'
    )

    parser.add_argument(
        '--resume-key',
        dest='resume_key',
        default=None,
        help='resumeKey to resume an interrupted fetch (use the key logged at failure time)'
    )

    parser.add_argument(
        '--limit',
        dest='limit',
        type=int,
        default=None,
        help='chunk size per request for resumeKey sequential fetch only '
             '(pagination mode ignores it; default: server default)'
    )
    parser.add_argument(
        '--page-size',
        dest='page_size',
        type=int,
        default=None,
        help='CDX pagination page size (default: server default)'
    )
    parser.add_argument(
        '--workers',
        dest='workers',
        type=int,
        default=4,
        help='parallel page fetch workers (default: 4)'
    )
    parser.add_argument(
        '--batch-size',
        dest='batch_size',
        type=int,
        default=LOOKUP_BATCH_SIZE,
        help=f'URL lookup batch size for DB scan (default: {LOOKUP_BATCH_SIZE})'
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {__version__}',
        help="show the program's version number and exit"
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='enable verbose (DEBUG-level) logging'
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(levelname)s: %(message)s'
    )

    temp_db: Optional[str] = None
    try:
        cache_file = args.cache_file
        if args.no_cache:
            fd, temp_db = tempfile.mkstemp(prefix="waygap_", suffix=".db")
            os.close(fd)
            cache_file = temp_db
            logger.info("Cache disabled (--no-cache): using temporary database")

        key_opts = build_key_opts(args.ignore_protocol, args.ignore_www)

        db_path = ensure_archived_db(
            args.target_url,
            cache_file,
            key_opts=key_opts,
            initial_resume_key=args.resume_key,
            limit=args.limit,
            page_size=args.page_size,
            workers=args.workers,
            refresh=args.refresh,
        )

        conn = sqlite3.connect(db_path, timeout=30.0)
        try:
            archived_count = count_archived(conn)
        finally:
            conn.close()
        logger.info(f"Archived URLs in cache: {archived_count}")

        total_count, not_count, arch_count = scan_input_against_db(
            args.input_file,
            db_path,
            key_opts=key_opts,
            output_file=args.output_file,
            output_archived=args.output_archived,
            batch_size=args.batch_size,
        )

        logger.info(f"Total input URLs: {total_count}")
        logger.info(f"Unarchived URLs: {not_count}")
        logger.info(f"Results written to {args.output_file}")

        if args.output_archived:
            logger.info(f"Archived URLs written to {args.output_archived}: {arch_count} entries")

        return 0

    except CDXAPIError as e:
        logger.error(f"{e}")
        return 1
    except InputFileError as e:
        logger.error(f"{e}")
        return 1
    except CacheError as e:
        logger.error(f"{e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1
    finally:
        if temp_db is not None and os.path.exists(temp_db):
            try:
                os.remove(temp_db)
            except OSError:
                pass


if __name__ == '__main__':
    sys.exit(main())
