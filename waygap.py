#!/usr/bin/env python3
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
from collections.abc import Callable, Generator, Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import requests
from requests.adapters import HTTPAdapter
from surt import surt
from surt.GoogleURLCanonicalizer import (
    DECIMAL_IP,
    escapeOnce,
    minimalEscape,
    normalizePath,
    unescapeRepeatedly,
)
from surt.IAURLCanonicalizer import canonicalize as ia_canonicalize
from surt.surt import CompositeCanonicalizer
from tqdm import tqdm
from urllib3.exceptions import InvalidHeader
from urllib3.util import Retry

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
CACHE_AGE_WARNING = timedelta(days=7)
ARCHIVED_FILE = "archived.txt"

__version__ = "0.1.0"
USER_AGENT = f"Wayback-Gap-Detector/{__version__} (https://github.com/nabikita3974/wayback-gap-detector)"

DB_SCHEMA_VERSION = "1"
# Written to meta["resumekey_v"] when a resumeKey fallback fetch starts from
# the beginning. Earlier versions could mark an incomplete resumeKey cache
# as completed (including after an unchecked manual resume), so older
# completed resumeKey caches are fetched again.
# Not part of expected_meta(): pagination caches are not affected.
RESUMEKEY_FETCH_VERSION = "3"
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
# Minimum seconds between the starts of two CDX requests, shared by all
# threads. The CDX search API has a hard limit of 30 requests per minute;
# the `wayback` library (v0.5.1, 2026-06) defaults to 80% of it, 24 per
# minute. 3 s (20 per minute, ~67% of the limit) leaves headroom for retries.
CDX_REQUEST_INTERVAL = 3.0
# Seconds to pause every CDX request after consecutive HTTP 429s. An IP that
# keeps sending after a 429 gets blocked, so the pauses are long.
CDX_429_PAUSES = (60.0, 120.0, 240.0)
# Server errors retried with longer waits than transport errors, and seconds
# the worker waits after the 1st and 2nd of them (a 3rd fails the request).
# 1 s and 2 s suit brief network glitches; a struggling server needs longer.
CDX_5XX_STATUSES = (500, 502, 503, 504)
CDX_5XX_WAITS = (10.0, 20.0)
# Page fetch workers. The request rate is set by CDX_REQUEST_INTERVAL, so
# workers only hide response latency; 2 keep the interval filled.
DEFAULT_WORKERS = 2
# Seconds between checks while waiting for page fetches. Windows delivers
# Ctrl+C to a waiting main thread only when its wait returns, so the wait
# for completed pages is split into polls of this length.
FETCH_POLL_INTERVAL = 0.5


# ========================================
# Custom Exceptions
# ========================================
class WaybackGapDetectorError(Exception):
    """Base exception for Wayback Gap Detector"""

    pass


class CDXAPIError(WaybackGapDetectorError):
    """CDX API related errors (network, response parsing, etc.)"""

    pass


class ResumeKeyRequestError(CDXAPIError):
    """A failed request in the sequential resumeKey fetch.

    resume_key is the key of the failed request (None for the first request
    of a fetch from the beginning). The caller logs it as the key to resume
    from once the rows before it are stored.
    """

    def __init__(self, message: str, resume_key: str | None) -> None:
        super().__init__(message)
        self.resume_key = resume_key


class InputFileError(WaybackGapDetectorError):
    """Input file related errors (not found, encoding issues, etc.)"""

    pass


class CacheError(WaybackGapDetectorError):
    """Local cache (SQLite) related errors"""

    pass


class _FetchCancelled(Exception):
    """Raised in a page fetch worker after the fetch was stopped.

    Internal: the consumer has already stopped reading results, so this
    never reaches the caller. Not a CDXAPIError, so it is not reported or
    wrapped as a request failure.
    """


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
        return socket.inet_ntoa(struct.pack(">L", int(host) & 0xFFFFFFFF)).encode(
            "ascii"
        )
    if DECIMAL_IP.match(host):
        parts = host.split(b".")
        if len(parts) == 4 and all(
            p.isdigit() and 0 <= int(p) <= 255 and (p == b"0" or not p.startswith(b"0"))
            for p in parts
        ):
            return host
        return None
    return None


def _unescape_bytes(data: bytes) -> bytes:
    """Type boundary for untyped unescapeRepeatedly(): bytes in, bytes out."""
    return cast(bytes, unescapeRepeatedly(data))


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
        host = _unescape_bytes(url.host)
        try:
            host.decode("ascii")
        except UnicodeDecodeError:
            try:
                host = host.decode("utf-8", "ignore").encode("idna")
            except ValueError:
                pass

        host = host.replace(b"..", b".").strip(b".")

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


def _surt_key(text: str, **opts: Any) -> str:
    """surt() always returns str for str input (bytes only for bytes input).
    Type boundary for the untyped surt library; the cast is centralized here."""
    return cast(str, surt(text, canonicalizer=KEY_CANONICALIZER, **opts))


def build_key_opts(ignore_protocol: bool, ignore_www: bool) -> dict[str, Any]:
    """Build the surt() options for one run.

    With both defaults (True/True) this is empty == surt defaults ==
    CDX urlkey semantics. --no-ignore-www keeps www/wwwN variants
    (host_massage=False); --no-ignore-protocol keeps the scheme in the
    key (with_scheme=True). Any non-empty opts activates strict mode
    (collapse=original instead of urlkey).
    """
    opts: dict[str, Any] = {}
    if not ignore_www:
        opts["host_massage"] = False
    if not ignore_protocol:
        opts["with_scheme"] = True
    return opts


def key_profile(opts: dict[str, Any]) -> str:
    """Stable fingerprint of key options for cache identity."""
    if not opts:
        return "surt-default"
    return "surt:" + ",".join(f"{k}={opts[k]}" for k in sorted(opts))


_SCHEME_RE = re.compile(r"\A([a-zA-Z][a-zA-Z0-9+.\-]*):")


def normalize_key(url: str, key_opts: dict[str, Any] | None = None) -> str:
    """Produce the CDX-comparable surt key for a URL.

    A deterministic, stable key (inverted host + canonicalized path/query).
    Callers must not pass blank-only URLs; blank-only input is mapped to
    surt's own empty-input sentinel "-" as a defensive fallback.
    """
    opts = key_opts or {}
    text = (url or "").strip()
    if not text:
        return "-"
    if opts.get("with_scheme"):
        # surt reproduces the input scheme verbatim; lower it so that
        # scheme-preserving (strict) matching does not depend on how the
        # scheme was spelled in the input file or in the CDX data.
        m = _SCHEME_RE.match(text)
        if m:
            # m.group(0) spans "scheme:"; lower it while keeping the colon
            # and everything after it intact.
            text = m.group(0).lower() + text[m.end() :]
    return _surt_key(text, **opts)


def _try_normalize_key(
    url: str, key_opts: dict[str, Any] | None, context: str
) -> str | None:
    """normalize_key(), or None with a warning when surt cannot parse the URL.

    surt raises ValueError for an invalid port and UnicodeEncodeError (a
    ValueError subclass) for a lone surrogate. `context` says where the URL
    came from and what the caller does with it.
    """
    try:
        return normalize_key(url, key_opts)
    except ValueError as e:
        logger.warning(f"Cannot parse URL {context}: {url!r} ({e})")
        return None


_CDX_ROW_CONTEXT = "in a CDX row, skipping it"


def _input_context(line_no: int) -> str:
    return f"at input line {line_no}, reporting it as unarchived"


# ========================================
# SQLite cache layer
# ========================================
def _cache_error(path: str, error: sqlite3.Error) -> CacheError:
    return CacheError(
        f"Cache database error for {path}: {error}. "
        "If the cache is corrupt, use --refresh to rebuild it."
    )


def open_db(path: str) -> sqlite3.Connection:
    """Open (and create if needed) the cache database.

    Uses a single-file layout (journal_mode=DELETE, no -wal/-shm sidecars)
    with WITHOUT ROWID tables for compact point-lookup storage.
    """
    is_new = not os.path.exists(path) or os.path.getsize(path) == 0
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    try:
        conn = sqlite3.connect(path, timeout=30.0)
    except sqlite3.Error as error:
        raise _cache_error(path, error) from error
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
            "CREATE TABLE IF NOT EXISTS archived(key TEXT PRIMARY KEY) WITHOUT ROWID;"
        )
        # pages_done: integer PK uses the rowid alias, which is the most
        # compact/fastest option for integers (deliberately NOT WITHOUT ROWID).
        conn.execute("CREATE TABLE IF NOT EXISTS pages_done(page INTEGER PRIMARY KEY);")
        conn.commit()
    except Exception as error:
        conn.close()
        if isinstance(error, sqlite3.Error):
            raise _cache_error(path, error) from error
        raise
    return conn


def archived_columns(conn: sqlite3.Connection) -> set[str]:
    """Column names of the archived table (empty set when it does not exist)."""
    try:
        return {r[1] for r in conn.execute("PRAGMA table_info(archived);")}
    except sqlite3.Error:
        return set()


def expected_meta(
    target_url: str, key_opts: dict[str, Any], page_size: int | None
) -> dict[str, str]:
    """Build parameters that define cache identity."""
    return {
        "schema_v": DB_SCHEMA_VERSION,
        "target_url": target_url,
        "filter": CDX_FILTER,
        "fl": CDX_FL,
        "key_profile": key_profile(key_opts),
        "page_size": str(page_size) if page_size is not None else "",
    }


def read_meta(conn: sqlite3.Connection) -> dict[str, str]:
    try:
        return {k: v for k, v in conn.execute("SELECT k, v FROM meta;")}
    except sqlite3.Error:
        return {}


def write_meta(conn: sqlite3.Connection, values: dict[str, str]) -> None:
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
        if done:
            conn.execute(
                "INSERT OR REPLACE INTO meta(k, v) VALUES ('built_at', ?);",
                (datetime.now(UTC).isoformat(),),
            )
        else:
            conn.execute("DELETE FROM meta WHERE k='built_at';")


def get_done_pages(conn: sqlite3.Connection) -> set[int]:
    try:
        return {r[0] for r in conn.execute("SELECT page FROM pages_done;")}
    except sqlite3.Error:
        return set()


def mark_page_done(conn: sqlite3.Connection, page: int) -> None:
    with conn:
        conn.execute("INSERT OR IGNORE INTO pages_done(page) VALUES (?);", (page,))


def insert_urls(conn: sqlite3.Connection, keys: Iterable[str]) -> int:
    """Bulk-insert surt keys (deduplicated by PK). Returns rows attempted."""
    batch: list[tuple[str]] = []
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


def batch_lookup_found(conn: sqlite3.Connection, keys: list[str]) -> set[str]:
    """Return the subset of surt `keys` present in the archived table."""
    found: set[str] = set()
    for i in range(0, len(keys), 999):
        chunk = keys[i : i + 999]
        placeholders = ",".join("?" * len(chunk))
        rows = conn.execute(
            f"SELECT key FROM archived WHERE key IN ({placeholders});", chunk
        ).fetchall()
        found.update(r[0] for r in rows)
    return found


# ========================================
# CDX API
# ========================================
def _pause(seconds: float, stop: threading.Event | None) -> None:
    """Sleep for `seconds`, waking early when `stop` is set.

    Raises _FetchCancelled if `stop` is set. Without `stop` this is a plain
    time.sleep().
    """
    if stop is None:
        time.sleep(seconds)
    elif stop.wait(seconds):
        raise _FetchCancelled


class _RateLimiter:
    """Spaces calls to wait() at least `interval` seconds apart across threads.

    Each caller reserves the next free slot under the lock and sleeps
    outside it, so a waiting thread does not block the others. pause() holds
    every caller, including those already waiting, until the pause ends.
    """

    def __init__(self, interval: float) -> None:
        self._interval = interval
        self._lock = threading.Lock()
        self._next = 0.0
        self._paused_until = 0.0

    def pause(self, seconds: float) -> None:
        """Hold every wait() until `seconds` from now (never shortens a pause)."""
        with self._lock:
            self._paused_until = max(self._paused_until, time.monotonic() + seconds)
            self._next = max(self._next, self._paused_until)

    def wait(self, stop: threading.Event | None = None) -> None:
        """Wait for the next slot; raises _FetchCancelled if `stop` is set."""
        while True:
            with self._lock:
                now = time.monotonic()
                start = max(now, self._next)
                self._next = start + self._interval
            delay = start - now
            if delay > 0:
                _pause(delay, stop)
            with self._lock:
                if self._paused_until <= start:
                    return
            # A pause began while waiting for the slot: take a slot after it.


_CDX_LIMITER = _RateLimiter(CDX_REQUEST_INTERVAL)


def make_session() -> requests.Session:
    session = requests.Session()
    # Retries connection and read errors only. No status is resent here: HTTP
    # 429 is left to _cdx_get() and 5xx to _get_with_retries(), whose resends
    # go through the shared limiter and observe `stop`.
    # Retry-After stays off so that a 503 carrying it is not resent either.
    retry = Retry(
        total=3,
        backoff_factor=1,
        allowed_methods=["GET"],
        raise_on_status=False,
        respect_retry_after_header=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def _split_resume_key(data: list) -> tuple[list, str | None]:
    """Split a trailing resumeKey off a CDX JSON response.

    Only the documented JSON pattern `[..., [], ["<resumeKey>"]]` is
    recognised. Without the empty separator row, a trailing single-element
    row is a data row (fl=original rows are single-column), so callers must
    pass the raw response before removing empty rows.
    """
    if not data:
        return data, None
    last = data[-1]
    if not (isinstance(last, list) and len(last) == 1 and isinstance(last[0], str)):
        return data, None
    if len(data) >= 2 and data[-2] == []:
        return data[:-2], last[0]
    if "://" not in last[0]:
        logger.debug(
            f"Trailing row without '://' and no resumeKey separator, "
            f"not treated as a resumeKey: {last[0]!r}"
        )
    return data, None


def _strip_header(data: list) -> list:
    if data and isinstance(data[0], list) and data[0]:
        if data[0][0] in ("urlkey", "original"):
            return data[1:]
    return data


def _cdx_get(
    session: requests.Session,
    api_url: str,
    params: dict,
    headers: dict,
    timeout: int,
    stop: threading.Event | None,
) -> requests.Response:
    """GET once through the shared limiter and return the first non-429 response.

    After an HTTP 429, pauses every CDX request (in all threads) through the
    limiter and sends again. Raises CDXAPIError when 429s continue after the
    last pause in CDX_429_PAUSES, or when Retry-After asks for longer than
    that pause. Raises _FetchCancelled once `stop` is set.
    """
    rate_limited = 0
    while True:
        _CDX_LIMITER.wait(stop)
        if stop is not None and stop.is_set():
            raise _FetchCancelled
        response = session.get(api_url, params=params, headers=headers, timeout=timeout)
        if stop is not None and stop.is_set():
            raise _FetchCancelled
        if response.status_code != 429:
            return response

        rate_limited += 1
        raw = response.headers.get("Retry-After")
        retry_after: float | None = None
        if raw is None:
            shown = "none"
        else:
            try:
                retry_after = Retry().parse_retry_after(raw)
                shown = raw
            except InvalidHeader:
                shown = f"{raw!r}, ignored as invalid"
        if rate_limited > len(CDX_429_PAUSES):
            pauses = ", ".join(f"{p:g}" for p in CDX_429_PAUSES)
            raise CDXAPIError(
                f"CDX API kept returning HTTP 429 after pausing {pauses} s "
                f"(Retry-After: {shown}). Wait several minutes before re-running; "
                "re-running at once counts against the rate limit again."
            )
        longest = CDX_429_PAUSES[-1]
        if retry_after is not None and retry_after > longest:
            raise CDXAPIError(
                f"CDX API returned HTTP 429 with Retry-After: {raw} "
                f"({retry_after:g} s), longer than the {longest:g} s this tool "
                "waits. Re-run after that time."
            )
        delay = max(CDX_429_PAUSES[rate_limited - 1], retry_after or 0.0)
        logger.warning(
            f"CDX API rate limit (HTTP 429, {rate_limited}/{len(CDX_429_PAUSES)}); "
            f"pausing all CDX requests for {delay:g} s (Retry-After: {shown})"
        )
        _CDX_LIMITER.pause(delay)


def _server_error_response(error: Exception) -> requests.Response | None:
    """Return the response of an HTTPError whose status is in CDX_5XX_STATUSES."""
    if not isinstance(error, requests.exceptions.HTTPError):
        return None
    response = error.response
    if response is None or response.status_code not in CDX_5XX_STATUSES:
        return None
    return response


def _wait_after_5xx(
    response: requests.Response,
    attempt: int,
    stop: threading.Event | None,
    *,
    pause_after_last: bool = True,
) -> None:
    """Wait before resending after the 5xx `response` to request `attempt` (0-based).

    Raises CDXAPIError when Retry-After asks for longer than the last 429
    pause, even after the last attempt. Otherwise a valid nonzero Retry-After
    pauses every CDX request through the limiter; after the last attempt
    only if `pause_after_last` (other workers keep sending until the run
    stops). Before the last attempt, this worker also waits
    CDX_5XX_WAITS[attempt]; the longer of the two decides when it resends.
    After the last attempt, returns without waiting.
    """
    last = attempt >= len(CDX_5XX_WAITS)
    raw = response.headers.get("Retry-After")
    retry_after: float | None = None
    if raw is not None:
        try:
            retry_after = Retry().parse_retry_after(raw) or None
        except InvalidHeader:
            pass
    status = response.status_code
    longest = CDX_429_PAUSES[-1]
    if retry_after is not None and retry_after > longest:
        raise CDXAPIError(
            f"CDX API returned HTTP {status} with Retry-After: {raw} "
            f"({retry_after:g} s), longer than the {longest:g} s this tool "
            "waits. Re-run after that time."
        )
    if retry_after is not None and (pause_after_last or not last):
        logger.warning(
            f"CDX API returned HTTP {status} with Retry-After: {raw}; "
            f"pausing all CDX requests for {retry_after:g} s"
        )
        _CDX_LIMITER.pause(retry_after)
    if not last:
        _pause(CDX_5XX_WAITS[attempt], stop)


def _json_body_problem(response: requests.Response) -> str | None:
    """Describe why `response` has no usable JSON body, or return None."""
    if (
        len(response.content) == 0
        or not response.text.strip()
        or "application/json" not in response.headers.get("Content-Type", "")
    ):
        return "Non-JSON or empty response"
    return None


def _parse_num_pages(response: requests.Response) -> int | None:
    """Return the page count in a showNumPages body, or None if it is not a number.

    The server returns a bare number (plain text or JSON int).
    """
    try:
        return int(response.text.strip())
    except ValueError:
        pass
    try:
        data = response.json()
    except ValueError:
        return None
    return int(data) if isinstance(data, int) else None


def _num_pages_body_problem(response: requests.Response) -> str | None:
    """Describe why `response` carries no page count, or return None."""
    if _parse_num_pages(response) is None:
        return "non-numeric response"
    return None


def _get_with_retries(
    session: requests.Session,
    api_url: str,
    params: dict,
    headers: dict,
    timeout: int = 60,
    stop: threading.Event | None = None,
    *,
    return_400: bool = False,
    body_problem: Callable[[requests.Response], str | None] = _json_body_problem,
    label: str | None = None,
    pause_after_last_5xx: bool = True,
) -> requests.Response:
    """GET with retries for transport errors, HTTP errors and unusable 200 bodies.

    Makes at most 3 attempts; within one, _cdx_get() may resend after HTTP
    429. HTTP 500/502/503/504 wait as in
    _wait_after_5xx(); other errors wait 1 s and 2 s. HTTP 429 is handled by
    _cdx_get(). Once `stop` is set, raises
    _FetchCancelled instead of sending, retrying or logging. A request
    already in progress is not interrupted.

    `return_400` returns an HTTP 400 response at once instead of retrying.
    `body_problem` judges a 200 body (by default it must be JSON). `label`
    names the request in the warnings and the final error.
    `pause_after_last_5xx` is passed to _wait_after_5xx() as
    `pause_after_last`.
    """
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            response = _cdx_get(session, api_url, params, headers, timeout, stop)
            # Judged on this attempt's response, before raise_for_status().
            if return_400 and response.status_code == 400:
                return response
            response.raise_for_status()
            problem = body_problem(response)
            if problem is None:
                return response
            detail = (
                f"status={response.status_code}, "
                f"Content-Type={response.headers.get('Content-Type', '')}, "
                f"content-length={len(response.content)}"
            )
            if label is None:
                logger.warning(f"{problem} (attempt {attempt + 1}/3): {detail}")
            else:
                logger.warning(
                    f"{label} request error (attempt {attempt + 1}/3): "
                    f"{problem}: {detail}"
                )
            if attempt < 2:
                _pause(2**attempt, stop)
                continue
            if label is None:
                raise CDXAPIError(f"{problem} (max retries reached)")
            raise CDXAPIError(
                f"{label} request failed (max retries reached): {problem}: {detail}"
            )
        except CDXAPIError:
            raise
        except requests.exceptions.RequestException as e:
            if stop is not None and stop.is_set():
                raise _FetchCancelled from e
            last_error = e
            prefix = "Request error" if label is None else f"{label} request error"
            logger.warning(f"{prefix} (attempt {attempt + 1}/3): {e}")
            server_error = _server_error_response(e)
            if server_error is not None:
                _wait_after_5xx(
                    server_error, attempt, stop, pause_after_last=pause_after_last_5xx
                )
                continue
            if attempt < 2:
                _pause(2**attempt, stop)
                continue
    if label is None:
        message = f"CDX API fetch error (max retries reached): {last_error}"
    else:
        message = f"{label} request failed (max retries reached): {last_error}"
    raise CDXAPIError(message) from last_error


def get_num_pages(
    target_url: str,
    page_size: int | None,
    collapse: str | None,
    session: requests.Session,
    headers: dict,
) -> int | None:
    """Ask the CDX server for the page count. Returns None on HTTP 400.

    Sends the same pageSize/collapse as the paged queries: the page count
    is only valid against the same query shape that will fetch the pages
    (the CDX contract pairs the two; a mismatched pageSize would silently
    truncate the fetch at the tail).

    Only HTTP 400 means "pagination unsupported" (the CDX server answers
    showNumPages and page=N with the same 400 when it has no paging index).
    Other errors and non-numeric bodies are retried as in
    _get_with_retries() and then raise CDXAPIError. No pause follows a
    Retry-After on the last 5xx, since no request follows it.
    """
    api_url = "https://web.archive.org/cdx/search/cdx"
    params: dict[str, Any] = {
        "url": target_url,
        "filter": CDX_FILTER,
        "showNumPages": "true",
    }
    if page_size is not None:
        params["pageSize"] = page_size
    if collapse:
        params["collapse"] = collapse
    # Runs in the main thread without `stop`, where Ctrl+C interrupts the waits.
    response = _get_with_retries(
        session,
        api_url,
        params,
        headers,
        return_400=True,
        body_problem=_num_pages_body_problem,
        label="showNumPages",
        pause_after_last_5xx=False,
    )
    if response.status_code == 400:
        logger.info(
            "showNumPages returned HTTP 400 (pagination unsupported), "
            "falling back to resumeKey mode"
        )
        return None
    # Never None here: _num_pages_body_problem() accepted the body.
    return _parse_num_pages(response)


def _cdx_params(
    target_url: str,
    *,
    page: int | None = None,
    page_size: int | None = None,
    resume_key: str | None = None,
    limit: int | None = None,
    collapse: str | None = None,
) -> dict[str, Any]:
    """CDX request parameters shared by both fetch paths.

    `collapse` carries the run's collapse mode: `urlkey` for lenient,
    `original` for strict. Callers may pass None to omit the parameter.
    """
    params: dict[str, Any] = {
        "url": target_url,
        "output": "json",
        "filter": CDX_FILTER,
        "fl": CDX_FL,
        "showResumeKey": "true",
    }
    if page is not None:
        params["page"] = page
    if page_size is not None:
        params["pageSize"] = page_size
    # Omit `limit` when unset so the CDX server applies its own default.
    if limit is not None:
        params["limit"] = limit
    if collapse:
        params["collapse"] = collapse
    if resume_key:
        params["resumeKey"] = resume_key
    return params


def fetch_page_rows(
    target_url: str,
    page: int,
    page_size: int | None,
    collapse: str | None,
    session: requests.Session,
    headers: dict,
    stop: threading.Event | None = None,
) -> list[list]:
    """Fetch one page (following in-page resumeKey chaining). Returns data rows.

    `stop` is passed to _get_with_retries(): once it is set, the fetch
    raises _FetchCancelled instead of sending further requests.

    NOTE: `limit` is intentionally NOT sent here. In pagination mode the
    server defines page boundaries, so `limit` would only truncate each page
    (extra round-trips at best, lost data at worst). If a single page exceeds
    the server-side per-response maximum, the response carries a resumeKey
    which is followed below ("in-page" chaining). A complete page carries no
    resumeKey, so the normal case costs nothing.
    """
    api_url = "https://web.archive.org/cdx/search/cdx"
    params = _cdx_params(target_url, page=page, page_size=page_size, collapse=collapse)

    rows: list[list] = []
    resume_key: str | None = None
    seen_keys: set[str] = set()
    # No hard cap on chaining: safety rests on the cycle detection below
    # (a repeated resumeKey breaks the loop) and on terminating when a
    # response carries no resumeKey.
    while True:
        if resume_key:
            if resume_key in seen_keys:
                logger.warning(f"resumeKey cycle detected within page {page}, stopping")
                break
            seen_keys.add(resume_key)
            params["resumeKey"] = resume_key
        response = _get_with_retries(session, api_url, params, headers, stop=stop)
        data = response.json()
        if not isinstance(data, list):
            raise CDXAPIError(
                f"CDX API returned unexpected type: {type(data).__name__}"
            )
        data, new_key = _split_resume_key(data)
        data = [row for row in data if row != []]
        data = _strip_header(data)
        rows.extend([r for r in data if isinstance(r, list) and r])
        if new_key:
            resume_key = new_key
        else:
            break
    return rows


def fetch_resumekey_rows(
    target_url: str,
    initial_resume_key: str | None,
    limit: int | None,
    collapse: str | None,
    session: requests.Session,
    headers: dict,
) -> Generator[list, None, None]:
    """Sequential resumeKey fetch (fallback path). Yields data rows.

    Ends normally only when a response carries no resumeKey. If the server
    repeats a resumeKey, raises CDXAPIError so that the caller does not
    mark the partial result as complete. A failed request raises
    ResumeKeyRequestError, which carries the key to resume from.
    """
    api_url = "https://web.archive.org/cdx/search/cdx"
    params = _cdx_params(target_url, limit=limit, collapse=collapse)
    resume_key = initial_resume_key
    seen_request_keys: set[str] = set()
    seen_response_keys: set[str] = set()
    if initial_resume_key:
        logger.info(f"Resuming from resumeKey: {initial_resume_key}")

    while True:
        if resume_key:
            if resume_key in seen_request_keys:
                raise CDXAPIError(
                    f"resumeKey cycle detected (request side): {resume_key}. "
                    "The fetch was aborted; retry later with --refresh."
                )
            seen_request_keys.add(resume_key)
            params["resumeKey"] = resume_key

        try:
            response = _get_with_retries(session, api_url, params, headers, timeout=60)
            data = response.json()
        except CDXAPIError as e:
            raise ResumeKeyRequestError(f"CDX API fetch error: {e}", resume_key) from e

        if not isinstance(data, list):
            raise CDXAPIError(
                f"CDX API returned unexpected type: {type(data).__name__}"
            )

        data, new_key = _split_resume_key(data)
        data = [row for row in data if row != []]
        if new_key and new_key in seen_response_keys:
            raise CDXAPIError(
                f"Previously seen resumeKey returned again: {new_key}. "
                "The fetch was aborted; retry later with --refresh."
            )
        if new_key:
            seen_response_keys.add(new_key)
        data = _strip_header(data)

        valid = [r for r in data if isinstance(r, list) and r]
        yield from valid
        if not new_key:
            return
        # A chunk may carry a resumeKey but no data rows; keep following it
        # (the cycle checks above stop a server that never advances).
        resume_key = new_key


def _rows_to_keys(rows: Iterable[list], key_opts: dict[str, Any] | None) -> list[str]:
    """Convert CDX data rows (fl=original) into surt keys.

    Original spellings are intentionally not returned (and not stored):
    the key set is the only thing the scan needs, and --output-archived
    reports the matched local input lines instead.
    """
    out: list[str] = []
    for row in rows:
        if not isinstance(row, list) or not row:
            continue
        original = row[0]
        if isinstance(original, str) and original and original.strip():
            key = _try_normalize_key(original, key_opts, _CDX_ROW_CONTEXT)
            if key is not None:
                out.append(key)
    return out


def _fetch_pages_parallel(
    target_url: str,
    pages: list[int],
    page_size: int | None,
    key_opts: dict[str, Any] | None,
    workers: int,
    headers: dict,
    collapse: str | None,
) -> Generator[tuple[int, list[str]], None, None]:
    """Fetch pages concurrently; yields (page, surt_keys) as they complete.

    At most twice the worker count is submitted at a time; consumed page
    results are released before more pages are yielded.
    Pages completed in the same wait are yielded in page order. If one of
    them failed, the workers are stopped before the successful ones are
    yielded, and the failure is raised after them. When the
    generator exits early (failed page, close(), Ctrl+C), queued pages are
    cancelled and the workers are told to stop; requests already in
    progress are not interrupted.
    """
    thread_state = threading.local()
    stop = threading.Event()

    def _get_session() -> requests.Session:
        sess = getattr(thread_state, "session", None)
        if sess is None:
            sess = make_session()
            thread_state.session = sess
        return sess

    def _work(page: int) -> tuple[int, list[str]]:
        sess = _get_session()
        rows = fetch_page_rows(
            target_url, page, page_size, collapse, sess, headers, stop=stop
        )
        return page, _rows_to_keys(rows, key_opts)

    workers = max(1, workers)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    remaining = iter(pages)
    pending: dict[concurrent.futures.Future[tuple[int, list[str]]], int] = {}
    try:
        while True:
            while len(pending) < workers * 2:
                page = next(remaining, None)
                if page is None:
                    break
                pending[ex.submit(_work, page)] = page
            if not pending:
                break
            # A timed wait, so Ctrl+C is noticed on Windows (see
            # FETCH_POLL_INTERVAL).
            done, _ = concurrent.futures.wait(
                pending,
                timeout=FETCH_POLL_INTERVAL,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            ordered = sorted(done, key=lambda f: pending[f], reverse=True)
            del done
            errors = [
                exc for f in reversed(ordered) if (exc := f.exception()) is not None
            ]
            if errors:
                # Stop before yielding the successful pages of this wait, so
                # workers do not fetch more pages while the consumer stores
                # them. Cancel first, as below.
                ex.shutdown(wait=False, cancel_futures=True)
                stop.set()
            while ordered:
                fut = ordered.pop()
                del pending[fut]
                if fut.exception() is None:
                    result = fut.result()
                    del fut
                    yield result
                    del result
                else:
                    del fut
            if errors:
                raise errors[0]
    except BaseException:
        # Includes GeneratorExit (close() or the consumer leaving its loop)
        # and KeyboardInterrupt. Cancel first, so that a worker woken by
        # `stop` does not pick up another queued page. `stop` is set only
        # after the cancel, so a set `stop` means both are already done.
        if not stop.is_set():
            ex.shutdown(wait=False, cancel_futures=True)
            stop.set()
        raise
    ex.shutdown()


def _store_resumekey_rows(
    conn: sqlite3.Connection,
    rows: Iterable[list],
    key_opts: dict[str, Any] | None,
) -> int:
    """Insert keys for rows from fetch_resumekey_rows(). Returns rows inserted.

    Pending keys are flushed on every exit, including a failed request or
    Ctrl+C. The rows before the failed request were already fetched, so
    dropping them would leave a gap that resuming from the failed request's
    resumeKey cannot fill. The request error propagates only after the flush
    succeeds, so the CLI can safely choose an appropriate recovery hint.
    """
    inserted = 0
    batch: list[str] = []
    with tqdm(desc="Fetching (resumeKey)", unit="rec") as bar:
        try:
            try:
                for row in rows:
                    if not isinstance(row, list) or not row:
                        continue
                    if isinstance(row[0], str) and row[0] and row[0].strip():
                        key = _try_normalize_key(row[0], key_opts, _CDX_ROW_CONTEXT)
                        if key is not None:
                            batch.append(key)
                    if len(batch) >= INSERT_CHUNK_SIZE:
                        insert_urls(conn, batch)
                        inserted += len(batch)
                        bar.update(len(batch))
                        batch.clear()
            finally:
                if batch:
                    insert_urls(conn, batch)
                    inserted += len(batch)
                    bar.update(len(batch))
        except CDXAPIError as error:
            if isinstance(error, ResumeKeyRequestError) and error.resume_key:
                # The finally block above has saved all rows before this request.
                # If either the flush or this write fails, no resume hint escapes.
                write_meta(conn, {"resume_key": error.resume_key})
            logger.error(f"Fetched rows stored ({inserted} records).")
            raise
    return inserted


def ensure_archived_db(
    target_url: str,
    cache_file: str,
    key_opts: dict[str, Any] | None = None,
    initial_resume_key: str | None = None,
    limit: int | None = None,
    page_size: int | None = None,
    workers: int = DEFAULT_WORKERS,
    refresh: bool = False,
) -> str:
    """Build (or reuse/resume) the SQLite archived-URL cache. Returns db path.

    Lenient mode (empty key_opts == surt defaults) adds collapse=urlkey to
    the CDX queries; strict mode (any non-default flags) adds
    collapse=original, which only folds repeated captures of identical
    original spellings. The key profile is part of the cache identity.
    """
    headers = {"User-Agent": USER_AGENT}
    collapse = CDX_COLLAPSE if not key_opts else CDX_COLLAPSE_STRICT
    logger.info(f"URL key profile: {key_profile(key_opts or {})}")

    if refresh and initial_resume_key is None and os.path.exists(cache_file):
        logger.info(f"Removing existing cache (--refresh): {cache_file}")
        os.remove(cache_file)

    # --resume-key only continues an interrupted resumeKey fetch. Check this
    # before open_db(), which would create an empty cache file.
    if initial_resume_key is not None and not os.path.exists(cache_file):
        raise CacheError(
            f"--resume-key needs the cache of the interrupted fetch, "
            f"but {cache_file} does not exist"
        )

    expected = expected_meta(target_url, key_opts or {}, page_size)
    conn = open_db(cache_file)
    try:
        meta = read_meta(conn)
        columns_ok = archived_columns(conn) == {"key"}
        params_match = columns_ok and all(meta.get(k) == v for k, v in expected.items())

        if initial_resume_key is not None:
            # Reject before the stale-cache rebuild below deletes the file.
            if not params_match:
                raise CacheError(
                    f"--resume-key needs a cache built with the same target URL "
                    f"and options, but {cache_file} was built with other settings"
                )
            if is_completed(conn):
                raise CacheError(
                    f"{cache_file} is already complete; run without --resume-key "
                    "to reuse it, or with --refresh to rebuild it"
                )
            if meta.get("mode") == "pagination":
                raise CacheError(
                    f"{cache_file} was built in pagination mode, which resumes "
                    "automatically; run without --resume-key"
                )

            if meta.get("resumekey_v") != RESUMEKEY_FETCH_VERSION or not meta.get(
                "resume_key"
            ):
                raise CacheError(
                    f"{cache_file} has no verified saved resume key; "
                    "run without --resume-key to fetch from the beginning"
                )
            if initial_resume_key != meta["resume_key"]:
                raise CacheError(
                    f"--resume-key does not match the saved resume key in {cache_file}; "
                    "use the key logged for this cache or run without --resume-key "
                    "to fetch from the beginning"
                )

        if initial_resume_key is None and params_match and is_completed(conn):
            if (
                meta.get("mode") == "resumekey"
                and meta.get("resumekey_v") != RESUMEKEY_FETCH_VERSION
            ):
                # Completed by an earlier version, which could mark an
                # incomplete resumeKey fetch as completed.
                logger.warning(
                    f"{cache_file} was completed by an earlier version in "
                    "resumeKey mode and may be missing rows; fetching again"
                )
                set_completed(conn, False)
            else:
                try:
                    built_at = datetime.fromisoformat(meta.get("built_at", ""))
                    if built_at.utcoffset() is None:
                        built_at = None
                except (TypeError, ValueError):
                    built_at = None
                build_time = (
                    built_at.astimezone(UTC).isoformat()
                    if built_at is not None
                    else "unknown"
                )
                refresh_hint = (
                    " Use --refresh to fetch newer archives."
                    if built_at is None
                    or datetime.now(UTC) - built_at >= CACHE_AGE_WARNING
                    else ""
                )
                logger.info(
                    f"Reusing completed cache: {cache_file} "
                    f"({count_archived(conn)} URLs; built at: {build_time})."
                    f"{refresh_hint}"
                )
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

        # ResumeKey manual-resume path takes precedence when explicitly requested.
        if initial_resume_key is not None:
            logger.info(f"Fetching data from CDX API (resumeKey mode): {target_url}")
            session = make_session()
            gen = fetch_resumekey_rows(
                target_url, initial_resume_key, limit, collapse, session, headers
            )
            inserted = _store_resumekey_rows(conn, gen, key_opts)
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
            # Record the mode before fetching, so an interrupted run can be
            # told apart from a pagination cache when --resume-key is used.
            # resumekey_v marks a fetch that started from the beginning with
            # this version; a --resume-key run keeps the cache's marker as is.
            # A previous checkpoint cannot verify progress in this new fetch.
            conn.execute("DELETE FROM meta WHERE k='resume_key';")
            write_meta(
                conn,
                {
                    "mode": "resumekey",
                    "num_pages": "0",
                    "resumekey_v": RESUMEKEY_FETCH_VERSION,
                },
            )
            gen = fetch_resumekey_rows(
                target_url, None, limit, collapse, session, headers
            )
            inserted = _store_resumekey_rows(conn, gen, key_opts)
            set_completed(conn, True)
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            logger.info(f"All chunks fetched successfully ({inserted} records total)")
            return cache_file

        done = get_done_pages(conn)
        pending = [p for p in range(num_pages) if p not in done]
        logger.info(
            f"Fetching data from CDX API: {target_url} ({num_pages} pages, {len(pending)} pending)"
        )
        write_meta(conn, {"mode": "pagination", "num_pages": str(num_pages)})
        archived_count = count_archived(conn)
        with tqdm(total=len(pending), desc="Fetching pages", unit="page") as bar:
            for page, keys in _fetch_pages_parallel(
                target_url,
                pending,
                page_size,
                key_opts,
                workers,
                headers,
                collapse,
            ):
                if keys:
                    changes_before = conn.total_changes
                    insert_urls(conn, keys)
                    archived_count += conn.total_changes - changes_before
                mark_page_done(conn, page)
                bar.update(1)
                bar.set_postfix(records=archived_count)
        set_completed(conn, True)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        logger.info(
            f"All pages fetched successfully ({count_archived(conn)} unique URLs)"
        )
        return cache_file
    except sqlite3.Error as error:
        raise _cache_error(cache_file, error) from error
    finally:
        conn.close()


def extract_archived_urls(
    cdx_data: Iterable[object] | None,
    key_opts: dict[str, Any] | None = None,
) -> set[str]:
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
    if not isinstance(cdx_data, Iterable):
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
            if "original" in lowered:
                col_idx = next(
                    i
                    for i, c in enumerate(row)
                    if isinstance(c, str) and c.lower() == "original"
                )
                continue  # skip the header row itself
            if any(h in lowered for h in ("urlkey", "url", "timestamp")):
                col_idx = 0
                continue  # header without an 'original' column; data starts at index 0
            # No recognizable header: treat this row as data (fall through).

        if col_idx >= len(row):
            continue
        original_url = row[col_idx]

        # Ensure the URL value is a string
        if isinstance(original_url, str) and original_url and original_url.strip():
            key = _try_normalize_key(original_url, key_opts, _CDX_ROW_CONTEXT)
            if key is not None:
                archived_keys.add(key)

    return archived_keys


# ========================================
# Main logic
# ========================================
def detect_not_archived(
    input_file: str,
    archived_keys: set[str],
    key_opts: dict[str, Any] | None = None,
    collect_archived: bool = False,
) -> tuple[list[str], list[str] | None, int]:
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

    with open(input_file, encoding="utf-8-sig") as f:
        for line_no, line in enumerate(f, start=1):
            original_url = line.strip()

            if not original_url:
                continue

            total_count += 1

            key = _try_normalize_key(original_url, key_opts, _input_context(line_no))

            if key is None or key not in archived_keys:
                not_archived.append(original_url)
            elif archived is not None:
                archived.append(original_url)

    return not_archived, archived, total_count


def count_input_lines(input_file: str) -> int | None:
    """Fast line count for progress bars. Returns None on failure."""
    try:
        count = 0
        with open(input_file, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                count += chunk.count(b"\n")
        return count
    except OSError:
        return None


def scan_input_against_db(
    input_file: str,
    db_path: str,
    key_opts: dict[str, Any] | None = None,
    output_file: str | None = None,
    output_archived: str | None = None,
    batch_size: int = LOOKUP_BATCH_SIZE,
) -> tuple[int, int, int]:
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
                out_f = open(output_file, "w", encoding="utf-8")
            if output_archived:
                Path(output_archived).parent.mkdir(parents=True, exist_ok=True)
                arch_f = open(output_archived, "w", encoding="utf-8")

            total_count = 0
            not_count = 0
            arch_count = 0
            # (original line, surt key); the key is None for an unparsable URL,
            # which is reported as unarchived.
            batch: list[tuple[str, str | None]] = []

            def _flush() -> None:
                nonlocal not_count, arch_count
                if not batch:
                    return
                key_list = [k for _, k in batch if k is not None]
                found = batch_lookup_found(conn, key_list)
                for original, key in batch:
                    if key is not None and key in found:
                        arch_count += 1
                        if arch_f is not None:
                            arch_f.write(original + "\n")
                    else:
                        not_count += 1
                        if out_f is not None:
                            out_f.write(original + "\n")
                batch.clear()

            with open(input_file, encoding="utf-8-sig") as f:
                with tqdm(total=total_lines, desc="Checking URLs", unit="url") as bar:
                    for line_no, line in enumerate(f, start=1):
                        original_url = line.strip()
                        if not original_url:
                            continue
                        total_count += 1
                        key = _try_normalize_key(
                            original_url, key_opts, _input_context(line_no)
                        )
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
        description="Wayback Gap Detector - Find URLs that have not been archived",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python waygap.py "https://example.com/blog/*"
  python waygap.py "https://example.com/blog/*" --no-ignore-www --output result.txt
        """,
    )

    parser.add_argument(
        "target_url",
        help="Wildcard URL to search in the CDX API (e.g. https://example.com/path/*)",
    )

    parser.add_argument(
        "--ignore-protocol",
        dest="ignore_protocol",
        action="store_true",
        default=IGNORE_PROTOCOL,
        help="treat http and https as equivalent (default: enabled)",
    )
    parser.add_argument(
        "--no-ignore-protocol",
        dest="ignore_protocol",
        action="store_false",
        help="distinguish between http and https",
    )
    parser.add_argument(
        "--ignore-www",
        dest="ignore_www",
        action="store_true",
        default=IGNORE_WWW,
        help="treat www.example.com / www2.example.com etc. as equivalent "
        "(default: enabled, matches CDX urlkey normalization)",
    )
    parser.add_argument(
        "--no-ignore-www",
        dest="ignore_www",
        action="store_false",
        help="distinguish www.example.com and example.com (strict key matching)",
    )

    parser.add_argument(
        "--input",
        dest="input_file",
        default=TARGET_URL_FILE,
        help=f"path to the input URL file (default: {TARGET_URL_FILE})",
    )

    parser.add_argument(
        "--output",
        dest="output_file",
        default=OUTPUT_FILE,
        help=f"path to the output file (default: {OUTPUT_FILE})",
    )

    parser.add_argument(
        "--cache",
        dest="cache_file",
        default=CACHE_FILE,
        help=f"path to the CDX cache file (default: {CACHE_FILE})",
    )
    parser.add_argument(
        "--refresh",
        dest="refresh",
        action="store_true",
        default=False,
        help="ignore and rebuild the existing cache file",
    )
    parser.add_argument(
        "--no-cache",
        dest="no_cache",
        action="store_true",
        default=False,
        help="do not reuse or keep the cache (uses a temporary database)",
    )

    parser.add_argument(
        "--output-archived",
        dest="output_archived",
        nargs="?",
        const=ARCHIVED_FILE,
        default=None,
        help=f"path to write archived URLs to (default: {ARCHIVED_FILE})",
    )

    parser.add_argument(
        "--resume-key",
        dest="resume_key",
        default=None,
        help="resumeKey to resume an interrupted fetch (use the key logged at failure time)",
    )

    parser.add_argument(
        "--limit",
        dest="limit",
        type=int,
        default=None,
        help="chunk size per request for resumeKey sequential fetch only "
        "(pagination mode ignores it; default: server default)",
    )
    parser.add_argument(
        "--page-size",
        dest="page_size",
        type=int,
        default=None,
        help="CDX pagination page size (default: server default)",
    )
    parser.add_argument(
        "--workers",
        dest="workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"parallel page fetch workers (default: {DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "--batch-size",
        dest="batch_size",
        type=int,
        default=LOOKUP_BATCH_SIZE,
        help=f"URL lookup batch size for DB scan (default: {LOOKUP_BATCH_SIZE})",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="show the program's version number and exit",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable verbose (DEBUG-level) logging",
    )

    args = parser.parse_args()
    if args.resume_key is not None and (args.no_cache or args.refresh):
        parser.error("--resume-key cannot be combined with --no-cache or --refresh")

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    cache_file = args.cache_file
    temp_db: str | None = None
    try:
        try:
            with open(args.input_file, encoding="utf-8") as input_file:
                while input_file.read(1024 * 1024):
                    pass
        except FileNotFoundError as e:
            raise InputFileError(f"Input file not found: {args.input_file}") from e
        except UnicodeDecodeError as e:
            raise InputFileError(
                f"Input file is not valid UTF-8: {args.input_file}. Save it as UTF-8 and try again."
            ) from e
        except OSError as e:
            raise InputFileError(
                f"Cannot read input file: {args.input_file}: {e}"
            ) from e

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
            logger.info(
                f"Archived URLs written to {args.output_archived}: {arch_count} entries"
            )

        return 0

    except CDXAPIError as e:
        logger.error(f"{e}")
        if isinstance(e, ResumeKeyRequestError):
            if temp_db is not None:
                logger.error(
                    "Re-run the same command to start from the beginning. "
                    "Omit --no-cache on future runs to retain progress."
                )
            elif e.resume_key:
                logger.error(
                    f"Failed at resumeKey={e.resume_key}. "
                    "To resume, remove --refresh if present and add:"
                )
                logger.error(f"  --resume-key {e.resume_key}")
            else:
                logger.error("Re-run the same command to start from the beginning.")
        return 1
    except InputFileError as e:
        logger.error(f"{e}")
        return 1
    except sqlite3.Error as e:
        logger.error(f"{_cache_error(cache_file, e)}")
        return 1
    except CacheError as e:
        logger.error(f"{e}")
        return 1
    except KeyboardInterrupt:
        if temp_db is not None:
            logger.error(
                "Interrupted. Re-run the same command to start from the beginning. "
                "Omit --no-cache on future runs to retain progress."
            )
        elif args.refresh:
            # Re-running with --refresh would delete the retained cache.
            logger.error(
                "Interrupted. Remove --refresh and re-run the command to resume."
            )
        else:
            logger.error("Interrupted. Re-run the same command to resume.")
        return 130
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=args.verbose)
        return 1
    finally:
        if temp_db is not None and os.path.exists(temp_db):
            try:
                os.remove(temp_db)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
