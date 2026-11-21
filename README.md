# Wayback Gap Detector

A command-line tool that compares a local list of URLs against the [Wayback Machine](https://web.archive.org/) CDX API to identify URLs that have **not** been archived.

---

## Features

- Fetches archived URL data from the Wayback Machine CDX API with pagination (`page=`) in parallel, falling back to `resumeKey` when pagination is unavailable
- Caches URL keys in a local SQLite file (single `.db`) and checks them against the run settings on startup; caches built with different settings or an incompatible layout are rebuilt automatically — no manual deletion needed
- Streams the input list against the database in batches, so tens of millions of URLs never accumulate in RAM
- Normalizes both the CDX responses and the local URL list into the same [surt](https://github.com/internetarchive/surt) keys — absorbing spelling differences such as scheme, `www.`, query order, percent-encoding, and IDN
- Outputs a plain-text file of unarchived URLs
- Optionally outputs a separate file of archived URLs (the matched local input lines)
- Resumes interrupted fetches (pagination mode records completed pages and resumes automatically; the `resumeKey` fallback uses `--resume-key`)

---

## Requirements

- Python 3.11+ (tested on 3.11 and 3.15)
- See [requirements.txt](requirements.txt) for library dependencies

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/nabikita3974/wayback-gap-detector.git
cd wayback-gap-detector

# 2. Create and activate a virtual environment (recommended)
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Usage

```
python waygap.py TARGET_URL [OPTIONS]
```

`TARGET_URL` is a wildcard URL passed to the CDX API (e.g. `https://example.com/blog/*`).

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--ignore-protocol` | enabled | Treat `http` and `https` as equivalent (keys are scheme-less by default) |
| `--no-ignore-protocol` | — | Distinguish `http` from `https` (fetches every variant; slower) |
| `--ignore-www` | enabled | Treat `www.example.com` / `www2.example.com` etc. as equivalent (leading `www`/`wwwN.` removed) |
| `--no-ignore-www` | — | Distinguish `www.example.com` from `example.com` (fetches every variant; slower) |
| `--input FILE` | `urls.txt` | Path to the local URL list file |
| `--output FILE` | `not_archived.txt` | Output file for unarchived URLs |
| `--cache FILE` | `archived_cdx.db` | Cache file for CDX results (SQLite) |
| `--refresh` | — | Ignore and rebuild the existing cache |
| `--no-cache` | — | Use a temporary database (do not reuse or keep) |
| `--page-size N` | *(server default)* | CDX pagination page size (on web.archive.org the default is 1 zipnum block per page) |
| `--workers N` | `2` | Parallel page fetch workers (requests are capped at one every 3 s across all workers) |
| `--batch-size N` | `500` | URL lookup batch size for DB scan |
| `--output-archived [FILE]` | `archived.txt` | Also write archived URLs (the matched local input lines) to a file |
| `--resume-key KEY` | *(none)* | Resume an interrupted `resumeKey` fallback fetch (pagination mode resumes automatically) |
| `--limit N` | *(server default)* | Chunk size per request for `resumeKey` sequential fetch only (pagination mode ignores it) |
| `--version` | — | Show the program version and exit |
| `-v`, `--verbose` | — | Enable DEBUG-level logging |

---

## Examples

### Basic usage

Fetch all CDX records for `https://example.com/blog/*` and write URLs not found in the archive to `not_archived.txt`:

```bash
python waygap.py "https://example.com/blog/*" --input urls.txt
```

### Custom cache and output files

```bash
python waygap.py "https://example.com/blog/*" \
  --input urls.txt \
  --cache my_cache.db \
  --output missing.txt
```

You can also add `--output-archived archived.txt` to write the archived URLs to a separate file.

### Resume an interrupted fetch

Pagination mode (the default) resumes automatically: completed pages are
recorded in the cache database, so re-running the same command fetches only
the missing pages. No manual cleanup is needed; use `--refresh` only when you
want to rebuild the cache from scratch.

`--resume-key` is only needed for the `resumeKey` fallback path (used when the
server does not support pagination). If a fallback run fails mid-way, the tool
logs the `resumeKey` value — add it to your original command (without
`--refresh`) to continue:

```bash
python waygap.py "https://example.com/blog/*" \
  --input urls.txt \
  --cache my_cache.db \
  --limit 50000 \
  --resume-key "<RESUME_KEY>"
```

`--resume-key` only continues an interrupted fallback fetch in the same cache:
the cache file must exist, be incomplete, and have been built with the same
target URL and options. The key must match the checkpoint saved in that cache
when a request failed, after its preceding rows were stored. Keys from another
run and older caches without a verified checkpoint are rejected; omit
`--resume-key` to fetch again from the beginning while keeping stored URLs.
Otherwise the tool stops with an error without
deleting or overwriting the cache. It cannot be combined with `--no-cache` or
`--refresh`.

If the first fallback request fails before receiving a resume key, re-run the
same command to start from the beginning. With `--no-cache`, the temporary
database is deleted when the run ends, so re-running also starts from the
beginning. Omit `--no-cache` on future runs to retain progress.

---

## Input file format

`urls.txt` (or the file specified via `--input`) should contain one URL per line:

```
https://example.com/blog/post-1
https://example.com/blog/post-2
https://example.com/blog/post-3
```

Blank lines are ignored.

---

## How URLs are matched (surt keys)

Both the CDX responses and your local URL list are converted into **surt
keys** with an identical set of flags ([surt](https://github.com/internetarchive/surt)),
e.g. `https://www.example.com/blog/post-1/` becomes `com,example)/blog/post-1`.
With the default settings, a leading `www.` (or `www2.` etc.) is removed
from the host and a trailing slash is dropped, so those spellings share
one key.

**Lenient mode (default)** passes surt's own defaults, which are the same
canonicalization family that CDX uses for `urlkey`:

- `http`/`https` merged (keys are scheme-less)
- `www.example.com`, `www2.example.com` … have the leading `www`/`wwwN.`
  removed and share the key of `example.com`
- query params sorted alphabetically and lowercased
- percent-encodings decoded (`%7E` → `~`), IDN hosts punycoded (`xn--…`),
  fragments/userinfo stripped, default ports removed

**Strict mode** (`--no-ignore-www` and/or `--no-ignore-protocol`) keeps
those distinctions instead. When either flag is set, the CDX query uses
`collapse=original`, which folds repeated captures of the same original
spelling while keeping every distinct variant, and the same non-default
flags are applied to both the CDX rows and the local list. This is still
slower than lenient mode.
Example: with `--no-ignore-www`, `http://www.a.com/p` becomes
`com,a,www)/p` (by default it is `com,a)/p`).

`--output-archived` reports the matched **local input lines**. Cache files
built with different settings or an incompatible layout are detected and
rebuilt automatically, without user action.

---

## Development

This project uses [uv](https://docs.astral.sh/uv/). `uv sync` creates `.venv`
and installs all dependencies (and Python itself, if needed).

```bash
uv sync
uv run pytest                           # tests (no network access; API calls are mocked)
uv run ruff check .                     # lint
uv run ruff format --check .            # format check
uv run basedpyright                     # type check
```

CI runs the same checks. After changing dependencies with `uv add`, regenerate
`requirements.txt` with
`uv export --no-dev --no-hashes --no-emit-project -o requirements.txt`.
For the internal design, see [ARCHITECTURE.md](ARCHITECTURE.md). To skip
formatting commits in `git blame`, run
`git config blame.ignoreRevsFile .git-blame-ignore-revs`.

Issues and pull requests are welcome; please keep each PR to one logical change.

---

## License

This project is licensed under **AGPL-3.0-or-later**
([GNU Affero General Public License v3 or later](https://www.gnu.org/licenses/agpl-3.0.html)).

It depends on [surt](https://github.com/internetarchive/surt), which is
licensed under AGPL-3.0-or-later; distributing this tool together with
that dependency requires the combined work to carry the same license.
