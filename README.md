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

- Python 3.9+ (tested on 3.13)
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
| `--workers N` | `4` | Parallel page fetch workers |
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

### Collect archived URLs to a separate file

```bash
python waygap.py "https://example.com/blog/*" \
  --input urls.txt \
  --output not_archived.txt \
  --output-archived archived.txt
```

### Resume an interrupted fetch

Pagination mode (the default) resumes automatically: completed pages are
recorded in the cache database, so re-running the same command fetches only
the missing pages. No manual cleanup is needed; use `--refresh` only when you
want to rebuild the cache from scratch.

`--resume-key` is only needed for the `resumeKey` fallback path (used when the
server does not support pagination). If a fallback run fails mid-way, the tool
logs the `resumeKey` value — add it to your original command to continue:

```bash
# Example - Original command that failed:
python waygap.py "https://example.com/blog/*" \
  --input urls.txt \
  --cache my_cache.db \
  --limit 50000

# Add --resume-key to resume (KEY is printed in the error message):
python waygap.py "https://example.com/blog/*" \
  --input urls.txt \
  --cache my_cache.db \
  --limit 50000 \
  --resume-key "<RESUME_KEY>"
```

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

## Development setup

This project uses [uv](https://docs.astral.sh/uv/) for development. After installing uv, the following commands create a virtual environment (`.venv`) and install all dependencies. If the required Python version is not installed, uv downloads it automatically.

```bash
git clone https://github.com/nabikita3974/wayback-gap-detector.git
cd wayback-gap-detector
uv sync
```

Run commands with `uv run`; there is no need to activate the virtual environment:

```bash
uv run python waygap.py "https://example.com/blog/*" --input urls.txt
uv run python -m unittest discover -v
```

To add or update a dependency, use `uv add <package>`, then regenerate `requirements.txt`:

```bash
uv export --no-dev --no-hashes --no-emit-project -o requirements.txt
```

Lint and format the code with [Ruff](https://docs.astral.sh/ruff/):

```bash
uv run ruff check .      # lint (add --fix to apply safe fixes)
uv run ruff format .     # format
```

Type checking is performed with [basedpyright](https://docs.basedpyright.com/latest/):

```bash
uv run basedpyright .    # Type check
```

To prevent formatting commits from fragmenting `git blame`, this repository uses `.git-blame-ignore-revs`.

Enable it locally with:

```bash
git config blame.ignoreRevsFile .git-blame-ignore-revs
```

---

## Running the tests

```bash
python -m unittest discover -v
```

Or run the test file directly:

```bash
python test_waygap.py
```

All tests make no external network calls (API calls are mocked).

---

## Project structure

```
wayback-gap-detector/
├── waygap.py           # Main script
├── test_waygap.py      # Unit tests
├── ARCHITECTURE.md     # Architecture notes (function list, data flow)
├── LICENSE             # AGPL-3.0-or-later
├── README.md           # This file (English)
├── README_ja.md        # Japanese README
├── pyproject.toml      # Project metadata and dependencies
├── uv.lock             # Lock file (managed by uv)
├── .python-version     # Python version used for development
├── requirements.txt    # Python dependencies (generated from pyproject.toml)
├── .github/workflows/tests.yml  # CI (unit tests)
├── .git-blame-ignore-revs  # hash list ignored by git blame (large mechanical commits)
└── .gitignore          # Git ignore rules
```

---

## Contributing

Contributions are welcome!

1. Fork the repository and create a feature branch.
2. Make your changes and add or update tests as appropriate.
3. If you change dependencies, update `pyproject.toml`, `uv.lock` and `requirements.txt` together (see "Development setup").
4. Make sure the code passes the lint, format, and type checks: `uv run ruff check .`, `uv run ruff format --check .`, and `uv run basedpyright .`
5. Ensure all tests pass: `uv run python -m unittest discover -v`
6. Open a pull request with a clear description of what changed and why.

Please keep pull requests focused — one logical change per PR.

---

## License

This project is licensed under **AGPL-3.0-or-later**
([GNU Affero General Public License v3 or later](https://www.gnu.org/licenses/agpl-3.0.html)).

It depends on [surt](https://github.com/internetarchive/surt), which is
licensed under AGPL-3.0-or-later; distributing this tool together with
that dependency requires the combined work to carry the same license.
