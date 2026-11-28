# Wayback Gap Detector（日本語版 README）

> This is the Japanese translation of [README.md](README.md).

ローカルのURLリストを [Wayback Machine](https://web.archive.org/) の CDX API と突き合わせ、アーカイブされて**いない**URLを検出するコマンドラインツールです。

---

## 特徴

- Wayback Machine CDX API から、pagination（`page=`）による並列取得でアーカイブ済みURLデータを取得（pagination非対応時は `resumeKey` 逐次取得にフォールバック）
- URLキーをローカルのSQLiteファイル（単一 `.db`）にキャッシュし、起動時に実行条件と照合。条件やレイアウトが異なるキャッシュは自動で再構築 — 手動削除は不要
- 入力リストをデータベースに対してバッチ処理でストリーム照合するため、数千万URLでもRAMに蓄積しない
- CDX応答と手元URLの両辺を [surt](https://github.com/internetarchive/surt) で同一設定のキーに正規化して突合 — スキーム・`www.`・クエリ順・パーセントエンコード・IDNなどの表記差を吸収
- 未アーカイブURLをプレーンテキストファイルに出力
- オプションでアーカイブ済みURL（照合された手元入力行）を別ファイルにも出力
- 中断した取得を再開可能（paginationモードは完了済みページを記録して自動再開、`resumeKey` フォールバック時は `--resume-key`）

---

## 要件

- Python 3.11+（3.11と3.15でテスト済み）
- ライブラリ依存は [requirements.txt](requirements.txt) を参照

---

## インストール

```bash
# 1. リポジトリをクローン
git clone https://github.com/nabikita3974/wayback-gap-detector.git
cd wayback-gap-detector

# 2. 仮想環境を作成して有効化（推奨）
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

# 3. ツールと依存関係をインストール
python -m pip install .
```

---

## 使い方

```
waygap TARGET_URL [OPTIONS]
```

チェックアウトしたディレクトリから `python waygap.py ...` で直接実行することもできます。

`TARGET_URL` はCDX APIに渡すワイルドカードURLです（例: `https://example.com/blog/*`）。

### オプション

| オプション | 既定値 | 説明 |
|--------|---------|-------------|
| `--ignore-protocol` | 有効 | `http` と `https` を同一視（既定ではスキームを含まないキーになる） |
| `--no-ignore-protocol` | — | `http` と `https` を区別（全バリエーションを取得するため遅い） |
| `--ignore-www` | 有効 | `www.example.com` / `www2.example.com` 等を同一視（先頭の `www`/`wwwN.` を除去） |
| `--no-ignore-www` | — | `www.example.com` と `example.com` を区別（全バリエーションを取得するため遅い） |
| `--input FILE` | `urls.txt` | ローカルURLリストファイルのパス |
| `--output FILE` | `not_archived.txt` | 未アーカイブURLの出力ファイル |
| `--cache FILE` | `archived_cdx.db` | CDX取得結果のキャッシュファイル（SQLite） |
| `--refresh` | — | 既存キャッシュを無視して再構築 |
| `--no-cache` | — | 一時DBを使用（キャッシュを再利用も保持もしない） |
| `--page-size N` | *(サーバ既定値)* | CDX paginationのページサイズ（web.archive.org の既定は1ブロック/ページ） |
| `--workers N` | `2` | 並列ページ取得のワーカー数（リクエストは全ワーカー合計で3秒に1回までに制限） |
| `--batch-size N` | `500` | DB照合時のURL照会バッチサイズ |
| `--output-archived [FILE]` | `archived.txt` | アーカイブ済みURL（照合された手元入力行）もファイルに書き出す |
| `--resume-key KEY` | *(なし)* | 中断した `resumeKey` フォールバック取得を再開（paginationモードは自動再開） |
| `--limit N` | *(サーバ 既定値)* | `resumeKey` 逐次取得専用の1リクエストあたりチャンク量（paginationモードでは無視される） |
| `--version` | — | プログラムのバージョンを表示して終了 |
| `-v`, `--verbose` | — | DEBUGレベルのログを有効化 |

---

## 使用例

### 基本的な使い方

`https://example.com/blog/*` のCDXレコードをすべて取得し、アーカイブに存在しないURLを `not_archived.txt` に書き出します:

```bash
waygap "https://example.com/blog/*" --input urls.txt
```

### キャッシュと出力ファイルの指定

```bash
waygap "https://example.com/blog/*" \
  --input urls.txt \
  --cache my_cache.db \
  --output missing.txt
```

`--output-archived archived.txt` により、アーカイブ済みURLの出力ファイルを指定することも可能です。

完了済みのキャッシュは `--refresh` を指定するまで再利用されます。再利用時のログにはUTCの作成日時（日時がない場合、不正な場合、タイムゾーンがない場合は `unknown`）が表示されます。作成から7日以上経過した場合、または作成日時が不明な場合に `--refresh` を案内します。これは案内のみで、キャッシュが自動的に失効することはありません。キャッシュ作成後にアーカイブされたURLを含めるには `--refresh` を使ってください。

SQLiteのエラーにはキャッシュファイルのパスと元のエラーメッセージが表示されます。キャッシュが破損している場合は `--refresh` で再構築してください。予期しないエラーの調査には `-v` を追加するとトレースバックも表示されます。

### 中断した取得の再開

paginationモード（既定）は自動で再開します: 完了済みページはキャッシュDBに記録されるため、同じコマンドを再実行すれば未取得のページだけを取得します。手動での削除は不要です。キャッシュを意図的に一から作り直したい場合のみ `--refresh` を使います。

CDX APIがHTTP 429（Too Many Requests）を返した場合、ツールはすべてのリクエストを止めてから再試行し、制限が続く間は約7分（サーバーがより長い待ちを指定した場合は最長で約12分）待ちます。それでも制限が続く場合はエラーで停止するので、数分待ってから、この節の手順で再実行してください。5xx の応答に Retry-After が付いている場合も同じようにすべてのリクエストをその時間止め、4分を超える待ちを指定された場合はエラーで停止するので、その時間の後に再実行してください。

`--resume-key` が必要になるのは `resumeKey` フォールバック経路（サーバがpagination非対応の場合）のみです。フォールバック実行が途中で失敗すると、ツールは `resumeKey` の値をログに出力するので、元のコマンドに（`--refresh` を指定していた場合は外して）追加して続行します:

```bash
waygap "https://example.com/blog/*" \
  --input urls.txt \
  --cache my_cache.db \
  --limit 50000 \
  --resume-key "<RESUME_KEY>"
```

`--resume-key` は、同じキャッシュで中断したフォールバック取得を続けるためだけのオプションです。キャッシュファイルが存在し、未完了で、同じ対象URL・オプションで作られている必要があります。キーは、リクエスト失敗時にそれ以前の行を保存してから同じキャッシュに記録したチェックポイントと一致する必要があります。別の実行のキーや、検証済みチェックポイントのない古いキャッシュは拒否されます。その場合は `--resume-key` を外すと、保存済みURLを残したまま最初から再取得できます。条件を満たさない場合は、キャッシュを削除・上書きせずにエラーで停止します。`--no-cache` や `--refresh` とは併用できません。

最初のフォールバックリクエストが失敗し、まだ再開キーを受け取っていない場合は、同じコマンドを再実行して最初から取得してください。`--no-cache` の場合も、終了時に一時DBが削除されるため、再実行は最初からになります。進捗を残したい場合は、次回の実行から `--no-cache` を外してください。

---

## 入力ファイル形式

`urls.txt`（または `--input` で指定したファイル）はUTF-8で保存し、1行に1URLを記述します:

```
https://example.com/blog/post-1
https://example.com/blog/post-2
https://example.com/blog/post-3
```

空行は無視されます。

surtキーに変換できないURL（例: ポート番号が65535を超えるもの）があっても、実行は止まりません。そのようなURLの入力行は、行番号付きで警告を出したうえで未アーカイブとして出力します。CDX側の行は警告を出して読み飛ばします。

---

## URL突合の仕組み（surtキー）

CDX応答と手元URLリストの**両辺**を、同一のフラグ設定で [surt](https://github.com/internetarchive/surt) のキーに変換して突き合わせます。
例: `https://www.example.com/blog/post-1/` → `com,example)/blog/post-1`。既定ではホスト先頭の `www.`（`www2.` 等）が除去され、パス末尾のスラッシュも落ちるため、これらの表記差は同じキーになります。

**寛容モード（既定）** は surt の既定値＝CDXが `urlkey` で使う正規化系譜そのもの:

- `http`/`https` を同一視（キーにスキームを含まない）
- `www.example.com`・`www2.example.com` 等は先頭の `www`/`wwwN.` が除かれ `example.com` と同じキーになる
- クエリ引数を辞書順ソート＋小文字化
- パーセントエンコードの展開（`%7E`→`~`）、IDNホストのpunycode化（`xn--…`）、fragment/userinfo除去、既定ポート除去

**厳格モード**（`--no-ignore-www` または `--no-ignore-protocol`）はこれらの区別を保持します。
厳格フラグのいずれかが指定されると、CDXクエリは `collapse=original` を使い、同一`original`綴りの連続した重複だけを畳んだ上で、異なるバリエーションの行はすべて取得します。非既定フラグはCDX側の `original` 行にも手元側にも同じく適用されます。このため寛容モードより遅くなります。
例: `--no-ignore-www` では `http://www.a.com/p` は `com,a,www)/p` になります（既定では `com,a)/p`）。

`--output-archived` は照合された**手元入力行**を出力します。実行条件が異なるキャッシュや、互換性のないレイアウトのキャッシュは自動検出して再構築します。

---

## 開発

開発には [uv](https://docs.astral.sh/uv/) を使用します。`uv sync` で仮想環境（`.venv`）の作成とツールおよび依存関係のインストールが完了します（必要なPythonも自動で用意されます）。

```bash
uv sync
uv run pytest                           # テスト（外部ネットワーク呼び出しなし。API呼び出しはモック化）
uv run ruff check .                     # Lint
uv run ruff format --check .            # フォーマットチェック
uv run basedpyright                     # 型チェック
```

CIでも同じチェックを実行します。`uv add` で依存関係を変更したら、`requirements.txt` を
`uv export --no-dev --no-hashes --no-emit-project -o requirements.txt` で再生成してください。
バージョンは `waygap.py` の `__version__` のみで定義します。変更後は `uv lock` で
`uv.lock` を更新してください。`uv build` でwheelとソースアーカイブを作成できます。
CIはそれぞれを別のクリーンな環境にインストールし、メタデータとインストール済みの
`waygap --version`・`waygap --help` を検証します。
内部設計は [ARCHITECTURE.md](ARCHITECTURE.md) を参照してください。`git blame` からフォーマットコミットを除外するには
`git config blame.ignoreRevsFile .git-blame-ignore-revs` を実行します。

Issueやプルリクエストは歓迎します。プルリクエストは1つの論理的変更に絞ってください。

---

## 貢献者

- [nabikita3974](https://github.com/nabikita3974)
- [abhinavrastogi2627](https://github.com/abhinavrastogi2627)
- [imshah-id](https://github.com/imshah-id)

---

## 謝辞

- Wayback Machine と CDX API を提供する [Internet Archive](https://archive.org/)
- URL正規化に使用している [surt](https://github.com/internetarchive/surt)
- CDX API のリクエスト上限の参考にした、EDGI の [wayback](https://github.com/edgi-govdata-archiving/wayback)

---

## ライセンス

このプロジェクトは **AGPL-3.0-or-later**（[GNU Affero General Public License v3以降](https://www.gnu.org/licenses/agpl-3.0.html)）の下で公開されています。

依存ライブラリ [surt](https://github.com/internetarchive/surt) がAGPL-3.0-or-laterであるため、この依存とともに本ツールを配布する場合、結合著作物は同一ライセンスになります。
