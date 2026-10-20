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

- Python 3.9+（3.13でテスト済み）
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

# 3. 依存関係をインストール
pip install -r requirements.txt
```

---

## 使い方

```
python waygap.py TARGET_URL [OPTIONS]
```

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
| `--page-size N` | *(サーバ 既定値)* | CDX paginationのページサイズ（web.archive.org の既定は1ブロック/ページ） |
| `--workers N` | `4` | 並列ページ取得のワーカー数 |
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
python waygap.py "https://example.com/blog/*" --input urls.txt
```

### キャッシュと出力ファイルの指定

```bash
python waygap.py "https://example.com/blog/*" \
  --input urls.txt \
  --cache my_cache.db \
  --output missing.txt
```

### アーカイブ済みURLを別ファイルに収集

```bash
python waygap.py "https://example.com/blog/*" \
  --input urls.txt \
  --output not_archived.txt \
  --output-archived archived.txt
```

### 中断した取得の再開

paginationモード（既定）は自動で再開します: 完了済みページはキャッシュDBに記録されるため、同じコマンドを再実行すれば未取得のページだけを取得します。手動での削除は不要です。キャッシュを意図的に一から作り直したい場合のみ `--refresh` を使います。

`--resume-key` が必要になるのは `resumeKey` フォールバック経路（サーバがpagination非対応の場合）のみです。フォールバック実行が途中で失敗すると、ツールは `resumeKey` の値をログに出力するので、元のコマンドに追加して続行します:

```bash
# 例 - 失敗した元のコマンド:
python waygap.py "https://example.com/blog/*" \
  --input urls.txt \
  --cache my_cache.db \
  --limit 50000

# --resume-key を追加して再開（KEY はエラーメッセージに出力されます）:
python waygap.py "https://example.com/blog/*" \
  --input urls.txt \
  --cache my_cache.db \
  --limit 50000 \
  --resume-key "<RESUME_KEY>"
```

---

## 入力ファイル形式

`urls.txt`（または `--input` で指定したファイル）は1行に1URLで記述します:

```
https://example.com/blog/post-1
https://example.com/blog/post-2
https://example.com/blog/post-3
```

空行は無視されます。

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

## テストの実行

```bash
python -m unittest discover -v
```

またはテストファイルを直接実行:

```bash
python test_waygap.py
```

すべてのテストは外部ネットワーク呼び出しを行いません（API呼び出しはモック化されています）。

---

## プロジェクト構成

```
wayback-gap-detector/
├── waygap.py           # メインスクリプト
├── test_waygap.py      # ユニットテスト
├── ARCHITECTURE.md     # アーキテクチャ解説（関数一覧・データフロー）
├── README.md           # 英語版 README
├── README_ja.md        # このファイル（日本語版）
├── requirements.txt    # Python依存ライブラリ
├── .github/workflows/tests.yml  # CI（ユニットテスト）
└── .gitignore          # Git ignore ルール
```

---

## コントリビューション

貢献を歓迎します！

1. リポジトリをフォークし、機能ブランチを作成してください。
2. 変更を加え、必要に応じてテストを追加・更新してください。
3. すべてのテストが通ることを確認してください: `python -m unittest discover -v`
4. 何を・なぜ変更したのかを明確に記述したプルリクエストを出してください。

プルリクエストは1つ1つの論理的変更に絞ってください。

---

## ライセンス

このプロジェクトは **AGPL-3.0-or-later**（[GNU Affero General Public License v3以降](https://www.gnu.org/licenses/agpl-3.0.html)）の下で公開されています。

依存ライブラリ [surt](https://github.com/internetarchive/surt) がAGPL-3.0-or-laterであるため、この依存とともに本ツールを配布する場合、結合著作物は同一ライセンスになります。
