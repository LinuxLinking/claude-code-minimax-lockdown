# claude-code-minimax-lockdown

> 🌐 [English](#english) · [日本語](#日本語) · [简体中文](#简体中文)

A Claude Code `PreToolUse` / `PostToolUse` hook that constrains the **MiniMax model only**. For any other model it exits immediately with zero overhead. Put an untrusted small model in a safety cage.

---

## English

A Claude Code hook that applies strict safety constraints **only when the active model is MiniMax**. Any other model: `exit 0` immediately (zero overhead).

### Why

An untrusted model (MiniMax, or any model you don't fully trust) may read credentials, edit global config, or download things outside the project when running tools. This hook stops that with three layers:

1. **Mechanical HARD DENY** — `rm`/`mv`/`mkdir` outside the project, reads of `~/.ssh`/`~/.aws`/`~/.claude/projects`/`~/.cc-switch`, registry edits → denied outright, no popup, no LLM.
2. **Mechanical ASK** — uncommon downloads (`git clone`/`wget`/`Invoke-WebRequest`) → popup for your review.
3. **AUDITOR** — gray-zone ops (curl downloads, dependency installs, cross-dir read/write) are judged by a **separate auditor model** returning verdict + confidence + severity.

Two fatigue controls so popups don't get annoying:

- **Trick 1 — confidence routing**: auditor confidence ≥ `conf_auto` (default 0.85) decides silently (allow OR deny); only uncertain cases pop up.
- **Trick 2 — session memo**: an operation you already approved is auto-allowed for the rest of the session (exact `(tool, command/path signature)` match only). Approvals are observed via the `PostToolUse` pass.

Every ask/deny/memo event is appended to `lockdown.log`; run `analyze-lockdown-log.py` for a summary report.

### Install

1. Copy the config:
   ```bash
   cp config.example.json config.json
   ```
   Edit `config.json` with your real values:
   - `proxy_url` — your local proxy `/v1/messages` endpoint (the channel the auditor model uses)
   - `auditor_model` — the auditor model name
   - `legit_roots` — your machine's legit toolchain / dependency-cache roots (reads/writes here are normal); replace with your own paths
   - `temp_roots` — optional; leave empty to auto-use `%TEMP%`

   `config.json` is gitignored — **it is never uploaded**.

2. Register the hook in Claude Code settings (change the path to yours):
   ```json
   {
     "hooks": {
       "PreToolUse": [
         { "matcher": "*", "hooks": [{"type": "command", "command": "python /path/to/hooks/minimax-lockdown.py"}] }
       ],
       "PostToolUse": [
         { "matcher": "*", "hooks": [{"type": "command", "command": "python /path/to/hooks/minimax-lockdown.py"}] }
       ]
     }
   }
   ```

### Files

| File | Purpose |
|---|---|
| `minimax-lockdown.py` | Hook body |
| `test-lockdown.py` | Self-contained test; fabricates a MiniMax transcript, runs 10 cases, no real session needed |
| `analyze-lockdown-log.py` | Summarizes `lockdown.log` into `lockdown-report.txt` |
| `minimax-lockdown-testcases.md` | Manual test cases (paste into a real MiniMax session) |
| `config.example.json` | Config template (committed) |
| `config.json` | Your real config (gitignored) |
| `chn/` | Chinese-localized copy of the code and docs |

`lockdown.log` / `lockdown-report.txt` / `minimax_lockdown/` (session state) are runtime artifacts, all gitignored.

### Test

```bash
python test-lockdown.py
```

### Design boundaries

- `$VARIABLE` paths can't be resolved statically → go to the auditor (may false-positive `mkdir "$BUILD_DIR"`; the auditor will allow it).
- Auditor down / timeout → fail-closed to **popup**, never a silent allow.
- Model detection: last `"model"` field in the session transcript; non-MiniMax → `exit 0`.

### Disclaimer

This hook is one layer of defense-in-depth, not a sandbox. MiniMax can still do unwanted things *inside* the project directory. For real isolation use a container/VM.

---

## 日本語

Claude Code の `PreToolUse` / `PostToolUse` フック。**MiniMax モデルにのみ**厳しい安全制約を適用し、それ以外のモデルなら即座に `exit 0`（オーバーヘッドなし）で通過します。信頼できない小モデルを安全の檻に入れます。

### なぜ必要か

信頼できないモデル（MiniMax や、完全に信用していない任意のモデル）はツール実行時に資格情報を読んだりグローバル設定を書き換えたりプロジェクト外へダウンロードしたりする可能性があります。本フックはこれを 3 層で防ぎます：

1. **機械層・即拒否** — `rm`/`mv`/プロジェクト外の `mkdir`、`~/.ssh`/`~/.aws`/`~/.claude/projects`/`~/.cc-switch` の読み取り、レジストリ編集 → ポップアップなし・LLM なしで即拒否。
2. **機械層・確認** — 例外的なダウンロード（`git clone`/`wget`/`Invoke-WebRequest`）→ 確認ポップアップ。
3. **監査層** — グレーゾーン操作（curl ダウンロード、依存インストール、ディレクトリを跨ぐ読み書き）は**別の監査モデル**が判定し、verdict + confidence + severity を返します。

ポップアップ疲れを防ぐ二つの工夫：

- **工夫1・信頼ルーティング** — 監査の confidence ≥ `conf_auto`（既定 0.85）なら黙って判定（許可も拒否も）。迷うケースだけポップアップ。
- **工夫2・セッションメモ** — 一度承認した操作は同一セッションでは自動許可（`(ツール, コマンド/パス署名)` の完全一致のみ）。承認は `PostToolUse` パスで観測します。

全 ask/deny/memo イベントは `lockdown.log` に追記され、`analyze-lockdown-log.py` で集計レポートを出せます。

### インストール

1. 設定をコピー：
   ```bash
   cp config.example.json config.json
   ```
   `config.json` に実際の値を記入：
   - `proxy_url` — ローカルプロキシの `/v1/messages` エンドポイント（監査モデルが使う経路）
   - `auditor_model` — 監査モデル名
   - `legit_roots` — 自分のマシンの正当なツールチェーン／依存キャッシュのルート（ここの読み書きは正常）。自分のパスに置き換えてください
   - `temp_roots` — 任意。空なら `%TEMP%` を自動使用

   `config.json` は gitignore 済みで**アップロードされません**。

2. Claude Code の設定にフックを登録（パスは自分用に変更）：
   ```json
   {
     "hooks": {
       "PreToolUse": [
         { "matcher": "*", "hooks": [{"type": "command", "command": "python /path/to/hooks/minimax-lockdown.py"}] }
       ],
       "PostToolUse": [
         { "matcher": "*", "hooks": [{"type": "command", "command": "python /path/to/hooks/minimax-lockdown.py"}] }
       ]
     }
   }
   ```

### ファイル

| ファイル | 役割 |
|---|---|
| `minimax-lockdown.py` | フック本体 |
| `test-lockdown.py` | 自己完結テスト。MiniMax トランスクリプトを捏造し 10 ケースを実行（実セッション不要） |
| `analyze-lockdown-log.py` | `lockdown.log` を `lockdown-report.txt` に集計 |
| `minimax-lockdown-testcases.md` | 手動テストケース（実 MiniMax セッションに貼り付け） |
| `config.example.json` | 設定テンプレート（コミット対象） |
| `config.json` | 実際の設定（gitignore） |
| `chn/` | コードとドキュメントの中国語版 |

`lockdown.log` / `lockdown-report.txt` / `minimax_lockdown/`（セッション状態）は実行時生成物で、すべて gitignore 済みです。

### テスト

```bash
python test-lockdown.py
```

### 設計上の境界

- `$変数` パスは静的に解決できない → 監査層へ回す（`mkdir "$BUILD_DIR"` を誤判定する可能性あり、監査が許可します）。
- 監査ダウン／タイムアウト → フェイルセーフで**ポップアップ**、黙許可はしない。
- モデル検出：セッショントランスクリプトの最後の `"model"` フィールド。MiniMax 以外は `exit 0`。

### 免責

本フックは纵深防御の一層であり、サンドボックスではありません。MiniMax はプロジェクトディレクトリ**内**で望ましくないことを依然として行えます。真の隔離にはコンテナ／VMを使ってください。

---

## 简体中文

Claude Code 的 `PreToolUse` / `PostToolUse` 钩子，**只对 MiniMax 模型**生效。其它模型直接 `exit 0`，零开销。给一个不可信的小模型套上安全笼子。

### 为什么

不可信的模型（MiniMax，或任何你不完全信任的模型）跑工具时，可能越界读凭据、改全局配置、往项目外下东西。这个 hook 用三层把它们管住：

1. **机械层·硬拦** —— `rm`/`mv`/`mkdir` 到项目外、读 `~/.ssh`/`~/.aws`/`~/.claude/projects`/`~/.cc-switch`、改注册表 → 直接拒绝，不弹窗、不过 LLM。
2. **机械层·弹窗** —— `git clone`/`wget`/`Invoke-WebRequest` 这类不常用下载 → 弹窗让你复审。
3. **审计层** —— 灰区操作（curl 下载、装依赖、跨目录读写）交给一个**独立的审计模型**判断，返回 verdict + confidence + severity。

降频两招，免得弹窗弹到烦：

- **招1 置信路由** —— 审计员 confidence ≥ `conf_auto`（默认 0.85）就静默定（放行或拒绝），只有拿不准才弹。
- **招2 会话记忆** —— 你批准过的相同操作，本会话内不再弹（按 `(工具, 命令/路径签名)` 记，仅精确匹配）。批准动作通过 `PostToolUse` 回调观察。

所有 ask/deny/memo 事件追加到 `lockdown.log`，用 `analyze-lockdown-log.py` 出报告。

### 安装

1. 复制配置：
   ```bash
   cp config.example.json config.json
   ```
   编辑 `config.json`，填你本机真实值：
   - `proxy_url` —— 你的本地代理 `/v1/messages` 端点（审计模型走的通道）
   - `auditor_model` —— 审计模型名
   - `legit_roots` —— 你本机合法工具链/依赖缓存根目录（读这些算正常），换成自己的路径
   - `temp_roots` —— 可选，留空则自动用 `%TEMP%`

   `config.json` 已被 `.gitignore` 忽略，**不会上传**。

2. 在 Claude Code 的 settings 里挂钩子（路径改成你的）：
   ```json
   {
     "hooks": {
       "PreToolUse": [
         { "matcher": "*", "hooks": [{"type": "command", "command": "python /path/to/hooks/minimax-lockdown.py"}] }
       ],
       "PostToolUse": [
         { "matcher": "*", "hooks": [{"type": "command", "command": "python /path/to/hooks/minimax-lockdown.py"}] }
       ]
     }
   }
   ```

### 文件

| 文件 | 作用 |
|---|---|
| `minimax-lockdown.py` | 钩子主体 |
| `test-lockdown.py` | 自包含测试，伪造 MiniMax transcript 跑 10 个用例，不需要真会话 |
| `analyze-lockdown-log.py` | 把 `lockdown.log` 汇总成 `lockdown-report.txt` |
| `minimax-lockdown-testcases.md` | 手动测试用例集（开真 MiniMax 会话照着粘） |
| `config.example.json` | 配置模板（提交进仓库） |
| `config.json` | 你的真实配置（gitignored） |
| `chn/` | 代码与文档的中文版副本 |

`lockdown.log` / `lockdown-report.txt` / `minimax_lockdown/`（会话状态）都是运行时产物，已 gitignore。

### 测试

```bash
python test-lockdown.py
```

### 设计边界

- `$变量` 路径静态抠不出，走审计员（可能误伤 `mkdir "$BUILD_DIR"`，审计员会放行）。
- 审计员挂了/超时：fail-closed 转**弹窗**，绝不静默放行。
- 模型检测：读 session transcript 里最后一条 `"model"` 字段；非 MiniMax 直接 `exit 0`。

### 注意

本 hook 是纵深防御的一层，不是沙箱。MiniMax 仍可能在项目目录内做你不想要的事。真正的隔离请用容器/VM。
