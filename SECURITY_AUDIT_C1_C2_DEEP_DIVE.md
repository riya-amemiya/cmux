# C-1 / C-2 深掘り検証レポート

**実施日:** 2026-03-13
**検証チーム:** 調査員10名 + 批評家10名（計20エージェント）
**目的:** 初回監査で CRITICAL と報告された C-1（ソケット認証バイパス）と C-2（任意JS実行）が本当に起きるのかを検証

---

## エグゼクティブサマリー

20エージェントによる徹底検証の結果、初回レポートの評価を大幅に修正します。

| 項目 | 初回評価 | 修正後評価 | 理由 |
|------|---------|-----------|------|
| C-1: パスワード認証バイパス | CRITICAL | **誤報（FALSE POSITIVE）** | 認証は正しく機能している |
| C-2: 任意JS実行の能力 | CRITICAL | **実在（確認済み）** | ただし深刻度は条件付き |
| 新発見: browser.eval の権限分離欠如 | — | **MEDIUM-HIGH** | 真の脆弱性はここにある |

---

## C-1: パスワード認証バイパス → 誤報確定

### 検証結果

**4名の調査員（INV1, INV2, INV3, INV6）と1名の批評家（CRIT1）が独立して確認: 認証は正しく動作している。**

#### コードパスの実態（TerminalController.swift:1277-1283）

```swift
// 1. 毎コマンドで認証チェック
if let authResponse = authResponseIfNeeded(for: trimmed, authenticated: &authenticated) {
    writeSocketResponse(authResponse, to: socket)
    continue   // ← processCommand() を完全にスキップ
}
// 2. ここに到達するのは認証済みの場合のみ
let response = processCommand(trimmed)
```

#### 認証が正しく機能する理由

1. **`authResponseIfNeeded()` は非nil を返す** → `continue` が発火 → `processCommand()` は呼ばれない
2. **`authenticated` はコネクション単位のローカル変数** (line 1262) → 毎接続で `false` に初期化
3. **V1 も V2 も同じゲートを通過** → プロトコル間のバイパスなし
4. **CRIT1 が6つの攻撃ベクトルで挑戦** → すべて失敗:
   - `processCommand()` への代替パスなし
   - `authenticated` の並行アクセス不可（ローカル変数）
   - 認証なしで通過するコマンドなし
   - 不正形式 JSON でのバイパス不可
   - タイミングウィンドウなし（同期処理）
   - パーサー破壊による回避不可

#### V2 プロトコルの `auth.login` が常に `true` を返す件

これは**デッドコード**である。パスワードモードでは `passwordLoginV2ResponseIfNeeded()` が先に `auth.login` を捕捉し、実際のパスワード検証を行う。V2 ディスパッチハンドラの `auth.login`（常に `true` を返す箇所）はパスワードモードでは到達不能。非パスワードモードではそもそも認証不要なので問題なし。

### 初回レポートでの誤りの原因

初回レポートは「`authenticated` フラグが `processCommand()` に渡されていない」ことを問題視したが、実際には `processCommand()` に渡す必要がない。認証チェックは `processCommand()` の**前段**で行われ、未認証コマンドは `continue` で完全にスキップされる。

---

## C-2: 任意 JavaScript 実行 → 能力は実在するが攻撃シナリオは限定的

### browser.eval の能力（確認済み）

**INV4, INV10 が確認:**

- `browser.eval` は `WKContentWorld.page`（ページ自身の JS コンテキスト）で実行される
- `eval()` を経由し、サニタイゼーションなし
- 永続データストア使用（Cookie、localStorage が持続）
- CSP 注入なし、WebView サンドボックスなし
- `addinitscript` は `WKUserScript` で `atDocumentStart`、`forMainFrameOnly: false` で登録

| アクセス可能なもの | 可否 |
|-------------------|------|
| 非 HttpOnly Cookie | YES |
| HttpOnly Cookie の直接読み取り | **NO** |
| HttpOnly Cookie を使った認証済み fetch | **YES** |
| localStorage / sessionStorage | YES |
| DOM 全体（フォーム値含む） | YES |
| 認証済み API リクエスト | YES |

### 攻撃到達経路の制約

**問題は「browser.eval は強力だが、そこに到達できるのか？」**

#### デフォルトモード（cmuxOnly）での到達可能性

| 攻撃者の位置 | 到達可能？ | 理由 |
|-------------|-----------|------|
| cmux ターミナル内のプロセス | **YES** | 祖先チェックをパス（設計通り） |
| 別のターミナル（iTerm2 等）のプロセス | **NO** | 祖先チェックで拒否 |
| LaunchAgent / cron ジョブ | **NO** | 祖先チェックで拒否 |
| 別ユーザーのプロセス | **NO** | ソケット権限 0600 で拒否 |

**CRIT2 の重要な発見:** INV9 が主張した「`ncat --send-only` で PID 取得失敗 → UID フォールバック」バイパスは**実用的ではない**。理由:
- `LOCAL_PEERPID` は `accept()` 直後に取得される（line 1182）
- macOS カーネルはソケット FD が開いている限り PID メタデータを保持
- ピアプロセスが exit しても PID 情報は消えない

#### 「npm postinstall から攻撃」シナリオの実用性（CRIT3 の分析）

| 制約 | 影響 |
|------|------|
| V1 `send` はフォーカス中のターミナルをターゲット | 攻撃者自身のターミナルに注入される |
| `browser.eval` はブラウザパネルが開いていないと失敗 | ブラウザパネルの存在が前提条件 |
| 注入されたテキストはユーザーに見える | 完全にステルスではない |
| npm postinstall で任意実行できるなら… | `~/.zshrc` 改変や SSH 鍵窃取の方がはるかに簡単 |

### 真の脆弱性: browser.eval の権限分離欠如

**CRIT9 の判定（全エージェントの合意）:**

| 側面 | 判定 | 根拠 |
|------|------|------|
| 子孫プロセスのソケットアクセス | **設計通り** | tmux/iTerm2/Kitty と同等 |
| `send_keys` によるターミナル入力 | **設計通り** | `tmux send-keys` と同等 |
| **`browser.eval` が同じ権限レベル** | **脆弱性** | 他のターミナルに存在しない |

**根拠:** シェル統合スクリプトが使用するコマンドは `report_pwd`、`report_git_branch`、`clear_git_branch`、`report_pr`、`clear_pr`、`report_tty`、`ports_kick` のみ。`browser.eval`、`send_keys`、`browser.cookies.get` は一切使用しない。にもかかわらず、全コマンドが同じ認証レベルで利用可能。

**CRIT8（他ターミナルとの比較）:**

| ツール | ターミナル入力注入 | ブラウザ自動化 | 同じ IPC で両方 |
|--------|-------------------|---------------|----------------|
| tmux | YES（send-keys） | なし | — |
| iTerm2 | YES（Python API） | なし | — |
| Terminal.app | YES（AppleScript） | なし | — |
| VS Code | YES（Extension API） | YES（WebView API） | YES |
| **cmux** | **YES（send_keys）** | **YES（browser.eval）** | **YES** |

cmux の認証メカニズムは tmux より**優れている**（祖先チェック）。しかし、ソケット経由の**攻撃面**はブラウザ自動化 API により業界標準を大幅に超える。

---

## 修正推奨

### 推奨: コマンド別アクセス階層の導入（CRIT10 分析）

| 修正案 | 実現性 | 破壊リスク | 効果 | 推奨 |
|--------|--------|-----------|------|------|
| UID フォールバック削除 | 中 | **高**（シェル統合が壊れる） | 中 | 非推奨 |
| **コマンド別アクセス階層** | **容易** | **低** | **高** | **強く推奨** |
| send_keys 確認ダイアログ | 困難 | 高 | 中 | 非推奨 |
| 分離コンテンツワールド | 容易 | 高（自動化が壊れる） | 中 | 選択的のみ |
| CSP 注入 | 容易 | 高 | **低**（データはソケット経由で戻る） | 非推奨 |

**具体的な実装案:**

```
Tier 0 (telemetry): report_*, clear_*, ports_kick, list_*, version
  → cmuxOnly モードのデフォルト

Tier 1 (terminal-write): send, send_key, surface.send_text, surface.send_key
  → automation モード以上、または明示的オプトイン

Tier 2 (browser): browser.eval, browser.click, browser.cookies.*, browser.storage.*, browser.addinitscript
  → password モード以上、または明示的オプトイン
```

シェル統合は Tier 0 のみ使用するため、**既存のワークフローは一切壊れない**。

---

## エージェント別の結論一覧

### 調査員10名

| ID | 角度 | 主要発見 |
|----|------|---------|
| INV1 | 認証コードパス追跡 | `continue` で `processCommand()` がスキップされ、認証は正しく動作 |
| INV2 | V2 プロトコル分析 | V2 の `auth.login` 常時 true はデッドコード。実際の検証は前段で実行 |
| INV3 | アクセスモード分析 | 全モードの認証フローを確認。パスワードモードは正しくゲート |
| INV4 | browser.eval パス追跡 | ゼロサニタイゼーションで `eval()` → `WKContentWorld.page` に到達 |
| INV5 | ソケット到達可能性 | `0o600` 権限で同一ユーザーのみ。cmuxOnly は PID ベースの祖先検証 |
| INV6 | 防御機構監査 | コマンド単位の ACL なし、レート制限なし、browser.eval 制限なし |
| INV7 | send_keys パス追跡 | 8つの入力注入コマンド、確認なし、視覚的区別なし |
| INV8 | PoC 構築分析 | socat/nc で理論的に実行可能だが、cmuxOnly 内からのみ |
| INV9 | cmuxOnly バイパス分析 | UID フォールバックの存在を発見（後に CRIT2 が実用性を否定） |
| INV10 | WebView 分離分析 | 永続データストア、CSP なし、`.page` コンテキストで全アクセス |

### 批評家10名

| ID | 角度 | 主要判定 |
|----|------|---------|
| CRIT1 | 認証正確性への挑戦 | 6ベクトルで挑戦 → 認証バイパスなし確定 |
| CRIT2 | cmuxOnly バイパスへの懐疑 | `LOCAL_PEERPID` は accept 直後に取得、バイパスは**非現実的** |
| CRIT3 | PoC 実現性への懐疑 | `send` はフォーカス中ターミナルのみ、攻撃者には簡単な代替手段あり |
| CRIT4 | WebView 影響への懐疑 | HttpOnly Cookie は読めない。認証済み fetch が真の脅威。CSP は無効 |
| CRIT5 | macOS セキュリティ | SIP/TCC/Gatekeeper いずれもソケットを保護しない |
| CRIT6 | 見落とした防御の探索 | INV6 を確認。一部 `#if DEBUG` 限定コマンドあるが、危険なものは全ビルド利用可能 |
| CRIT7 | 入力注入の検出可能性 | Ghostty API に「合成」フラグなし。全レイヤーで**完全に区別不可能** |
| CRIT8 | 他ターミナルとの比較 | 認証は業界標準以上。**ブラウザ面**が業界標準を超える唯一のリスク |
| CRIT9 | 設計 vs 脆弱性の判別 | ターミナル制御=設計通り。**browser.eval の権限未分離=脆弱性** |
| CRIT10 | 修正実現性分析 | **コマンド別アクセス階層**が最も実現性が高く効果的 |

---

## 最終判定

### C-1（パスワード認証バイパス）: 誤報

初回レポートの CRITICAL 評価は**完全に誤り**でした。認証メカニズムは設計通りに正しく機能しています。

### C-2（任意 JavaScript 実行）: 能力は実在、深刻度は Medium-High

`browser.eval` の能力自体は強力で実在しますが、以下の理由で当初の CRITICAL から格下げ:

1. **到達にはソケットアクセスが必要** — デフォルトモードでは cmux の子孫プロセスのみ
2. **cmuxOnly の祖先チェックは健全** — UID フォールバックバイパスは非現実的
3. **ブラウザパネルが開いている必要がある** — 前提条件
4. **HttpOnly Cookie は直接読めない** — ただし認証済み fetch は可能
5. **競合する攻撃手段の方が容易** — 同じ権限なら `~/.ssh/id_rsa` 窃取の方が簡単

### 真の脆弱性: コマンド権限の未分離

cmux 固有の問題は、テレメトリコマンド（`report_pwd` 等）と高権限コマンド（`browser.eval`、`browser.cookies.get` 等）が**同じ認証レベル**で提供されていることです。これはシェル統合に不要な権限を全子孫プロセスに付与しており、他のターミナルエミュレータには存在しないリスクです。

**推奨される修正:** コマンド別アクセス階層の導入（実現性: 容易、破壊リスク: 低、効果: 高）

---

*本レポートは20の専門エージェント（調査員10名 + 批評家10名）によるコード静的解析に基づきます。*
