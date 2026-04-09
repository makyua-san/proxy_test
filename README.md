# Proxy Test Tool

アプリのホワイトリスト要件を検証するためのローカルプロキシテストツール。
ドメイン単位でのホワイトリスト制御、リクエストのログ記録、リアルタイムモニタリングUIを提供します。

## セットアップ

```bash
npm install
```

## 起動

```bash
npm start
```

- **プロキシサーバー**: `http://localhost:8080`
- **モニタリングUI**: `http://localhost:3000`

ポートを変更する場合は環境変数で指定できます:

```bash
PROXY_PORT=9090 UI_PORT=4000 npm start
```

## ブラウザのプロキシ設定

### Chrome (専用プロファイルで起動)

```bash
chrome --proxy-server=http://localhost:8080
```

### Windows システムプロキシ

設定 → ネットワークとインターネット → プロキシ → 手動プロキシセットアップ
- アドレス: `localhost`
- ポート: `8080`

## 使い方

1. `npm start` でサーバーを起動
2. ブラウザで `http://localhost:3000` を開いてモニタリングUIにアクセス
3. UIの左パネルでホワイトリストにドメインを追加（例: `example.com`, `*.example.com`）
4. テスト対象ブラウザのプロキシを `localhost:8080` に設定
5. ブラウザでWebサイトにアクセスし、許可/ブロックの動作をUIで確認

## モニターリスト（HTTPS通信の監視）

特定のドメインをモニターリストに追加すると、HTTPS通信をMITM（Man-in-the-Middle）方式で復号し、リクエスト/レスポンスの詳細を記録します。

### 記録される情報

- フルURL（パス・クエリパラメータ含む）
- HTTPメソッド（GET, POST 等）
- リクエスト/レスポンスヘッダ
- リクエストボディ（最大10KB）
- レスポンスステータスコード
- レスポンスボディ（テキスト系MIMEタイプ、最大50KB）

### CA証明書のセットアップ

HTTPS通信の復号にはCA証明書の信頼設定が必要です。起動時にコンソールにCA証明書のパスが表示されます。

#### Windows OS（Chrome, Edge 等）

```bash
certutil -addstore Root data\certs\ca.pem
```

#### VS Code / Node.js

システム環境変数を設定してからVS Codeを再起動:

```
変数名: NODE_EXTRA_CA_CERTS
値:     <プロジェクトパス>\data\certs\ca.pem
```

またはVS Code設定（GUI）:
- `Ctrl + ,` → 「proxy」で検索
- **Http: Proxy** → `http://localhost:8080`
- **Http: Proxy Support** → `on`

### 使い方

1. CA証明書をインポート（上記参照）
2. UIの左パネル「Monitor List」に監視対象ドメインを追加
3. 監視対象のHTTPS通信がフルURL付きでログに表示される
4. 「Monitored only」チェックボックスで監視対象のみフィルター可能
5. 行クリックで詳細パネルにリクエスト/レスポンスの全情報を表示

## ホワイトリストのルール

| パターン | マッチ例 | 非マッチ例 |
|---------|---------|-----------|
| `example.com` | `example.com` | `sub.example.com` |
| `*.example.com` | `sub.example.com`, `a.b.example.com` | `example.com` |

モニターリストも同じパターンルールに対応しています。

## API

| Method | Path | 説明 |
|--------|------|------|
| GET | `/api/logs?limit=100&offset=0` | ログ取得 |
| GET | `/api/logs/detail?id=xxx` | ログ詳細取得 |
| POST | `/api/logs/clear` | ログクリア |
| GET | `/api/whitelist` | ホワイトリスト取得 |
| POST | `/api/whitelist` | ドメイン追加 `{"domain":"..."}` |
| DELETE | `/api/whitelist` | ドメイン削除 `{"domain":"..."}` |
| GET | `/api/monitorlist` | モニターリスト取得 |
| POST | `/api/monitorlist` | ドメイン追加 `{"domain":"..."}` |
| DELETE | `/api/monitorlist` | ドメイン削除 `{"domain":"..."}` |
| WS | `/ws` | リアルタイムログ配信 |

## 技術スタック

- Node.js (built-in `http`, `https`, `net`, `tls`, `fs`, `crypto`)
- [ws](https://github.com/websockets/ws) (WebSocket)
- [node-forge](https://github.com/digitalbazaar/forge) (証明書生成)
