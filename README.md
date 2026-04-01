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

## ホワイトリストのルール

| パターン | マッチ例 | 非マッチ例 |
|---------|---------|-----------|
| `example.com` | `example.com` | `sub.example.com` |
| `*.example.com` | `sub.example.com`, `a.b.example.com` | `example.com` |

## API

| Method | Path | 説明 |
|--------|------|------|
| GET | `/api/logs?limit=100&offset=0` | ログ取得 |
| POST | `/api/logs/clear` | ログクリア |
| GET | `/api/whitelist` | ホワイトリスト取得 |
| POST | `/api/whitelist` | ドメイン追加 `{"domain":"..."}` |
| DELETE | `/api/whitelist` | ドメイン削除 `{"domain":"..."}` |
| WS | `/ws` | リアルタイムログ配信 |

## 技術スタック

- Node.js (built-in `http`, `net`, `fs`)
- [ws](https://github.com/websockets/ws) (WebSocket)
