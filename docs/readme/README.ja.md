# VibeSec / BTS Sec

> Passive, non-destructive security auditing for vibe-coded and AI-assisted web projects.

[Overview](../../README.md) | [English](README.en.md) | [한국어](README.ko.md) | [中文](README.zh-CN.md) | [日本語](README.ja.md)

VibeSec / BTS Sec は、vibe-coded Web アプリ、AI 支援コードベース、許可された Web サービス向けの防御的なセキュリティ監査ツールです。AI coding agent、low-code AI app builder、自動生成された認証/データベース/決済フロー、公開デフォルトのデプロイで起きやすいリスクに注目します。

デフォルトは passive、non-destructive な検査です。ログはローカルに残し、検出した secret は redaction し、URL スキャンは明示的な承認確認がない限り拒否します。

### クイックスタート

```bash
npm install
npm run build
vibesec scan --dir ./path/to/project --profile vibe-risk --out reports/local
vibesec scan --api-spec ./openapi.json --out reports/api
```

### 安全モデル

- exploit 実行なし
- brute force なし
- credential theft なし
- destructive payload なし
- URL スキャンは指定された same-origin に限定
- URL スキャンには明示的な authorization confirmation が必要
- レポートには raw secret、token、response body を保存しない

### デモ手順

1. `npm install` を実行します。
2. `npm run build` を実行します。
3. 自分が所有している、または監査許可を得たローカルプロジェクトに対して `npm run scan -- scan --dir "<project-path>" --profile vibe-risk --out reports/local` を実行します。
4. OpenAPI ファイルがある場合は `--api-spec "<openapi-path>"` を追加します。
5. `reports\local\report.html` をブラウザで開き、`Coverage & Known Gaps` と `Findings` を確認します。
