# MUSIC STUDY v22 — POSTGRES NATIVE

v22はv21のデプロイ準備版からSQLite依存を外し、PostgreSQLをアプリの本番DBとして直接利用する版。

## データ
- users
- sessions
- teachers
- learning_events

すべてPostgreSQLに保存され、user_idを外部キーとしてユーザー単位に分離。

## Render
`render.yaml`でWeb Service + PostgreSQLを定義。
GitHubへpush → RenderでBlueprintを選択 → OPENAI_API_KEYをSecretとして設定。

## 注意
これは本番公開へ近づけた実装だが、「完全に安全」を意味しない。
公開前に、HTTPS/HSTS、Redis等の分散Rate Limit、メール確認・リセット、Secrets Manager、バックアップ、監査ログ、依存脆弱性検査、WAF、プライバシー/利用規約、AIコスト上限、セキュリティレビューを行うこと。


v23は実ユーザーテストを想定したBeta版。`/health` とテストチェックリストを追加。
