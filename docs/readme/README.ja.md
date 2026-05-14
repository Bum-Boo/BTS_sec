# VibeSec / BTS Sec

> vibe-coded および AI-assisted web project 向けの passive、non-destructive な defensive security auditing toolkit。

[Overview](../../README.md) | [English](README.en.md) | [한국어](README.ko.md) | [中文](README.zh-CN.md) | [日本語](README.ja.md)

VibeSec は、vibe-coded web applications、AI-assisted codebases、authorized web services のための防御的セキュリティ監査ツールキットです。AI coding agents、low-code AI app builders、generated auth/database/payment flows、public-by-default deployments が持ち込みやすい問題に焦点を当てています。

既定では passive、non-destructive checks を行います。logs は local に保管し、検出された secrets は redacted されます。URL scans は authorization が明示的に確認された場合にのみ許可されます。

## Quick Start

```bash
npm install
npm run build
vibesec scan --dir ./path/to/project --profile vibe-risk --out reports/local
vibesec scan --api-spec ./openapi.json --out reports/api
vibesec scan --url https://example.internal --profile vibe-risk --authorization-confirmation "I confirm I own or am authorized to test this target." --out reports/url
vibesec scan --url https://example.internal --dir ./path/to/project --api-spec ./openapi.yaml --profile vibe-risk --authorization-confirmation "I confirm I own or am authorized to test this target." --out reports/full
```

生成される reports:

- `report.md`
- `report.html`
- `report.json`
- `report.sarif`
- `agent-fix-prompt.md`

## Safety Model

- exploit execution、brute force、credential theft、destructive payload、data extraction routine は実装していません。
- URL scanning は user-provided exact origin に限定されます。passive crawler は same-origin links のみを追跡します。
- URL scanning には explicit authorization confirmation が必要です。`--authorization-confirmation "I confirm I own or am authorized to test this target."` を推奨します。
- built-in HTTP checks は `--rate-limit-rps` で制限され、既定は 1 request/second です。
- built-in web checks は `GET`、`HEAD`、`OPTIONS` のみを使います。form submit、authenticate、state mutation、exploit payload 実行はしません。
- external adapters は隔離されています。tool が無い場合は scan 全体を失敗させず informational adapter finding として報告します。
- external adapters は `--include-external` がある場合のみ実行されます。
- Nuclei execution は allowlisted template IDs と paths に制限されます。
- TruffleHog live credential validation は既定で無効です。
- report のすべての evidence は出力前に redactor を通過します。raw secret/token/body content は保存しません。
- package install、dependency script execution、arbitrary target code execution、destructive HTTP methods、active GraphQL introspection POSTs は行いません。

## CLI

```bash
bts-sec --target <url-or-directory> [options]
```

主な options:

- `--target <value>` authorized URL または local project directory。
- `--url <value>` `vibesec scan` 用 authorized URL target。
- `--dir <path>` `vibesec scan` 用 local project directory target。
- `--api-spec <path>` passive OpenAPI/Swagger JSON または YAML specification scan。
- `--profile <baseline|vibe-risk>` scan profile。既定は `baseline`。
- `--confirm-authorization` URL targets に必要。
- `--authorization-confirmation "I confirm I own or am authorized to test this target."` 推奨 authorization phrase。
- `--out <dir>` output directory。既定は `reports/latest`。
- `--rate-limit-rps <n>` built-in HTTP request rate limit。既定は `1`。
- `--timeout-ms <n>` per-request と adapter timeout。既定は `15000`。
- `--max-crawl-depth <n>` same-origin passive crawler depth。既定は `1`。
- `--max-crawl-pages <n>` same-origin passive crawler page cap。既定は `25`。
- `--include-external` installed external tool adapters を実行。
- `--kev-catalog <path>` CVE enrichment 用 local CISA KEV JSON catalog。
- `--refresh-kev` public CISA KEV JSON feed を取得。
- `--epss-csv <path>` CVE enrichment 用 local FIRST EPSS CSV。
- `--refresh-epss` reported CVEs に対する FIRST EPSS API data を取得。
- `--nuclei-template <path-or-id>` allowlisted Nuclei template。繰り返し指定可。

## Module Layout

- `scanner-core`: target validation、orchestration、task runner、finding schema、scoring、aggregation。
- `api-scanner`: authentication、authorization、inventory、SSRF、mass assignment、resource-consumption hints 向け passive OpenAPI/Swagger static checks。
- `web-scanner`: safe header、cookie、CORS、exposure checks、same-origin passive crawler、GraphQL static hints、ZAP Baseline/Nuclei adapters。
- `code-scanner`: custom static rules、multiline matching、standards mappings、suppress comments、Semgrep adapter。
- `dependency-scanner`: lockfile-based SBOM、supply-chain hygiene checks、Trivy、OSV-Scanner、npm audit、pip-audit。
- `secret-scanner`: internal redaction、Gitleaks、TruffleHog adapters。
- `knowledge-base`: OWASP、OWASP API、MITRE CWE Top 25、CISA KEV enrichment、remediation guidance。
- `report-generator`: Markdown、HTML、JSON、SARIF reports。
- `vibe-scanner`: AI agent artifacts、dependency hallucination/slopsquatting、auth/payment/database static review、public URL exposure、pre-agent-run checklist 向け vibe-risk profile scanners。

## Vibe-Risk Profile

`--profile vibe-risk` は deterministic、non-destructive checks を追加します。

- dashboard、admin、customer、support、internal pages の public exposure。
- client-side-only または missing server-side auth checks。
- ownership、role、user、tenant、account authorization boundaries の不足。
- Stripe webhook signature verification と client-only payment success handling。
- Supabase RLS と Firebase open rule risks。
- public Supabase、Firebase、Clerk、Stripe、OpenAI、Resend configuration risks。
- `.cursor/rules`、`.cursorrules`、`CLAUDE.md`、`AGENTS.md`、`GEMINI.md`、`.windsurfrules`、`.cline/`、`.roo/`、MCP configs などの AI coding assistant artifacts。
- dependency hallucination、import/manifest mismatch、typosquatting-like names、registry metadata がある場合の suspiciously new packages、install script risk。
- Vercel、Netlify、Replit、Lovable、Base44、Bolt、v0、Cursor-generated projects などの platform hints。
- sensitive raw content を保存せずに、PII、medical、financial、customer conversation、credential、internal-business exposure indicators を検出。

## Report Schema

Findings は normalized schema を使い、severity、confidence、category、target type、redacted evidence、optional vibe-risk metadata、OWASP Top 10:2025、OWASP LLM Top 10:2025、OWASP API Top 10:2023、CWE Top 25:2025、CISA KEV priority、remediation guidance、verification steps、Codex-ready remediation prompt を含みます。

Markdown、HTML、JSON、SARIF reports には `Coverage & Known Gaps` matrix、standard item ごとの `covered` / `partial` / `not_covered` status、scanner configuration summary、suppressed findings summary、priority score、KEV/EPSS fields、利用可能な場合の dependency direct/transitive context が含まれます。

coverage model は **standards-aligned passive coverage with explicit known gaps** です。`covered` は first-class passive/static check または enrichment path があることを意味します。`partial` は review signal は出せるが weakness が存在しないことや exploitability を証明しないことを意味します。`not_covered` は dedicated SAST/compiler/runtime analysis または active authorized testing が必要なため、意図的に built-in detection を実装していないことを意味します。

## OpenAPI/API Scanning

`--api-spec <openapi-json-or-yaml>` は OpenAPI/Swagger specs を local に読み、次の passive/static checks を実行します。

- global または operation-level security requirements の不足。
- BOLA review が必要そうな object-id endpoints。
- admin/internal/function-level authorization sensitive paths。
- request schemas の object property exposure と mass assignment risk。
- SSRF risk を示す user-controlled URL fields。
- collection endpoints の pagination/rate-limit hints 不足。
- deprecated または undocumented-looking endpoints。

API scanner は requests を送信しません。URL target が一緒に指定されても、web checks は same-origin かつ non-destructive のままです。

## Dependency, SBOM, and Supply Chain

SBOM generation は package install をせず manifests と lockfiles を読みます。対応 input は `package.json`、`package-lock.json`、`pnpm-lock.yaml`、`yarn.lock`、`requirements.txt`、`Pipfile.lock`、`poetry.lock`、`go.sum`、`Cargo.lock`、`pom.xml`、`build.gradle`、`gradle.lockfile` です。

Supply-chain hygiene checks は static で、OWASP SCVS の考え方に沿っています。missing lockfiles、package-manager mismatch、unpinned dependencies、git/URL dependencies、lifecycle install scripts、suspicious internal-looking namespaces、dependency-confusion candidates を flag します。BTS Sec は package installs や arbitrary package scripts を実行しません。

CVE findings は local catalogs が提供された場合、または refresh flags が明示的に使われた場合のみ CISA KEV と FIRST EPSS で enrich されます。Priority score は severity、KEV presence、EPSS percentile、fix availability、direct/transitive dependency context を組み合わせます。

## Pre-Agent-Run Checklist

VibeSec は report section で次を警告します。

- dirty git working trees。
- missing commits。
- missing lockfiles。
- missing tests または auth/payment/database tests。
- risky package lifecycle scripts。
- vibe-risk profile が見つけた AI rule と MCP configuration risks。

`git status`、`git diff`、`npm test`、`pnpm test`、`pytest` などの command は suggestions のみです。VibeSec は project test scripts や arbitrary target code を実行しません。

## Agent Fix Prompts

各 scan は `agent-fix-prompt.md` も書き出します。これは Codex や別の AI coding agent に貼り付けられる English prompt です。prompt には actionable findings、redacted evidence、recommended fixes、verification steps、exploit execution、credential validation、brute force、destructive payloads、out-of-scope scanning を禁止する safety instructions が含まれます。

同じ text は automation 用に `report.json` の `agentFixPrompt` にも埋め込まれます。

## Adding Rules

- vibe-coded または AI-agent workflows 固有の static local rules は `src/vibe-scanner/*` に追加します。
- generic web URL checks は `src/web-scanner/*`、vibe-specific URL checks は `src/vibe-scanner/url-vibe-scanner.ts` に追加します。
- mapping defaults は `src/knowledge-base/mappings.ts` に追加します。
- 複数 rule が再利用できる remediation text は `src/knowledge-base/remediation.ts` に追加します。
- tests は temporary fixture projects を使って `tests/` に追加します。Rules は deterministic にし、test が明示的に mock しない限り network access を避けます。

## Known Limitations

- toolkit は static/passive/heuristic です。review すべき risky patterns を示しますが、exploitability や vulnerability absence を証明しません。
- suspicious dependency age は supplied registry metadata を使い、paid APIs を呼びません。
- typosquatting detection は intentionally conservative で、manual review が必要です。
- URL checks は form submit、authenticate、third-party links crawl、state mutation、GraphQL introspection POST、bypass attempt を行いません。
- auth/payment/database analysis は framework-pattern based で、custom abstractions を見逃すことがあります。
- memory-safety CWEs は built-in passive scanner の外にある dedicated tooling が必要です。
- YAML OpenAPI parsing には conservative fallback があり、JSON または fully parsed OpenAPI objects の方が richer schema analysis を提供します。

## Demo Walkthrough

demo flow では、所有または評価権限のある local sample project と OpenAPI file を scan し、generated HTML report で coverage と findings を確認します。

1. `npm install` を実行します。
2. `npm run build` を実行します。
3. `npm run scan -- scan --dir "<project-path>" --profile vibe-risk --out reports/local` で local project を scan します。
4. OpenAPI file があれば `--api-spec "<openapi-path>"` を含めます。
5. browser で `reports\local\report.html` を開き、`Coverage & Known Gaps` と `Findings` を確認します。

report 上部には scan target、run time、severity summary、scanner configuration が表示されます。

![Report top](../demo-screenshots/sec-kit-flow-01-report-top.png)

`Coverage & Known Gaps` と `Findings` まで scroll して、どの checks が実行され何が報告されたかを確認します。

![Findings section](../demo-screenshots/sec-kit-flow-02-findings.png)
