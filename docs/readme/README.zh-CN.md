# VibeSec / BTS Sec

> 面向 vibe-coded 和 AI-assisted Web 项目的 passive、non-destructive 防御性安全审计工具包。

[Overview](../../README.md) | [English](README.en.md) | [한국어](README.ko.md) | [中文](README.zh-CN.md) | [日本語](README.ja.md)

VibeSec 是一个 defensive security auditing toolkit，面向 vibe-coded web applications、AI-assisted codebases 和 authorized web services。它关注 AI coding agents、low-code AI app builders、generated auth/database/payment flows 以及 public-by-default deployments 常引入的问题。

默认行为是 passive、non-destructive checks。日志保存在本地，检测到的 secrets 会被 redacted；除非明确确认 authorization，否则拒绝 URL scans。

## Quick Start

```bash
npm install
npm run build
vibesec scan --dir ./path/to/project --profile vibe-risk --out reports/local
vibesec scan --api-spec ./openapi.json --out reports/api
vibesec scan --url https://example.internal --profile vibe-risk --authorization-confirmation "I confirm I own or am authorized to test this target." --out reports/url
vibesec scan --url https://example.internal --dir ./path/to/project --api-spec ./openapi.yaml --profile vibe-risk --authorization-confirmation "I confirm I own or am authorized to test this target." --out reports/full
```

生成的 reports:

- `report.md`
- `report.html`
- `report.json`
- `report.sarif`
- `agent-fix-prompt.md`

## Safety Model

- 不实现 exploit execution、brute force、credential theft、destructive payload 或 data extraction routines。
- URL scanning 限制在用户提供的 exact origin。passive crawler 只跟随 same-origin links。
- URL scanning 需要 explicit authorization confirmation。推荐使用 `--authorization-confirmation "I confirm I own or am authorized to test this target."`。
- built-in HTTP checks 受 `--rate-limit-rps` 限制，默认每秒 1 个 request。
- built-in web checks 只使用 `GET`、`HEAD` 和 `OPTIONS`；不 submit forms、不 authenticate、不 mutate state、不运行 exploit payloads。
- external adapters 被隔离；缺失工具会作为 informational adapter findings 报告，而不是让整个 scan 失败。
- external adapters 只有在提供 `--include-external` 时才运行。
- Nuclei execution 限制在 allowlisted template IDs 和 paths。
- TruffleHog live credential validation 默认禁用。
- report 中的所有 evidence 输出前都会经过 redactor。report 不保存 raw secret/token/body content。
- 不执行 package install、dependency script execution、arbitrary target code execution、destructive HTTP methods 或 active GraphQL introspection POSTs。

## CLI

```bash
bts-sec --target <url-or-directory> [options]
```

主要 options:

- `--target <value>` authorized URL 或 local project directory。
- `--url <value>` `vibesec scan` 的 authorized URL target。
- `--dir <path>` `vibesec scan` 的 local project directory target。
- `--api-spec <path>` passive OpenAPI/Swagger JSON 或 YAML specification scan。
- `--profile <baseline|vibe-risk>` scan profile。默认是 `baseline`。
- `--confirm-authorization` URL targets 需要。
- `--authorization-confirmation "I confirm I own or am authorized to test this target."` 推荐 authorization phrase。
- `--out <dir>` output directory。默认 `reports/latest`。
- `--rate-limit-rps <n>` built-in HTTP request rate limit。默认 `1`。
- `--timeout-ms <n>` per-request 和 adapter timeout。默认 `15000`。
- `--max-crawl-depth <n>` same-origin passive crawler depth。默认 `1`。
- `--max-crawl-pages <n>` same-origin passive crawler page cap。默认 `25`。
- `--include-external` 运行 installed external tool adapters。
- `--kev-catalog <path>` CVE enrichment 用 local CISA KEV JSON catalog。
- `--refresh-kev` 获取 public CISA KEV JSON feed。
- `--epss-csv <path>` CVE enrichment 用 local FIRST EPSS CSV。
- `--refresh-epss` 针对 reported CVEs 获取 FIRST EPSS API data。
- `--nuclei-template <path-or-id>` allowlisted Nuclei template，可重复。

## Module Layout

- `scanner-core`: target validation、orchestration、task runner、finding schema、scoring、aggregation。
- `api-scanner`: passive OpenAPI/Swagger static checks，覆盖 authentication、authorization、inventory、SSRF、mass assignment 和 resource-consumption hints。
- `web-scanner`: safe header、cookie、CORS、exposure checks、same-origin passive crawler、GraphQL static hints，以及 ZAP Baseline 和 Nuclei adapters。
- `code-scanner`: custom static rules、multiline matching、standards mappings、suppress comments、Semgrep adapter。
- `dependency-scanner`: lockfile-based SBOM、supply-chain hygiene checks、Trivy、OSV-Scanner、npm audit、pip-audit。
- `secret-scanner`: internal redaction、Gitleaks、TruffleHog adapters。
- `knowledge-base`: OWASP、OWASP API、MITRE CWE Top 25、CISA KEV enrichment、remediation guidance。
- `report-generator`: Markdown、HTML、JSON、SARIF reports。
- `vibe-scanner`: vibe-risk profile scanners，覆盖 AI agent artifacts、dependency hallucination/slopsquatting、auth/payment/database static review、public URL exposure 和 pre-agent-run checklist。

## Vibe-Risk Profile

`--profile vibe-risk` 会添加 deterministic、non-destructive checks:

- dashboard、admin、customer、support、internal pages 的 public exposure。
- client-side-only 或 missing server-side auth checks。
- missing ownership、role、user、tenant、account authorization boundaries。
- Stripe webhook signature verification 和 client-only payment success handling。
- Supabase RLS 与 Firebase open rule risks。
- public Supabase、Firebase、Clerk、Stripe、OpenAI、Resend configuration risks。
- `.cursor/rules`、`.cursorrules`、`CLAUDE.md`、`AGENTS.md`、`GEMINI.md`、`.windsurfrules`、`.cline/`、`.roo/` 和 MCP configs 等 AI coding assistant artifacts。
- dependency hallucination、import/manifest mismatch、typosquatting-like names、使用 registry metadata 时 suspiciously new packages，以及 install script risk。
- Vercel、Netlify、Replit、Lovable、Base44、Bolt、v0、Cursor-generated projects 等 platform hints。
- 不保存 sensitive raw content 的 PII、medical、financial、customer conversation、credential 和 internal-business exposure indicators。

## Report Schema

Findings 使用 normalized schema，包含 severity、confidence、category、target type、redacted evidence、optional vibe-risk metadata、OWASP Top 10:2025、OWASP LLM Top 10:2025、OWASP API Top 10:2023、CWE Top 25:2025、CISA KEV priority、remediation guidance、verification steps 和 Codex-ready remediation prompt。

Markdown、HTML、JSON、SARIF reports 包含 `Coverage & Known Gaps` matrix、每个 standard item 的 `covered` / `partial` / `not_covered` status、scanner configuration summary、suppressed findings summary、priority score、KEV/EPSS fields，以及可用时的 dependency direct/transitive context。

coverage model 是 **standards-aligned passive coverage with explicit known gaps**。`covered` 表示有 first-class passive/static check 或 enrichment path；`partial` 表示可以产生 review signals，但不能证明 weakness 不存在或可被利用；`not_covered` 表示该类别通常需要 dedicated SAST/compiler/runtime analysis 或 active authorized testing，因此 intentionally not implemented。

## OpenAPI/API Scanning

`--api-spec <openapi-json-or-yaml>` 在本地读取 OpenAPI/Swagger specs，并执行 passive/static checks:

- Missing global 或 operation-level security requirements。
- 可能需要 BOLA review 的 object-id endpoints。
- admin/internal/function-level authorization sensitive paths。
- request schemas 中的 object property exposure 和 mass assignment risk。
- 指向 SSRF risk 的 user-controlled URL fields。
- collection endpoints 缺少 pagination/rate-limit hints。
- deprecated 或 undocumented-looking endpoints。

API scanner 不发送 requests。即使同时提供 URL target，web checks 仍保持 same-origin 和 non-destructive。

## Dependency, SBOM, and Supply Chain

SBOM generation 只读取 manifests 和 lockfiles，不安装 packages。支持 `package.json`、`package-lock.json`、`pnpm-lock.yaml`、`yarn.lock`、`requirements.txt`、`Pipfile.lock`、`poetry.lock`、`go.sum`、`Cargo.lock`、`pom.xml`、`build.gradle` 和 `gradle.lockfile`。

Supply-chain hygiene checks 是 static 的，精神上对齐 OWASP SCVS。它会标记 missing lockfiles、package-manager mismatch、unpinned dependencies、git/URL dependencies、lifecycle install scripts、suspicious internal-looking namespaces 和 dependency-confusion candidates。BTS Sec 从不运行 package installs 或 arbitrary package scripts。

CVE findings 只有在提供 local catalogs 或明确使用 refresh flags 时，才会用 CISA KEV 和 FIRST EPSS enrichment。Priority score 综合 severity、KEV presence、EPSS percentile、fix availability 和 direct/transitive dependency context。

## Pre-Agent-Run Checklist

VibeSec 在 report 中增加 section，警告：

- dirty git working trees。
- missing commits。
- missing lockfiles。
- missing tests 或 auth/payment/database tests。
- risky package lifecycle scripts。
- vibe-risk profile 发现的 AI rule 和 MCP configuration risks。

`git status`、`git diff`、`npm test`、`pnpm test`、`pytest` 等 command 只是 suggestions。VibeSec 不执行 project test scripts 或 arbitrary target code。

## Agent Fix Prompts

每次 scan 也会写入 `agent-fix-prompt.md`，这是可粘贴到 Codex 或其他 AI coding agent 的 English prompt。prompt 包含 actionable findings、redacted evidence、recommended fixes、verification steps，以及禁止 exploit execution、credential validation、brute force、destructive payloads 和 out-of-scope scanning 的 safety instructions。

同一文本也会作为 `agentFixPrompt` 嵌入 `report.json`，便于 automation。

## Adding Rules

- vibe-coded 或 AI-agent workflows 特有的 static local rules 放在 `src/vibe-scanner/*`。
- generic web URL checks 放在 `src/web-scanner/*`，vibe-specific URL checks 放在 `src/vibe-scanner/url-vibe-scanner.ts`。
- mapping defaults 放在 `src/knowledge-base/mappings.ts`。
- 可被多个 rules 复用的 remediation text 放在 `src/knowledge-base/remediation.ts`。
- tests 放在 `tests/`，使用 temporary fixture projects。Rules 应 deterministic，除非 test 明确 mock，否则避免 network access。

## Known Limitations

- toolkit 是 static/passive/heuristic。它标记 risky patterns 供 review，但不证明 exploitability 或 vulnerability absence。
- suspicious dependency age 使用 supplied registry metadata，不调用 paid APIs。
- typosquatting detection intentionally conservative，需要 manual review。
- URL checks 不 submit forms、不 authenticate、不 crawl third-party links、不 mutate state、不执行 GraphQL introspection POSTs、不尝试 bypasses。
- auth/payment/database analysis 基于 framework-pattern，可能漏掉 custom abstractions。
- memory-safety CWEs 需要 built-in passive scanner 之外的 dedicated tooling。
- YAML OpenAPI parsing 有 conservative fallback；JSON 或 fully parsed OpenAPI objects 可提供更丰富的 schema analysis。

## Demo Walkthrough

demo flow 会扫描一个你拥有或获授权评估的 local sample project 和 OpenAPI file，然后在 generated HTML report 中查看 coverage 和 findings。

1. 运行 `npm install`。
2. 运行 `npm run build`。
3. 使用 `npm run scan -- scan --dir "<project-path>" --profile vibe-risk --out reports/local` 扫描 local project。
4. 如果有 OpenAPI file，加入 `--api-spec "<openapi-path>"`。
5. 在浏览器中打开 `reports\local\report.html`，查看 `Coverage & Known Gaps` 和 `Findings`。

report 顶部显示 scan target、run time、severity summary 和 scanner configuration。

![Report top](../demo-screenshots/sec-kit-flow-01-report-top.png)

滚动到 `Coverage & Known Gaps` 和 `Findings`，查看运行了哪些 checks 以及报告了什么。

![Findings section](../demo-screenshots/sec-kit-flow-02-findings.png)
