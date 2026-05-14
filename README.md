# VibeSec / BTS Sec

> Passive, non-destructive security auditing for vibe-coded and AI-assisted web projects.

[English](#english) | [한국어](#한국어) | [中文](#中文) | [日本語](#日本語)

| Area | Detail |
|---|---|
| Scan style | Passive/static checks by default |
| Targets | Authorized URLs, local projects, OpenAPI specs |
| Reports | Markdown, HTML, JSON, SARIF, and Codex-ready fix prompts |
| Safety rule | No exploit execution, brute force, credential theft, or destructive payloads |

## English

VibeSec is a defensive security auditing toolkit for vibe-coded web applications, AI-assisted codebases, and authorized web services. It focuses on issues commonly introduced by AI coding agents, low-code AI app builders, generated auth/database/payment flows, and public-by-default deployments.

It defaults to passive, non-destructive checks, keeps logs local, redacts detected secrets, and refuses URL scans unless authorization is explicitly confirmed.

## Quick Start

```bash
npm install
npm run build
vibesec scan --dir ./path/to/project --profile vibe-risk --out reports/local
vibesec scan --api-spec ./openapi.json --out reports/api
vibesec scan --url https://example.internal --profile vibe-risk --authorization-confirmation "I confirm I own or am authorized to test this target." --out reports/url
vibesec scan --url https://example.internal --dir ./path/to/project --api-spec ./openapi.yaml --profile vibe-risk --authorization-confirmation "I confirm I own or am authorized to test this target." --out reports/full
```

Generated reports:

- `report.md`
- `report.html`
- `report.json`
- `report.sarif`
- `agent-fix-prompt.md`

## Safety Model

- No exploit execution, brute force, credential theft, destructive payloads, or data extraction routines are implemented.
- URL scanning is limited to the exact user-provided origin. The passive crawler follows same-origin links only.
- URL scanning requires explicit authorization confirmation. Prefer `--authorization-confirmation "I confirm I own or am authorized to test this target."`.
- Built-in HTTP checks are rate-limited with `--rate-limit-rps` and default to one request per second.
- Built-in web checks use only `GET`, `HEAD`, and `OPTIONS`; they do not submit forms, authenticate, mutate state, or run exploit payloads.
- External adapters are isolated. Missing tools are reported as informational adapter findings instead of failing the whole scan.
- External adapters remain disabled unless `--include-external` is provided.
- Nuclei execution is restricted to allowlisted template IDs and paths.
- TruffleHog live credential validation is disabled by default.
- All evidence in reports is passed through the redactor before output. Reports do not store raw secret/token/body content.
- Package install, dependency script execution, arbitrary target code execution, destructive HTTP methods, and active GraphQL introspection POSTs are not performed.

## CLI

```bash
bts-sec --target <url-or-directory> [options]
```

Options:

- `--target <value>` authorized URL or local project directory.
- `--url <value>` authorized URL target for `vibesec scan`.
- `--dir <path>` local project directory target for `vibesec scan`.
- `--api-spec <path>` passive OpenAPI/Swagger JSON or YAML specification scan.
- `--profile <baseline|vibe-risk>` scan profile. Default: `baseline`.
- `--confirm-authorization` required for URL targets.
- `--authorization-confirmation "I confirm I own or am authorized to test this target."` recommended exact URL authorization phrase.
- `--out <dir>` output directory. Default: `reports/latest`.
- `--rate-limit-rps <n>` built-in HTTP request rate limit. Default: `1`.
- `--timeout-ms <n>` per-request and adapter timeout. Default: `15000`.
- `--max-crawl-depth <n>` same-origin passive crawler depth. Default: `1`.
- `--max-crawl-pages <n>` same-origin passive crawler page cap. Default: `25`.
- `--include-external` run installed external tool adapters.
- `--kev-catalog <path>` local CISA KEV JSON catalog for CVE enrichment.
- `--refresh-kev` fetch the public CISA KEV JSON feed for CVE enrichment.
- `--epss-csv <path>` local FIRST EPSS CSV for CVE enrichment.
- `--refresh-epss` fetch FIRST EPSS API data for reported CVEs with timeout and local report-cache use.
- `--nuclei-template <path-or-id>` allowlisted Nuclei template. Repeatable.

## Module Layout

- `scanner-core`: target validation, orchestration, task runner, finding schema, scoring, aggregation.
- `api-scanner`: passive OpenAPI/Swagger static checks for authentication, authorization, inventory, SSRF, mass assignment, and resource-consumption hints.
- `web-scanner`: safe header, cookie, CORS, exposure checks, same-origin passive crawler, GraphQL static hints, plus ZAP Baseline and Nuclei adapters.
- `code-scanner`: custom static rules with multiline matching, standards mappings, suppress comments, and Semgrep adapter.
- `dependency-scanner`: lockfile-based SBOM, supply-chain hygiene checks, Trivy, OSV-Scanner, npm audit, and pip-audit.
- `secret-scanner`: internal redaction, Gitleaks, and TruffleHog adapters.
- `knowledge-base`: OWASP, OWASP API, MITRE CWE Top 25, CISA KEV enrichment, remediation guidance.
- `report-generator`: Markdown, HTML, JSON, and SARIF reports.
- `vibe-scanner`: vibe-risk profile scanners for AI agent artifacts, dependency hallucination/slopsquatting, auth/payment/database static review, public URL exposure, and pre-agent-run checklist.

## Vibe-Risk Profile

`--profile vibe-risk` adds deterministic, non-destructive checks for:

- Public exposure of dashboard, admin, customer, support, and internal pages.
- Client-side-only or missing server-side auth checks.
- Missing ownership, role, user, tenant, or account authorization boundaries.
- Stripe webhook signature verification and client-only payment success handling.
- Supabase RLS and Firebase open rule risks.
- Public Supabase, Firebase, Clerk, Stripe, OpenAI, and Resend configuration risks.
- AI coding assistant artifacts including `.cursor/rules`, `.cursorrules`, `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.windsurfrules`, `.cline/`, `.roo/`, and MCP configs.
- Dependency hallucination, import/manifest mismatch, typosquatting-like names, suspiciously new packages when registry metadata is supplied, and install script risk.
- Platform hints for Vercel, Netlify, Replit, Lovable, Base44, Bolt, v0, Cursor-generated projects, and related builder environments.
- PII, medical, financial, customer conversation, credential, and internal-business exposure indicators without storing sensitive raw content.

## Report Schema

Findings use a normalized schema with severity, confidence, category, target type, redacted evidence, optional vibe-risk metadata, OWASP Top 10:2025, OWASP LLM Top 10:2025, OWASP API Top 10:2023, CWE Top 25:2025, CISA KEV priority, remediation guidance, verification steps, and a Codex-ready remediation prompt.

Reports in Markdown, HTML, JSON, and SARIF include:

- `Coverage & Known Gaps` matrix for OWASP Top 10:2025, OWASP API Security Top 10:2023, MITRE CWE Top 25:2025, and MITRE CWE Top 10 KEV Weaknesses:2025.
- Status per standard item: `covered`, `partial`, or `not_covered`.
- Scanner configuration summary, suppressed findings summary, priority score, KEV/EPSS fields, and dependency direct/transitive context when available.
- SARIF properties for `owasp`, `apiTop10`, `cwe`, `kevKnownExploited`, `epss`, `epssPercentile`, and `priorityScore`.

The coverage model is **standards-aligned passive coverage with explicit known gaps**. `covered` means BTS Sec has a first-class passive/static check or enrichment path for that standard item. `partial` means BTS Sec can produce review signals but does not prove the weakness is absent or exploitable. `not_covered` means the toolkit intentionally does not implement meaningful built-in detection for that weakness class, typically because it requires dedicated SAST/compiler/runtime analysis or active authorized testing.

## OpenAPI/API Scanning

`--api-spec <openapi-json-or-yaml>` reads OpenAPI/Swagger specs locally and performs passive/static checks for:

- Missing global or operation-level security requirements.
- Object-id endpoints likely requiring BOLA checks.
- Admin/internal/function-level authorization sensitive paths.
- Object property exposure and mass assignment risk in request schemas.
- User-controlled URL fields indicating SSRF risk.
- Missing pagination/rate-limit hints for collection endpoints.
- Deprecated or undocumented-looking endpoints.

The API scanner does not send requests. If a URL target is also supplied, web checks still remain same-origin and non-destructive.

## Dependency, SBOM, and Supply Chain

SBOM generation reads manifests and lockfiles without installing packages. Supported inputs include `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `go.sum`, `Cargo.lock`, `pom.xml`, `build.gradle`, and `gradle.lockfile`.

Supply-chain hygiene checks are static and OWASP SCVS-aligned in spirit. They flag missing lockfiles, package-manager mismatch, unpinned dependencies, git/URL dependencies, lifecycle install scripts, suspicious internal-looking namespaces, and dependency-confusion candidates. BTS Sec never runs package installs or arbitrary package scripts.

CVE findings can be enriched with CISA KEV and FIRST EPSS only when local catalogs are supplied or refresh flags are explicitly used. Priority score combines severity, KEV presence, EPSS percentile, fix availability, and direct/transitive dependency context.

## Pre-Agent-Run Checklist

VibeSec adds a report section that warns about:

- Dirty git working trees.
- Missing commits.
- Missing lockfiles.
- Missing tests or auth/payment/database tests.
- Risky package lifecycle scripts.
- AI rule and MCP configuration risks found by the vibe-risk profile.

Suggested commands such as `git status`, `git diff`, `npm test`, `pnpm test`, and `pytest` are suggestions only. VibeSec does not execute project test scripts or arbitrary target code.

## Agent Fix Prompts

Every scan also writes `agent-fix-prompt.md`, an English prompt that can be pasted into Codex or another AI coding agent for the affected application. The prompt includes actionable findings, redacted evidence, recommended fixes, verification steps, and safety instructions that prohibit exploit execution, credential validation, brute force, destructive payloads, and out-of-scope scanning.

The same text is also embedded in `report.json` as `agentFixPrompt` for automation.

## Adding Rules

- Add static local rules to `src/vibe-scanner/*` when the rule is specific to vibe-coded or AI-agent workflows.
- Add generic web URL checks to `src/web-scanner/*` or vibe-specific URL checks to `src/vibe-scanner/url-vibe-scanner.ts`.
- Add mapping defaults in `src/knowledge-base/mappings.ts`.
- Add remediation text in `src/knowledge-base/remediation.ts` when multiple rules can reuse the guidance.
- Add tests under `tests/` using temporary fixture projects. Rules should be deterministic and avoid network access unless the test explicitly mocks it.

## Known Limitations

- The toolkit is static/passive and heuristic. It flags risky patterns for review; it does not prove exploitability or absence of vulnerability.
- Suspicious dependency age uses supplied registry metadata and does not call paid APIs.
- Typosquatting detection is intentionally conservative and should be reviewed manually.
- URL checks do not submit forms, authenticate, crawl third-party links, mutate state, perform GraphQL introspection POSTs, or attempt bypasses.
- Auth/payment/database analysis is framework-pattern based and can miss custom abstractions.
- Memory-safety CWEs such as use-after-free and out-of-bounds read/write require dedicated tooling beyond the built-in passive scanner.
- YAML OpenAPI parsing has a conservative fallback; JSON or fully parsed OpenAPI objects provide richer schema analysis.
## Demo Walkthrough

The demo flow scans a local sample project and an OpenAPI file, then reviews coverage and findings in the generated HTML report.

1. Run `npm install`.
2. Run `npm run build`.
3. Scan a local project you own or are authorized to assess with `npm run scan -- scan --dir "<project-path>" --profile vibe-risk --out reports/local`.
4. If an OpenAPI file is available, include `--api-spec "<openapi-path>"`.
5. Open `reports\local\report.html` in a browser and review `Coverage & Known Gaps` and `Findings`.

The top of the report shows the scan target, run time, severity summary, and scanner configuration.

![Report top](docs/demo-screenshots/sec-kit-flow-01-report-top.png)

Scroll down to `Coverage & Known Gaps` and `Findings` to see which checks ran and what was reported.

![Findings section](docs/demo-screenshots/sec-kit-flow-02-findings.png)

---

## 한국어

VibeSec / BTS Sec는 vibe-coded 웹 애플리케이션, AI-assisted 코드베이스, 승인된 웹 서비스를 위한 방어적 보안 감사 도구입니다. AI 코딩 에이전트, low-code AI app builder, 자동 생성된 인증/데이터베이스/결제 흐름, 기본 공개 배포에서 자주 생기는 위험을 점검합니다.

기본 동작은 passive, non-destructive 검사입니다. 로그는 로컬에 남기고, 감지된 secret은 redaction하며, URL 스캔은 명시적 승인 문구 없이는 실행하지 않습니다.

### 빠른 시작

```bash
npm install
npm run build
vibesec scan --dir ./path/to/project --profile vibe-risk --out reports/local
vibesec scan --api-spec ./openapi.json --out reports/api
```

### 안전 모델

- exploit 실행 없음
- brute force 없음
- credential theft 없음
- destructive payload 없음
- URL 스캔은 사용자가 지정한 same-origin 범위로 제한
- URL 스캔에는 명시적 authorization confirmation 필요
- 보고서에는 raw secret, token, response body를 저장하지 않음

### 데모 흐름

1. `npm install`을 실행합니다.
2. `npm run build`를 실행합니다.
3. 본인 소유 또는 점검 허가를 받은 로컬 프로젝트를 대상으로 `npm run scan -- scan --dir "<project-path>" --profile vibe-risk --out reports/local`을 실행합니다.
4. OpenAPI 파일이 있으면 `--api-spec "<openapi-path>"`를 함께 넣습니다.
5. `reports\local\report.html`을 브라우저에서 열고 `Coverage & Known Gaps`, `Findings`를 확인합니다.

---

## 中文

VibeSec / BTS Sec 是一个防御性安全审计工具，用于 vibe-coded Web 应用、AI 辅助代码库和已授权的 Web 服务。它关注 AI coding agent、low-code AI app builder、自动生成的认证/数据库/支付流程以及默认公开部署中常见的风险。

默认行为是 passive、non-destructive 检查。日志保留在本地，检测到的 secret 会被 redaction，URL 扫描必须有明确授权确认。

### 快速开始

```bash
npm install
npm run build
vibesec scan --dir ./path/to/project --profile vibe-risk --out reports/local
vibesec scan --api-spec ./openapi.json --out reports/api
```

### 安全模型

- 不执行 exploit
- 不进行 brute force
- 不窃取 credential
- 不发送 destructive payload
- URL 扫描限制在用户提供的 same-origin 范围内
- URL 扫描需要明确的 authorization confirmation
- 报告不会保存 raw secret、token 或 response body

### 演示流程

1. 运行 `npm install`。
2. 运行 `npm run build`。
3. 对你拥有或被授权评估的本地项目运行 `npm run scan -- scan --dir "<project-path>" --profile vibe-risk --out reports/local`。
4. 如果有 OpenAPI 文件，加入 `--api-spec "<openapi-path>"`。
5. 在浏览器中打开 `reports\local\report.html`，查看 `Coverage & Known Gaps` 和 `Findings`。

---

## 日本語

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
