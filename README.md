# VibeSec / BTS Sec

VibeSec is a defensive security auditing toolkit for vibe-coded web applications, AI-assisted codebases, and authorized web services. It focuses on issues commonly introduced by AI coding agents, low-code AI app builders, generated auth/database/payment flows, and public-by-default deployments.

It defaults to passive, non-destructive checks, keeps logs local, redacts detected secrets, and refuses URL scans unless authorization is explicitly confirmed.

## Quick Start

```bash
npm install
npm run build
vibesec scan --dir ./path/to/project --profile vibe-risk --out reports/local
vibesec scan --url https://example.internal --profile vibe-risk --authorization-confirmation "I confirm I own or am authorized to test this target." --out reports/url
vibesec scan --url https://example.internal --dir ./path/to/project --profile vibe-risk --authorization-confirmation "I confirm I own or am authorized to test this target." --out reports/full
```

Generated reports:

- `report.md`
- `report.html`
- `report.json`
- `report.sarif`
- `agent-fix-prompt.md`

## Safety Model

- No exploit execution, brute force, credential theft, destructive payloads, or data extraction routines are implemented.
- URL scanning is limited to the exact user-provided origin and approved allowlisted paths.
- URL scanning requires `--confirm-authorization`.
- Built-in HTTP checks are rate-limited with `--rate-limit-rps` and default to one request per second.
- External adapters are isolated. Missing tools are reported as informational adapter findings instead of failing the whole scan.
- Nuclei execution is restricted to allowlisted template IDs and paths.
- TruffleHog live credential validation is disabled by default.
- All evidence in reports is passed through the redactor before output.

## CLI

```bash
bts-sec --target <url-or-directory> [options]
```

Options:

- `--target <value>` authorized URL or local project directory.
- `--url <value>` authorized URL target for `vibesec scan`.
- `--dir <path>` local project directory target for `vibesec scan`.
- `--profile <baseline|vibe-risk>` scan profile. Default: `baseline`.
- `--confirm-authorization` required for URL targets.
- `--authorization-confirmation "I confirm I own or am authorized to test this target."` recommended exact URL authorization phrase.
- `--out <dir>` output directory. Default: `reports/latest`.
- `--rate-limit-rps <n>` built-in HTTP request rate limit. Default: `1`.
- `--timeout-ms <n>` per-request and adapter timeout. Default: `15000`.
- `--include-external` run installed external tool adapters.
- `--kev-catalog <path>` local CISA KEV JSON catalog for CVE enrichment.
- `--refresh-kev` fetch the public CISA KEV JSON feed for CVE enrichment.
- `--nuclei-template <path-or-id>` allowlisted Nuclei template. Repeatable.

## Module Layout

- `scanner-core`: target validation, orchestration, task runner, finding schema, scoring, aggregation.
- `web-scanner`: safe header, cookie, CORS, exposure checks plus ZAP Baseline and Nuclei adapters.
- `code-scanner`: custom static rules and Semgrep adapter.
- `dependency-scanner`: Trivy, OSV-Scanner, npm audit, pip-audit, and SBOM support.
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

- The MVP is static and heuristic. It flags risky patterns for review; it does not prove exploitability.
- Suspicious dependency age uses supplied registry metadata and does not call paid APIs.
- Typosquatting detection is intentionally conservative and should be reviewed manually.
- URL checks do not submit forms, authenticate, crawl third-party links, mutate state, or attempt bypasses.
- Auth/payment/database analysis is framework-pattern based and can miss custom abstractions.
