# BTS Sec

BTS Sec is a defensive security auditing toolkit for authorized web services and local web application projects.

It defaults to passive, non-destructive checks, keeps logs local, redacts detected secrets, and refuses URL scans unless authorization is explicitly confirmed.

## Quick Start

```bash
npm install
npm run build
npm run scan -- --target ./path/to/project --out reports/local
npm run scan -- --target https://example.internal --confirm-authorization --out reports/url
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
- `--confirm-authorization` required for URL targets.
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

## Agent Fix Prompts

Every scan also writes `agent-fix-prompt.md`, an English prompt that can be pasted into Codex or another AI coding agent for the affected application. The prompt includes actionable findings, redacted evidence, recommended fixes, verification steps, and safety instructions that prohibit exploit execution, credential validation, brute force, destructive payloads, and out-of-scope scanning.

The same text is also embedded in `report.json` as `agentFixPrompt` for automation.
