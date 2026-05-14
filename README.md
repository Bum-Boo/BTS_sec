# BTS Sec / VibeSec

> Defensive security audit toolkit for authorized web and local projects.

[Overview](README.md) | [English](docs/readme/README.en.md) | [Korean](docs/readme/README.ko.md) | [Chinese](docs/readme/README.zh-CN.md) | [Japanese](docs/readme/README.ja.md)

| Area | Detail |
|---|---|
| Scan style | Passive/static checks by default |
| Targets | Authorized URLs, local projects, OpenAPI specs |
| Reports | Markdown, HTML, JSON, SARIF, and Codex-ready fix prompts |
| Safety rule | No exploit execution, brute force, credential theft, or destructive payloads |

## Authorized Use Only

Use BTS Sec only on projects, URLs, APIs, and codebases you own or are explicitly authorized to assess. URL scans require authorization confirmation and stay same-origin. The tool is designed for defensive review and release readiness, not offensive testing.

## What It Checks

- AI-assisted and vibe-coded app risks.
- Public dashboard, admin, customer, support, and internal page exposure.
- Client-only or missing server-side auth patterns.
- Ownership, role, user, tenant, and account authorization hints.
- Stripe webhook and payment-flow static risks.
- Supabase RLS and Firebase rule risks.
- Public Supabase, Firebase, Clerk, Stripe, OpenAI, and Resend config exposure.
- OpenAPI auth, BOLA, sensitive path, SSRF, mass-assignment, and pagination/rate-limit hints.
- Dependency lockfile, SBOM, supply-chain, and package hygiene issues.
- Secret patterns with redacted evidence.
- AI assistant artifacts and MCP/config review signals.

## What It Does Not Do

- Does not exploit targets.
- Does not brute force.
- Does not steal, validate, or exfiltrate credentials.
- Does not submit forms, authenticate, mutate state, or run destructive payloads.
- Does not crawl third-party links.
- Does not prove exploitability or prove that a weakness is absent.
- Does not replace a full security review for production systems.

## Safety Model

- Built-in HTTP checks use only `GET`, `HEAD`, and `OPTIONS`.
- URL scans are rate-limited and same-origin.
- External adapters are disabled unless `--include-external` is provided.
- Nuclei execution is restricted to allowlisted templates.
- TruffleHog live credential validation is disabled by default.
- Evidence is redacted before report output.
- Package installs, dependency scripts, arbitrary target code execution, destructive HTTP methods, and active GraphQL introspection POSTs are not performed.

## Example Output Report

The generated HTML report summarizes scan configuration, coverage, known gaps, and findings.

![Report top](docs/demo-screenshots/sec-kit-flow-01-report-top.png)

![Findings section](docs/demo-screenshots/sec-kit-flow-02-findings.png)

TODO: add a sanitized sample project and checked-in sample report fixture for public review.

## CLI Quick Start

```bash
npm install
npm run build
npm run scan -- scan --dir ./path/to/project --profile vibe-risk --out reports/local
```

Authorized URL scan example:

```bash
npm run scan -- scan --url https://example.internal --profile vibe-risk --authorization-confirmation "I confirm I own or am authorized to test this target." --out reports/url
```

Generated reports:

- `report.md`
- `report.html`
- `report.json`
- `report.sarif`
- `agent-fix-prompt.md`

## Module Layout

- `scanner-core`: target validation, orchestration, scoring, aggregation.
- `api-scanner`: passive OpenAPI/Swagger checks.
- `web-scanner`: safe headers, cookies, CORS, exposure checks, passive crawler, adapters.
- `code-scanner`: static local code rules and Semgrep adapter.
- `dependency-scanner`: SBOM and supply-chain hygiene checks.
- `secret-scanner`: redaction, internal patterns, Gitleaks, TruffleHog adapter.
- `knowledge-base`: standards mappings and remediation text.
- `report-generator`: Markdown, HTML, JSON, SARIF, and agent prompt outputs.
- `vibe-scanner`: AI-agent and vibe-risk profile checks.

## Documentation

- [English README](docs/readme/README.en.md)
- [Korean README](docs/readme/README.ko.md)
- [Chinese README](docs/readme/README.zh-CN.md)
- [Japanese README](docs/readme/README.ja.md)
- [Portfolio case study](docs/portfolio-case-study.md)

## Status

BTS Sec is a defensive, heuristic, passive/static toolkit. Findings should be reviewed manually and verified through safe, authorized follow-up.
