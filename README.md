# VibeSec / BTS Sec

> Passive, non-destructive security auditing for vibe-coded and AI-assisted web projects.

[English](README.md) | [한국어](docs/readme/README.ko.md) | [中文](docs/readme/README.zh-CN.md) | [日本語](docs/readme/README.ja.md)

| Area | Detail |
|---|---|
| Scan style | Passive/static checks by default |
| Targets | Authorized URLs, local projects, OpenAPI specs |
| Reports | Markdown, HTML, JSON, SARIF, and Codex-ready fix prompts |
| Safety rule | No exploit execution, brute force, credential theft, or destructive payloads |

## Preview

The generated HTML report summarizes scan configuration, coverage, known gaps, and findings.

![Report top](docs/demo-screenshots/sec-kit-flow-01-report-top.png)

<details>
<summary>View full demo walkthrough</summary>

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

</details>

## Quick Start

```bash
npm install
npm run build
vibesec scan --dir ./path/to/project --profile vibe-risk --out reports/local
```

## Documentation

- [Full English README](docs/readme/README.en.md)
- [한국어 README](docs/readme/README.ko.md)
- [中文 README](docs/readme/README.zh-CN.md)
- [日本語 README](docs/readme/README.ja.md)

## Notes

The root README is intentionally short. Detailed setup, architecture, limitations, and localized walkthroughs live in the linked README files.
