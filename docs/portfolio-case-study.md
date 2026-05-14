# BTS Sec Portfolio Case Study

BTS Sec, also presented as VibeSec in the README, is a defensive security auditing toolkit for authorized projects. It focuses on passive and static checks for AI-assisted web apps, generated codebases, OpenAPI specs, dependency manifests, local projects, and explicitly authorized URL targets.

## Positioning

BTS Sec fits the portfolio theme of safety-aware tooling design. The important story is not offensive security; it is a practical review tool for people shipping AI-built or fast-prototyped apps who need a structured way to find common risks before release.

The public framing should stay centered on:

- defensive security review
- authorized targets only
- passive/static checks by default
- redacted evidence
- explicit known gaps
- Codex-ready remediation prompts

## Problem

AI-assisted app builders and coding agents can produce working software quickly, but they often miss security boundaries around authentication, ownership checks, environment variables, webhooks, public deployment exposure, dependency hygiene, and generated configuration files.

BTS Sec addresses that gap with deterministic checks and reports that help a developer review risk without asking the scanner to exploit the target.

## Product Shape

The tool can scan:

- local project directories
- OpenAPI or Swagger specifications
- authorized same-origin URL targets
- dependency manifests and lockfiles
- AI assistant rule files and MCP/config artifacts

It produces multiple report formats:

- Markdown
- HTML
- JSON
- SARIF
- agent remediation prompt

The generated `agent-fix-prompt.md` is designed to hand findings back to Codex or another coding agent with safety constraints and verification steps.

## Safety Boundaries

BTS Sec should always be documented as a defensive toolkit. The repository should avoid language that implies bypassing, exploiting, credential validation, brute force, destructive payloads, or unauthorized scanning.

Important boundaries:

- URL scans require explicit authorization confirmation.
- Built-in HTTP checks are same-origin and rate-limited.
- Built-in web checks use non-mutating methods.
- External adapters are disabled unless explicitly requested.
- Evidence is redacted before report output.
- The scanner reports likely risks and known gaps; it does not prove exploitability.

## Implementation Notes

The codebase is a TypeScript CLI organized into scanner modules: core orchestration, web scanner, API scanner, code scanner, dependency scanner, secret scanner, vibe-risk scanner, knowledge base mappings, and report generation.

Tests cover target validation, no-destructive-mode expectations, passive crawler behavior, secret redaction, OpenAPI scanning, dependency/SBOM checks, report generation, Nuclei allowlisting, and adapter failure handling.

## Portfolio Value

BTS Sec demonstrates:

- defensive security tooling
- AI-workflow-aware risk detection
- static/passive scanner architecture
- standards mapping and report generation
- secret redaction and evidence handling
- safety constraints around authorized testing
- agent handoff prompts for remediation

## Next Steps

- Keep README examples strictly authorized and defensive.
- Add a sanitized sample project and sample HTML report.
- Keep exploit-like language out of public descriptions and topics.
- Expand documentation around known gaps and false-positive review.
- Keep validation commands and expected report outputs easy to reproduce.
