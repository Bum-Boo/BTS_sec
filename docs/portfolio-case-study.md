# BTS Sec Portfolio Case Study

## Problem

AI-assisted app builders and coding agents can produce working software quickly, but they often miss security boundaries around authentication, ownership checks, environment variables, webhooks, public deployment exposure, dependency hygiene, and generated configuration files.

## Target Users

- Developers reviewing AI-assisted or fast-prototyped web apps.
- Solo builders preparing a release checklist.
- Teams that want passive/static review signals before deeper security testing.
- Codex users who want structured remediation prompts.

## Design Goal

Provide a defensive, authorized-use-only scanner that surfaces common release risks without exploiting targets or storing sensitive raw evidence.

## Core Workflow

1. Install dependencies and build the CLI.
2. Scan a local project directory, OpenAPI spec, or explicitly authorized URL.
3. Review Markdown, HTML, JSON, SARIF, and `agent-fix-prompt.md` outputs.
4. Use the report to prioritize manual fixes.
5. Hand the safe remediation prompt to Codex when useful.

## Architecture Summary

The TypeScript CLI is organized into scanner modules: core orchestration, web scanner, API scanner, code scanner, dependency scanner, secret scanner, vibe-risk scanner, knowledge-base mappings, and report generation.

## Safety / Privacy Decisions

- URL scans require explicit authorization confirmation.
- Built-in HTTP checks are same-origin and rate-limited.
- Built-in web checks use non-mutating methods.
- External adapters are disabled unless explicitly requested.
- Evidence is redacted before report output.
- The scanner reports likely risks and known gaps; it does not prove exploitability.

## Technical Highlights

- Passive/static scan orchestration.
- Vibe-risk profile for AI-assisted app artifacts.
- OpenAPI and dependency review paths.
- Secret redaction.
- SARIF report output.
- Codex-ready remediation prompt generation.
- Tests around no-destructive-mode expectations and adapter behavior.

## Current Limitations

- Findings are heuristic and require manual review.
- The tool does not exploit targets or prove vulnerabilities.
- Some weakness classes require dedicated SAST, compiler, runtime, or active authorized testing beyond this toolkit.
- Public sample report fixtures still need to be added.

## Next Steps

- Add a sanitized sample project and sample HTML report.
- Keep README examples strictly authorized and defensive.
- Expand documentation around false positives and known gaps.
- Keep exploit-like language out of public descriptions and topics.

## Portfolio Value

BTS Sec demonstrates defensive security tooling, AI-workflow-aware risk detection, static/passive scanner architecture, standards mapping, secret redaction, safety constraints around authorized testing, and agent handoff prompts for remediation.
