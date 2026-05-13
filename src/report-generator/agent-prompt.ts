import { ScanResult, Severity } from "../scanner-core/types";
import { sanitizeFindingsForReport } from "./sanitize";
import { targetLabel } from "./target-label";

const ACTIONABLE_SEVERITIES = new Set<Severity>(["low", "medium", "high", "critical"]);

export function renderAgentFixPrompt(result: ScanResult): string {
  const target = targetLabel(result.target);
  const actionableFindings = sanitizeFindingsForReport(result.findings)
    .filter((finding) => ACTIONABLE_SEVERITIES.has(finding.severity))
    .filter((finding) => finding.category !== "adapter");

  const lines = [
    "# Agent Fix Prompt",
    "",
    "You are working on the application that was scanned by a defensive security auditing tool. Fix the reported issues with minimal, production-quality code or configuration changes.",
    "",
    "## Context",
    "",
    `- Target: ${target}`,
    `- Target type: ${result.target.kind}`,
    `- Scan started: ${result.startedAt}`,
    `- Scan finished: ${result.finishedAt}`,
    `- Critical: ${result.summary.critical}`,
    `- High: ${result.summary.high}`,
    `- Medium: ${result.summary.medium}`,
    `- Low: ${result.summary.low}`,
    `- Info: ${result.summary.info}`,
    "",
    "## Safety Requirements",
    "",
    "- Do not run exploits, brute force, credential validation, credential theft, destructive payloads, or data extraction.",
    "- Do not scan or modify third-party targets outside the explicitly provided application scope.",
    "- Do not remove functionality just to silence a finding unless the behavior is demonstrably unused and safe to remove.",
    "- Do not hardcode secrets or print sensitive values in logs.",
    "- Keep changes focused on the findings below and preserve existing project conventions.",
    "",
    "## Task",
    "",
    "1. Inspect the application code and deployment configuration relevant to the findings.",
    "2. Implement fixes for each actionable finding below.",
    "3. Add or update focused tests where the project has an appropriate test pattern.",
    "4. Run the relevant build, test, lint, or framework verification commands.",
    "5. Report the changed files, verification commands, and any findings that could not be fully fixed.",
    "",
    "## Actionable Findings",
    ""
  ];

  if (actionableFindings.length === 0) {
    lines.push("No actionable low-or-higher findings were reported. Review informational findings separately if needed.", "");
    return lines.join("\n");
  }

  actionableFindings.forEach((finding, index) => {
    lines.push(
      `### ${index + 1}. ${finding.title}`,
      "",
      `- ID: ${finding.id}`,
      `- Severity: ${finding.severity}`,
      `- Confidence: ${finding.confidence}`,
      `- Category: ${finding.category}`,
      `- Source tool: ${finding.sourceTool}`,
      `- Target: ${finding.target}`
    );

    if (finding.file) {
      lines.push(`- File: ${finding.file}${finding.line ? `:${finding.line}` : ""}`);
    }
    if (finding.endpoint) {
      lines.push(`- Endpoint: ${finding.endpoint}`);
    }
    if (finding.cve) {
      lines.push(`- CVE: ${finding.cve}${finding.kevKnownExploited ? " (CISA KEV known exploited)" : ""}`);
    }
    lines.push(
      `- OWASP mapping: ${formatMappings(finding.owaspMapping)}`,
      `- CWE mapping: ${formatMappings(finding.cweMapping)}`,
      "",
      "Evidence:",
      fenced(finding.redactedEvidence || "No evidence text provided."),
      "",
      "Recommended fix:",
      finding.recommendation,
      "",
      "Verification expected:",
      finding.verification,
      ""
    );
  });

  lines.push(
    "## Final Response Format",
    "",
    "Return a concise implementation summary with:",
    "",
    "- Files changed",
    "- Findings fixed",
    "- Verification commands and results",
    "- Remaining risks or follow-up work"
  );

  return lines.join("\n");
}

function formatMappings(mappings: Array<{ id: string; name: string }>): string {
  return mappings.length > 0
    ? mappings.map((mapping) => `${mapping.id} ${mapping.name}`).join(", ")
    : "None";
}

function fenced(value: string): string {
  return ["```", value, "```"].join("\n");
}
