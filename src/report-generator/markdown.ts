import { ScanResult } from "../scanner-core/types";
import { sanitizeFindingsForReport } from "./sanitize";
import { targetLabel } from "./target-label";

export function renderMarkdownReport(result: ScanResult): string {
  const findings = sanitizeFindingsForReport(result.findings);
  const target = targetLabel(result.target);
  const lines = [
    "# Security Audit Report",
    "",
    `- Target: \`${target}\``,
    `- Target type: \`${result.target.kind}\``,
    `- Started: ${result.startedAt}`,
    `- Finished: ${result.finishedAt}`,
    "",
    "## Severity Summary",
    "",
    "| Severity | Count |",
    "| --- | ---: |",
    `| Critical | ${result.summary.critical} |`,
    `| High | ${result.summary.high} |`,
    `| Medium | ${result.summary.medium} |`,
    `| Low | ${result.summary.low} |`,
    `| Info | ${result.summary.info} |`,
    "",
    "## Pre-Agent-Run Checklist",
    "",
    ...preAgentChecklistLines(findings),
    "",
    "## Findings",
    ""
  ];

  if (findings.length === 0) {
    lines.push("No findings were reported by the enabled safe checks.", "");
    return lines.join("\n");
  }

  for (const finding of findings) {
    lines.push(
      `### ${finding.title}`,
      "",
      `- ID: \`${finding.id}\``,
      `- Severity: \`${finding.severity}\``,
      `- Confidence: \`${finding.confidence}\``,
      `- Category: \`${finding.category}\``,
      `- Target type: \`${finding.targetType}\``,
      `- Source: \`${finding.sourceTool}\``,
      `- Target: \`${finding.target}\``
    );
    if (finding.vibeRiskCategory) lines.push(`- Vibe risk category: \`${finding.vibeRiskCategory}\``);
    if (finding.affectedDataType) lines.push(`- Affected data type: \`${finding.affectedDataType}\``);
    if (finding.platformHint) lines.push(`- Platform hint: \`${finding.platformHint}\``);
    if (finding.file) lines.push(`- File: \`${finding.file}${finding.line ? `:${finding.line}` : ""}\``);
    if (finding.endpoint) lines.push(`- Endpoint: \`${finding.endpoint}\``);
    if (finding.cve) lines.push(`- CVE: \`${finding.cve}\`${finding.kevKnownExploited ? " (CISA KEV known exploited)" : ""}`);
    lines.push(
      `- OWASP: ${formatMappings(finding.owaspMapping)}`,
      `- CWE: ${formatMappings(finding.cweMapping)}`,
      "",
      "**Evidence**",
      "",
      codeBlock(finding.redactedEvidence),
      "",
      "**Recommendation**",
      "",
      finding.recommendation,
      "",
      "**Verification**",
      "",
      finding.verification,
      ""
    );
  }

  return lines.join("\n");
}

function preAgentChecklistLines(findings: ReturnType<typeof sanitizeFindingsForReport>): string[] {
  const checklistFindings = findings.filter((finding) => finding.vibeRiskCategory === "pre-agent-run-checklist");
  if (checklistFindings.length === 0) {
    return ["No pre-agent checklist warnings were reported."];
  }
  return checklistFindings.map((finding) => `- [${finding.severity}] ${finding.title}: ${finding.verification}`);
}

function formatMappings(mappings: Array<{ id: string; name: string }>): string {
  return mappings.length > 0
    ? mappings.map((mapping) => `\`${mapping.id}\` ${mapping.name}`).join(", ")
    : "None";
}

function codeBlock(value: string): string {
  return ["```", value || "No evidence text provided.", "```"].join("\n");
}
