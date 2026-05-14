import { buildCoverageReport, CoverageReport } from "../knowledge-base/standards";
import { ScanResult } from "../scanner-core/types";
import { sanitizeFindingsForReport } from "./sanitize";
import { targetLabel } from "./target-label";

export function renderMarkdownReport(result: ScanResult): string {
  const findings = sanitizeFindingsForReport(result.findings);
  const target = targetLabel(result.target);
  const coverage = coverageFor(result, findings);
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
    "## Scanner Configuration",
    "",
    ...scannerConfigurationLines(result),
    "",
    "## Coverage & Known Gaps",
    "",
    ...coverageLines(coverage),
    "",
    "## Suppressed Findings Summary",
    "",
    ...suppressedLines(result),
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
      `- Priority score: \`${finding.priorityScore}\``,
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
    if (finding.cvssScore !== undefined) lines.push(`- CVSS: \`${finding.cvssScore}\`${finding.cvssVector ? ` \`${finding.cvssVector}\`` : ""}`);
    if (finding.epssScore !== undefined || finding.epssPercentile !== undefined) {
      lines.push(`- EPSS: score \`${finding.epssScore ?? "unknown"}\`, percentile \`${finding.epssPercentile ?? "unknown"}\``);
    }
    if (finding.dependencyName) {
      lines.push(`- Dependency: \`${finding.dependencyName}${finding.dependencyVersion ? `@${finding.dependencyVersion}` : ""}\` (${finding.dependencyRelation ?? "unknown"})`);
    }
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

function scannerConfigurationLines(result: ScanResult): string[] {
  const config = result.metadata.scanOptions as Record<string, unknown> | undefined;
  const safety = result.metadata.safety as Record<string, unknown> | undefined;
  const entries = {
    profile: config?.profile,
    includeExternal: config?.includeExternal,
    noDestructive: config?.noDestructive ?? safety?.noDestructive,
    rateLimitRps: config?.rateLimitRps ?? safety?.rateLimitRps,
    timeoutMs: config?.timeoutMs,
    maxCrawlDepth: config?.maxCrawlDepth,
    maxCrawlPages: config?.maxCrawlPages,
    refreshKev: config?.refreshKev,
    refreshEpss: config?.refreshEpss,
    apiSpecPath: config?.apiSpecPath
  };
  return Object.entries(entries)
    .filter(([, value]) => value !== undefined)
    .map(([key, value]) => `- ${key}: \`${String(value)}\``);
}

function coverageLines(coverage: CoverageReport): string[] {
  return [
    `Coverage model: \`${coverage.model}\``,
    "",
    "| Standard | ID | Name | Status | Findings | Notes |",
    "| --- | --- | --- | --- | ---: | --- |",
    ...coverage.matrix.map((item) =>
      `| ${item.standard} | \`${item.id}\` | ${escapeTable(item.name)} | \`${item.status}\` | ${item.relatedFindings} | ${escapeTable(item.notes)} |`
    ),
    "",
    "Known gaps:",
    ...coverage.knownGaps.map((gap) => `- ${gap}`)
  ];
}

function suppressedLines(result: ScanResult): string[] {
  const suppressed = result.metadata.suppressedFindings;
  if (!Array.isArray(suppressed) || suppressed.length === 0) {
    return ["No findings were suppressed."];
  }
  return suppressed.map((item) => {
    const record = item as Record<string, unknown>;
    return `- \`${record.id}\` at \`${record.file}:${record.line}\`: ${record.reason}`;
  });
}

function coverageFor(result: ScanResult, findings: ReturnType<typeof sanitizeFindingsForReport>): CoverageReport {
  const coverage = result.metadata.coverage as CoverageReport | undefined;
  return coverage ?? buildCoverageReport(findings);
}

function escapeTable(value: string): string {
  return value.replaceAll("|", "\\|");
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
